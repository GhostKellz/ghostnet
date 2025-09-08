//! NATS - Neural Autonomic Transport System
//! High-performance publish/subscribe messaging system

const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");
const tcp = @import("../transport/tcp.zig");
const errors = @import("../errors/errors.zig");
const tls = @import("../crypto/handshake.zig");

/// NATS connection options
pub const ConnectOptions = struct {
    name: ?[]const u8 = null,
    user: ?[]const u8 = null,
    pass: ?[]const u8 = null,
    token: ?[]const u8 = null,
    verbose: bool = false,
    pedantic: bool = false,
    tls_required: bool = false,
    auth_token: ?[]const u8 = null,
    timeout: u64 = 2000, // milliseconds
    ping_interval: u64 = 120000, // 2 minutes
    max_reconnect: u32 = 60,
    reconnect_wait: u64 = 2000,
    max_pending_msgs: usize = 65536,
    max_pending_bytes: usize = 65536 * 1024,
};

/// NATS message
pub const Message = struct {
    subject: []const u8,
    reply: ?[]const u8,
    data: []const u8,
    headers: ?std.StringHashMap([]const u8) = null,
    
    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        allocator.free(self.subject);
        if (self.reply) |reply| {
            allocator.free(reply);
        }
        allocator.free(self.data);
        
        if (self.headers) |*headers| {
            var it = headers.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            headers.deinit();
        }
    }
};

/// NATS subscription
pub const Subscription = struct {
    id: u64,
    subject: []const u8,
    queue_group: ?[]const u8,
    handler: *const fn (Message) void,
    max_msgs: ?u64 = null,
    delivered: u64 = 0,
    
    pub fn deinit(self: *Subscription, allocator: std.mem.Allocator) void {
        allocator.free(self.subject);
        if (self.queue_group) |queue| {
            allocator.free(queue);
        }
    }
};

/// NATS protocol operations
const NatsOp = enum {
    CONNECT,
    PUB,
    SUB,
    UNSUB,
    MSG,
    PING,
    PONG,
    INFO,
    OK,
    ERR,
    HPUB, // Publish with headers
    HMSG, // Message with headers
};

/// NATS server info
pub const ServerInfo = struct {
    server_id: []const u8,
    server_name: []const u8,
    version: []const u8,
    proto: i32,
    host: []const u8,
    port: u16,
    max_payload: i64,
    auth_required: bool = false,
    tls_required: bool = false,
    tls_verify: bool = false,
    connect_urls: ?[][]const u8 = null,
    
    pub fn deinit(self: *ServerInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.server_name);
        allocator.free(self.version);
        allocator.free(self.host);
        
        if (self.connect_urls) |urls| {
            for (urls) |url| {
                allocator.free(url);
            }
            allocator.free(urls);
        }
    }
};

/// NATS client for pub/sub messaging
pub const NatsClient = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    connection: ?transport.Connection,
    options: ConnectOptions,
    connected: bool,
    server_info: ?ServerInfo,
    subscriptions: std.HashMap(u64, *Subscription, std.hash_map.DefaultContext(u64), std.hash_map.default_max_load_percentage),
    subscription_counter: u64,
    pending_requests: std.HashMap([]const u8, zsync.Promise(Message), std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    inbox_prefix: []u8,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, options: ConnectOptions) !*NatsClient {
        // Generate unique inbox prefix
        var rng = std.rand.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        var inbox_prefix = try std.fmt.allocPrint(allocator, "_INBOX.{d}", .{rng.random().int(u64)});
        
        var client = try allocator.create(NatsClient);
        client.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .connection = null,
            .options = options,
            .connected = false,
            .server_info = null,
            .subscriptions = @TypeOf(client.subscriptions).init(allocator),
            .subscription_counter = 1,
            .pending_requests = @TypeOf(client.pending_requests).init(allocator),
            .inbox_prefix = inbox_prefix,
        };
        return client;
    }
    
    pub fn deinit(self: *NatsClient) void {
        if (self.connected) {
            self.disconnect() catch {};
        }
        
        var sub_it = self.subscriptions.iterator();
        while (sub_it.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.subscriptions.deinit();
        
        var req_it = self.pending_requests.iterator();
        while (req_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.pending_requests.deinit();
        
        self.allocator.free(self.inbox_prefix);
        
        if (self.server_info) |*info| {
            info.deinit(self.allocator);
        }
        
        self.allocator.destroy(self);
    }
    
    pub fn connect(self: *NatsClient, address: transport.Address, port: u16) !void {
        // Create TCP connection
        var tcp_transport = try tcp.TcpTransport.init(self.allocator, self.runtime);
        defer tcp_transport.deinit();
        
        const tcp_address = switch (address) {
            .ipv4 => |addr| transport.Address{ .ipv4 = std.net.Ip4Address.init(.{ addr.host[0], addr.host[1], addr.host[2], addr.host[3] }, port) },
            .ipv6 => |addr| transport.Address{ .ipv6 = std.net.Ip6Address.init(addr.host, port, 0, 0) },
            else => return error.InvalidAddress,
        };
        
        self.connection = try tcp_transport.connectAsync(tcp_address, .{}).get();
        
        // Read server INFO
        try self.readServerInfo();
        
        // Send CONNECT
        try self.sendConnect();
        
        // Wait for +OK
        try self.expectOK();
        
        self.connected = true;
        
        // Start message processing loop
        _ = zsync.spawn(self.messageLoop, .{});
        
        // Start ping loop
        _ = zsync.spawn(self.pingLoop, .{});
    }
    
    pub fn disconnect(self: *NatsClient) !void {
        if (!self.connected) return;
        
        self.connected = false;
        
        if (self.connection) |conn| {
            conn.close();
            self.connection = null;
        }
    }
    
    pub fn publish(self: *NatsClient, subject: []const u8, data: []const u8) !void {
        if (!self.connected) return error.NotConnected;
        
        const msg = try std.fmt.allocPrint(self.allocator, "PUB {s} {d}\r\n", .{ subject, data.len });
        defer self.allocator.free(msg);
        
        if (self.connection) |conn| {
            _ = try conn.writeAsync(msg).get();
            _ = try conn.writeAsync(data).get();
            _ = try conn.writeAsync("\r\n").get();
        }
    }
    
    pub fn publishWithReply(self: *NatsClient, subject: []const u8, reply: []const u8, data: []const u8) !void {
        if (!self.connected) return error.NotConnected;
        
        const msg = try std.fmt.allocPrint(self.allocator, "PUB {s} {s} {d}\r\n", .{ subject, reply, data.len });
        defer self.allocator.free(msg);
        
        if (self.connection) |conn| {
            _ = try conn.writeAsync(msg).get();
            _ = try conn.writeAsync(data).get();
            _ = try conn.writeAsync("\r\n").get();
        }
    }
    
    pub fn subscribe(self: *NatsClient, subject: []const u8, handler: *const fn (Message) void) !*Subscription {
        return self.subscribeWithQueue(subject, null, handler);
    }
    
    pub fn subscribeWithQueue(self: *NatsClient, subject: []const u8, queue_group: ?[]const u8, handler: *const fn (Message) void) !*Subscription {
        if (!self.connected) return error.NotConnected;
        
        const sub_id = self.subscription_counter;
        self.subscription_counter += 1;
        
        var subscription = try self.allocator.create(Subscription);
        subscription.* = .{
            .id = sub_id,
            .subject = try self.allocator.dupe(u8, subject),
            .queue_group = if (queue_group) |queue| try self.allocator.dupe(u8, queue) else null,
            .handler = handler,
        };
        
        try self.subscriptions.put(sub_id, subscription);
        
        // Send SUB command
        const msg = if (queue_group) |queue|
            try std.fmt.allocPrint(self.allocator, "SUB {s} {s} {d}\r\n", .{ subject, queue, sub_id })
        else
            try std.fmt.allocPrint(self.allocator, "SUB {s} {d}\r\n", .{ subject, sub_id });
        defer self.allocator.free(msg);
        
        if (self.connection) |conn| {
            _ = try conn.writeAsync(msg).get();
        }
        
        return subscription;
    }
    
    pub fn unsubscribe(self: *NatsClient, subscription: *Subscription) !void {
        if (!self.connected) return error.NotConnected;
        
        const msg = try std.fmt.allocPrint(self.allocator, "UNSUB {d}\r\n", .{subscription.id});
        defer self.allocator.free(msg);
        
        if (self.connection) |conn| {
            _ = try conn.writeAsync(msg).get();
        }
        
        _ = self.subscriptions.remove(subscription.id);
        subscription.deinit(self.allocator);
        self.allocator.destroy(subscription);
    }
    
    pub fn request(self: *NatsClient, subject: []const u8, data: []const u8, timeout_ms: u64) zsync.Future(errors.GhostnetError!Message) {
        return self.runtime.async(struct {
            client: *NatsClient,
            subj: []const u8,
            payload: []const u8,
            timeout: u64,
            
            pub fn run(args: @This()) errors.GhostnetError!Message {
                if (!args.client.connected) return error.NotConnected;
                
                // Generate unique inbox
                var rng = std.rand.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
                const inbox = try std.fmt.allocPrint(args.client.allocator, "{s}.{d}", .{ args.client.inbox_prefix, rng.random().int(u64) });
                defer args.client.allocator.free(inbox);
                
                // Create promise for response
                var promise = zsync.Promise(Message).init();
                try args.client.pending_requests.put(try args.client.allocator.dupe(u8, inbox), promise);
                
                // Subscribe to inbox
                const subscription = try args.client.subscribe(inbox, struct {
                    fn handler(msg: Message) void {
                        // This would need access to the promise to fulfill it
                        _ = msg;
                    }
                }.handler);
                
                // Publish request
                try args.client.publishWithReply(args.subj, inbox, args.payload);
                
                // Wait for response with timeout
                const response = promise.future().getWithTimeout(args.timeout * std.time.ns_per_ms) catch |err| switch (err) {
                    error.Timeout => return error.RequestTimeout,
                    else => return err,
                };
                
                // Cleanup
                try args.client.unsubscribe(subscription);
                _ = args.client.pending_requests.remove(inbox);
                
                return response;
            }
        }{ .client = self, .subj = subject, .payload = data, .timeout = timeout_ms });
    }
    
    fn readServerInfo(self: *NatsClient) !void {
        var buffer: [4096]u8 = undefined;
        
        if (self.connection) |conn| {
            const bytes_read = try conn.readAsync(&buffer).get();
            const data = buffer[0..bytes_read];
            
            if (!std.mem.startsWith(u8, data, "INFO ")) {
                return error.InvalidServerInfo;
            }
            
            const json_start = std.mem.indexOf(u8, data, "{") orelse return error.InvalidServerInfo;
            const json_end = std.mem.lastIndexOf(u8, data, "}") orelse return error.InvalidServerInfo;
            const json_data = data[json_start..json_end + 1];
            
            // Parse JSON (simplified - real implementation would use proper JSON parser)
            self.server_info = try self.parseServerInfo(json_data);
        }
    }
    
    fn parseServerInfo(self: *NatsClient, json_data: []const u8) !ServerInfo {
        // Simplified JSON parsing - real implementation would use json parser
        _ = json_data;
        
        return ServerInfo{
            .server_id = try self.allocator.dupe(u8, "test-server"),
            .server_name = try self.allocator.dupe(u8, "nats-server"),
            .version = try self.allocator.dupe(u8, "2.0.0"),
            .proto = 1,
            .host = try self.allocator.dupe(u8, "localhost"),
            .port = 4222,
            .max_payload = 1048576,
        };
    }
    
    fn sendConnect(self: *NatsClient) !void {
        var connect_obj = std.json.ObjectMap.init(self.allocator);
        defer connect_obj.deinit();
        
        try connect_obj.put("verbose", .{ .bool = self.options.verbose });
        try connect_obj.put("pedantic", .{ .bool = self.options.pedantic });
        try connect_obj.put("tls_required", .{ .bool = self.options.tls_required });
        try connect_obj.put("auth_token", if (self.options.auth_token) |token| .{ .string = token } else .null);
        try connect_obj.put("name", if (self.options.name) |name| .{ .string = name } else .null);
        try connect_obj.put("lang", .{ .string = "zig" });
        try connect_obj.put("version", .{ .string = "0.1.0" });
        try connect_obj.put("protocol", .{ .integer = 1 });
        
        if (self.options.user) |user| {
            try connect_obj.put("user", .{ .string = user });
        }
        if (self.options.pass) |pass| {
            try connect_obj.put("pass", .{ .string = pass });
        }
        
        var json_string = std.ArrayList(u8).init(self.allocator);
        defer json_string.deinit();
        
        try std.json.stringify(connect_obj, .{}, json_string.writer());
        
        const connect_msg = try std.fmt.allocPrint(self.allocator, "CONNECT {s}\r\n", .{json_string.items});
        defer self.allocator.free(connect_msg);
        
        if (self.connection) |conn| {
            _ = try conn.writeAsync(connect_msg).get();
        }
    }
    
    fn expectOK(self: *NatsClient) !void {
        var buffer: [16]u8 = undefined;
        
        if (self.connection) |conn| {
            const bytes_read = try conn.readAsync(&buffer).get();
            const data = buffer[0..bytes_read];
            
            if (!std.mem.startsWith(u8, data, "+OK")) {
                if (std.mem.startsWith(u8, data, "-ERR")) {
                    return error.ServerError;
                }
                return error.UnexpectedResponse;
            }
        }
    }
    
    fn messageLoop(self: *NatsClient) void {
        while (self.connected) {
            self.processMessage() catch |err| switch (err) {
                error.ConnectionClosed => break,
                else => continue,
            };
        }
    }
    
    fn processMessage(self: *NatsClient) !void {
        var buffer: [4096]u8 = undefined;
        
        if (self.connection) |conn| {
            const bytes_read = try conn.readAsync(&buffer).get();
            const data = buffer[0..bytes_read];
            
            var lines = std.mem.split(u8, data, "\r\n");
            while (lines.next()) |line| {
                if (line.len == 0) continue;
                
                if (std.mem.startsWith(u8, line, "MSG ")) {
                    try self.handleMessage(line);
                } else if (std.mem.startsWith(u8, line, "PING")) {
                    try self.handlePing();
                } else if (std.mem.startsWith(u8, line, "PONG")) {
                    // Pong received, nothing to do
                } else if (std.mem.startsWith(u8, line, "+OK")) {
                    // OK received, nothing to do
                } else if (std.mem.startsWith(u8, line, "-ERR")) {
                    std.log.err("NATS server error: {s}", .{line});
                }
            }
        }
    }
    
    fn handleMessage(self: *NatsClient, msg_line: []const u8) !void {
        // Parse MSG line: MSG <subject> <sid> [reply-to] <#bytes>
        var parts = std.mem.split(u8, msg_line, " ");
        _ = parts.next(); // Skip "MSG"
        
        const subject = parts.next() orelse return error.InvalidMessage;
        const sid_str = parts.next() orelse return error.InvalidMessage;
        const sid = try std.fmt.parseInt(u64, sid_str, 10);
        
        const maybe_reply = parts.next();
        const maybe_bytes = parts.next();
        
        const (reply, bytes_str) = if (maybe_bytes) |bytes| 
            (.{ .reply = maybe_reply, .bytes = bytes })
        else 
            (.{ .reply = null, .bytes = maybe_reply orelse return error.InvalidMessage });
        
        const payload_size = try std.fmt.parseInt(usize, bytes_str, 10);
        
        // Read payload
        var payload = try self.allocator.alloc(u8, payload_size);
        
        if (self.connection) |conn| {
            _ = try conn.readAsync(payload).get();
        }
        
        // Find subscription and call handler
        if (self.subscriptions.get(sid)) |subscription| {
            const message = Message{
                .subject = try self.allocator.dupe(u8, subject),
                .reply = if (reply.reply) |r| try self.allocator.dupe(u8, r) else null,
                .data = payload,
            };
            
            subscription.handler(message);
            subscription.delivered += 1;
            
            // Auto-unsubscribe if max messages reached
            if (subscription.max_msgs) |max| {
                if (subscription.delivered >= max) {
                    try self.unsubscribe(subscription);
                }
            }
        } else {
            // No subscription found, free payload
            self.allocator.free(payload);
        }
    }
    
    fn handlePing(self: *NatsClient) !void {
        if (self.connection) |conn| {
            _ = try conn.writeAsync("PONG\r\n").get();
        }
    }
    
    fn pingLoop(self: *NatsClient) void {
        while (self.connected) {
            zsync.sleep(self.options.ping_interval * std.time.ns_per_ms) catch continue;
            
            if (self.connection) |conn| {
                conn.writeAsync("PING\r\n").get() catch break;
            }
        }
    }
};