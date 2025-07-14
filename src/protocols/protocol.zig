const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");
const errors = @import("../errors/errors.zig");

pub const ProtocolType = enum {
    tcp,
    udp,
    quic,
    wireguard,
    tls,
    noise,
    websocket,
    http,
    gossip,
    kademlia,
    mdns,
    mqtt,
    coap,
    custom,
};

pub const ProtocolInfo = struct {
    name: []const u8,
    version: []const u8,
    protocol_type: ProtocolType,
    description: []const u8,
    default_port: ?u16 = null,
    requires_encryption: bool = false,
    supports_multiplexing: bool = false,
    is_connection_oriented: bool = true,
};

pub const ProtocolCapabilities = struct {
    reliable_delivery: bool = false,
    ordered_delivery: bool = false,
    flow_control: bool = false,
    congestion_control: bool = false,
    multiplexing: bool = false,
    bidirectional: bool = true,
    secure_by_default: bool = false,
    supports_broadcast: bool = false,
    supports_multicast: bool = false,
    zero_copy: bool = false,
    connection_pooling: bool = false,
};

pub const Message = struct {
    data: []const u8,
    sender: ?transport.Address = null,
    recipient: ?transport.Address = null,
    message_type: u32 = 0,
    flags: u32 = 0,
    timestamp: i64,
    metadata: ?std.json.Value = null,
    
    pub fn init(data: []const u8) Message {
        return .{
            .data = data,
            .timestamp = std.time.timestamp(),
        };
    }
};

pub const ProtocolHandler = struct {
    const Self = @This();
    
    pub const VTable = struct {
        handle_message: *const fn (self: *anyopaque, message: Message) zsync.Future,
        handle_connection: *const fn (self: *anyopaque, connection: transport.Connection) zsync.Future,
        handle_error: *const fn (self: *anyopaque, err: errors.ErrorContext) void,
        get_info: *const fn (self: *anyopaque) ProtocolInfo,
        get_capabilities: *const fn (self: *anyopaque) ProtocolCapabilities,
        configure: *const fn (self: *anyopaque, config: std.json.Value) errors.GhostnetError!void,
        start: *const fn (self: *anyopaque) zsync.Future,
        stop: *const fn (self: *anyopaque) zsync.Future,
        get_stats: *const fn (self: *anyopaque) std.json.Value,
    };
    
    ptr: *anyopaque,
    vtable: *const VTable,
    
    pub fn handleMessage(self: Self, message: Message) zsync.Future(errors.GhostnetError!void) {
        return self.vtable.handle_message(self.ptr, message);
    }
    
    pub fn handleConnection(self: Self, connection: transport.Connection) zsync.Future(errors.GhostnetError!void) {
        return self.vtable.handle_connection(self.ptr, connection);
    }
    
    pub fn handleError(self: Self, err: errors.ErrorContext) void {
        self.vtable.handle_error(self.ptr, err);
    }
    
    pub fn getInfo(self: Self) ProtocolInfo {
        return self.vtable.get_info(self.ptr);
    }
    
    pub fn getCapabilities(self: Self) ProtocolCapabilities {
        return self.vtable.get_capabilities(self.ptr);
    }
    
    pub fn configure(self: Self, config: std.json.Value) errors.GhostnetError!void {
        return self.vtable.configure(self.ptr, config);
    }
    
    pub fn start(self: Self) zsync.Future(errors.GhostnetError!void) {
        return self.vtable.start(self.ptr);
    }
    
    pub fn stop(self: Self) zsync.Future(void) {
        return self.vtable.stop(self.ptr);
    }
    
    pub fn getStats(self: Self) std.json.Value {
        return self.vtable.get_stats(self.ptr);
    }
};

pub const ProtocolRegistry = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    protocols: std.StringHashMap(ProtocolHandler),
    type_map: std.AutoHashMap(ProtocolType, []const u8),
    port_map: std.AutoHashMap(u16, []const u8),
    message_handlers: std.StringHashMap(std.ArrayList(ProtocolHandler)),
    middleware: std.ArrayList(MiddlewareHandler),
    stats: RegistryStats,
    mutex: std.Thread.Mutex,
    
    pub const RegistryStats = struct {
        total_protocols: std.atomic.Value(u32),
        active_protocols: std.atomic.Value(u32),
        messages_processed: std.atomic.Value(u64),
        errors_encountered: std.atomic.Value(u64),
        average_message_time: std.atomic.Value(u64),
    };
    
    pub const MiddlewareHandler = struct {
        const MwSelf = @This();
        
        pub const VTable = struct {
            process_inbound: *const fn (self: *anyopaque, message: *Message) zsync.Future,
            process_outbound: *const fn (self: *anyopaque, message: *Message) zsync.Future,
            name: *const fn (self: *anyopaque) []const u8,
            priority: *const fn (self: *anyopaque) i32,
        };
        
        ptr: *anyopaque,
        vtable: *const VTable,
        
        pub fn processInbound(self: MwSelf, message: *Message) zsync.Future(errors.GhostnetError!void) {
            return self.vtable.process_inbound(self.ptr, message);
        }
        
        pub fn processOutbound(self: MwSelf, message: *Message) zsync.Future(errors.GhostnetError!void) {
            return self.vtable.process_outbound(self.ptr, message);
        }
        
        pub fn name(self: MwSelf) []const u8 {
            return self.vtable.name(self.ptr);
        }
        
        pub fn priority(self: MwSelf) i32 {
            return self.vtable.priority(self.ptr);
        }
    };
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) !*ProtocolRegistry {
        const registry = try allocator.create(ProtocolRegistry);
        errdefer allocator.destroy(registry);
        
        registry.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .protocols = std.StringHashMap(ProtocolHandler).init(allocator),
            .type_map = std.AutoHashMap(ProtocolType, []const u8).init(allocator),
            .port_map = std.AutoHashMap(u16, []const u8).init(allocator),
            .message_handlers = std.StringHashMap(std.ArrayList(ProtocolHandler)).init(allocator),
            .middleware = std.ArrayList(MiddlewareHandler).init(allocator),
            .stats = .{
                .total_protocols = std.atomic.Value(u32).init(0),
                .active_protocols = std.atomic.Value(u32).init(0),
                .messages_processed = std.atomic.Value(u64).init(0),
                .errors_encountered = std.atomic.Value(u64).init(0),
                .average_message_time = std.atomic.Value(u64).init(0),
            },
            .mutex = .{},
        };
        
        return registry;
    }
    
    pub fn deinit(self: *ProtocolRegistry) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Stop all protocols
        var iter = self.protocols.iterator();
        while (iter.next()) |entry| {
            _ = entry.value_ptr.stop();
        }
        
        self.protocols.deinit();
        self.type_map.deinit();
        self.port_map.deinit();
        
        var msg_iter = self.message_handlers.iterator();
        while (msg_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.message_handlers.deinit();
        
        self.middleware.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn register(self: *ProtocolRegistry, name: []const u8, handler: ProtocolHandler) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.protocols.contains(name)) {
            return error.ProtocolAlreadyRegistered;
        }
        
        const info = handler.getInfo();
        
        try self.protocols.put(name, handler);
        try self.type_map.put(info.protocol_type, name);
        
        if (info.default_port) |port| {
            try self.port_map.put(port, name);
        }
        
        _ = self.stats.total_protocols.fetchAdd(1, .SeqCst);
    }
    
    pub fn unregister(self: *ProtocolRegistry, name: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.protocols.fetchRemove(name)) |kv| {
            const info = kv.value.getInfo();
            _ = self.type_map.remove(info.protocol_type);
            
            if (info.default_port) |port| {
                _ = self.port_map.remove(port);
            }
            
            _ = kv.value.stop();
            _ = self.stats.total_protocols.fetchSub(1, .SeqCst);
        }
    }
    
    pub fn getProtocol(self: *ProtocolRegistry, name: []const u8) ?ProtocolHandler {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        return self.protocols.get(name);
    }
    
    pub fn getProtocolByType(self: *ProtocolRegistry, protocol_type: ProtocolType) ?ProtocolHandler {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.type_map.get(protocol_type)) |name| {
            return self.protocols.get(name);
        }
        return null;
    }
    
    pub fn getProtocolByPort(self: *ProtocolRegistry, port: u16) ?ProtocolHandler {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.port_map.get(port)) |name| {
            return self.protocols.get(name);
        }
        return null;
    }
    
    pub fn dispatchMessage(self: *ProtocolRegistry, protocol_name: []const u8, message: Message) zsync.Future(errors.GhostnetError!void) {
        return zsync.Future(errors.GhostnetError!void).init(self.runtime, struct {
            registry: *ProtocolRegistry,
            proto_name: []const u8,
            msg: Message,
            
            pub fn poll(ctx: *@This()) zsync.Poll(errors.GhostnetError!void) {
                ctx.registry.mutex.lock();
                defer ctx.registry.mutex.unlock();
                
                const start_time = std.time.nanoTimestamp();
                
                if (ctx.registry.protocols.get(ctx.proto_name)) |handler| {
                    var processed_msg = ctx.msg;
                    
                    // Process through middleware
                    for (ctx.registry.middleware.items) |middleware| {
                        switch (middleware.processInbound(&processed_msg)) {
                            .ready => |result| {
                                if (result) |_| {
                                    // Continue
                                } else |err| {
                                    _ = ctx.registry.stats.errors_encountered.fetchAdd(1, .SeqCst);
                                    return .{ .ready = err };
                                }
                            },
                            .pending => return .pending,
                        }
                    }
                    
                    // Handle the message
                    switch (handler.handleMessage(processed_msg)) {
                        .ready => |result| {
                            _ = ctx.registry.stats.messages_processed.fetchAdd(1, .SeqCst);
                            
                            const end_time = std.time.nanoTimestamp();
                            const duration: u64 = @intCast(end_time - start_time);
                            
                            // Update running average
                            const current_avg = ctx.registry.stats.average_message_time.load(.SeqCst);
                            const new_avg = (current_avg + duration) / 2;
                            ctx.registry.stats.average_message_time.store(new_avg, .SeqCst);
                            
                            return .{ .ready = result };
                        },
                        .pending => return .pending,
                    }
                } else {
                    return .{ .ready = errors.GhostnetError!void{ error.ProtocolNotFound } };
                }
            }
        }{ .registry = self, .proto_name = protocol_name, .msg = message });
    }
    
    pub fn addMiddleware(self: *ProtocolRegistry, middleware: MiddlewareHandler) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Insert in priority order
        const priority = middleware.priority();
        var insert_index: usize = 0;
        
        for (self.middleware.items, 0..) |existing, i| {
            if (priority > existing.priority()) {
                insert_index = i;
                break;
            }
        } else {
            insert_index = self.middleware.items.len;
        }
        
        try self.middleware.insert(insert_index, middleware);
    }
    
    pub fn removeMiddleware(self: *ProtocolRegistry, name: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var i: usize = 0;
        while (i < self.middleware.items.len) {
            if (std.mem.eql(u8, self.middleware.items[i].name(), name)) {
                _ = self.middleware.orderedRemove(i);
                return;
            }
            i += 1;
        }
    }
    
    pub fn startProtocol(self: *ProtocolRegistry, name: []const u8) zsync.Future(errors.GhostnetError!void) {
        return zsync.Future(errors.GhostnetError!void).init(self.runtime, struct {
            registry: *ProtocolRegistry,
            proto_name: []const u8,
            
            pub fn poll(ctx: *@This()) zsync.Poll(errors.GhostnetError!void) {
                ctx.registry.mutex.lock();
                defer ctx.registry.mutex.unlock();
                
                if (ctx.registry.protocols.get(ctx.proto_name)) |handler| {
                    switch (handler.start()) {
                        .ready => |result| {
                            if (result) |_| {
                                _ = ctx.registry.stats.active_protocols.fetchAdd(1, .SeqCst);
                            }
                            return .{ .ready = result };
                        },
                        .pending => return .pending,
                    }
                } else {
                    return .{ .ready = errors.GhostnetError!void{ error.ProtocolNotFound } };
                }
            }
        }{ .registry = self, .proto_name = name });
    }
    
    pub fn stopProtocol(self: *ProtocolRegistry, name: []const u8) zsync.Future(void) {
        return zsync.Future(void).init(self.runtime, struct {
            registry: *ProtocolRegistry,
            proto_name: []const u8,
            
            pub fn poll(ctx: *@This()) zsync.Poll(void) {
                ctx.registry.mutex.lock();
                defer ctx.registry.mutex.unlock();
                
                if (ctx.registry.protocols.get(ctx.proto_name)) |handler| {
                    switch (handler.stop()) {
                        .ready => |_| {
                            _ = ctx.registry.stats.active_protocols.fetchSub(1, .SeqCst);
                            return .{ .ready = {} };
                        },
                        .pending => return .pending,
                    }
                } else {
                    return .{ .ready = {} };
                }
            }
        }{ .registry = self, .proto_name = name });
    }
    
    pub fn getStats(self: *ProtocolRegistry) RegistryStats {
        return .{
            .total_protocols = std.atomic.Value(u32).init(self.stats.total_protocols.load(.SeqCst)),
            .active_protocols = std.atomic.Value(u32).init(self.stats.active_protocols.load(.SeqCst)),
            .messages_processed = std.atomic.Value(u64).init(self.stats.messages_processed.load(.SeqCst)),
            .errors_encountered = std.atomic.Value(u64).init(self.stats.errors_encountered.load(.SeqCst)),
            .average_message_time = std.atomic.Value(u64).init(self.stats.average_message_time.load(.SeqCst)),
        };
    }
    
    pub fn listProtocols(self: *ProtocolRegistry, allocator: std.mem.Allocator) ![]ProtocolInfo {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var infos = std.ArrayList(ProtocolInfo).init(allocator);
        
        var iter = self.protocols.iterator();
        while (iter.next()) |entry| {
            try infos.append(entry.value_ptr.getInfo());
        }
        
        return infos.toOwnedSlice();
    }
};