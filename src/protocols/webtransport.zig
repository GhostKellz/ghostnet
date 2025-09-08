//! WebTransport - Modern web transport protocol over HTTP/3
//! Provides bidirectional streams, datagrams, and low-latency communication

const std = @import("std");
const zsync = @import("zsync");
const http3 = @import("http3.zig"); // Would need HTTP/3 implementation
const quic = @import("quic.zig");
const transport = @import("../transport/transport.zig");
const errors = @import("../errors/errors.zig");

/// WebTransport session state
pub const SessionState = enum {
    connecting,
    connected,
    closing,
    closed,
    failed,
};

/// WebTransport stream type
pub const StreamType = enum {
    unidirectional,
    bidirectional,
};

/// WebTransport stream direction
pub const StreamDirection = enum {
    send,
    receive,
    bidirectional,
};

/// WebTransport close info
pub const CloseInfo = struct {
    code: u32,
    reason: []const u8,
    
    pub fn deinit(self: *CloseInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.reason);
    }
};

/// WebTransport connection options
pub const ConnectionOptions = struct {
    server_certificate_hashes: ?[][]const u8 = null,
    congestion_control: ?[]const u8 = null,
    require_unreliable: bool = false,
    protocols: ?[][]const u8 = null,
    timeout: u64 = 30000, // milliseconds
};

/// WebTransport datagram
pub const Datagram = struct {
    data: []const u8,
    timestamp: i64,
    
    pub fn deinit(self: *Datagram, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

/// WebTransport stream
pub const WebTransportStream = struct {
    allocator: std.mem.Allocator,
    id: u64,
    stream_type: StreamType,
    direction: StreamDirection,
    quic_stream: quic.QuicStream,
    readable: bool,
    writable: bool,
    
    pub fn init(
        allocator: std.mem.Allocator,
        id: u64,
        stream_type: StreamType,
        direction: StreamDirection,
        quic_stream: quic.QuicStream
    ) WebTransportStream {
        return .{
            .allocator = allocator,
            .id = id,
            .stream_type = stream_type,
            .direction = direction,
            .quic_stream = quic_stream,
            .readable = direction == .receive or direction == .bidirectional,
            .writable = direction == .send or direction == .bidirectional,
        };
    }
    
    pub fn write(self: *WebTransportStream, data: []const u8) !usize {
        if (!self.writable) return error.NotWritable;
        
        return try self.quic_stream.write(data);
    }
    
    pub fn writeAsync(self: *WebTransportStream, data: []const u8) zsync.Future(errors.GhostnetError!usize) {
        return self.quic_stream.writeAsync(data);
    }
    
    pub fn read(self: *WebTransportStream, buffer: []u8) !usize {
        if (!self.readable) return error.NotReadable;
        
        return try self.quic_stream.read(buffer);
    }
    
    pub fn readAsync(self: *WebTransportStream, buffer: []u8) zsync.Future(errors.GhostnetError!usize) {
        return self.quic_stream.readAsync(buffer);
    }
    
    pub fn close(self: *WebTransportStream) void {
        self.quic_stream.close();
        self.readable = false;
        self.writable = false;
    }
    
    pub fn abort(self: *WebTransportStream, error_code: u64) void {
        self.quic_stream.reset(error_code);
        self.readable = false;
        self.writable = false;
    }
    
    pub fn getState(self: *WebTransportStream) quic.StreamState {
        return self.quic_stream.getState();
    }
    
    pub fn writer(self: *WebTransportStream) Writer {
        return .{ .context = self };
    }
    
    pub fn reader(self: *WebTransportStream) Reader {
        return .{ .context = self };
    }
    
    pub const Writer = std.io.Writer(*WebTransportStream, error{NotWritable}, write);
    pub const Reader = std.io.Reader(*WebTransportStream, error{NotReadable}, read);
};

/// WebTransport session
pub const WebTransportSession = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    quic_connection: quic.QuicConnection,
    state: SessionState,
    url: []const u8,
    options: ConnectionOptions,
    streams: std.HashMap(u64, *WebTransportStream, std.hash_map.DefaultContext(u64), std.hash_map.default_max_load_percentage),
    stream_counter: u64,
    datagram_handlers: std.ArrayList(*const fn (Datagram) void),
    stream_handlers: std.ArrayList(*const fn (*WebTransportStream) void),
    close_handlers: std.ArrayList(*const fn (CloseInfo) void),
    
    pub fn init(
        allocator: std.mem.Allocator,
        runtime: *zsync.Runtime,
        url: []const u8,
        options: ConnectionOptions
    ) !*WebTransportSession {
        var session = try allocator.create(WebTransportSession);
        session.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .quic_connection = undefined, // Will be initialized in connect()
            .state = .connecting,
            .url = try allocator.dupe(u8, url),
            .options = options,
            .streams = @TypeOf(session.streams).init(allocator),
            .stream_counter = 1,
            .datagram_handlers = std.ArrayList(*const fn (Datagram) void).init(allocator),
            .stream_handlers = std.ArrayList(*const fn (*WebTransportStream) void).init(allocator),
            .close_handlers = std.ArrayList(*const fn (CloseInfo) void).init(allocator),
        };
        return session;
    }
    
    pub fn deinit(self: *WebTransportSession) void {
        if (self.state == .connected) {
            self.close(.{ .code = 0, .reason = "Session terminated" });
        }
        
        // Clean up streams
        var stream_it = self.streams.iterator();
        while (stream_it.next()) |entry| {
            entry.value_ptr.*.close();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.streams.deinit();
        
        self.datagram_handlers.deinit();
        self.stream_handlers.deinit();
        self.close_handlers.deinit();
        self.allocator.free(self.url);
        self.allocator.destroy(self);
    }
    
    /// Connect to WebTransport server
    pub fn connect(self: *WebTransportSession) zsync.Future(errors.GhostnetError!void) {
        return self.runtime.async(struct {
            session: *WebTransportSession,
            
            pub fn run(args: @This()) errors.GhostnetError!void {
                const session = args.session;
                
                // Parse URL to extract host and port
                const uri = std.Uri.parse(session.url) catch return error.InvalidUrl;
                
                if (!std.mem.eql(u8, uri.scheme, "https")) {
                    return error.InvalidScheme;
                }
                
                const host = uri.host orelse return error.MissingHost;
                const port = uri.port orelse 443;
                
                const host_str = switch (host) {
                    .percent_encoded => |h| h,
                    .raw => |h| h,
                };
                
                // Establish QUIC connection
                const quic_config = quic.QuicConfig{
                    .alpn_protocols = &[_][]const u8{"h3"},
                    .enable_webtransport = true,
                };
                
                var quic_client = try quic.QuicClient.init(session.allocator, session.runtime, quic_config);
                defer quic_client.deinit();
                
                const address = try std.net.Address.resolveIp(host_str, port);
                const transport_addr = switch (address.any.family) {
                    std.posix.AF.INET => transport.Address{ .ipv4 = address.in },
                    std.posix.AF.INET6 => transport.Address{ .ipv6 = address.in6 },
                    else => return error.UnsupportedAddressFamily,
                };
                
                session.quic_connection = try quic_client.connectAsync(transport_addr).get();
                
                // Send WebTransport handshake over HTTP/3
                try session.performHandshake();
                
                session.state = .connected;
                
                // Start event loop
                _ = zsync.spawn(session.eventLoop, .{});
            }
        }{ .session = self });
    }
    
    /// Close the WebTransport session
    pub fn close(self: *WebTransportSession, close_info: CloseInfo) void {
        if (self.state == .closed or self.state == .closing) return;
        
        self.state = .closing;
        
        // Close all streams
        var stream_it = self.streams.iterator();
        while (stream_it.next()) |entry| {
            entry.value_ptr.*.close();
        }
        
        // Send close frame
        self.sendCloseFrame(close_info) catch {};
        
        // Close QUIC connection
        self.quic_connection.close();
        
        self.state = .closed;
        
        // Notify close handlers
        for (self.close_handlers.items) |handler| {
            handler(close_info);
        }
    }
    
    /// Create outgoing unidirectional stream
    pub fn createUnidirectionalStream(self: *WebTransportSession) !*WebTransportStream {
        if (self.state != .connected) return error.NotConnected;
        
        const quic_stream = try self.quic_connection.createUnidirectionalStream();
        const stream_id = self.stream_counter;
        self.stream_counter += 1;
        
        var stream = try self.allocator.create(WebTransportStream);
        stream.* = WebTransportStream.init(
            self.allocator,
            stream_id,
            .unidirectional,
            .send,
            quic_stream
        );
        
        try self.streams.put(stream_id, stream);
        return stream;
    }
    
    /// Create outgoing bidirectional stream
    pub fn createBidirectionalStream(self: *WebTransportSession) !*WebTransportStream {
        if (self.state != .connected) return error.NotConnected;
        
        const quic_stream = try self.quic_connection.createBidirectionalStream();
        const stream_id = self.stream_counter;
        self.stream_counter += 1;
        
        var stream = try self.allocator.create(WebTransportStream);
        stream.* = WebTransportStream.init(
            self.allocator,
            stream_id,
            .bidirectional,
            .bidirectional,
            quic_stream
        );
        
        try self.streams.put(stream_id, stream);
        return stream;
    }
    
    /// Send datagram
    pub fn sendDatagram(self: *WebTransportSession, data: []const u8) !void {
        if (self.state != .connected) return error.NotConnected;
        
        try self.quic_connection.sendDatagram(data);
    }
    
    /// Send datagram asynchronously
    pub fn sendDatagramAsync(self: *WebTransportSession, data: []const u8) zsync.Future(errors.GhostnetError!void) {
        return self.quic_connection.sendDatagramAsync(data);
    }
    
    /// Add datagram handler
    pub fn onDatagram(self: *WebTransportSession, handler: *const fn (Datagram) void) !void {
        try self.datagram_handlers.append(handler);
    }
    
    /// Add incoming stream handler
    pub fn onIncomingStream(self: *WebTransportSession, handler: *const fn (*WebTransportStream) void) !void {
        try self.stream_handlers.append(handler);
    }
    
    /// Add close handler
    pub fn onClose(self: *WebTransportSession, handler: *const fn (CloseInfo) void) !void {
        try self.close_handlers.append(handler);
    }
    
    /// Get session statistics
    pub fn getStats(self: *WebTransportSession) WebTransportStats {
        const quic_stats = self.quic_connection.getStats();
        
        return WebTransportStats{
            .bytes_sent = quic_stats.bytes_sent,
            .bytes_received = quic_stats.bytes_received,
            .datagrams_sent = quic_stats.datagrams_sent,
            .datagrams_received = quic_stats.datagrams_received,
            .streams_created = self.stream_counter - 1,
            .streams_active = self.streams.count(),
            .round_trip_time = quic_stats.rtt,
        };
    }
    
    fn performHandshake(self: *WebTransportSession) !void {
        // WebTransport handshake over HTTP/3
        // This is simplified - real implementation would need full HTTP/3 support
        
        // Send HTTP/3 request with WebTransport upgrade
        const request_headers = try std.fmt.allocPrint(self.allocator,
            ":method: CONNECT\r\n" ++
            ":protocol: webtransport\r\n" ++
            ":scheme: https\r\n" ++
            ":path: {s}\r\n" ++
            ":authority: {s}\r\n" ++
            "sec-webtransport-http3-draft: draft02\r\n" ++
            "\r\n",
            .{ self.getPathFromUrl(), self.getHostFromUrl() }
        );
        defer self.allocator.free(request_headers);
        
        // Send handshake data over control stream
        const control_stream = try self.quic_connection.getControlStream();
        try control_stream.write(request_headers);
        
        // Wait for response
        var response_buffer: [1024]u8 = undefined;
        const response_len = try control_stream.read(&response_buffer);
        const response = response_buffer[0..response_len];
        
        // Parse response (simplified)
        if (!std.mem.containsAtLeast(u8, response, 1, "200")) {
            return error.HandshakeFailed;
        }
    }
    
    fn eventLoop(self: *WebTransportSession) void {
        while (self.state == .connected) {
            self.processEvents() catch |err| {
                std.log.err("WebTransport event loop error: {}", .{err});
                break;
            };
        }
    }
    
    fn processEvents(self: *WebTransportSession) !void {
        // Check for incoming streams
        if (self.quic_connection.acceptIncomingStream()) |quic_stream| {
            const stream_id = self.stream_counter;
            self.stream_counter += 1;
            
            // Determine stream type and direction
            const stream_type = if (quic_stream.isBidirectional()) StreamType.bidirectional else StreamType.unidirectional;
            const direction = if (stream_type == .bidirectional) StreamDirection.bidirectional else StreamDirection.receive;
            
            var stream = try self.allocator.create(WebTransportStream);
            stream.* = WebTransportStream.init(
                self.allocator,
                stream_id,
                stream_type,
                direction,
                quic_stream
            );
            
            try self.streams.put(stream_id, stream);
            
            // Notify stream handlers
            for (self.stream_handlers.items) |handler| {
                handler(stream);
            }
        } else |err| switch (err) {
            error.NoIncomingStream => {},
            else => return err,
        }
        
        // Check for incoming datagrams
        var datagram_buffer: [65536]u8 = undefined;
        if (self.quic_connection.receiveDatagram(&datagram_buffer)) |datagram_data| {
            const datagram = Datagram{
                .data = try self.allocator.dupe(u8, datagram_data),
                .timestamp = std.time.milliTimestamp(),
            };
            
            // Notify datagram handlers
            for (self.datagram_handlers.items) |handler| {
                handler(datagram);
            }
        } else |err| switch (err) {
            error.NoDatagram => {},
            else => return err,
        }
        
        // Small delay to avoid busy loop
        zsync.sleep(1_000_000) catch {}; // 1ms
    }
    
    fn sendCloseFrame(self: *WebTransportSession, close_info: CloseInfo) !void {
        // Send WebTransport close frame
        const close_data = try std.fmt.allocPrint(self.allocator, "CLOSE {d} {s}", .{ close_info.code, close_info.reason });
        defer self.allocator.free(close_data);
        
        // Send over control stream
        if (self.quic_connection.getControlStream()) |control_stream| {
            try control_stream.write(close_data);
        } else |_| {
            // Control stream not available, close QUIC connection directly
        }
    }
    
    fn getHostFromUrl(self: *WebTransportSession) []const u8 {
        const uri = std.Uri.parse(self.url) catch return "localhost";
        const host = uri.host orelse return "localhost";
        return switch (host) {
            .percent_encoded => |h| h,
            .raw => |h| h,
        };
    }
    
    fn getPathFromUrl(self: *WebTransportSession) []const u8 {
        const uri = std.Uri.parse(self.url) catch return "/";
        return uri.path;
    }
};

/// WebTransport statistics
pub const WebTransportStats = struct {
    bytes_sent: u64,
    bytes_received: u64,
    datagrams_sent: u64,
    datagrams_received: u64,
    streams_created: u64,
    streams_active: u32,
    round_trip_time: u64, // microseconds
};

/// WebTransport server
pub const WebTransportServer = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    quic_server: quic.QuicServer,
    sessions: std.ArrayList(*WebTransportSession),
    session_handlers: std.ArrayList(*const fn (*WebTransportSession) void),
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) !*WebTransportServer {
        var server = try allocator.create(WebTransportServer);
        server.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .quic_server = try quic.QuicServer.init(allocator, runtime),
            .sessions = std.ArrayList(*WebTransportSession).init(allocator),
            .session_handlers = std.ArrayList(*const fn (*WebTransportSession) void).init(allocator),
        };
        return server;
    }
    
    pub fn deinit(self: *WebTransportServer) void {
        // Close all sessions
        for (self.sessions.items) |session| {
            session.close(.{ .code = 0, .reason = "Server shutdown" });
            session.deinit();
        }
        self.sessions.deinit();
        
        self.session_handlers.deinit();
        self.quic_server.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn listen(self: *WebTransportServer, address: transport.Address, port: u16) !void {
        try self.quic_server.bind(address, port);
        try self.quic_server.listen();
        
        _ = zsync.spawn(self.acceptLoop, .{});
    }
    
    pub fn onSession(self: *WebTransportServer, handler: *const fn (*WebTransportSession) void) !void {
        try self.session_handlers.append(handler);
    }
    
    fn acceptLoop(self: *WebTransportServer) void {
        while (true) {
            const quic_connection = self.quic_server.accept() catch |err| {
                std.log.err("Failed to accept QUIC connection: {}", .{err});
                continue;
            };
            
            _ = zsync.spawn(self.handleConnection, .{quic_connection});
        }
    }
    
    fn handleConnection(self: *WebTransportServer, quic_connection: quic.QuicConnection) void {
        // Create WebTransport session
        const session = self.allocator.create(WebTransportSession) catch return;
        session.* = .{
            .allocator = self.allocator,
            .runtime = self.runtime,
            .quic_connection = quic_connection,
            .state = .connected,
            .url = self.allocator.dupe(u8, "/") catch return,
            .options = .{},
            .streams = @TypeOf(session.streams).init(self.allocator),
            .stream_counter = 1,
            .datagram_handlers = std.ArrayList(*const fn (Datagram) void).init(self.allocator),
            .stream_handlers = std.ArrayList(*const fn (*WebTransportStream) void).init(self.allocator),
            .close_handlers = std.ArrayList(*const fn (CloseInfo) void).init(self.allocator),
        };
        
        self.sessions.append(session) catch return;
        
        // Notify session handlers
        for (self.session_handlers.items) |handler| {
            handler(session);
        }
        
        // Start session event loop
        session.eventLoop();
        
        // Clean up after session ends
        for (self.sessions.items, 0..) |s, i| {
            if (s == session) {
                _ = self.sessions.orderedRemove(i);
                break;
            }
        }
        session.deinit();
    }
};