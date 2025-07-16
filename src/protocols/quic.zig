const std = @import("std");
const zsync = @import("zsync");
const zquic = @import("zquic");
const transport = @import("../transport/transport.zig");
const udp = @import("../transport/udp.zig");
const errors = @import("../errors/errors.zig");
const protocol = @import("protocol.zig");

pub const QuicConfig = struct {
    max_streams: u32 = 1000,
    max_stream_data: u64 = 1024 * 1024, // 1MB
    max_connection_data: u64 = 10 * 1024 * 1024, // 10MB
    idle_timeout: u64 = 30000, // 30 seconds
    keep_alive_interval: u64 = 5000, // 5 seconds
    max_ack_delay: u64 = 25, // 25ms
    ack_delay_exponent: u8 = 3,
    max_packet_size: u16 = 1200,
    initial_rtt: u32 = 100, // 100ms
    congestion_window: u32 = 10,
    enable_0rtt: bool = false,
    enable_migration: bool = true,
    certificate_file: ?[]const u8 = null,
    private_key_file: ?[]const u8 = null,
    alpn_protocols: []const []const u8 = &[_][]const u8{},
};

pub const QuicStreamType = enum {
    bidirectional,
    unidirectional,
};

pub const QuicStreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
    reset,
};

pub const QuicStream = struct {
    id: u64,
    stream_type: QuicStreamType,
    state: QuicStreamState,
    connection: *QuicConnection,
    send_buffer: std.ArrayList(u8),
    recv_buffer: std.ArrayList(u8),
    send_offset: u64,
    recv_offset: u64,
    max_send_data: u64,
    max_recv_data: u64,
    send_fin: bool,
    recv_fin: bool,
    reset_code: ?u64,
    priority: u8,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,
    
    pub fn init(allocator: std.mem.Allocator, id: u64, stream_type: QuicStreamType, connection: *QuicConnection) !*QuicStream {
        const quic_stream = try allocator.create(QuicStream);
        quic_stream.* = .{
            .id = id,
            .stream_type = stream_type,
            .state = .idle,
            .connection = connection,
            .send_buffer = std.ArrayList(u8).init(allocator),
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .send_offset = 0,
            .recv_offset = 0,
            .max_send_data = connection.config.max_stream_data,
            .max_recv_data = connection.config.max_stream_data,
            .send_fin = false,
            .recv_fin = false,
            .reset_code = null,
            .priority = 0,
            .allocator = allocator,
            .mutex = .{},
        };
        return quic_stream;
    }
    
    pub fn deinit(self: *QuicStream) void {
        self.send_buffer.deinit();
        self.recv_buffer.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn write(self: *QuicStream, data: []const u8) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.state == .closed or self.state == .reset or self.state == .half_closed_local) {
            return error.StreamClosed;
        }
        
        if (self.send_offset + data.len > self.max_send_data) {
            return error.FlowControlViolation;
        }
        
        try self.send_buffer.appendSlice(data);
        self.send_offset += data.len;
        
        if (self.state == .idle) {
            self.state = .open;
        }
        
        return data.len;
    }
    
    pub fn read(self: *QuicStream, buffer: []u8) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.recv_buffer.items.len == 0) {
            if (self.recv_fin or self.state == .closed or self.state == .reset) {
                return 0;
            }
            return error.WouldBlock;
        }
        
        const bytes_to_read = std.math.min(buffer.len, self.recv_buffer.items.len);
        std.mem.copy(u8, buffer, self.recv_buffer.items[0..bytes_to_read]);
        
        // Remove read bytes from buffer
        std.mem.copy(u8, self.recv_buffer.items, self.recv_buffer.items[bytes_to_read..]);
        self.recv_buffer.shrinkRetainingCapacity(self.recv_buffer.items.len - bytes_to_read);
        
        self.recv_offset += bytes_to_read;
        
        return bytes_to_read;
    }
    
    pub fn writeAsync(self: *QuicStream, data: []const u8) zsync.Future(transport.TransportError!usize) {
        return zsync.Future(transport.TransportError!usize).init(self.connection.runtime, struct {
            stream: *QuicStream,
            data: []const u8,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport.TransportError!usize) {
                const result = ctx.stream.write(ctx.data);
                return .{ .ready = result catch |err| errors.mapSystemError(err) };
            }
        }{ .stream = self, .data = data });
    }
    
    pub fn readAsync(self: *QuicStream, buffer: []u8) zsync.Future(transport.TransportError!usize) {
        return zsync.Future(transport.TransportError!usize).init(self.connection.runtime, struct {
            stream: *QuicStream,
            buffer: []u8,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport.TransportError!usize) {
                const result = ctx.stream.read(ctx.buffer);
                return switch (result) {
                    error.WouldBlock => .pending,
                    else => .{ .ready = result catch |err| errors.mapSystemError(err) },
                };
            }
        }{ .stream = self, .buffer = buffer });
    }
    
    pub fn close(self: *QuicStream) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        self.send_fin = true;
        if (self.state == .open) {
            self.state = if (self.recv_fin) .closed else .half_closed_local;
        }
    }
    
    pub fn reset(self: *QuicStream, error_code: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        self.reset_code = error_code;
        self.state = .reset;
    }
    
    pub fn stream(self: *QuicStream) transport.Stream {
        return .{
            .ptr = self,
            .vtable = &.{
                .read_async = readAsyncStream,
                .write_async = writeAsyncStream,
                .flush_async = flushAsyncStream,
                .close_async = closeAsyncStream,
            },
        };
    }
    
    fn readAsyncStream(ptr: *anyopaque, buffer: []u8) zsync.Future(transport.TransportError!usize) {
        const self: *QuicStream = @ptrCast(@alignCast(ptr));
        return self.readAsync(buffer);
    }
    
    fn writeAsyncStream(ptr: *anyopaque, buffer: []const u8) zsync.Future(transport.TransportError!usize) {
        const self: *QuicStream = @ptrCast(@alignCast(ptr));
        return self.writeAsync(buffer);
    }
    
    fn flushAsyncStream(ptr: *anyopaque) zsync.Future(transport.TransportError!void) {
        const self: *QuicStream = @ptrCast(@alignCast(ptr));
        return zsync.Future(transport.TransportError!void).init(self.connection.runtime, struct {
            stream: *QuicStream,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport.TransportError!void) {
                _ = ctx;
                return .{ .ready = {} };
            }
        }{ .stream = self });
    }
    
    fn closeAsyncStream(ptr: *anyopaque) zsync.Future(void) {
        const self: *QuicStream = @ptrCast(@alignCast(ptr));
        return zsync.Future(void).init(self.connection.runtime, struct {
            stream: *QuicStream,
            
            pub fn poll(ctx: *@This()) zsync.Poll(void) {
                ctx.stream.close();
                return .{ .ready = {} };
            }
        }{ .stream = self });
    }
};

pub const QuicConnectionState = enum {
    initial,
    handshaking,
    established,
    closing,
    closed,
    draining,
    failed,
};

pub const QuicConnection = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    config: QuicConfig,
    quic_conn: zquic.Connection,
    socket: udp.UdpSocket,
    state: QuicConnectionState,
    local_addr: transport.Address,
    remote_addr: transport.Address,
    connection_id: [20]u8,
    streams: std.AutoHashMap(u64, *QuicStream),
    next_stream_id: std.atomic.Value(u64),
    bytes_sent: std.atomic.Value(u64),
    bytes_received: std.atomic.Value(u64),
    packets_sent: std.atomic.Value(u64),
    packets_received: std.atomic.Value(u64),
    last_activity: std.atomic.Value(i64),
    mutex: std.Thread.Mutex,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, config: QuicConfig) !*QuicConnection {
        var conn = try allocator.create(QuicConnection);
        errdefer allocator.destroy(conn);
        
        conn.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .config = config,
            .quic_conn = undefined,
            .socket = udp.UdpSocket.init(allocator, runtime),
            .state = .initial,
            .local_addr = undefined,
            .remote_addr = undefined,
            .connection_id = undefined,
            .streams = std.AutoHashMap(u64, *QuicStream).init(allocator),
            .next_stream_id = std.atomic.Value(u64).init(0),
            .bytes_sent = std.atomic.Value(u64).init(0),
            .bytes_received = std.atomic.Value(u64).init(0),
            .packets_sent = std.atomic.Value(u64).init(0),
            .packets_received = std.atomic.Value(u64).init(0),
            .last_activity = std.atomic.Value(i64).init(std.time.timestamp()),
            .mutex = .{},
        };
        
        // Generate random connection ID
        std.crypto.random.bytes(&conn.connection_id);
        
        return conn;
    }
    
    pub fn deinit(self: *QuicConnection) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Clean up streams
        var stream_iter = self.streams.iterator();
        while (stream_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.streams.deinit();
        
        self.socket.close();
        self.allocator.destroy(self);
    }
    
    pub fn connect(self: *QuicConnection, address: transport.Address) !void {
        self.remote_addr = address;
        self.state = .handshaking;
        
        // Initialize QUIC connection
        self.quic_conn = try zquic.Connection.initClient(self.allocator, self.config);
        
        // Start handshake
        try self.performHandshake();
        
        // Start receive loop
        _ = try self.runtime.spawn(receiveLoop, .{self}, .normal);
    }
    
    pub fn accept(self: *QuicConnection, socket: udp.UdpSocket, remote_addr: transport.Address) !void {
        self.socket = socket;
        self.remote_addr = remote_addr;
        self.state = .handshaking;
        
        // Initialize QUIC connection for server
        self.quic_conn = try zquic.Connection.initServer(self.allocator, self.config);
        
        // Start handshake
        try self.performHandshake();
        
        // Start receive loop
        _ = try self.runtime.spawn(receiveLoop, .{self}, .normal);
    }
    
    pub fn openStream(self: *QuicConnection, stream_type: QuicStreamType) !*QuicStream {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.state != .established) {
            return error.ConnectionNotEstablished;
        }
        
        const stream_id = self.next_stream_id.fetchAdd(1, .SeqCst);
        const stream = try QuicStream.init(self.allocator, stream_id, stream_type, self);
        
        try self.streams.put(stream_id, stream);
        
        return stream;
    }
    
    pub fn closeStream(self: *QuicConnection, stream_id: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.streams.fetchRemove(stream_id)) |kv| {
            kv.value.deinit();
        }
    }
    
    pub fn close(self: *QuicConnection) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        self.state = .closing;
        
        // Close all streams
        var stream_iter = self.streams.iterator();
        while (stream_iter.next()) |entry| {
            entry.value_ptr.*.close();
        }
        
        // Send connection close frame
        self.sendConnectionClose() catch {};
        
        self.state = .closed;
    }
    
    pub fn connection(self: *QuicConnection) transport.Connection {
        return .{
            .ptr = self,
            .vtable = &.{
                .read = read,
                .write = write,
                .close = closeConnection,
                .local_address = localAddress,
                .remote_address = remoteAddress,
                .state = getState,
                .set_timeout = setTimeout,
            },
        };
    }
    
    fn performHandshake(self: *QuicConnection) !void {
        // Simplified handshake - real implementation would be more complex
        var handshake_buffer: [1024]u8 = undefined;
        
        // Send initial packet
        const initial_packet = try self.quic_conn.createInitialPacket(&handshake_buffer);
        _ = try self.socket.sendTo(initial_packet, self.remote_addr);
        
        // Wait for response
        var response_buffer: [1024]u8 = undefined;
        const response = try self.socket.recvFrom(&response_buffer);
        
        // Process handshake response
        try self.quic_conn.processHandshakePacket(response.data);
        
        self.state = .established;
        self.updateActivity();
    }
    
    fn receiveLoop(self: *QuicConnection) void {
        var buffer: [2048]u8 = undefined;
        
        while (self.state != .closed and self.state != .failed) {
            const packet = self.socket.recvFromAsync(&buffer) catch continue;
            
            switch (packet) {
                .ready => |result| {
                    if (result) |pkt| {
                        self.handlePacket(pkt.data) catch |err| {
                            std.log.err("QUIC packet handling error: {}", .{err});
                        };
                    } else |_| {
                        continue;
                    }
                },
                .pending => {
                    std.time.sleep(1000000); // 1ms
                    continue;
                },
            }
        }
    }
    
    fn handlePacket(self: *QuicConnection, data: []const u8) !void {
        _ = self.packets_received.fetchAdd(1, .SeqCst);
        _ = self.bytes_received.fetchAdd(data.len, .SeqCst);
        
        // Process QUIC packet
        const frames = try self.quic_conn.processPacket(data);
        
        for (frames) |frame| {
            try self.handleFrame(frame);
        }
        
        self.updateActivity();
    }
    
    fn handleFrame(self: *QuicConnection, frame: zquic.Frame) !void {
        switch (frame.frame_type) {
            .stream => {
                const stream_id = frame.stream_id;
                
                self.mutex.lock();
                defer self.mutex.unlock();
                
                var stream = self.streams.get(stream_id);
                if (stream == null) {
                    // Create new stream
                    stream = try QuicStream.init(self.allocator, stream_id, .bidirectional, self);
                    try self.streams.put(stream_id, stream.?);
                }
                
                // Add data to stream buffer
                try stream.?.recv_buffer.appendSlice(frame.data);
                
                if (frame.fin) {
                    stream.?.recv_fin = true;
                    if (stream.?.state == .open) {
                        stream.?.state = if (stream.?.send_fin) .closed else .half_closed_remote;
                    }
                }
            },
            .connection_close => {
                self.state = .draining;
                // Handle connection close
            },
            .max_data => {
                // Update flow control
            },
            .max_stream_data => {
                // Update stream flow control
            },
            else => {
                // Handle other frame types
            },
        }
    }
    
    fn sendConnectionClose(self: *QuicConnection) !void {
        const close_frame = zquic.Frame{
            .frame_type = .connection_close,
            .error_code = 0,
            .reason_phrase = "Connection closed by application",
            .data = &[_]u8{},
            .stream_id = 0,
            .fin = false,
        };
        
        const packet = try self.quic_conn.createPacket(&[_]zquic.Frame{close_frame});
        _ = try self.socket.sendTo(packet, self.remote_addr);
        
        _ = self.packets_sent.fetchAdd(1, .SeqCst);
        _ = self.bytes_sent.fetchAdd(packet.len, .SeqCst);
    }
    
    fn updateActivity(self: *QuicConnection) void {
        self.last_activity.store(std.time.timestamp(), .SeqCst);
    }
    
    fn isExpired(self: *QuicConnection) bool {
        const last = self.last_activity.load(.SeqCst);
        const now = std.time.timestamp();
        return (now - last) > @as(i64, @intCast(self.config.idle_timeout));
    }
    
    // Transport interface implementations
    
    fn read(ptr: *anyopaque, buffer: []u8) transport.TransportError!usize {
        _ = ptr;
        _ = buffer;
        return error.OperationNotSupported;
    }
    
    fn write(ptr: *anyopaque, buffer: []const u8) transport.TransportError!usize {
        _ = ptr;
        _ = buffer;
        return error.OperationNotSupported;
    }
    
    fn closeConnection(ptr: *anyopaque) void {
        const self: *QuicConnection = @ptrCast(@alignCast(ptr));
        self.close();
    }
    
    fn localAddress(ptr: *anyopaque) transport.TransportError!transport.Address {
        const self: *QuicConnection = @ptrCast(@alignCast(ptr));
        return self.local_addr;
    }
    
    fn remoteAddress(ptr: *anyopaque) transport.TransportError!transport.Address {
        const self: *QuicConnection = @ptrCast(@alignCast(ptr));
        return self.remote_addr;
    }
    
    fn getState(ptr: *anyopaque) transport.ConnectionState {
        const self: *QuicConnection = @ptrCast(@alignCast(ptr));
        return switch (self.state) {
            .initial, .handshaking => .connecting,
            .established => .connected,
            .closing => .closing,
            .closed, .draining, .failed => .closed,
        };
    }
    
    fn setTimeout(ptr: *anyopaque, read_timeout: ?u64, write_timeout: ?u64) transport.TransportError!void {
        _ = ptr;
        _ = read_timeout;
        _ = write_timeout;
        return error.OperationNotSupported;
    }
};

pub const QuicServer = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    config: QuicConfig,
    socket: udp.UdpSocket,
    connections: std.AutoHashMap(u64, *QuicConnection),
    next_connection_id: std.atomic.Value(u64),
    stats: ServerStats,
    mutex: std.Thread.Mutex,
    running: std.atomic.Value(bool),
    
    pub const ServerStats = struct {
        total_connections: std.atomic.Value(u64),
        active_connections: std.atomic.Value(u64),
        handshakes_completed: std.atomic.Value(u64),
        handshakes_failed: std.atomic.Value(u64),
        bytes_sent: std.atomic.Value(u64),
        bytes_received: std.atomic.Value(u64),
    };
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, config: QuicConfig) !*QuicServer {
        const server = try allocator.create(QuicServer);
        errdefer allocator.destroy(server);
        
        server.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .config = config,
            .socket = udp.UdpSocket.init(allocator, runtime),
            .connections = std.AutoHashMap(u64, *QuicConnection).init(allocator),
            .next_connection_id = std.atomic.Value(u64).init(0),
            .stats = .{
                .total_connections = std.atomic.Value(u64).init(0),
                .active_connections = std.atomic.Value(u64).init(0),
                .handshakes_completed = std.atomic.Value(u64).init(0),
                .handshakes_failed = std.atomic.Value(u64).init(0),
                .bytes_sent = std.atomic.Value(u64).init(0),
                .bytes_received = std.atomic.Value(u64).init(0),
            },
            .mutex = .{},
            .running = std.atomic.Value(bool).init(false),
        };
        
        return server;
    }
    
    pub fn deinit(self: *QuicServer) void {
        self.stop();
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Clean up connections
        var conn_iter = self.connections.iterator();
        while (conn_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.connections.deinit();
        
        self.socket.close();
        self.allocator.destroy(self);
    }
    
    pub fn listen(self: *QuicServer, address: transport.Address) !void {
        try self.socket.bind(address, .{
            .allocator = self.allocator,
        });
        
        self.running.store(true, .SeqCst);
        
        // Start accept loop
        _ = try self.runtime.spawn(acceptLoop, .{self}, .normal);
    }
    
    pub fn stop(self: *QuicServer) void {
        self.running.store(false, .SeqCst);
    }
    
    pub fn acceptAsync(self: *QuicServer) zsync.Future(transport.TransportError!transport.Connection) {
        return zsync.Future(transport.TransportError!transport.Connection).init(self.runtime, struct {
            server: *QuicServer,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport.TransportError!transport.Connection) {
                _ = ctx;
                return .pending;
            }
        }{ .server = self });
    }
    
    fn acceptLoop(self: *QuicServer) void {
        var buffer: [2048]u8 = undefined;
        
        while (self.running.load(.SeqCst)) {
            const packet = self.socket.recvFromAsync(&buffer) catch continue;
            
            switch (packet) {
                .ready => |result| {
                    if (result) |pkt| {
                        self.handleIncomingPacket(pkt.data, pkt.address) catch |err| {
                            std.log.err("QUIC server packet handling error: {}", .{err});
                        };
                    } else |_| {
                        continue;
                    }
                },
                .pending => {
                    std.time.sleep(1000000); // 1ms
                    continue;
                },
            }
        }
    }
    
    fn handleIncomingPacket(self: *QuicServer, data: []const u8, remote_addr: transport.Address) !void {
        // Parse QUIC packet header to get connection ID
        if (data.len < 20) return error.PacketTooSmall;
        
        const conn_id = std.mem.readIntBig(u64, data[1..9]);
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var connection = self.connections.get(conn_id);
        if (connection == null) {
            // Create new connection
            connection = try QuicConnection.init(self.allocator, self.runtime, self.config);
            try connection.?.accept(self.socket, remote_addr);
            
            const new_conn_id = self.next_connection_id.fetchAdd(1, .SeqCst);
            try self.connections.put(new_conn_id, connection.?);
            
            _ = self.stats.total_connections.fetchAdd(1, .SeqCst);
            _ = self.stats.active_connections.fetchAdd(1, .SeqCst);
        }
        
        // Forward packet to connection
        try connection.?.handlePacket(data);
    }
    
    pub fn getStats(self: *QuicServer) ServerStats {
        return self.stats;
    }
};

pub const QuicClient = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    config: QuicConfig,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, config: QuicConfig) QuicClient {
        return .{
            .allocator = allocator,
            .runtime = runtime,
            .config = config,
        };
    }
    
    pub fn connect(self: *QuicClient, address: transport.Address) !*QuicConnection {
        const connection = try QuicConnection.init(self.allocator, self.runtime, self.config);
        try connection.connect(address);
        return connection;
    }
};