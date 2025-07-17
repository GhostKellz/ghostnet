const std = @import("std");
const zsync = @import("zsync");
const zquic = @import("zquic");
const transport = @import("../transport/transport.zig");
const udp = @import("../transport/udp.zig");
const errors = @import("../errors/errors.zig");
const protocol = @import("protocol.zig");

// High-performance ring buffer for zero-copy stream operations
pub const RingBuffer = struct {
    buffer: []u8,
    read_pos: usize,
    write_pos: usize,
    size: usize,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, buffer_capacity: usize) !RingBuffer {
        const buffer = try allocator.alloc(u8, buffer_capacity);
        return RingBuffer{
            .buffer = buffer,
            .read_pos = 0,
            .write_pos = 0,
            .size = 0,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *RingBuffer) void {
        self.allocator.free(self.buffer);
    }
    
    pub fn available(self: *const RingBuffer) usize {
        return self.size;
    }
    
    pub fn capacity(self: *const RingBuffer) usize {
        return self.buffer.len;
    }
    
    pub fn freeSpace(self: *const RingBuffer) usize {
        return self.buffer.len - self.size;
    }
    
    pub fn read(self: *RingBuffer, dest: []u8) usize {
        const bytes_to_read = std.math.min(dest.len, self.size);
        if (bytes_to_read == 0) return 0;
        
        // Handle wrap-around case
        if (self.read_pos + bytes_to_read <= self.buffer.len) {
            std.mem.copy(u8, dest[0..bytes_to_read], self.buffer[self.read_pos..self.read_pos + bytes_to_read]);
        } else {
            const first_chunk = self.buffer.len - self.read_pos;
            const second_chunk = bytes_to_read - first_chunk;
            std.mem.copy(u8, dest[0..first_chunk], self.buffer[self.read_pos..]);
            std.mem.copy(u8, dest[first_chunk..bytes_to_read], self.buffer[0..second_chunk]);
        }
        
        self.read_pos = (self.read_pos + bytes_to_read) % self.buffer.len;
        self.size -= bytes_to_read;
        return bytes_to_read;
    }
    
    pub fn write(self: *RingBuffer, src: []const u8) usize {
        const bytes_to_write = std.math.min(src.len, self.freeSpace());
        if (bytes_to_write == 0) return 0;
        
        // Handle wrap-around case
        if (self.write_pos + bytes_to_write <= self.buffer.len) {
            std.mem.copy(u8, self.buffer[self.write_pos..self.write_pos + bytes_to_write], src[0..bytes_to_write]);
        } else {
            const first_chunk = self.buffer.len - self.write_pos;
            const second_chunk = bytes_to_write - first_chunk;
            std.mem.copy(u8, self.buffer[self.write_pos..], src[0..first_chunk]);
            std.mem.copy(u8, self.buffer[0..second_chunk], src[first_chunk..bytes_to_write]);
        }
        
        self.write_pos = (self.write_pos + bytes_to_write) % self.buffer.len;
        self.size += bytes_to_write;
        return bytes_to_write;
    }
};

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
    send_buffer: RingBuffer,
    recv_buffer: RingBuffer,
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
            .send_buffer = try RingBuffer.init(allocator, @as(usize, @intCast(connection.config.max_stream_data))),
            .recv_buffer = try RingBuffer.init(allocator, @as(usize, @intCast(connection.config.max_stream_data))),
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
        
        if (self.recv_buffer.available() == 0) {
            if (self.recv_fin or self.state == .closed or self.state == .reset) {
                return 0;
            }
            return error.WouldBlock;
        }
        
        const bytes_read = self.recv_buffer.read(buffer);
        self.recv_offset += bytes_read;
        
        return bytes_read;
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
    early_data_accepted: bool,
    early_data_buffer: std.ArrayList(u8),
    session_cache_key: ?[]const u8,
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
            .early_data_accepted = false,
            .early_data_buffer = std.ArrayList(u8).init(allocator),
            .session_cache_key = null,
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
        
        self.early_data_buffer.deinit();
        if (self.session_cache_key) |key| {
            self.allocator.free(key);
        }
        
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
        
        const stream_id = self.next_stream_id.fetchAdd(1, .seq_cst);
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
        
        // Check for 0-RTT support
        if (self.config.enable_0rtt) {
            // Try to send early data with initial packet
            const zero_rtt_packet = try self.create0RTTPacket(&handshake_buffer);
            if (zero_rtt_packet.len > 0) {
                _ = try self.socket.sendTo(zero_rtt_packet, self.remote_addr);
                // Continue with regular handshake
            }
        }
        
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
        _ = self.packets_received.fetchAdd(1, .seq_cst);
        _ = self.bytes_received.fetchAdd(data.len, .seq_cst);
        
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
                // Update connection-level flow control
                self.mutex.lock();
                defer self.mutex.unlock();
                
                // Update max data we can send on this connection
                const max_data = frame.max_data orelse return error.InvalidFrame;
                // Store max_data in connection state (simplified)
                _ = max_data;
            },
            .max_stream_data => {
                // Update stream-level flow control
                const stream_id = frame.stream_id;
                const max_stream_data = frame.max_stream_data orelse return error.InvalidFrame;
                
                self.mutex.lock();
                defer self.mutex.unlock();
                
                if (self.streams.get(stream_id)) |stream| {
                    stream.max_send_data = max_stream_data;
                }
            },
            .reset_stream => {
                // Handle stream reset
                const stream_id = frame.stream_id;
                const error_code = frame.error_code orelse 0;
                
                self.mutex.lock();
                defer self.mutex.unlock();
                
                if (self.streams.get(stream_id)) |stream| {
                    stream.reset(error_code);
                }
            },
            .stop_sending => {
                // Handle stop sending frame
                const stream_id = frame.stream_id;
                
                self.mutex.lock();
                defer self.mutex.unlock();
                
                if (self.streams.get(stream_id)) |stream| {
                    stream.send_fin = true;
                    if (stream.state == .open) {
                        stream.state = if (stream.recv_fin) .closed else .half_closed_local;
                    }
                }
            },
            .ack => {
                // Handle ACK frame - update congestion control
                self.handleAckFrame(frame) catch {};
            },
            .ping => {
                // Respond to ping with pong
                try self.sendPong();
            },
            .padding => {
                // Padding frames are ignored
            },
            .crypto => {
                // Handle crypto frame for handshake
                try self.handleCryptoFrame(frame);
            },
            .new_connection_id => {
                // Handle new connection ID
                try self.handleNewConnectionId(frame);
            },
            .retire_connection_id => {
                // Handle retire connection ID
                try self.handleRetireConnectionId(frame);
            },
            else => {
                // Log unhandled frame types
                std.log.warn("Unhandled QUIC frame type: {}", .{frame.frame_type});
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
            .max_data = null,
            .max_stream_data = null,
        };
        
        const packet = try self.quic_conn.createPacket(&[_]zquic.Frame{close_frame});
        _ = try self.socket.sendTo(packet, self.remote_addr);
        
        _ = self.packets_sent.fetchAdd(1, .seq_cst);
        _ = self.bytes_sent.fetchAdd(packet.len, .seq_cst);
    }
    
    fn handleAckFrame(self: *QuicConnection, frame: zquic.Frame) !void {
        // Update RTT and congestion control based on ACK
        const now = std.time.timestamp();
        
        // Extract ACK information from frame data
        if (frame.data.len >= 8) {
            const ack_delay = std.mem.readInt(u64, frame.data[0..8], .big);
            
            // Calculate RTT (simplified)
            const rtt = now - @as(i64, @intCast(ack_delay));
            
            // Update connection statistics
            if (rtt > 0) {
                // Simplified RTT smoothing
                const current_rtt = @as(u32, @intCast(@min(rtt, std.math.maxInt(u32))));
                
                // Update congestion window based on ACK (simplified CUBIC)
                self.updateCongestionWindow(current_rtt);
            }
        }
        
        // Remove acknowledged packets from retransmission queue
        // (In real implementation, would track sent packets)
    }
    
    fn updateCongestionWindow(self: *QuicConnection, rtt: u32) void {
        _ = self;
        _ = rtt;
        // Simplified congestion control - would implement CUBIC or BBR
        // For now, just track the RTT
    }
    
    fn sendPong(self: *QuicConnection) !void {
        const pong_frame = zquic.Frame{
            .frame_type = .pong,
            .error_code = null,
            .reason_phrase = "",
            .data = &[_]u8{},
            .stream_id = 0,
            .fin = false,
            .max_data = null,
            .max_stream_data = null,
        };
        
        const packet = try self.quic_conn.createPacket(&[_]zquic.Frame{pong_frame});
        _ = try self.socket.sendTo(packet, self.remote_addr);
        
        _ = self.packets_sent.fetchAdd(1, .seq_cst);
        _ = self.bytes_sent.fetchAdd(packet.len, .seq_cst);
    }
    
    fn handleCryptoFrame(self: *QuicConnection, frame: zquic.Frame) !void {
        // Process TLS handshake data from crypto frame
        if (self.state == .handshaking) {
            // Forward crypto data to TLS handshake handler
            // In real implementation, would integrate with handshake manager
            
            if (frame.data.len > 0) {
                // Validate crypto frame structure
                if (frame.data.len < 4) return error.InvalidCryptoFrame;
                
                const crypto_length = std.mem.readInt(u32, frame.data[0..4], .big);
                if (crypto_length + 4 > frame.data.len) return error.InvalidCryptoLength;
                
                const crypto_data = frame.data[4..4 + crypto_length];
                
                // Process handshake data (simplified)
                
                // If handshake is complete, transition to established
                if (self.isHandshakeComplete(crypto_data)) {
                    self.state = .established;
                    self.updateActivity();
                }
            }
        }
    }
    
    fn isHandshakeComplete(self: *QuicConnection, crypto_data: []const u8) bool {
        _ = self;
        // Check if crypto data indicates handshake completion
        // In real implementation, would check TLS finished message
        return crypto_data.len > 0 and crypto_data[0] == 0x14; // TLS Finished message type
    }
    
    fn handleNewConnectionId(self: *QuicConnection, frame: zquic.Frame) !void {
        // Handle new connection ID for connection migration
        if (frame.data.len >= 21) { // sequence + length + conn_id + token
            const sequence = std.mem.readInt(u64, frame.data[0..8], .big);
            const length = frame.data[8];
            
            if (length <= 20 and frame.data.len >= 9 + length + 16) {
                const conn_id = frame.data[9..9 + length];
                const stateless_reset_token = frame.data[9 + length..9 + length + 16];
                
                // Store new connection ID for migration
                _ = sequence;
                _ = conn_id;
                _ = stateless_reset_token;
                
                // In real implementation, would store in connection ID map
                self.updateActivity();
            }
        }
    }
    
    fn handleRetireConnectionId(self: *QuicConnection, frame: zquic.Frame) !void {
        // Handle retire connection ID
        if (frame.data.len >= 8) {
            const sequence = std.mem.readInt(u64, frame.data[0..8], .big);
            
            // Remove connection ID from active set
            _ = sequence;
            
            // In real implementation, would remove from connection ID map
            self.updateActivity();
        }
    }
    
    fn updateActivity(self: *QuicConnection) void {
        self.last_activity.store(std.time.timestamp(), .seq_cst);
    }
    
    fn isExpired(self: *QuicConnection) bool {
        const last = self.last_activity.load(.seq_cst);
        const now = std.time.timestamp();
        return (now - last) > @as(i64, @intCast(self.config.idle_timeout));
    }
    
    fn create0RTTPacket(self: *QuicConnection, buffer: []u8) ![]u8 {
        if (!self.config.enable_0rtt) {
            return buffer[0..0];
        }
        
        // Check if we have cached session data
        // In real implementation, would check session cache
        
        // For now, prepare early data packet structure
        var packet_len: usize = 0;
        
        // Add 0-RTT packet header
        buffer[0] = 0x7d; // 0-RTT packet type
        packet_len += 1;
        
        // Add connection ID
        @memcpy(buffer[packet_len..packet_len + 20], &self.connection_id);
        packet_len += 20;
        
        // Add any buffered early data
        if (self.early_data_buffer.items.len > 0) {
            const data_len = @min(self.early_data_buffer.items.len, buffer.len - packet_len - 16);
            @memcpy(buffer[packet_len..packet_len + data_len], self.early_data_buffer.items[0..data_len]);
            packet_len += data_len;
            
            // Mark early data as sent
            self.early_data_accepted = true;
        }
        
        return buffer[0..packet_len];
    }
    
    pub fn sendEarlyData(self: *QuicConnection, data: []const u8) !void {
        if (!self.config.enable_0rtt) {
            return error.EarlyDataNotEnabled;
        }
        
        if (self.state != .initial and self.state != .handshaking) {
            return error.InvalidState;
        }
        
        try self.early_data_buffer.appendSlice(data);
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
        
        self.running.store(true, .seq_cst);
        
        // Start accept loop
        _ = try self.runtime.spawn(acceptLoop, .{self}, .normal);
    }
    
    pub fn stop(self: *QuicServer) void {
        self.running.store(false, .seq_cst);
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
        
        while (self.running.load(.seq_cst)) {
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
            
            const new_conn_id = self.next_connection_id.fetchAdd(1, .seq_cst);
            try self.connections.put(new_conn_id, connection.?);
            
            _ = self.stats.total_connections.fetchAdd(1, .seq_cst);
            _ = self.stats.active_connections.fetchAdd(1, .seq_cst);
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