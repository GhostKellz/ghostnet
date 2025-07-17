const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");
const tcp = @import("../transport/tcp.zig");
const errors = @import("../errors/errors.zig");
const handshake = @import("../crypto/handshake.zig");

pub const WebSocketOpcode = enum(u8) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    
    pub fn isControl(self: WebSocketOpcode) bool {
        return @intFromEnum(self) >= 0x8;
    }
    
    pub fn isData(self: WebSocketOpcode) bool {
        return @intFromEnum(self) < 0x8;
    }
};

pub const WebSocketCloseCode = enum(u16) {
    normal_closure = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    no_status_rcvd = 1005,
    abnormal_closure = 1006,
    invalid_frame_payload_data = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_server_error = 1011,
    service_restart = 1012,
    try_again_later = 1013,
    tls_handshake_failure = 1015,
};

pub const WebSocketFrame = struct {
    fin: bool,
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: WebSocketOpcode,
    masked: bool,
    payload_length: u64,
    masking_key: ?[4]u8,
    payload: []u8,
    
    pub fn init(allocator: std.mem.Allocator, opcode: WebSocketOpcode, payload: []const u8, fin: bool) !WebSocketFrame {
        return WebSocketFrame{
            .fin = fin,
            .opcode = opcode,
            .masked = false,
            .payload_length = payload.len,
            .masking_key = null,
            .payload = try allocator.dupe(u8, payload),
        };
    }
    
    pub fn deinit(self: *WebSocketFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }
    
    pub fn serialize(self: *WebSocketFrame, allocator: std.mem.Allocator) ![]u8 {
        var frame = std.ArrayList(u8).init(allocator);
        
        // First byte: FIN + RSV + Opcode
        var first_byte: u8 = @intFromEnum(self.opcode);
        if (self.fin) first_byte |= 0x80;
        if (self.rsv1) first_byte |= 0x40;
        if (self.rsv2) first_byte |= 0x20;
        if (self.rsv3) first_byte |= 0x10;
        
        try frame.append(first_byte);
        
        // Second byte: MASK + Payload length
        var second_byte: u8 = 0;
        if (self.masked) second_byte |= 0x80;
        
        if (self.payload_length < 126) {
            second_byte |= @intCast(self.payload_length);
            try frame.append(second_byte);
        } else if (self.payload_length < 65536) {
            second_byte |= 126;
            try frame.append(second_byte);
            try frame.append(@intCast(self.payload_length >> 8));
            try frame.append(@intCast(self.payload_length & 0xFF));
        } else {
            second_byte |= 127;
            try frame.append(second_byte);
            
            // 64-bit length
            var i: u8 = 8;
            while (i > 0) {
                i -= 1;
                try frame.append(@intCast((self.payload_length >> @intCast(i * 8)) & 0xFF));
            }
        }
        
        // Masking key
        if (self.masking_key) |key| {
            try frame.appendSlice(&key);
        }
        
        // Payload (apply masking if needed)
        if (self.masked and self.masking_key != null) {
            const key = self.masking_key.?;
            for (self.payload, 0..) |byte, i| {
                try frame.append(byte ^ key[i % 4]);
            }
        } else {
            try frame.appendSlice(self.payload);
        }
        
        return frame.toOwnedSlice();
    }
    
    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !WebSocketFrame {
        if (data.len < 2) return error.InvalidFrameLength;
        
        var offset: usize = 0;
        
        // Parse first byte
        const first_byte = data[offset];
        offset += 1;
        
        const fin = (first_byte & 0x80) != 0;
        const rsv1 = (first_byte & 0x40) != 0;
        const rsv2 = (first_byte & 0x20) != 0;
        const rsv3 = (first_byte & 0x10) != 0;
        const opcode: WebSocketOpcode = @enumFromInt(first_byte & 0x0F);
        
        // Parse second byte
        const second_byte = data[offset];
        offset += 1;
        
        const masked = (second_byte & 0x80) != 0;
        var payload_length: u64 = second_byte & 0x7F;
        
        // Extended payload length
        if (payload_length == 126) {
            if (data.len < offset + 2) return error.InvalidFrameLength;
            payload_length = (@as(u64, data[offset]) << 8) | data[offset + 1];
            offset += 2;
        } else if (payload_length == 127) {
            if (data.len < offset + 8) return error.InvalidFrameLength;
            payload_length = 0;
            for (0..8) |i| {
                payload_length = (payload_length << 8) | data[offset + i];
            }
            offset += 8;
        }
        
        // Masking key
        var masking_key: ?[4]u8 = null;
        if (masked) {
            if (data.len < offset + 4) return error.InvalidFrameLength;
            masking_key = data[offset..offset + 4][0..4].*;
            offset += 4;
        }
        
        // Payload
        if (data.len < offset + payload_length) return error.InvalidFrameLength;
        
        var payload = try allocator.alloc(u8, payload_length);
        
        if (masked and masking_key != null) {
            const key = masking_key.?;
            for (0..payload_length) |i| {
                payload[i] = data[offset + i] ^ key[i % 4];
            }
        } else {
            @memcpy(payload, data[offset..offset + payload_length]);
        }
        
        return WebSocketFrame{
            .fin = fin,
            .rsv1 = rsv1,
            .rsv2 = rsv2,
            .rsv3 = rsv3,
            .opcode = opcode,
            .masked = masked,
            .payload_length = payload_length,
            .masking_key = masking_key,
            .payload = payload,
        };
    }
};

pub const WebSocketMessage = struct {
    opcode: WebSocketOpcode,
    payload: []u8,
    
    pub fn init(allocator: std.mem.Allocator, opcode: WebSocketOpcode, payload: []const u8) !WebSocketMessage {
        return WebSocketMessage{
            .opcode = opcode,
            .payload = try allocator.dupe(u8, payload),
        };
    }
    
    pub fn deinit(self: *WebSocketMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }
    
    pub fn text(allocator: std.mem.Allocator, text_data: []const u8) !WebSocketMessage {
        return WebSocketMessage.init(allocator, .text, text_data);
    }
    
    pub fn binary(allocator: std.mem.Allocator, data: []const u8) !WebSocketMessage {
        return WebSocketMessage.init(allocator, .binary, data);
    }
    
    pub fn close(allocator: std.mem.Allocator, code: WebSocketCloseCode, reason: []const u8) !WebSocketMessage {
        var payload = std.ArrayList(u8).init(allocator);
        
        const code_value = @intFromEnum(code);
        try payload.writer().writeInt(u16, code_value, .big);
        try payload.appendSlice(reason);
        
        return WebSocketMessage{
            .opcode = .close,
            .payload = try payload.toOwnedSlice(),
        };
    }
    
    pub fn ping(allocator: std.mem.Allocator, data: []const u8) !WebSocketMessage {
        return WebSocketMessage.init(allocator, .ping, data);
    }
    
    pub fn pong(allocator: std.mem.Allocator, data: []const u8) !WebSocketMessage {
        return WebSocketMessage.init(allocator, .pong, data);
    }
};

pub const WebSocketConfig = struct {
    max_frame_size: usize = 16 * 1024 * 1024, // 16MB
    max_message_size: usize = 64 * 1024 * 1024, // 64MB
    ping_interval: u64 = 30000, // 30 seconds
    pong_timeout: u64 = 10000, // 10 seconds
    close_timeout: u64 = 5000, // 5 seconds
    enable_compression: bool = false,
    enable_extensions: bool = false,
    subprotocols: []const []const u8 = &[_][]const u8{},
    headers: std.StringHashMap([]const u8),
    
    pub fn init(allocator: std.mem.Allocator) WebSocketConfig {
        return WebSocketConfig{
            .headers = std.StringHashMap([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *WebSocketConfig) void {
        self.headers.deinit();
    }
};

pub const WebSocketState = enum {
    connecting,
    open,
    closing,
    closed,
};

pub const WebSocketConnection = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    config: WebSocketConfig,
    stream: transport.Stream,
    state: WebSocketState,
    is_client: bool,
    
    // Message assembly
    message_buffer: std.ArrayList(u8),
    current_opcode: ?WebSocketOpcode,
    
    // Ping/Pong tracking
    last_ping: i64,
    last_pong: i64,
    awaiting_pong: bool,
    
    // Statistics
    bytes_sent: std.atomic.Value(u64),
    bytes_received: std.atomic.Value(u64),
    messages_sent: std.atomic.Value(u64),
    messages_received: std.atomic.Value(u64),
    
    mutex: std.Thread.Mutex,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, config: WebSocketConfig, stream: transport.Stream, is_client: bool) !*WebSocketConnection {
        const conn = try allocator.create(WebSocketConnection);
        conn.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .config = config,
            .stream = stream,
            .state = .connecting,
            .is_client = is_client,
            .message_buffer = std.ArrayList(u8).init(allocator),
            .current_opcode = null,
            .last_ping = 0,
            .last_pong = 0,
            .awaiting_pong = false,
            .bytes_sent = std.atomic.Value(u64).init(0),
            .bytes_received = std.atomic.Value(u64).init(0),
            .messages_sent = std.atomic.Value(u64).init(0),
            .messages_received = std.atomic.Value(u64).init(0),
            .mutex = .{},
        };
        
        return conn;
    }
    
    pub fn deinit(self: *WebSocketConnection) void {
        self.message_buffer.deinit();
        self.config.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn performHandshake(self: *WebSocketConnection, url: []const u8) !void {
        if (self.is_client) {
            try self.clientHandshake(url);
        } else {
            try self.serverHandshake();
        }
        
        self.state = .open;
        
        // Start ping/pong loop
        _ = try self.runtime.spawn(pingPongLoop, .{self}, .normal);
    }
    
    fn clientHandshake(self: *WebSocketConnection, url: []const u8) !void {
        // Parse URL
        const uri = std.Uri.parse(url) catch return error.InvalidUrl;
        
        // Generate WebSocket key
        var key_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&key_bytes);
        
        var key_b64: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key_b64, &key_bytes);
        
        // Build HTTP upgrade request
        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit();
        
        try request.writer().print(
            "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n",
            .{ uri.path, uri.host orelse "localhost", key_b64 }
        );
        
        // Add subprotocols
        if (self.config.subprotocols.len > 0) {
            try request.appendSlice("Sec-WebSocket-Protocol: ");
            for (self.config.subprotocols, 0..) |proto, i| {
                if (i > 0) try request.appendSlice(", ");
                try request.appendSlice(proto);
            }
            try request.appendSlice("\r\n");
        }
        
        // Add custom headers
        var iter = self.config.headers.iterator();
        while (iter.next()) |entry| {
            try request.writer().print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
        
        try request.appendSlice("\r\n");
        
        // Send request
        _ = try self.stream.writeAsync(request.items);
        
        // Read response
        var response_buffer: [4096]u8 = undefined;
        const response_len = try self.stream.readAsync(&response_buffer);
        const response = response_buffer[0..response_len];
        
        // Validate response
        if (!std.mem.startsWith(u8, response, "HTTP/1.1 101")) {
            return error.HandshakeFailed;
        }
        
        // Validate Sec-WebSocket-Accept
        const expected_accept = try self.computeWebSocketAccept(&key_b64);
        if (std.mem.indexOf(u8, response, expected_accept) == null) {
            return error.InvalidWebSocketAccept;
        }
    }
    
    fn serverHandshake(self: *WebSocketConnection) !void {
        // Read HTTP request
        var request_buffer: [4096]u8 = undefined;
        const request_len = try self.stream.readAsync(&request_buffer);
        const request = request_buffer[0..request_len];
        
        // Parse WebSocket key
        const key_start = std.mem.indexOf(u8, request, "Sec-WebSocket-Key: ") orelse return error.MissingWebSocketKey;
        const key_line_start = key_start + "Sec-WebSocket-Key: ".len;
        const key_line_end = std.mem.indexOf(u8, request[key_line_start..], "\r\n") orelse return error.MalformedRequest;
        const key = request[key_line_start..key_line_start + key_line_end];
        
        // Compute accept key
        const accept = try self.computeWebSocketAccept(key);
        
        // Build response
        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();
        
        try response.writer().print(
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n" ++
            "\r\n",
            .{accept}
        );
        
        // Send response
        _ = try self.stream.writeAsync(response.items);
    }
    
    fn computeWebSocketAccept(self: *WebSocketConnection, key: []const u8) ![]u8 {
        const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        
        var concat = std.ArrayList(u8).init(self.allocator);
        defer concat.deinit();
        
        try concat.appendSlice(key);
        try concat.appendSlice(magic);
        
        var sha1_hash: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(concat.items, &sha1_hash, .{});
        
        const accept = try self.allocator.alloc(u8, 28);
        _ = std.base64.standard.Encoder.encode(accept, &sha1_hash);
        
        return accept;
    }
    
    pub fn sendMessage(self: *WebSocketConnection, message: WebSocketMessage) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.state != .open) {
            return error.ConnectionNotOpen;
        }
        
        // Create frame
        var frame = try WebSocketFrame.init(self.allocator, message.opcode, message.payload, true);
        defer frame.deinit(self.allocator);
        
        // Client frames must be masked
        if (self.is_client) {
            frame.masked = true;
            var key: [4]u8 = undefined;
            std.crypto.random.bytes(&key);
            frame.masking_key = key;
        }
        
        // Serialize and send
        const frame_data = try frame.serialize(self.allocator);
        defer self.allocator.free(frame_data);
        
        _ = self.stream.writeAsync(frame_data);
        
        _ = self.bytes_sent.fetchAdd(frame_data.len, .seq_cst);
        _ = self.messages_sent.fetchAdd(1, .seq_cst);
    }
    
    pub fn receiveMessage(self: *WebSocketConnection) !WebSocketMessage {
        while (true) {
            const frame = try self.receiveFrame();
            defer frame.deinit(self.allocator);
            
            switch (frame.opcode) {
                .text, .binary => {
                    if (self.current_opcode == null) {
                        self.current_opcode = frame.opcode;
                    }
                    
                    try self.message_buffer.appendSlice(frame.payload);
                    
                    if (frame.fin) {
                        const message = WebSocketMessage{
                            .opcode = self.current_opcode.?,
                            .payload = try self.message_buffer.toOwnedSlice(),
                        };
                        
                        self.current_opcode = null;
                        _ = self.messages_received.fetchAdd(1, .seq_cst);
                        
                        return message;
                    }
                },
                .continuation => {
                    if (self.current_opcode == null) {
                        return error.UnexpectedContinuation;
                    }
                    
                    try self.message_buffer.appendSlice(frame.payload);
                    
                    if (frame.fin) {
                        const message = WebSocketMessage{
                            .opcode = self.current_opcode.?,
                            .payload = try self.message_buffer.toOwnedSlice(),
                        };
                        
                        self.current_opcode = null;
                        _ = self.messages_received.fetchAdd(1, .seq_cst);
                        
                        return message;
                    }
                },
                .ping => {
                    // Respond with pong
                    const pong_message = try WebSocketMessage.pong(self.allocator, frame.payload);
                    defer pong_message.deinit(self.allocator);
                    
                    try self.sendMessage(pong_message);
                },
                .pong => {
                    self.last_pong = std.time.timestamp();
                    self.awaiting_pong = false;
                },
                .close => {
                    self.state = .closing;
                    
                    // Send close frame if we haven't already
                    if (self.state == .open) {
                        const close_message = try WebSocketMessage.close(self.allocator, .normal_closure, "");
                        defer close_message.deinit(self.allocator);
                        
                        try self.sendMessage(close_message);
                    }
                    
                    self.state = .closed;
                    return error.ConnectionClosed;
                },
            }
        }
    }
    
    fn receiveFrame(self: *WebSocketConnection) !WebSocketFrame {
        // Read frame header (minimum 2 bytes)
        var header: [2]u8 = undefined;
        _ = try self.stream.readAsync(&header);
        
        // Determine full frame size
        var frame_size: usize = 2;
        const payload_len = header[1] & 0x7F;
        
        if (payload_len == 126) {
            frame_size += 2;
        } else if (payload_len == 127) {
            frame_size += 8;
        }
        
        if ((header[1] & 0x80) != 0) { // Masked
            frame_size += 4;
        }
        
        // Read extended length if needed
        var extended_buffer: [8]u8 = undefined;
        if (payload_len >= 126) {
            const extended_len = if (payload_len == 126) 2 else 8;
            _ = try self.stream.readAsync(extended_buffer[0..extended_len]);
            frame_size += extended_len;
        }
        
        // Read masking key if present
        var mask_buffer: [4]u8 = undefined;
        if ((header[1] & 0x80) != 0) {
            _ = try self.stream.readAsync(&mask_buffer);
        }
        
        // Calculate actual payload length
        var actual_payload_len: u64 = payload_len;
        if (payload_len == 126) {
            actual_payload_len = (@as(u64, extended_buffer[0]) << 8) | extended_buffer[1];
        } else if (payload_len == 127) {
            actual_payload_len = 0;
            for (0..8) |i| {
                actual_payload_len = (actual_payload_len << 8) | extended_buffer[i];
            }
        }
        
        // Read payload
        const payload = try self.allocator.alloc(u8, actual_payload_len);
        _ = try self.stream.readAsync(payload);
        
        // Build full frame data for deserialization
        var frame_data = std.ArrayList(u8).init(self.allocator);
        defer frame_data.deinit();
        
        try frame_data.appendSlice(&header);
        
        if (payload_len == 126) {
            try frame_data.appendSlice(extended_buffer[0..2]);
        } else if (payload_len == 127) {
            try frame_data.appendSlice(extended_buffer[0..8]);
        }
        
        if ((header[1] & 0x80) != 0) {
            try frame_data.appendSlice(&mask_buffer);
        }
        
        try frame_data.appendSlice(payload);
        
        _ = self.bytes_received.fetchAdd(frame_data.items.len, .seq_cst);
        
        return WebSocketFrame.deserialize(self.allocator, frame_data.items);
    }
    
    pub fn close(self: *WebSocketConnection, code: WebSocketCloseCode, reason: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.state == .open) {
            self.state = .closing;
            
            var close_message = try WebSocketMessage.close(self.allocator, code, reason);
            defer close_message.deinit(self.allocator);
            
            try self.sendMessage(close_message);
        }
        
        self.state = .closed;
    }
    
    fn pingPongLoop(self: *WebSocketConnection) void {
        while (self.state == .open) {
            const now = std.time.timestamp();
            
            // Send ping if interval has passed
            if (now - self.last_ping >= @as(i64, @intCast(self.config.ping_interval))) {
                const ping_message = WebSocketMessage.ping(self.allocator, "ghostnet-ping") catch continue;
                defer ping_message.deinit(self.allocator);
                
                self.sendMessage(ping_message) catch continue;
                
                self.last_ping = now;
                self.awaiting_pong = true;
            }
            
            // Check for pong timeout
            if (self.awaiting_pong and now - self.last_ping >= @as(i64, @intCast(self.config.pong_timeout))) {
                self.close(.abnormal_closure, "Pong timeout") catch {};
                break;
            }
            
            // Use async sleep instead of blocking
            try self.runtime.sleep(1000); // 1 second
        }
    }
    
    pub fn getStats(self: *WebSocketConnection) struct {
        bytes_sent: u64,
        bytes_received: u64,
        messages_sent: u64,
        messages_received: u64,
        state: WebSocketState,
    } {
        return .{
            .bytes_sent = self.bytes_sent.load(.seq_cst),
            .bytes_received = self.bytes_received.load(.seq_cst),
            .messages_sent = self.messages_sent.load(.seq_cst),
            .messages_received = self.messages_received.load(.seq_cst),
            .state = self.state,
        };
    }
};

pub const WebSocketClient = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    config: WebSocketConfig,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, config: WebSocketConfig) WebSocketClient {
        return .{
            .allocator = allocator,
            .runtime = runtime,
            .config = config,
        };
    }
    
    pub fn connect(self: *WebSocketClient, url: []const u8) !*WebSocketConnection {
        // Parse URL to get host and port
        const uri = std.Uri.parse(url) catch return error.InvalidUrl;
        
        const host = uri.host orelse return error.MissingHost;
        const port = uri.port orelse if (std.mem.eql(u8, uri.scheme, "wss")) 443 else 80;
        _ = port;
        
        // Create TCP connection
        const tcp_conn = try tcp.TcpConnection.connect(
            self.allocator,
            self.runtime,
            transport.Address{ .ipv4 = try std.net.Ip4Address.parse(host) },
            transport.TransportOptions{ .allocator = self.allocator }
        );
        
        // Create WebSocket connection
        var ws_conn = try WebSocketConnection.init(
            self.allocator,
            self.runtime,
            self.config,
            tcp_conn.stream(),
            true
        );
        
        // Perform handshake
        try ws_conn.performHandshake(url);
        
        return ws_conn;
    }
};

pub const WebSocketServer = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    config: WebSocketConfig,
    listener: tcp.TcpListener,
    connections: std.ArrayList(*WebSocketConnection),
    mutex: std.Thread.Mutex,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, config: WebSocketConfig) !*WebSocketServer {
        const server = try allocator.create(WebSocketServer);
        server.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .config = config,
            .listener = tcp.TcpListener.init(allocator, runtime),
            .connections = std.ArrayList(*WebSocketConnection).init(allocator),
            .mutex = .{},
        };
        
        return server;
    }
    
    pub fn deinit(self: *WebSocketServer) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (self.connections.items) |conn| {
            conn.deinit();
        }
        self.connections.deinit();
        
        self.allocator.destroy(self);
    }
    
    pub fn listen(self: *WebSocketServer, address: transport.Address) !void {
        try self.listener.bind(address, transport.TransportOptions{ .allocator = self.allocator });
        
        // Start accept loop
        _ = try self.runtime.spawn(acceptLoop, .{self}, .normal);
    }
    
    fn acceptLoop(self: *WebSocketServer) void {
        while (true) {
            const tcp_conn = self.listener.listener().acceptAsync() catch continue;
            
            switch (tcp_conn) {
                .ready => |result| {
                    if (result) |conn| {
                        _ = self.runtime.spawn(handleConnection, .{ self, conn }, .normal) catch continue;
                    } else |_| {
                        continue;
                    }
                },
                .pending => {
                    // Use async sleep instead of blocking
                    try self.runtime.sleep(1); // 1ms
                    continue;
                },
            }
        }
    }
    
    fn handleConnection(self: *WebSocketServer, tcp_conn: transport.Connection) void {
        const ws_conn = WebSocketConnection.init(
            self.allocator,
            self.runtime,
            self.config,
            tcp_conn.stream(),
            false
        ) catch return;
        
        // Perform handshake
        ws_conn.performHandshake("") catch {
            ws_conn.deinit();
            return;
        };
        
        // Add to connections list
        self.mutex.lock();
        self.connections.append(ws_conn) catch {
            self.mutex.unlock();
            ws_conn.deinit();
            return;
        };
        self.mutex.unlock();
        
        // Handle messages
        while (ws_conn.state == .open) {
            const message = ws_conn.receiveMessage() catch break;
            defer message.deinit(self.allocator);
            
            // Echo message back (example)
            ws_conn.sendMessage(message) catch break;
        }
        
        // Remove from connections list
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (self.connections.items, 0..) |conn, i| {
            if (conn == ws_conn) {
                _ = self.connections.swapRemove(i);
                break;
            }
        }
        
        ws_conn.deinit();
    }
};

test "WebSocketMessage close functionality" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test creating a close message
    var close_message = try WebSocketMessage.close(allocator, .normal_closure, "Normal closure");
    defer close_message.deinit(allocator);
    
    // Verify the opcode is correct for close
    try testing.expectEqual(WebSocketOpcode.close, close_message.opcode);
    
    // Verify the payload contains the close code and reason
    try testing.expect(close_message.payload.len >= 2);
    
    // The first two bytes should be the close code (1000 in network byte order)
    const close_code = std.mem.readInt(u16, close_message.payload[0..2], .big);
    try testing.expectEqual(@as(u16, 1000), close_code);
    
    // The rest should be the reason string
    if (close_message.payload.len > 2) {
        const reason = close_message.payload[2..];
        try testing.expectEqualStrings("Normal closure", reason);
    }
}