const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");
const http = @import("http.zig");
const errors = @import("../errors/errors.zig");

// HTTP/2 Frame Types
pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
};

pub const FrameFlags = packed struct(u8) {
    end_stream: bool = false,
    end_headers: bool = false,
    padded: bool = false,
    priority: bool = false,
    _reserved: u4 = 0,
};

pub const Frame = struct {
    length: u24,
    frame_type: FrameType,
    flags: FrameFlags,
    stream_id: u31,
    payload: []const u8,
    
    pub const FRAME_HEADER_SIZE = 9;
    
    pub fn parse(data: []const u8) !Frame {
        if (data.len < FRAME_HEADER_SIZE) return error.InvalidFrame;
        
        const length = std.mem.readIntBig(u24, data[0..3]);
        const frame_type = @as(FrameType, @enumFromInt(data[3]));
        const flags = @as(FrameFlags, @bitCast(data[4]));
        const stream_id = std.mem.readIntBig(u32, data[5..9]) & 0x7FFFFFFF;
        
        if (data.len < FRAME_HEADER_SIZE + length) return error.IncompleteFrame;
        
        return Frame{
            .length = length,
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = @intCast(stream_id),
            .payload = data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + length],
        };
    }
    
    pub fn serialize(self: Frame, allocator: std.mem.Allocator) ![]u8 {
        var data = try allocator.alloc(u8, FRAME_HEADER_SIZE + self.payload.len);
        
        std.mem.writeIntBig(u24, data[0..3], @intCast(self.payload.len));
        data[3] = @intFromEnum(self.frame_type);
        data[4] = @bitCast(self.flags);
        std.mem.writeIntBig(u32, data[5..9], self.stream_id);
        
        @memcpy(data[FRAME_HEADER_SIZE..], self.payload);
        
        return data;
    }
};

pub const StreamState = enum {
    idle,
    reserved_local,
    reserved_remote,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

pub const Stream = struct {
    id: u31,
    state: StreamState,
    window_size: i32,
    headers: std.StringHashMap([]const u8),
    data: std.ArrayList(u8),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, id: u31) Stream {
        return Stream{
            .id = id,
            .state = .idle,
            .window_size = 65535, // Default window size
            .headers = std.StringHashMap([]const u8).init(allocator),
            .data = std.ArrayList(u8).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Stream) void {
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        self.data.deinit();
    }
    
    pub fn addHeader(self: *Stream, name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.headers.put(name_copy, value_copy);
    }
    
    pub fn appendData(self: *Stream, data: []const u8) !void {
        try self.data.appendSlice(data);
    }
    
    pub fn canSendData(self: *Stream) bool {
        return self.state == .open or self.state == .half_closed_remote;
    }
    
    pub fn canReceiveData(self: *Stream) bool {
        return self.state == .open or self.state == .half_closed_local;
    }
};

pub const ConnectionSettings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: u32 = 100,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,
};

pub const Http2Connection = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    transport_stream: transport.Stream,
    streams: std.HashMap(u31, Stream, std.hash_map.AutoContext(u31), 80),
    next_stream_id: u31,
    settings: ConnectionSettings,
    peer_settings: ConnectionSettings,
    window_size: i32,
    peer_window_size: i32,
    is_client: bool,
    state: ConnectionState,
    
    pub const ConnectionState = enum {
        idle,
        connected,
        closing,
        closed,
    };
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, transport_stream: transport.Stream, is_client: bool) !*Http2Connection {
        const conn = try allocator.create(Http2Connection);
        conn.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .transport_stream = transport_stream,
            .streams = std.HashMap(u31, Stream, std.hash_map.AutoContext(u31), 80).init(allocator),
            .next_stream_id = if (is_client) 1 else 2,
            .settings = ConnectionSettings{},
            .peer_settings = ConnectionSettings{},
            .window_size = 65535,
            .peer_window_size = 65535,
            .is_client = is_client,
            .state = .idle,
        };
        
        return conn;
    }
    
    pub fn deinit(self: *Http2Connection) void {
        var iter = self.streams.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.streams.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn performHandshake(self: *Http2Connection) !void {
        if (self.is_client) {
            // Send HTTP/2 preface
            const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            _ = try self.transport_stream.writeAsync(preface);
            
            // Send initial SETTINGS frame
            try self.sendSettings();
        }
        
        self.state = .connected;
    }
    
    pub fn createStream(self: *Http2Connection) !u31 {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 2; // Increment by 2 to maintain odd/even distinction
        
        var stream = Stream.init(self.allocator, stream_id);
        stream.state = .open;
        try self.streams.put(stream_id, stream);
        
        return stream_id;
    }
    
    pub fn sendRequest(self: *Http2Connection, stream_id: u31, request: *http.HttpRequest) !void {
        var stream = self.streams.getPtr(stream_id) orelse return error.InvalidStreamId;
        
        // Convert HTTP request to HTTP/2 headers
        try stream.addHeader(":method", request.method.toString());
        try stream.addHeader(":path", request.path);
        try stream.addHeader(":scheme", "https");
        
        var header_iter = request.headers.iterator();
        while (header_iter.next()) |entry| {
            if (std.mem.eql(u8, entry.key_ptr.*, "Host")) {
                try stream.addHeader(":authority", entry.value_ptr.*);
            } else {
                try stream.addHeader(entry.key_ptr.*, entry.value_ptr.*);
            }
        }
        
        // Send HEADERS frame
        try self.sendHeaders(stream_id, true);
        
        // Send DATA frame if there's a body
        if (request.body) |body| {
            try self.sendData(stream_id, body, true);
        }
    }
    
    pub fn sendHeaders(self: *Http2Connection, stream_id: u31, end_stream: bool) !void {
        var stream = self.streams.getPtr(stream_id) orelse return error.InvalidStreamId;
        
        // Simplified header encoding (would normally use HPACK)
        var header_data = std.ArrayList(u8).init(self.allocator);
        defer header_data.deinit();
        
        var iter = stream.headers.iterator();
        while (iter.next()) |entry| {
            // Very simplified header encoding
            const header_line = try std.fmt.allocPrint(self.allocator, "{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
            defer self.allocator.free(header_line);
            try header_data.appendSlice(header_line);
        }
        
        const frame = Frame{
            .length = @intCast(header_data.items.len),
            .frame_type = .headers,
            .flags = .{ .end_headers = true, .end_stream = end_stream },
            .stream_id = stream_id,
            .payload = header_data.items,
        };
        
        const frame_data = try frame.serialize(self.allocator);
        defer self.allocator.free(frame_data);
        
        _ = try self.transport_stream.writeAsync(frame_data);
    }
    
    pub fn sendData(self: *Http2Connection, stream_id: u31, data: []const u8, end_stream: bool) !void {
        const frame = Frame{
            .length = @intCast(data.len),
            .frame_type = .data,
            .flags = .{ .end_stream = end_stream },
            .stream_id = stream_id,
            .payload = data,
        };
        
        const frame_data = try frame.serialize(self.allocator);
        defer self.allocator.free(frame_data);
        
        _ = try self.transport_stream.writeAsync(frame_data);
    }
    
    pub fn sendSettings(self: *Http2Connection) !void {
        // Send empty SETTINGS frame for now
        const frame = Frame{
            .length = 0,
            .frame_type = .settings,
            .flags = .{},
            .stream_id = 0,
            .payload = &[_]u8{},
        };
        
        const frame_data = try frame.serialize(self.allocator);
        defer self.allocator.free(frame_data);
        
        _ = try self.transport_stream.writeAsync(frame_data);
    }
    
    pub fn receiveFrame(self: *Http2Connection) !Frame {
        var header_buffer: [Frame.FRAME_HEADER_SIZE]u8 = undefined;
        
        // Read frame header
        const read_result = try self.transport_stream.readAsync(&header_buffer);
        const bytes_read = switch (read_result) {
            .ready => |result| result orelse return error.ConnectionClosed,
            .pending => return error.WouldBlock,
        };
        
        if (bytes_read < Frame.FRAME_HEADER_SIZE) return error.IncompleteFrame;
        
        const frame_length = std.mem.readIntBig(u24, header_buffer[0..3]);
        
        // Read frame payload
        const payload = try self.allocator.alloc(u8, frame_length);
        defer self.allocator.free(payload);
        
        const payload_read = try self.transport_stream.readAsync(payload);
        const payload_bytes = switch (payload_read) {
            .ready => |result| result orelse return error.ConnectionClosed,
            .pending => return error.WouldBlock,
        };
        
        if (payload_bytes < frame_length) return error.IncompleteFrame;
        
        // Combine header and payload
        const frame_data = try self.allocator.alloc(u8, Frame.FRAME_HEADER_SIZE + frame_length);
        defer self.allocator.free(frame_data);
        
        @memcpy(frame_data[0..Frame.FRAME_HEADER_SIZE], &header_buffer);
        @memcpy(frame_data[Frame.FRAME_HEADER_SIZE..], payload);
        
        return Frame.parse(frame_data);
    }
    
    pub fn processFrame(self: *Http2Connection, frame: Frame) !void {
        switch (frame.frame_type) {
            .headers => try self.processHeaders(frame),
            .data => try self.processData(frame),
            .settings => try self.processSettings(frame),
            .ping => try self.processPing(frame),
            .goaway => try self.processGoAway(frame),
            .window_update => try self.processWindowUpdate(frame),
            else => {
                // Unknown frame type, ignore
                std.debug.print("Ignoring unknown frame type: {}\n", .{frame.frame_type});
            },
        }
    }
    
    fn processHeaders(self: *Http2Connection, frame: Frame) !void {
        const stream_id = frame.stream_id;
        
        var stream = self.streams.getPtr(stream_id);
        if (stream == null) {
            stream = try self.allocator.create(Stream);
            stream.?.* = Stream.init(self.allocator, stream_id);
            try self.streams.put(stream_id, stream.*);
        }
        
        // Simplified header processing (would normally use HPACK)
        std.debug.print("Received headers for stream {d}: {s}\n", .{ stream_id, frame.payload });
        
        if (frame.flags.end_stream) {
            stream.?.state = .half_closed_remote;
        }
    }
    
    fn processData(self: *Http2Connection, frame: Frame) !void {
        const stream_id = frame.stream_id;
        
        var stream = self.streams.getPtr(stream_id) orelse return error.InvalidStreamId;
        
        if (!stream.canReceiveData()) {
            return error.StreamNotOpen;
        }
        
        try stream.appendData(frame.payload);
        
        if (frame.flags.end_stream) {
            stream.state = .half_closed_remote;
        }
    }
    
    fn processSettings(self: *Http2Connection, frame: Frame) !void {
        if (frame.flags.end_stream) {
            // ACK frame
            return;
        }
        
        // Process settings (simplified)
        std.debug.print("Received settings frame with {d} bytes\n", .{frame.payload.len});
        
        // Send settings ACK
        const ack_frame = Frame{
            .length = 0,
            .frame_type = .settings,
            .flags = .{ .end_stream = true }, // ACK flag
            .stream_id = 0,
            .payload = &[_]u8{},
        };
        
        const frame_data = try ack_frame.serialize(self.allocator);
        defer self.allocator.free(frame_data);
        
        _ = try self.transport_stream.writeAsync(frame_data);
    }
    
    fn processPing(self: *Http2Connection, frame: Frame) !void {
        if (!frame.flags.end_stream) {
            // Send PING response
            const pong_frame = Frame{
                .length = @intCast(frame.payload.len),
                .frame_type = .ping,
                .flags = .{ .end_stream = true }, // ACK flag
                .stream_id = 0,
                .payload = frame.payload,
            };
            
            const frame_data = try pong_frame.serialize(self.allocator);
            defer self.allocator.free(frame_data);
            
            _ = try self.transport_stream.writeAsync(frame_data);
        }
    }
    
    fn processGoAway(self: *Http2Connection, frame: Frame) !void {
        _ = frame;
        self.state = .closing;
        std.debug.print("Received GOAWAY frame, closing connection\n", .{});
    }
    
    fn processWindowUpdate(self: *Http2Connection, frame: Frame) !void {
        if (frame.payload.len < 4) return error.InvalidFrame;
        
        const window_size_increment = std.mem.readIntBig(u32, frame.payload[0..4]) & 0x7FFFFFFF;
        
        if (frame.stream_id == 0) {
            self.peer_window_size += @intCast(window_size_increment);
        } else {
            var stream = self.streams.getPtr(frame.stream_id) orelse return error.InvalidStreamId;
            stream.window_size += @intCast(window_size_increment);
        }
    }
};

// HTTP/2 Client implementation
pub const Http2Client = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    connection: *Http2Connection,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, transport_stream: transport.Stream) !*Http2Client {
        var client = try allocator.create(Http2Client);
        client.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .connection = try Http2Connection.init(allocator, runtime, transport_stream, true),
        };
        
        try client.connection.performHandshake();
        
        return client;
    }
    
    pub fn deinit(self: *Http2Client) void {
        self.connection.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn sendRequest(self: *Http2Client, request: *http.HttpRequest) !http.HttpResponse {
        const stream_id = try self.connection.createStream();
        
        try self.connection.sendRequest(stream_id, request);
        
        // Wait for response (simplified)
        var response_complete = false;
        var response_headers = std.StringHashMap([]const u8).init(self.allocator);
        defer response_headers.deinit();
        
        var response_body = std.ArrayList(u8).init(self.allocator);
        defer response_body.deinit();
        
        while (!response_complete) {
            const frame = self.connection.receiveFrame() catch |err| switch (err) {
                error.WouldBlock => {
                    std.time.sleep(1000000); // 1ms
                    continue;
                },
                else => return err,
            };
            
            try self.connection.processFrame(frame);
            
            if (frame.stream_id == stream_id) {
                switch (frame.frame_type) {
                    .headers => {
                        if (frame.flags.end_stream) {
                            response_complete = true;
                        }
                    },
                    .data => {
                        try response_body.appendSlice(frame.payload);
                        if (frame.flags.end_stream) {
                            response_complete = true;
                        }
                    },
                    else => {},
                }
            }
        }
        
        // Create HTTP response
        var response = try http.HttpResponse.init(self.allocator, 200, "OK");
        if (response_body.items.len > 0) {
            try response.setBody(self.allocator, response_body.items);
        }
        
        return response;
    }
};