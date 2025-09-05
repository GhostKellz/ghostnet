const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");
const http = @import("http.zig");
const errors = @import("../errors/errors.zig");

// HPACK Implementation for HTTP/2 header compression
const hpack = @import("hpack.zig");

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

pub const StreamPriority = struct {
    exclusive: bool = false,
    dependency: u31 = 0,
    weight: u8 = 16, // Default weight (16)
};

pub const Stream = struct {
    id: u31,
    state: StreamState,
    window_size: i32,
    peer_window_size: i32,
    headers: std.StringHashMap([]const u8),
    data: std.ArrayList(u8),
    allocator: std.mem.Allocator,
    priority: StreamPriority,
    created_time: i64,
    
    pub fn init(allocator: std.mem.Allocator, id: u31) Stream {
        return Stream{
            .id = id,
            .state = .idle,
            .window_size = 65535, // Default window size
            .peer_window_size = 65535,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .data = std.ArrayList(u8).init(allocator),
            .allocator = allocator,
            .priority = StreamPriority{},
            .created_time = std.time.milliTimestamp(),
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
    hpack_context: hpack.Context,
    last_stream_id: u31,
    ping_counter: u64,
    
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
            .hpack_context = hpack.Context.init(allocator),
            .last_stream_id = 0,
            .ping_counter = 0,
        };
        
        return conn;
    }
    
    pub fn deinit(self: *Http2Connection) void {
        var iter = self.streams.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.streams.deinit();
        self.hpack_context.deinit();
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
        
        // Convert headers to HPACK format
        var hpack_headers = std.ArrayList(hpack.HeaderField).init(self.allocator);
        defer {
            for (hpack_headers.items) |header| {
                header.deinit(self.allocator);
            }
            hpack_headers.deinit();
        }
        
        var iter = stream.headers.iterator();
        while (iter.next()) |entry| {
            try hpack_headers.append(hpack.HeaderField{
                .name = try self.allocator.dupe(u8, entry.key_ptr.*),
                .value = try self.allocator.dupe(u8, entry.value_ptr.*),
            });
        }
        
        // Encode headers using HPACK
        const encoded_headers = try self.hpack_context.encode(hpack_headers.items);
        defer self.allocator.free(encoded_headers);
        
        // Check if headers fit in a single frame
        const max_frame_size = self.peer_settings.max_frame_size;
        if (encoded_headers.len <= max_frame_size) {
            // Single HEADERS frame
            const frame = Frame{
                .length = @intCast(encoded_headers.len),
                .frame_type = .headers,
                .flags = .{ .end_headers = true, .end_stream = end_stream },
                .stream_id = stream_id,
                .payload = encoded_headers,
            };
            
            const frame_data = try frame.serialize(self.allocator);
            defer self.allocator.free(frame_data);
            
            _ = try self.transport_stream.writeAsync(frame_data);
        } else {
            // Multiple frames with CONTINUATION
            var offset: usize = 0;
            var is_first = true;
            
            while (offset < encoded_headers.len) {
                const chunk_size = @min(max_frame_size, encoded_headers.len - offset);
                const is_last = (offset + chunk_size) >= encoded_headers.len;
                
                const frame_type: FrameType = if (is_first) .headers else .continuation;
                const frame = Frame{
                    .length = @intCast(chunk_size),
                    .frame_type = frame_type,
                    .flags = .{ 
                        .end_headers = is_last, 
                        .end_stream = if (is_first) end_stream else false 
                    },
                    .stream_id = stream_id,
                    .payload = encoded_headers[offset..offset + chunk_size],
                };
                
                const frame_data = try frame.serialize(self.allocator);
                defer self.allocator.free(frame_data);
                
                _ = try self.transport_stream.writeAsync(frame_data);
                
                offset += chunk_size;
                is_first = false;
            }
        }
    }
    
    pub fn sendData(self: *Http2Connection, stream_id: u31, data: []const u8, end_stream: bool) !void {
        var stream = self.streams.getPtr(stream_id) orelse return error.InvalidStreamId;
        
        if (!stream.canSendData()) {
            return error.StreamNotOpen;
        }
        
        // Implement flow control
        var offset: usize = 0;
        const max_frame_size = self.peer_settings.max_frame_size;
        
        while (offset < data.len) {
            // Check connection-level window
            if (self.peer_window_size <= 0) {
                // Would need to wait for WINDOW_UPDATE frame
                return error.FlowControlBlocked;
            }
            
            // Check stream-level window
            if (stream.peer_window_size <= 0) {
                return error.StreamFlowControlBlocked;
            }
            
            // Calculate chunk size respecting both frame size and flow control
            const max_by_frame = max_frame_size;
            const max_by_connection_window = @as(usize, @intCast(@max(0, self.peer_window_size)));
            const max_by_stream_window = @as(usize, @intCast(@max(0, stream.peer_window_size)));
            const remaining_data = data.len - offset;
            
            const chunk_size = @min(@min(@min(max_by_frame, max_by_connection_window), max_by_stream_window), remaining_data);
            
            if (chunk_size == 0) {
                return error.FlowControlBlocked;
            }
            
            const is_last_chunk = (offset + chunk_size) >= data.len;
            const frame = Frame{
                .length = @intCast(chunk_size),
                .frame_type = .data,
                .flags = .{ .end_stream = end_stream and is_last_chunk },
                .stream_id = stream_id,
                .payload = data[offset..offset + chunk_size],
            };
            
            const frame_data = try frame.serialize(self.allocator);
            defer self.allocator.free(frame_data);
            
            _ = try self.transport_stream.writeAsync(frame_data);
            
            // Update flow control windows
            self.peer_window_size -= @intCast(chunk_size);
            stream.peer_window_size -= @intCast(chunk_size);
            
            offset += chunk_size;
        }
    }
    
    pub fn sendSettings(self: *Http2Connection) !void {
        // Create settings payload
        var settings_data = std.ArrayList(u8).init(self.allocator);
        defer settings_data.deinit();
        
        // SETTINGS_HEADER_TABLE_SIZE (0x1)
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 0x1)));
        try settings_data.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, self.settings.header_table_size)));
        
        // SETTINGS_ENABLE_PUSH (0x2)
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 0x2)));
        try settings_data.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, if (self.settings.enable_push) @as(u32, 1) else @as(u32, 0))));
        
        // SETTINGS_MAX_CONCURRENT_STREAMS (0x3)
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 0x3)));
        try settings_data.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, self.settings.max_concurrent_streams)));
        
        // SETTINGS_INITIAL_WINDOW_SIZE (0x4)
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 0x4)));
        try settings_data.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, self.settings.initial_window_size)));
        
        // SETTINGS_MAX_FRAME_SIZE (0x5)
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 0x5)));
        try settings_data.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, self.settings.max_frame_size)));
        
        // SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 0x6)));
        try settings_data.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, self.settings.max_header_list_size)));
        
        const frame = Frame{
            .length = @intCast(settings_data.items.len),
            .frame_type = .settings,
            .flags = .{},
            .stream_id = 0,
            .payload = settings_data.items,
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
    
    /// Send GOAWAY frame
    pub fn sendGoAway(self: *Http2Connection, last_stream_id: u31, error_code: u32, debug_data: []const u8) !void {
        var payload = std.ArrayList(u8).init(self.allocator);
        defer payload.deinit();
        
        try payload.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, last_stream_id)));
        try payload.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, error_code)));
        try payload.appendSlice(debug_data);
        
        const frame = Frame{
            .length = @intCast(payload.items.len),
            .frame_type = .goaway,
            .flags = .{},
            .stream_id = 0,
            .payload = payload.items,
        };
        
        const frame_data = try frame.serialize(self.allocator);
        defer self.allocator.free(frame_data);
        
        _ = try self.transport_stream.writeAsync(frame_data);
    }
    
    /// Send RST_STREAM frame  
    pub fn resetStream(self: *Http2Connection, stream_id: u31, error_code: u32) !void {
        var payload: [4]u8 = undefined;
        std.mem.writeIntBig(u32, &payload, error_code);
        
        const frame = Frame{
            .length = 4,
            .frame_type = .rst_stream,
            .flags = .{},
            .stream_id = stream_id,
            .payload = &payload,
        };
        
        const frame_data = try frame.serialize(self.allocator);
        defer self.allocator.free(frame_data);
        
        _ = try self.transport_stream.writeAsync(frame_data);
        
        // Update stream state
        if (self.streams.getPtr(stream_id)) |stream| {
            stream.state = .closed;
        }
    }
    
    /// Send WINDOW_UPDATE frame
    pub fn updateWindow(self: *Http2Connection, stream_id: u31, increment: u32) !void {
        if (increment == 0 or increment > 0x7FFFFFFF) {
            return error.InvalidWindowUpdate;
        }
        
        var payload: [4]u8 = undefined;
        std.mem.writeIntBig(u32, &payload, increment);
        
        const frame = Frame{
            .length = 4,
            .frame_type = .window_update,
            .flags = .{},
            .stream_id = stream_id,
            .payload = &payload,
        };
        
        const frame_data = try frame.serialize(self.allocator);
        defer self.allocator.free(frame_data);
        
        _ = try self.transport_stream.writeAsync(frame_data);
        
        // Update local window size
        if (stream_id == 0) {
            self.window_size += @intCast(increment);
        } else if (self.streams.getPtr(stream_id)) |stream| {
            stream.window_size += @intCast(increment);
        }
    }
    
    /// Handle connection maintenance (ping, flow control, etc.)
    pub fn maintainConnection(self: *Http2Connection) !void {
        // Send window updates if needed
        if (self.window_size < 32768) { // Half of default window
            try self.updateWindow(0, 32768);
        }
        
        // Check for streams that need window updates
        var iter = self.streams.iterator();
        while (iter.next()) |entry| {
            const stream = entry.value_ptr;
            if (stream.window_size < 16384) {
                try self.updateWindow(stream.id, 32768);
            }
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
    
    /// Send a PING frame to test connection liveness
    pub fn ping(self: *Http2Client) !void {
        self.connection.ping_counter += 1;
        
        var ping_data: [8]u8 = undefined;
        std.mem.writeIntBig(u64, &ping_data, self.connection.ping_counter);
        
        const frame = Frame{
            .length = 8,
            .frame_type = .ping,
            .flags = .{},
            .stream_id = 0,
            .payload = &ping_data,
        };
        
        const frame_data = try frame.serialize(self.connection.allocator);
        defer self.connection.allocator.free(frame_data);
        
        _ = try self.connection.transport_stream.writeAsync(frame_data);
    }
    
    /// Gracefully close the connection
    pub fn close(self: *Http2Client) !void {
        try self.connection.sendGoAway(0, 0, "Normal closure");
        self.connection.state = .closing;
    }
};

// HTTP/2 Server implementation  
pub const Http2Server = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    connection: *Http2Connection,
    request_handler: *const fn(*Http2Server, u31, *http.HttpRequest) anyerror!http.HttpResponse,
    
    pub fn init(
        allocator: std.mem.Allocator, 
        runtime: *zsync.Runtime, 
        transport_stream: transport.Stream,
        request_handler: *const fn(*Http2Server, u31, *http.HttpRequest) anyerror!http.HttpResponse
    ) !*Http2Server {
        var server = try allocator.create(Http2Server);
        server.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .connection = try Http2Connection.init(allocator, runtime, transport_stream, false),
            .request_handler = request_handler,
        };
        
        try server.connection.performHandshake();
        
        return server;
    }
    
    pub fn deinit(self: *Http2Server) void {
        self.connection.deinit();
        self.allocator.destroy(self);
    }
    
    /// Server push implementation
    pub fn pushResource(self: *Http2Server, parent_stream_id: u31, request: *http.HttpRequest) !u31 {
        if (!self.connection.peer_settings.enable_push) {
            return error.PushNotEnabled;
        }
        
        const push_stream_id = try self.connection.createStream();
        
        // Send PUSH_PROMISE frame
        var promise_headers = std.ArrayList(hpack.HeaderField).init(self.allocator);
        defer {
            for (promise_headers.items) |header| {
                header.deinit(self.allocator);
            }
            promise_headers.deinit();
        }
        
        try promise_headers.append(hpack.HeaderField{
            .name = try self.allocator.dupe(u8, ":method"),
            .value = try self.allocator.dupe(u8, request.method.toString()),
        });
        try promise_headers.append(hpack.HeaderField{
            .name = try self.allocator.dupe(u8, ":path"),
            .value = try self.allocator.dupe(u8, request.path),
        });
        try promise_headers.append(hpack.HeaderField{
            .name = try self.allocator.dupe(u8, ":scheme"),
            .value = try self.allocator.dupe(u8, "https"),
        });
        
        const encoded_headers = try self.connection.hpack_context.encode(promise_headers.items);
        defer self.allocator.free(encoded_headers);
        
        // Create PUSH_PROMISE payload: 4 bytes for promised stream ID + headers
        var promise_payload = std.ArrayList(u8).init(self.allocator);
        defer promise_payload.deinit();
        
        try promise_payload.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, push_stream_id)));
        try promise_payload.appendSlice(encoded_headers);
        
        const frame = Frame{
            .length = @intCast(promise_payload.items.len),
            .frame_type = .push_promise,
            .flags = .{ .end_headers = true },
            .stream_id = parent_stream_id,
            .payload = promise_payload.items,
        };
        
        const frame_data = try frame.serialize(self.allocator);
        defer self.allocator.free(frame_data);
        
        _ = try self.connection.transport_stream.writeAsync(frame_data);
        
        return push_stream_id;
    }
    
    /// Process incoming request
    pub fn handleRequest(self: *Http2Server, stream_id: u31) !void {
        var stream = self.connection.streams.getPtr(stream_id) orelse return error.InvalidStreamId;
        
        // Convert stream headers to HttpRequest
        var request = try http.HttpRequest.init(self.allocator);
        defer request.deinit();
        
        // Set method, path, etc. from :method, :path headers
        var header_iter = stream.headers.iterator();
        while (header_iter.next()) |entry| {
            if (std.mem.eql(u8, entry.key_ptr.*, ":method")) {
                request.method = http.HttpMethod.fromString(entry.value_ptr.*) orelse .GET;
            } else if (std.mem.eql(u8, entry.key_ptr.*, ":path")) {
                try request.setPath(entry.value_ptr.*);
            } else {
                try request.setHeader(entry.key_ptr.*, entry.value_ptr.*);
            }
        }
        
        if (stream.data.items.len > 0) {
            try request.setBody(stream.data.items);
        }
        
        // Call user handler
        const response = try self.request_handler(self, stream_id, &request);
        defer response.deinit();
        
        // Send response
        try self.sendResponse(stream_id, &response);
    }
    
    fn sendResponse(self: *Http2Server, stream_id: u31, response: *const http.HttpResponse) !void {
        var stream = self.connection.streams.getPtr(stream_id) orelse return error.InvalidStreamId;
        
        // Clear existing headers and add response headers
        stream.headers.clearAndFree();
        
        // Add status header
        const status_str = try std.fmt.allocPrint(self.allocator, "{d}", .{response.status_code});
        defer self.allocator.free(status_str);
        try stream.addHeader(":status", status_str);
        
        // Add response headers
        var header_iter = response.headers.iterator();
        while (header_iter.next()) |entry| {
            try stream.addHeader(entry.key_ptr.*, entry.value_ptr.*);
        }
        
        // Send headers
        const has_body = response.body != null and response.body.?.len > 0;
        try self.connection.sendHeaders(stream_id, !has_body);
        
        // Send body if present
        if (has_body) {
            try self.connection.sendData(stream_id, response.body.?, true);
        }
    }
};