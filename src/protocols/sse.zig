//! Server-Sent Events (SSE) - HTTP streaming for real-time data
//! RFC 6202 implementation for real-time web applications

const std = @import("std");
const zsync = @import("zsync");
const http = @import("http.zig");
const transport = @import("../transport/transport.zig");
const errors = @import("../errors/errors.zig");

/// SSE event types
pub const EventType = enum {
    message,
    open,
    error,
    custom,
    
    pub fn toString(self: EventType) []const u8 {
        return switch (self) {
            .message => "message",
            .open => "open", 
            .error => "error",
            .custom => "",
        };
    }
};

/// SSE event data
pub const Event = struct {
    event_type: EventType,
    custom_type: ?[]const u8 = null,
    data: []const u8,
    id: ?[]const u8 = null,
    retry: ?u32 = null,
    
    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        if (self.id) |id| {
            allocator.free(id);
        }
        if (self.custom_type) |custom| {
            allocator.free(custom);
        }
    }
    
    /// Format event for transmission
    pub fn format(self: Event, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        // Event type
        const event_name = if (self.event_type == .custom and self.custom_type != null)
            self.custom_type.?
        else
            self.event_type.toString();
            
        if (event_name.len > 0) {
            try buffer.writer().print("event: {s}\n", .{event_name});
        }
        
        // Event ID
        if (self.id) |id| {
            try buffer.writer().print("id: {s}\n", .{id});
        }
        
        // Retry interval
        if (self.retry) |retry_ms| {
            try buffer.writer().print("retry: {d}\n", .{retry_ms});
        }
        
        // Event data (handle multiline data)
        var lines = std.mem.split(u8, self.data, "\n");
        while (lines.next()) |line| {
            try buffer.writer().print("data: {s}\n", .{line});
        }
        
        // End event with double newline
        try buffer.writer().writeAll("\n");
        
        return buffer.toOwnedSlice();
    }
    
    /// Parse event from SSE stream
    pub fn parse(data: []const u8, allocator: std.mem.Allocator) !?Event {
        if (data.len == 0) return null;
        
        var event = Event{
            .event_type = .message,
            .data = "",
        };
        
        var data_lines = std.ArrayList([]const u8).init(allocator);
        defer data_lines.deinit();
        
        var lines = std.mem.split(u8, data, "\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            
            const colon_pos = std.mem.indexOf(u8, trimmed, ":");
            if (colon_pos == null) continue;
            
            const field = std.mem.trim(u8, trimmed[0..colon_pos.?], " \t");
            const value = std.mem.trim(u8, trimmed[colon_pos.? + 1..], " \t");
            
            if (std.mem.eql(u8, field, "event")) {
                if (std.mem.eql(u8, value, "message")) {
                    event.event_type = .message;
                } else if (std.mem.eql(u8, value, "open")) {
                    event.event_type = .open;
                } else if (std.mem.eql(u8, value, "error")) {
                    event.event_type = .error;
                } else {
                    event.event_type = .custom;
                    event.custom_type = try allocator.dupe(u8, value);
                }
            } else if (std.mem.eql(u8, field, "data")) {
                try data_lines.append(value);
            } else if (std.mem.eql(u8, field, "id")) {
                event.id = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, field, "retry")) {
                event.retry = try std.fmt.parseInt(u32, value, 10);
            }
        }
        
        // Combine data lines
        if (data_lines.items.len > 0) {
            const combined_data = try std.mem.join(allocator, "\n", data_lines.items);
            event.data = combined_data;
        } else {
            event.data = try allocator.dupe(u8, "");
        }
        
        return event;
    }
};

/// SSE connection options
pub const ConnectionOptions = struct {
    last_event_id: ?[]const u8 = null,
    timeout: u64 = 30000, // 30 seconds
    retry_interval: u32 = 3000, // 3 seconds
    max_retries: u32 = 0, // 0 = unlimited
    headers: ?std.StringHashMap([]const u8) = null,
};

/// SSE client for consuming server-sent events
pub const SseClient = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    http_client: *http.HttpClient,
    url: []const u8,
    options: ConnectionOptions,
    connected: bool,
    last_event_id: ?[]u8,
    event_handlers: std.StringHashMap(*const fn (Event) void),
    retry_count: u32,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, url: []const u8, options: ConnectionOptions) !*SseClient {
        var client = try allocator.create(SseClient);
        client.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .http_client = try http.HttpClient.init(allocator, runtime),
            .url = try allocator.dupe(u8, url),
            .options = options,
            .connected = false,
            .last_event_id = if (options.last_event_id) |id| try allocator.dupe(u8, id) else null,
            .event_handlers = std.StringHashMap(*const fn (Event) void).init(allocator),
            .retry_count = 0,
        };
        return client;
    }
    
    pub fn deinit(self: *SseClient) void {
        if (self.connected) {
            self.disconnect();
        }
        
        self.http_client.deinit();
        self.allocator.free(self.url);
        
        if (self.last_event_id) |id| {
            self.allocator.free(id);
        }
        
        var handler_it = self.event_handlers.iterator();
        while (handler_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.event_handlers.deinit();
        
        self.allocator.destroy(self);
    }
    
    pub fn connect(self: *SseClient) !void {
        if (self.connected) return;
        
        // Start connection loop
        _ = zsync.spawn(self.connectionLoop, .{});
    }
    
    pub fn disconnect(self: *SseClient) void {
        self.connected = false;
    }
    
    pub fn addEventListener(self: *SseClient, event_type: []const u8, handler: *const fn (Event) void) !void {
        const owned_type = try self.allocator.dupe(u8, event_type);
        try self.event_handlers.put(owned_type, handler);
    }
    
    pub fn removeEventListener(self: *SseClient, event_type: []const u8) void {
        if (self.event_handlers.fetchRemove(event_type)) |entry| {
            self.allocator.free(entry.key);
        }
    }
    
    fn connectionLoop(self: *SseClient) void {
        while (self.options.max_retries == 0 or self.retry_count < self.options.max_retries) {
            self.connectOnce() catch |err| {
                std.log.err("SSE connection error: {}", .{err});
                
                // Wait before retry
                if (self.options.max_retries == 0 or self.retry_count < self.options.max_retries) {
                    zsync.sleep(self.options.retry_interval * std.time.ns_per_ms) catch {};
                    self.retry_count += 1;
                    continue;
                }
                break;
            };
            
            // Connection successful, reset retry count
            self.retry_count = 0;
        }
    }
    
    fn connectOnce(self: *SseClient) !void {
        // Prepare request headers
        var request = try http.HttpRequest.init(self.allocator, .GET, self.url);
        defer request.deinit(self.allocator);
        
        // Set SSE-specific headers
        try request.setHeader(self.allocator, "Accept", "text/event-stream");
        try request.setHeader(self.allocator, "Cache-Control", "no-cache");
        
        // Set Last-Event-ID if available
        if (self.last_event_id) |id| {
            try request.setHeader(self.allocator, "Last-Event-ID", id);
        }
        
        // Add custom headers
        if (self.options.headers) |headers| {
            var it = headers.iterator();
            while (it.next()) |entry| {
                try request.setHeader(self.allocator, entry.key_ptr.*, entry.value_ptr.*);
            }
        }
        
        // Send request and get streaming response
        const response = try self.http_client.sendRequest(&request, self.url);
        defer response.deinit(self.allocator);
        
        if (response.status_code != 200) {
            return error.HTTPError;
        }
        
        // Check content type
        if (response.headers.get("content-type")) |content_type| {
            if (!std.mem.startsWith(u8, content_type, "text/event-stream")) {
                return error.InvalidContentType;
            }
        }
        
        self.connected = true;
        
        // Process event stream
        try self.processEventStream(response.body);
        
        self.connected = false;
    }
    
    fn processEventStream(self: *SseClient, stream_data: []const u8) !void {
        var pos: usize = 0;
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        while (pos < stream_data.len) {
            const line_end = std.mem.indexOfPos(u8, stream_data, pos, "\n") orelse stream_data.len;
            const line = stream_data[pos..line_end];
            
            // Check for event boundary (empty line)
            if (std.mem.trim(u8, line, " \t\r").len == 0) {
                // Process accumulated event data
                if (buffer.items.len > 0) {
                    if (Event.parse(buffer.items, self.allocator)) |event| {
                        if (event) |ev| {
                            try self.handleEvent(ev);
                        }
                    } else |err| {
                        std.log.err("Failed to parse SSE event: {}", .{err});
                    }
                    buffer.clearRetainingCapacity();
                }
            } else {
                // Accumulate event data
                try buffer.appendSlice(line);
                try buffer.append('\n');
            }
            
            pos = if (line_end < stream_data.len) line_end + 1 else stream_data.len;
        }
        
        // Process any remaining data
        if (buffer.items.len > 0) {
            if (Event.parse(buffer.items, self.allocator)) |event| {
                if (event) |ev| {
                    try self.handleEvent(ev);
                }
            } else |err| {
                std.log.err("Failed to parse final SSE event: {}", .{err});
            }
        }
    }
    
    fn handleEvent(self: *SseClient, event: Event) !void {
        // Update last event ID
        if (event.id) |id| {
            if (self.last_event_id) |old_id| {
                self.allocator.free(old_id);
            }
            self.last_event_id = try self.allocator.dupe(u8, id);
        }
        
        // Find appropriate handler
        const handler_key = switch (event.event_type) {
            .message => "message",
            .open => "open",
            .error => "error",
            .custom => event.custom_type orelse "message",
        };
        
        if (self.event_handlers.get(handler_key)) |handler| {
            handler(event);
        } else if (self.event_handlers.get("message")) |default_handler| {
            // Fall back to message handler
            default_handler(event);
        }
        
        // Special handling for error events
        if (event.event_type == .error) {
            self.connected = false;
        }
    }
};

/// SSE server for broadcasting events
pub const SseServer = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    clients: std.ArrayList(*SseConnection),
    channels: std.StringHashMap(std.ArrayList(*SseConnection)),
    event_history: std.ArrayList(Event),
    max_history: usize,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, max_history: usize) !*SseServer {
        var server = try allocator.create(SseServer);
        server.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .clients = std.ArrayList(*SseConnection).init(allocator),
            .channels = std.StringHashMap(std.ArrayList(*SseConnection)).init(allocator),
            .event_history = std.ArrayList(Event).init(allocator),
            .max_history = max_history,
        };
        return server;
    }
    
    pub fn deinit(self: *SseServer) void {
        // Close all connections
        for (self.clients.items) |client| {
            client.close();
            client.deinit();
            self.allocator.destroy(client);
        }
        self.clients.deinit();
        
        // Clean up channels
        var channel_it = self.channels.iterator();
        while (channel_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.channels.deinit();
        
        // Clean up event history
        for (self.event_history.items) |*event| {
            event.deinit(self.allocator);
        }
        self.event_history.deinit();
        
        self.allocator.destroy(self);
    }
    
    pub fn handleConnection(self: *SseServer, response_writer: anytype, last_event_id: ?[]const u8) !*SseConnection {
        // Create SSE connection
        var connection = try SseConnection.init(self.allocator, response_writer);
        try self.clients.append(connection);
        
        // Send connection opened event
        try connection.sendEvent(.{
            .event_type = .open,
            .data = try self.allocator.dupe(u8, "connected"),
        });
        
        // Send missed events if last_event_id is provided
        if (last_event_id) |id| {
            var found = false;
            for (self.event_history.items) |event| {
                if (found) {
                    try connection.sendEvent(event);
                } else if (event.id != null and std.mem.eql(u8, event.id.?, id)) {
                    found = true;
                }
            }
        }
        
        return connection;
    }
    
    pub fn broadcast(self: *SseServer, event: Event) !void {
        // Add to history
        if (event.id != null) {
            try self.addToHistory(event);
        }
        
        // Send to all clients
        for (self.clients.items) |client| {
            client.sendEvent(event) catch |err| {
                std.log.err("Failed to send event to client: {}", .{err});
                // Mark client for removal
                client.close();
            };
        }
        
        // Remove closed clients
        var i: usize = 0;
        while (i < self.clients.items.len) {
            if (self.clients.items[i].closed) {
                const client = self.clients.orderedRemove(i);
                client.deinit();
                self.allocator.destroy(client);
            } else {
                i += 1;
            }
        }
    }
    
    pub fn broadcastToChannel(self: *SseServer, channel: []const u8, event: Event) !void {
        if (self.channels.get(channel)) |clients| {
            for (clients.items) |client| {
                client.sendEvent(event) catch |err| {
                    std.log.err("Failed to send event to client in channel {s}: {}", .{ channel, err });
                    client.close();
                };
            }
        }
    }
    
    pub fn subscribeToChannel(self: *SseServer, connection: *SseConnection, channel: []const u8) !void {
        if (self.channels.getPtr(channel)) |clients| {
            try clients.append(connection);
        } else {
            var clients = std.ArrayList(*SseConnection).init(self.allocator);
            try clients.append(connection);
            const owned_channel = try self.allocator.dupe(u8, channel);
            try self.channels.put(owned_channel, clients);
        }
    }
    
    fn addToHistory(self: *SseServer, event: Event) !void {
        // Make a copy of the event
        var event_copy = Event{
            .event_type = event.event_type,
            .data = try self.allocator.dupe(u8, event.data),
            .id = if (event.id) |id| try self.allocator.dupe(u8, id) else null,
            .custom_type = if (event.custom_type) |custom| try self.allocator.dupe(u8, custom) else null,
            .retry = event.retry,
        };
        
        try self.event_history.append(event_copy);
        
        // Limit history size
        while (self.event_history.items.len > self.max_history) {
            var old_event = self.event_history.orderedRemove(0);
            old_event.deinit(self.allocator);
        }
    }
};

/// Individual SSE connection
pub const SseConnection = struct {
    allocator: std.mem.Allocator,
    writer: std.io.AnyWriter,
    closed: bool,
    
    fn init(allocator: std.mem.Allocator, writer: std.io.AnyWriter) !*SseConnection {
        var connection = try allocator.create(SseConnection);
        connection.* = .{
            .allocator = allocator,
            .writer = writer,
            .closed = false,
        };
        return connection;
    }
    
    fn deinit(self: *SseConnection) void {
        // Writer cleanup is handled externally
    }
    
    pub fn sendEvent(self: *SseConnection, event: Event) !void {
        if (self.closed) return error.ConnectionClosed;
        
        const formatted = try event.format(self.allocator);
        defer self.allocator.free(formatted);
        
        self.writer.writeAll(formatted) catch {
            self.closed = true;
            return error.ConnectionClosed;
        };
    }
    
    pub fn sendMessage(self: *SseConnection, data: []const u8, event_id: ?[]const u8) !void {
        const event = Event{
            .event_type = .message,
            .data = data,
            .id = event_id,
        };
        try self.sendEvent(event);
    }
    
    pub fn sendCustomEvent(self: *SseConnection, event_type: []const u8, data: []const u8, event_id: ?[]const u8) !void {
        const event = Event{
            .event_type = .custom,
            .custom_type = event_type,
            .data = data,
            .id = event_id,
        };
        try self.sendEvent(event);
    }
    
    pub fn close(self: *SseConnection) void {
        self.closed = true;
    }
};