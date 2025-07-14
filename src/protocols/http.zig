const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");
const tcp = @import("../transport/tcp.zig");
const websocket = @import("websocket.zig");
const handshake = @import("../crypto/handshake.zig");
const errors = @import("../errors/errors.zig");

pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
    
    pub fn toString(self: HttpMethod) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
            .PATCH => "PATCH",
        };
    }
};

pub const HttpStatus = enum(u16) {
    continue_status = 100,
    switching_protocols = 101,
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    moved_permanently = 301,
    found = 302,
    not_modified = 304,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    
    pub fn toString(self: HttpStatus) []const u8 {
        return switch (self) {
            .continue_status => "Continue",
            .switching_protocols => "Switching Protocols",
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .no_content => "No Content",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .not_modified => "Not Modified",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
        };
    }
};

pub const HttpVersion = enum {
    http_1_0,
    http_1_1,
    http_2_0,
    
    pub fn toString(self: HttpVersion) []const u8 {
        return switch (self) {
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
            .http_2_0 => "HTTP/2.0",
        };
    }
};

pub const HttpRequest = struct {
    method: HttpMethod,
    path: []const u8,
    version: HttpVersion,
    headers: std.StringHashMap([]const u8),
    body: ?[]const u8,
    
    pub fn init(allocator: std.mem.Allocator, method: HttpMethod, path: []const u8) !HttpRequest {
        return HttpRequest{
            .method = method,
            .path = try allocator.dupe(u8, path),
            .version = .http_1_1,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = null,
        };
    }
    
    pub fn deinit(self: *HttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        
        if (self.body) |body| {
            allocator.free(body);
        }
    }
    
    pub fn setHeader(self: *HttpRequest, allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
        const name_copy = try allocator.dupe(u8, name);
        const value_copy = try allocator.dupe(u8, value);
        try self.headers.put(name_copy, value_copy);
    }
    
    pub fn setBody(self: *HttpRequest, allocator: std.mem.Allocator, body: []const u8) !void {
        self.body = try allocator.dupe(u8, body);
        
        // Set Content-Length header
        const content_length = try std.fmt.allocPrint(allocator, "{d}", .{body.len});
        try self.setHeader(allocator, "Content-Length", content_length);
    }
    
    pub fn serialize(self: *HttpRequest, allocator: std.mem.Allocator) ![]u8 {
        var request = std.ArrayList(u8).init(allocator);
        
        // Request line
        try request.writer().print("{s} {s} {s}\r\n", .{ self.method.toString(), self.path, self.version.toString() });
        
        // Headers
        var header_iter = self.headers.iterator();
        while (header_iter.next()) |entry| {
            try request.writer().print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
        
        // Empty line
        try request.appendSlice("\r\n");
        
        // Body
        if (self.body) |body| {
            try request.appendSlice(body);
        }
        
        return request.toOwnedSlice();
    }
};

pub const HttpResponse = struct {
    version: HttpVersion,
    status_code: u16,
    status_text: []const u8,
    headers: std.StringHashMap([]const u8),
    body: ?[]const u8,
    
    pub fn init(allocator: std.mem.Allocator, status_code: u16, status_text: []const u8) !HttpResponse {
        return HttpResponse{
            .version = .http_1_1,
            .status_code = status_code,
            .status_text = try allocator.dupe(u8, status_text),
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = null,
        };
    }
    
    pub fn deinit(self: *HttpResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.status_text);
        
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        
        if (self.body) |body| {
            allocator.free(body);
        }
    }
    
    pub fn setHeader(self: *HttpResponse, allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
        const name_copy = try allocator.dupe(u8, name);
        const value_copy = try allocator.dupe(u8, value);
        try self.headers.put(name_copy, value_copy);
    }
    
    pub fn setBody(self: *HttpResponse, allocator: std.mem.Allocator, body: []const u8) !void {
        self.body = try allocator.dupe(u8, body);
        
        // Set Content-Length header
        const content_length = try std.fmt.allocPrint(allocator, "{d}", .{body.len});
        try self.setHeader(allocator, "Content-Length", content_length);
    }
    
    pub fn getHeader(self: *HttpResponse, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }
    
    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !HttpResponse {
        var lines = std.mem.split(u8, data, "\r\n");
        
        // Parse status line
        const status_line = lines.next() orelse return error.InvalidResponse;
        var status_parts = std.mem.split(u8, status_line, " ");
        
        const version_str = status_parts.next() orelse return error.InvalidResponse;
        const status_code_str = status_parts.next() orelse return error.InvalidResponse;
        const status_text = status_parts.rest();
        
        const version = if (std.mem.eql(u8, version_str, "HTTP/1.0"))
            HttpVersion.http_1_0
        else if (std.mem.eql(u8, version_str, "HTTP/1.1"))
            HttpVersion.http_1_1
        else if (std.mem.eql(u8, version_str, "HTTP/2.0"))
            HttpVersion.http_2_0
        else
            return error.UnsupportedVersion;
        
        const status_code = try std.fmt.parseInt(u16, status_code_str, 10);
        
        var response = HttpResponse{
            .version = version,
            .status_code = status_code,
            .status_text = try allocator.dupe(u8, status_text),
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = null,
        };
        
        // Parse headers
        var content_length: ?usize = null;
        while (lines.next()) |line| {
            if (line.len == 0) break; // Empty line indicates end of headers
            
            const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
            const name = std.mem.trim(u8, line[0..colon_pos], " \t");
            const value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");
            
            if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                content_length = try std.fmt.parseInt(usize, value, 10);
            }
            
            try response.setHeader(allocator, name, value);
        }
        
        // Parse body
        if (content_length) |len| {
            const body_start = std.mem.indexOf(u8, data, "\r\n\r\n");
            if (body_start) |start| {
                const body_data = data[start + 4 ..];
                if (body_data.len >= len) {
                    response.body = try allocator.dupe(u8, body_data[0..len]);
                }
            }
        }
        
        return response;
    }
};

pub const HttpClient = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    user_agent: []const u8,
    default_headers: std.StringHashMap([]const u8),
    timeout: u64, // milliseconds
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) !*HttpClient {
        var client = try allocator.create(HttpClient);
        client.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .user_agent = try allocator.dupe(u8, "ghostnet/0.1.0"),
            .default_headers = std.StringHashMap([]const u8).init(allocator),
            .timeout = 30000, // 30 seconds
        };
        
        // Set default headers
        try client.setDefaultHeader("User-Agent", client.user_agent);
        try client.setDefaultHeader("Accept", "*/*");
        try client.setDefaultHeader("Connection", "close");
        
        return client;
    }
    
    pub fn deinit(self: *HttpClient) void {
        self.allocator.free(self.user_agent);
        
        var iter = self.default_headers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.default_headers.deinit();
        
        self.allocator.destroy(self);
    }
    
    pub fn setDefaultHeader(self: *HttpClient, name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.default_headers.put(name_copy, value_copy);
    }
    
    pub fn get(self: *HttpClient, url: []const u8) !HttpResponse {
        var request = try HttpRequest.init(self.allocator, .GET, url);
        defer request.deinit(self.allocator);
        
        return try self.sendRequest(&request, url);
    }
    
    pub fn post(self: *HttpClient, url: []const u8, body: []const u8, content_type: []const u8) !HttpResponse {
        var request = try HttpRequest.init(self.allocator, .POST, url);
        defer request.deinit(self.allocator);
        
        try request.setBody(self.allocator, body);
        try request.setHeader(self.allocator, "Content-Type", content_type);
        
        return try self.sendRequest(&request, url);
    }
    
    pub fn postJson(self: *HttpClient, url: []const u8, json_body: []const u8) !HttpResponse {
        return try self.post(url, json_body, "application/json");
    }
    
    pub fn sendRequest(self: *HttpClient, request: *HttpRequest, url: []const u8) !HttpResponse {
        // Parse URL
        const uri = std.Uri.parse(url) catch return error.InvalidUrl;
        
        const host = uri.host orelse return error.MissingHost;
        const port = uri.port orelse if (std.mem.eql(u8, uri.scheme, "https")) 443 else 80;
        const is_https = std.mem.eql(u8, uri.scheme, "https");
        
        // Add default headers
        var header_iter = self.default_headers.iterator();
        while (header_iter.next()) |entry| {
            if (!request.headers.contains(entry.key_ptr.*)) {
                try request.setHeader(self.allocator, entry.key_ptr.*, entry.value_ptr.*);
            }
        }
        
        // Add Host header
        if (!request.headers.contains("Host")) {
            try request.setHeader(self.allocator, "Host", host);
        }
        
        // Create TCP connection
        const address = transport.Address{
            .ipv4 = try std.net.Ip4Address.parse(host, port)
        };
        
        var tcp_conn = try tcp.TcpConnection.connect(
            self.allocator,
            self.runtime,
            address,
            transport.TransportOptions{ .allocator = self.allocator }
        );
        defer tcp_conn.deinit();
        
        var stream = tcp_conn.stream();
        
        // Perform TLS handshake if HTTPS
        if (is_https) {
            const tls_config = handshake.HandshakeConfig{
                .handshake_type = .tls,
                .cipher_suite = .chacha20_poly1305,
                .key_exchange = .curve25519,
                .is_initiator = true,
                .server_name = host,
                .alpn_protocols = &[_][]const u8{ "http/1.1", "h2" },
            };
            
            var handshake_manager = handshake.HandshakeManager.init(self.allocator, self.runtime);
            const handshake_result = try handshake_manager.performHandshake(tls_config, stream);
            
            // Use encrypted stream (would need to wrap with TLS)
            _ = handshake_result;
        }
        
        // Send request
        const request_data = try request.serialize(self.allocator);
        defer self.allocator.free(request_data);
        
        _ = try stream.writeAsync(request_data);
        
        // Read response
        var response_buffer = std.ArrayList(u8).init(self.allocator);
        defer response_buffer.deinit();
        
        var temp_buffer: [4096]u8 = undefined;
        var total_read: usize = 0;
        
        while (total_read < 1024 * 1024) { // Max 1MB response
            const bytes_read = stream.readAsync(&temp_buffer) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            
            switch (bytes_read) {
                .ready => |result| {
                    if (result) |n| {
                        if (n == 0) break; // EOF
                        try response_buffer.appendSlice(temp_buffer[0..n]);
                        total_read += n;
                    } else |read_err| {
                        return read_err;
                    }
                },
                .pending => {
                    std.time.sleep(1000000); // 1ms
                    continue;
                },
            }
        }
        
        // Parse response
        return HttpResponse.parse(self.allocator, response_buffer.items);
    }
    
    pub fn upgradeToWebSocket(self: *HttpClient, url: []const u8, protocols: []const []const u8) !*websocket.WebSocketConnection {
        // Parse URL
        const uri = std.Uri.parse(url) catch return error.InvalidUrl;
        
        const host = uri.host orelse return error.MissingHost;
        const port = uri.port orelse if (std.mem.eql(u8, uri.scheme, "wss")) 443 else 80;
        
        // Create WebSocket config
        var ws_config = websocket.WebSocketConfig.init(self.allocator);
        ws_config.subprotocols = protocols;
        
        // Create TCP connection
        const address = transport.Address{
            .ipv4 = try std.net.Ip4Address.parse(host, port)
        };
        
        var tcp_conn = try tcp.TcpConnection.connect(
            self.allocator,
            self.runtime,
            address,
            transport.TransportOptions{ .allocator = self.allocator }
        );
        
        // Create WebSocket connection
        var ws_conn = try websocket.WebSocketConnection.init(
            self.allocator,
            self.runtime,
            ws_config,
            tcp_conn.stream(),
            true
        );
        
        // Perform WebSocket handshake
        try ws_conn.performHandshake(url);
        
        return ws_conn;
    }
};

// AI Service specific clients
pub const ClaudeClient = struct {
    http_client: *HttpClient,
    api_key: []const u8,
    base_url: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, api_key: []const u8) !*ClaudeClient {
        var client = try allocator.create(ClaudeClient);
        client.* = .{
            .http_client = try HttpClient.init(allocator, runtime),
            .api_key = try allocator.dupe(u8, api_key),
            .base_url = try allocator.dupe(u8, "https://api.anthropic.com/v1"),
        };
        
        // Set Claude-specific headers
        const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_key});
        try client.http_client.setDefaultHeader("Authorization", auth_header);
        try client.http_client.setDefaultHeader("anthropic-version", "2023-06-01");
        
        return client;
    }
    
    pub fn deinit(self: *ClaudeClient) void {
        self.http_client.deinit();
        self.http_client.allocator.free(self.api_key);
        self.http_client.allocator.free(self.base_url);
        self.http_client.allocator.destroy(self);
    }
    
    pub fn sendMessage(self: *ClaudeClient, message: []const u8, model: []const u8) !HttpResponse {
        const url = try std.fmt.allocPrint(self.http_client.allocator, "{s}/messages", .{self.base_url});
        defer self.http_client.allocator.free(url);
        
        const request_body = try std.fmt.allocPrint(self.http_client.allocator,
            \\{{
            \\  "model": "{s}",
            \\  "max_tokens": 4096,
            \\  "messages": [
            \\    {{
            \\      "role": "user",
            \\      "content": "{s}"
            \\    }}
            \\  ]
            \\}}
        , .{ model, message });
        defer self.http_client.allocator.free(request_body);
        
        return try self.http_client.postJson(url, request_body);
    }
};

pub const CopilotClient = struct {
    http_client: *HttpClient,
    access_token: []const u8,
    base_url: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, access_token: []const u8) !*CopilotClient {
        var client = try allocator.create(CopilotClient);
        client.* = .{
            .http_client = try HttpClient.init(allocator, runtime),
            .access_token = try allocator.dupe(u8, access_token),
            .base_url = try allocator.dupe(u8, "https://api.github.com/copilot"),
        };
        
        // Set GitHub-specific headers
        const auth_header = try std.fmt.allocPrint(allocator, "token {s}", .{access_token});
        try client.http_client.setDefaultHeader("Authorization", auth_header);
        try client.http_client.setDefaultHeader("Accept", "application/vnd.github.v3+json");
        
        return client;
    }
    
    pub fn deinit(self: *CopilotClient) void {
        self.http_client.deinit();
        self.http_client.allocator.free(self.access_token);
        self.http_client.allocator.free(self.base_url);
        self.http_client.allocator.destroy(self);
    }
    
    pub fn getCompletions(self: *CopilotClient, prompt: []const u8, language: []const u8) !HttpResponse {
        const url = try std.fmt.allocPrint(self.http_client.allocator, "{s}/completions", .{self.base_url});
        defer self.http_client.allocator.free(url);
        
        const request_body = try std.fmt.allocPrint(self.http_client.allocator,
            \\{{
            \\  "prompt": "{s}",
            \\  "language": "{s}",
            \\  "max_tokens": 100
            \\}}
        , .{ prompt, language });
        defer self.http_client.allocator.free(request_body);
        
        return try self.http_client.postJson(url, request_body);
    }
};