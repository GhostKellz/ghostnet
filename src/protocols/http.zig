const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");
const tcp = @import("../transport/tcp.zig");
const websocket = @import("websocket.zig");
const handshake = @import("../crypto/handshake.zig");
const errors = @import("../errors/errors.zig");
const middleware = @import("middleware.zig");
const pool = @import("../transport/pool.zig");
const quic = @import("quic.zig");
const http2 = @import("http2.zig");

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
    http_3_0,
    
    pub fn toString(self: HttpVersion) []const u8 {
        return switch (self) {
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
            .http_2_0 => "HTTP/2.0",
            .http_3_0 => "HTTP/3.0",
        };
    }
};

pub const ProtocolPreference = enum {
    http3,
    http2,
    http1_1,
    http1_0,
};

pub const ProtocolConfig = struct {
    preference_order: []const ProtocolPreference = &.{ .http3, .http2, .http1_1 },
    fallback_on_error: bool = true,
    protocol_cache_ttl: u64 = 3600000, // 1 hour in milliseconds
    connection_timeout: u64 = 10000, // 10 seconds
    enable_0rtt: bool = false,
    max_retries_per_protocol: u32 = 2,
};

pub const ProtocolCache = struct {
    entries: std.StringHashMap(CacheEntry),
    allocator: std.mem.Allocator,
    
    const CacheEntry = struct {
        protocol: HttpVersion,
        cached_at: i64,
        success_count: u32,
        failure_count: u32,
    };
    
    pub fn init(allocator: std.mem.Allocator) ProtocolCache {
        return .{
            .entries = std.StringHashMap(CacheEntry).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ProtocolCache) void {
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();
    }
    
    pub fn getProtocol(self: *ProtocolCache, host: []const u8, ttl: u64) ?HttpVersion {
        if (self.entries.get(host)) |entry| {
            const now = std.time.timestamp();
            if (now - entry.cached_at < @as(i64, @intCast(ttl / 1000))) {
                return entry.protocol;
            } else {
                _ = self.entries.remove(host);
            }
        }
        return null;
    }
    
    pub fn cacheProtocol(self: *ProtocolCache, host: []const u8, protocol: HttpVersion, success: bool) !void {
        const now = std.time.timestamp();
        const host_copy = try self.allocator.dupe(u8, host);
        
        if (self.entries.getPtr(host_copy)) |entry| {
            entry.protocol = protocol;
            entry.cached_at = now;
            if (success) {
                entry.success_count += 1;
            } else {
                entry.failure_count += 1;
            }
        } else {
            try self.entries.put(host_copy, .{
                .protocol = protocol,
                .cached_at = now,
                .success_count = if (success) 1 else 0,
                .failure_count = if (success) 0 else 1,
            });
        }
    }
};

pub const RateLimiter = struct {
    requests_per_second: f64,
    burst_size: u32,
    tokens: f64,
    last_refill: i64,
    mutex: std.Thread.Mutex,
    
    pub fn init(requests_per_second: f64, burst_size: u32) RateLimiter {
        return .{
            .requests_per_second = requests_per_second,
            .burst_size = burst_size,
            .tokens = @floatFromInt(burst_size),
            .last_refill = std.time.timestamp(),
            .mutex = .{},
        };
    }
    
    pub fn allowRequest(self: *RateLimiter) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const now = std.time.timestamp();
        const time_passed = @as(f64, @floatFromInt(now - self.last_refill));
        
        // Refill tokens based on time passed
        self.tokens += time_passed * self.requests_per_second;
        if (self.tokens > @as(f64, @floatFromInt(self.burst_size))) {
            self.tokens = @floatFromInt(self.burst_size);
        }
        
        self.last_refill = now;
        
        if (self.tokens >= 1.0) {
            self.tokens -= 1.0;
            return true;
        }
        
        return false;
    }
    
    pub fn waitTime(self: *RateLimiter) u64 {
        if (self.tokens >= 1.0) return 0;
        
        const tokens_needed = 1.0 - self.tokens;
        const wait_time = tokens_needed / self.requests_per_second;
        return @intFromFloat(wait_time * 1000); // Convert to milliseconds
    }
};

pub const RetryPolicy = struct {
    max_attempts: u32 = 3,
    backoff: BackoffStrategy = .exponential,
    base_delay_ms: u64 = 1000,
    max_delay_ms: u64 = 30000,
    retry_on: []const ErrorType = &.{ .timeout, .connection_reset, .server_error },
    jitter: bool = true,
    
    pub const BackoffStrategy = enum {
        fixed,
        linear,
        exponential,
    };
    
    pub const ErrorType = enum {
        timeout,
        connection_reset,
        server_error,
        dns_error,
        tls_error,
    };
    
    pub fn shouldRetry(self: *const RetryPolicy, error_type: ErrorType, attempt: u32) bool {
        if (attempt >= self.max_attempts) return false;
        
        for (self.retry_on) |retry_error| {
            if (retry_error == error_type) return true;
        }
        
        return false;
    }
    
    pub fn getDelay(self: *const RetryPolicy, attempt: u32) u64 {
        var delay = switch (self.backoff) {
            .fixed => self.base_delay_ms,
            .linear => self.base_delay_ms * attempt,
            .exponential => self.base_delay_ms * (std.math.pow(u64, 2, attempt - 1)),
        };
        
        if (delay > self.max_delay_ms) {
            delay = self.max_delay_ms;
        }
        
        if (self.jitter) {
            var rng = std.rand.DefaultPrng.init(@intCast(std.time.timestamp()));
            const jitter_range = delay / 4; // ±25% jitter
            const jitter_offset = rng.random().uintLessThan(u64, jitter_range * 2);
            delay = delay - jitter_range + jitter_offset;
        }
        
        return delay;
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
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, status_code: u16, status_text: []const u8) !HttpResponse {
        return HttpResponse{
            .version = .http_1_1,
            .status_code = status_code,
            .status_text = try allocator.dupe(u8, status_text),
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = null,
            .allocator = allocator,
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
    
    pub fn getJson(self: *HttpResponse, comptime T: type) !T {
        const body = self.body orelse return error.NoBody;
        return try std.json.parseFromSlice(T, self.allocator, body, .{});
    }
    
    pub fn isSuccess(self: *HttpResponse) bool {
        return self.status_code >= 200 and self.status_code < 300;
    }
    
    pub fn isRedirect(self: *HttpResponse) bool {
        return self.status_code >= 300 and self.status_code < 400;
    }
    
    pub fn isClientError(self: *HttpResponse) bool {
        return self.status_code >= 400 and self.status_code < 500;
    }
    
    pub fn isServerError(self: *HttpResponse) bool {
        return self.status_code >= 500 and self.status_code < 600;
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
            .allocator = allocator,
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
    bearer_token: ?[]const u8,
    basic_auth: ?struct { username: []const u8, password: []const u8 },
    api_key: ?struct { header: []const u8, value: []const u8 },
    middleware_chain: middleware.MiddlewareChain,
    connection_pool: ?*pool.ConnectionPool,
    protocol_config: ProtocolConfig,
    protocol_cache: ProtocolCache,
    rate_limiter: ?RateLimiter,
    retry_policy: RetryPolicy,
    quic_client: quic.QuicClient,
    enable_compression: bool,
    max_redirects: u32,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) !*HttpClient {
        var client = try allocator.create(HttpClient);
        client.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .user_agent = try allocator.dupe(u8, "ghostnet/0.2.1"),
            .default_headers = std.StringHashMap([]const u8).init(allocator),
            .timeout = 30000, // 30 seconds
            .bearer_token = null,
            .basic_auth = null,
            .api_key = null,
            .middleware_chain = middleware.MiddlewareChain.init(allocator),
            .connection_pool = null,
            .protocol_config = ProtocolConfig{},
            .protocol_cache = ProtocolCache.init(allocator),
            .rate_limiter = null,
            .retry_policy = RetryPolicy{},
            .quic_client = quic.QuicClient.init(allocator, runtime, quic.QuicConfig{}),
            .enable_compression = true,
            .max_redirects = 5,
        };
        
        // Set default headers
        try client.setDefaultHeader("User-Agent", client.user_agent);
        try client.setDefaultHeader("Accept", "*/*");
        if (client.enable_compression) {
            try client.setDefaultHeader("Accept-Encoding", "gzip, br, deflate");
        }
        try client.setDefaultHeader("Connection", "close");
        
        return client;
    }
    
    pub fn initWithPool(allocator: std.mem.Allocator, runtime: *zsync.Runtime, pool_config: pool.PoolConfig) !*HttpClient {
        var client = try HttpClient.init(allocator, runtime);
        client.connection_pool = try pool.ConnectionPool.init(allocator, runtime, pool_config);
        
        // Update default headers for pooled connections
        try client.setDefaultHeader("Connection", "keep-alive");
        
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
        
        if (self.bearer_token) |token| {
            self.allocator.free(token);
        }
        if (self.basic_auth) |auth| {
            self.allocator.free(auth.username);
            self.allocator.free(auth.password);
        }
        if (self.api_key) |key| {
            self.allocator.free(key.header);
            self.allocator.free(key.value);
        }
        
        self.middleware_chain.deinit();
        self.protocol_cache.deinit();
        if (self.connection_pool) |pool_ptr| {
            pool_ptr.deinit();
        }
        
        self.allocator.destroy(self);
    }
    
    pub fn setDefaultHeader(self: *HttpClient, name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.default_headers.put(name_copy, value_copy);
    }
    
    pub fn setBearerToken(self: *HttpClient, token: []const u8) !void {
        if (self.bearer_token) |old_token| {
            self.allocator.free(old_token);
        }
        self.bearer_token = try self.allocator.dupe(u8, token);
    }
    
    pub fn setBasicAuth(self: *HttpClient, username: []const u8, password: []const u8) !void {
        if (self.basic_auth) |auth| {
            self.allocator.free(auth.username);
            self.allocator.free(auth.password);
        }
        self.basic_auth = .{
            .username = try self.allocator.dupe(u8, username),
            .password = try self.allocator.dupe(u8, password),
        };
    }
    
    pub fn setApiKey(self: *HttpClient, header: []const u8, value: []const u8) !void {
        if (self.api_key) |key| {
            self.allocator.free(key.header);
            self.allocator.free(key.value);
        }
        self.api_key = .{
            .header = try self.allocator.dupe(u8, header),
            .value = try self.allocator.dupe(u8, value),
        };
    }
    
    pub fn setDefaultTimeout(self: *HttpClient, timeout_ms: u64) void {
        self.timeout = timeout_ms;
    }
    
    pub fn addMiddleware(self: *HttpClient, mw: middleware.Middleware) !void {
        try self.middleware_chain.add(mw);
    }
    
    pub fn enableDebugLogging(self: *HttpClient) !void {
        try self.addMiddleware(middleware.LoggingMiddleware.create());
    }
    
    pub fn setRetryConfig(self: *HttpClient, config: middleware.RetryConfig) !void {
        try self.addMiddleware(middleware.RetryMiddleware.create(config));
    }
    
    pub fn setRateLimit(self: *HttpClient, requests_per_second: f64, burst_size: u32) void {
        self.rate_limiter = RateLimiter.init(requests_per_second, burst_size);
    }
    
    pub fn setProtocolPreference(self: *HttpClient, preference: []const ProtocolPreference) !void {
        self.protocol_config.preference_order = try self.allocator.dupe(ProtocolPreference, preference);
    }
    
    pub fn enableCompression(self: *HttpClient, enable: bool) !void {
        self.enable_compression = enable;
        if (enable) {
            try self.setDefaultHeader("Accept-Encoding", "gzip, br, deflate");
        } else {
            _ = self.default_headers.remove("Accept-Encoding");
        }
    }
    
    fn selectProtocol(self: *HttpClient, host: []const u8) HttpVersion {
        // Check cache first
        if (self.protocol_cache.getProtocol(host, self.protocol_config.protocol_cache_ttl)) |cached_protocol| {
            return cached_protocol;
        }
        
        // Default to HTTP/3 first
        for (self.protocol_config.preference_order) |preference| {
            const protocol = switch (preference) {
                .http3 => HttpVersion.http_3_0,
                .http2 => HttpVersion.http_2_0,
                .http1_1 => HttpVersion.http_1_1,
                .http1_0 => HttpVersion.http_1_0,
            };
            return protocol;
        }
        
        return .http_3_0; // Default fallback to HTTP/3
    }
    
    fn shouldRetryWithDifferentProtocol(_: *HttpClient, _: anyerror, current_protocol: HttpVersion) ?HttpVersion {
        
        return switch (current_protocol) {
            .http_3_0 => .http_2_0,
            .http_2_0 => .http_1_1,
            .http_1_1 => .http_1_0,
            .http_1_0 => null,
        };
    }
    
    pub fn get(self: *HttpClient, url: []const u8) !HttpResponse {
        var request = try HttpRequest.init(self.allocator, .GET, url);
        defer request.deinit(self.allocator);
        
        return try self.sendRequest(&request, url);
    }
    
    pub fn getWithHeaders(self: *HttpClient, url: []const u8, headers: std.StringHashMap([]const u8)) !HttpResponse {
        var request = try HttpRequest.init(self.allocator, .GET, url);
        defer request.deinit(self.allocator);
        
        var header_iter = headers.iterator();
        while (header_iter.next()) |entry| {
            try request.setHeader(self.allocator, entry.key_ptr.*, entry.value_ptr.*);
        }
        
        return try self.sendRequest(&request, url);
    }
    
    pub fn getWithTimeout(self: *HttpClient, url: []const u8, timeout_ms: u64) !HttpResponse {
        const old_timeout = self.timeout;
        self.timeout = timeout_ms;
        defer self.timeout = old_timeout;
        
        return try self.get(url);
    }
    
    pub fn getJson(self: *HttpClient, url: []const u8, comptime T: type) !T {
        const response = try self.get(url);
        defer response.deinit(self.allocator);
        
        return try response.getJson(T);
    }
    
    pub fn post(self: *HttpClient, url: []const u8, body: []const u8, content_type: []const u8) !HttpResponse {
        var request = try HttpRequest.init(self.allocator, .POST, url);
        defer request.deinit(self.allocator);
        
        try request.setBody(self.allocator, body);
        try request.setHeader(self.allocator, "Content-Type", content_type);
        
        return try self.sendRequest(&request, url);
    }
    
    pub fn postWithHeaders(self: *HttpClient, url: []const u8, body: []const u8, headers: std.StringHashMap([]const u8)) !HttpResponse {
        var request = try HttpRequest.init(self.allocator, .POST, url);
        defer request.deinit(self.allocator);
        
        try request.setBody(self.allocator, body);
        
        var header_iter = headers.iterator();
        while (header_iter.next()) |entry| {
            try request.setHeader(self.allocator, entry.key_ptr.*, entry.value_ptr.*);
        }
        
        return try self.sendRequest(&request, url);
    }
    
    pub fn postJsonData(self: *HttpClient, url: []const u8, data: anytype) !HttpResponse {
        const json_string = try std.json.stringifyAlloc(self.allocator, data, .{});
        defer self.allocator.free(json_string);
        
        return try self.postJson(url, json_string);
    }
    
    pub fn postJson(self: *HttpClient, url: []const u8, json_body: []const u8) !HttpResponse {
        return try self.post(url, json_body, "application/json");
    }
    
    // New batch operations for package manager efficiency
    pub fn batchGet(self: *HttpClient, urls: []const []const u8) ![]HttpResponse {
        var responses = try self.allocator.alloc(HttpResponse, urls.len);
        errdefer {
            for (responses[0..urls.len]) |*response| {
                response.deinit(self.allocator);
            }
            self.allocator.free(responses);
        }
        
        // Use HTTP/3 multiplexing for concurrent requests to same host
        var host_groups = std.StringHashMap(std.ArrayList(usize)).init(self.allocator);
        defer {
            var iter = host_groups.iterator();
            while (iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit();
            }
            host_groups.deinit();
        }
        
        // Group URLs by host for efficient multiplexing
        for (urls, 0..) |url, i| {
            const uri = std.Uri.parse(url) catch continue;
            const host = uri.host orelse continue;
            
            const host_copy = try self.allocator.dupe(u8, host);
            var group = host_groups.get(host_copy) orelse blk: {
                const new_group = std.ArrayList(usize).init(self.allocator);
                try host_groups.put(host_copy, new_group);
                break :blk host_groups.getPtr(host_copy).?;
            };
            try group.append(i);
        }
        
        // Process each host group concurrently
        var host_iter = host_groups.iterator();
        while (host_iter.next()) |entry| {
            const url_indices = entry.value_ptr.items;
            
            // For HTTP/3, we can multiplex all requests to same host
            for (url_indices) |url_idx| {
                responses[url_idx] = self.get(urls[url_idx]) catch blk: {
                    // Return error response
                    const error_response = HttpResponse.init(self.allocator, 0, "Request Failed") catch break :blk HttpResponse{
                        .version = .http_3_0,
                        .status_code = 0,
                        .status_text = "Error",
                        .headers = std.StringHashMap([]const u8).init(self.allocator),
                        .body = null,
                        .allocator = self.allocator,
                    };
                    break :blk error_response;
                };
            }
        }
        
        return responses;
    }
    
    pub const DownloadOptions = struct {
        progress_callback: ?*const fn (downloaded: u64, total: u64) void = null,
        chunk_size: usize = 8192,
        resume_partial: bool = true,
        verify_checksum: ?[]const u8 = null, // SHA256 checksum
        max_speed: ?u64 = null, // bytes per second
    };
    
    pub fn downloadStream(self: *HttpClient, url: []const u8, dest_path: []const u8, options: DownloadOptions) !void {
        var request = try HttpRequest.init(self.allocator, .GET, url);
        defer request.deinit(self.allocator);
        
        // Check if we can resume
        var start_byte: u64 = 0;
        if (options.resume_partial) {
            if (std.fs.cwd().statFile(dest_path)) |stat| {
                start_byte = stat.size;
                const range_header = try std.fmt.allocPrint(self.allocator, "bytes={d}-", .{start_byte});
                defer self.allocator.free(range_header);
                try request.setHeader(self.allocator, "Range", range_header);
            } else |_| {
                // File doesn't exist, start from beginning
            }
        }
        
        const response = try self.sendRequest(&request, url);
        defer response.deinit(self.allocator);
        
        if (!response.isSuccess() and response.status_code != 206) { // 206 = Partial Content
            return error.DownloadFailed;
        }
        
        // Get content length
        var total_size: ?u64 = null;
        if (response.getHeader("Content-Length")) |content_length| {
            total_size = std.fmt.parseInt(u64, content_length, 10) catch null;
        }
        
        // Open destination file
        const file = if (start_byte > 0)
            try std.fs.cwd().openFile(dest_path, .{ .mode = .write_only })
        else
            try std.fs.cwd().createFile(dest_path, .{});
        defer file.close();
        
        if (start_byte > 0) {
            try file.seekTo(start_byte);
        }
        
        // Download with progress tracking
        var downloaded: u64 = start_byte;
        _ = std.time.timestamp(); // Track time for progress updates
        const buffer = try self.allocator.alloc(u8, options.chunk_size);
        defer self.allocator.free(buffer);
        
        // In a real implementation, we'd stream from the HTTP response
        if (response.body) |body| {
            try file.writeAll(body);
            downloaded += body.len;
            
            if (options.progress_callback) |callback| {
                callback(downloaded, total_size orelse downloaded);
            }
        }
    }
    
    pub fn downloadStreamAsync(self: *HttpClient, url: []const u8, dest_path: []const u8, options: DownloadOptions) zsync.Future(transport.TransportError!void) {
        return zsync.Future(transport.TransportError!void).init(self.runtime, struct {
            client: *HttpClient,
            url: []const u8,
            dest_path: []const u8,
            options: DownloadOptions,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport.TransportError!void) {
                ctx.client.downloadStream(ctx.url, ctx.dest_path, ctx.options) catch |err| {
                    return .{ .ready = errors.mapSystemError(err) };
                };
                return .{ .ready = {} };
            }
        }{ .client = self, .url = url, .dest_path = dest_path, .options = options });
    }
    
    pub fn sendRequest(self: *HttpClient, request: *HttpRequest, url: []const u8) !HttpResponse {
        // Rate limiting check
        if (self.rate_limiter) |*limiter| {
            if (!limiter.allowRequest()) {
                const wait_time = limiter.waitTime();
                if (wait_time > 0) {
                    std.time.sleep(wait_time * 1_000_000); // Convert to nanoseconds
                }
            }
        }
        
        // Parse URL
        const uri = std.Uri.parse(url) catch return error.InvalidUrl;
        const host = uri.host orelse return error.MissingHost;
        _ = uri.port orelse if (std.mem.eql(u8, uri.scheme, "https")) 443 else 80;
        _ = std.mem.eql(u8, uri.scheme, "https");
        
        // Protocol selection - HTTP/3 first!
        var selected_protocol = self.selectProtocol(host);
        var attempt: u32 = 0;
        var last_error: ?anyerror = null;
        
        while (attempt < self.retry_policy.max_attempts) {
            const result = self.sendRequestWithProtocol(request, url, selected_protocol) catch |err| blk: {
                last_error = err;
                
                // Try different protocol on failure
                if (self.shouldRetryWithDifferentProtocol(err, selected_protocol)) |fallback_protocol| {
                    selected_protocol = fallback_protocol;
                    attempt += 1;
                    
                    // Wait before retry
                    const delay = self.retry_policy.getDelay(attempt);
                    std.time.sleep(delay * 1_000_000);
                    
                    continue;
                } else {
                    break :blk err;
                }
            };
            
            // Cache successful protocol
            self.protocol_cache.cacheProtocol(host, selected_protocol, true) catch {};
            return result;
        }
        
        // Cache failed protocol
        self.protocol_cache.cacheProtocol(host, selected_protocol, false) catch {};
        
        return last_error orelse error.RequestFailed;
    }
    
    fn sendRequestWithProtocol(self: *HttpClient, request: *HttpRequest, url: []const u8, protocol: HttpVersion) !HttpResponse {
        const uri = std.Uri.parse(url) catch return error.InvalidUrl;
        const host = uri.host orelse return error.MissingHost;
        const port = uri.port orelse if (std.mem.eql(u8, uri.scheme, "https")) 443 else 80;
        const is_https = std.mem.eql(u8, uri.scheme, "https");
        
        // Prepare request headers
        try self.prepareRequestHeaders(request, host);
        
        return switch (protocol) {
            .http_3_0 => self.sendHttp3Request(request, host, port, is_https),
            .http_2_0 => self.sendHttp2Request(request, host, port, is_https),
            .http_1_1, .http_1_0 => self.sendHttp1Request(request, host, port, is_https, protocol),
        };
    }
    
    fn prepareRequestHeaders(self: *HttpClient, request: *HttpRequest, host: []const u8) !void {
        // Add authentication headers
        if (self.bearer_token) |token| {
            const auth_header = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{token});
            defer self.allocator.free(auth_header);
            try request.setHeader(self.allocator, "Authorization", auth_header);
        } else if (self.basic_auth) |auth| {
            const credentials = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ auth.username, auth.password });
            defer self.allocator.free(credentials);
            
            const encoder = std.base64.standard.Encoder;
            const encoded_len = encoder.calcSize(credentials.len);
            const encoded = try self.allocator.alloc(u8, encoded_len);
            defer self.allocator.free(encoded);
            
            _ = encoder.encode(encoded, credentials);
            const auth_header = try std.fmt.allocPrint(self.allocator, "Basic {s}", .{encoded});
            defer self.allocator.free(auth_header);
            
            try request.setHeader(self.allocator, "Authorization", auth_header);
        }
        
        if (self.api_key) |key| {
            try request.setHeader(self.allocator, key.header, key.value);
        }
        
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
    }
    
    fn sendHttp3Request(self: *HttpClient, request: *HttpRequest, host: []const u8, port: u16, is_https: bool) !HttpResponse {
        _ = is_https; // HTTP/3 is always encrypted
        
        const address = transport.Address{
            .ipv4 = try std.net.Ip4Address.parse(host, port)
        };
        
        // Connect via QUIC/HTTP3
        const quic_conn = try self.quic_client.connect(address);
        defer quic_conn.deinit();
        
        const stream = try quic_conn.openStream(.bidirectional);
        defer stream.deinit();
        
        // Convert HTTP request to HTTP/3 format
        var request_data = std.ArrayList(u8).init(self.allocator);
        defer request_data.deinit();
        
        // HTTP/3 uses QPACK for header compression
        try request_data.writer().print("{s} {s} HTTP/3.0\r\n", .{ request.method.toString(), request.path });
        
        var header_iter = request.headers.iterator();
        while (header_iter.next()) |entry| {
            try request_data.writer().print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
        
        try request_data.appendSlice("\r\n");
        
        if (request.body) |body| {
            try request_data.appendSlice(body);
        }
        
        // Send via QUIC stream
        _ = try stream.write(request_data.items);
        stream.close();
        
        // Read response
        var response_buffer = std.ArrayList(u8).init(self.allocator);
        defer response_buffer.deinit();
        
        var temp_buffer: [4096]u8 = undefined;
        while (true) {
            const bytes_read = stream.read(&temp_buffer) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            
            if (bytes_read == 0) break;
            try response_buffer.appendSlice(temp_buffer[0..bytes_read]);
        }
        
        return HttpResponse.parse(self.allocator, response_buffer.items);
    }
    
    fn sendHttp2Request(self: *HttpClient, request: *HttpRequest, host: []const u8, port: u16, is_https: bool) !HttpResponse {
        const address = transport.Address{
            .ipv4 = try std.net.Ip4Address.parse(host, port)
        };
        
        // Create TCP connection
        var tcp_conn = try tcp.TcpConnection.connect(
            self.allocator,
            self.runtime,
            address,
            transport.TransportOptions{ .allocator = self.allocator }
        );
        defer tcp_conn.deinit();
        
        const stream = tcp_conn.stream();
        
        // TLS with HTTP/2 ALPN
        if (is_https) {
            const tls_config = handshake.HandshakeConfig{
                .handshake_type = .tls,
                .cipher_suite = .chacha20_poly1305,
                .key_exchange = .curve25519,
                .is_initiator = true,
                .server_name = host,
                .alpn_protocols = &[_][]const u8{ "h2", "http/1.1" },
            };
            
            var handshake_manager = handshake.HandshakeManager.init(self.allocator, self.runtime);
            _ = try handshake_manager.performHandshake(tls_config, stream);
        }
        
        // Create HTTP/2 connection
        var h2_conn = try http2.Http2Connection.init(self.allocator, self.runtime, stream, true);
        defer h2_conn.deinit();
        
        try h2_conn.performHandshake();
        
        // Create HTTP/2 client and send request
        var h2_client = try http2.Http2Client.init(self.allocator, self.runtime, stream);
        defer h2_client.deinit();
        
        return try h2_client.sendRequest(request);
    }
    
    fn sendHttp1Request(self: *HttpClient, request: *HttpRequest, host: []const u8, port: u16, is_https: bool, version: HttpVersion) !HttpResponse {
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
        
        const stream = tcp_conn.stream();
        
        // TLS handshake if HTTPS
        if (is_https) {
            const tls_config = handshake.HandshakeConfig{
                .handshake_type = .tls,
                .cipher_suite = .chacha20_poly1305,
                .key_exchange = .curve25519,
                .is_initiator = true,
                .server_name = host,
                .alpn_protocols = &[_][]const u8{ "http/1.1" },
            };
            
            var handshake_manager = handshake.HandshakeManager.init(self.allocator, self.runtime);
            _ = try handshake_manager.performHandshake(tls_config, stream);
        }
        
        // Set proper HTTP version
        request.version = version;
        
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
pub const OpenAIClient = struct {
    http_client: *HttpClient,
    api_key: []const u8,
    base_url: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, api_key: []const u8) !*OpenAIClient {
        var client = try allocator.create(OpenAIClient);
        client.* = .{
            .http_client = try HttpClient.init(allocator, runtime),
            .api_key = try allocator.dupe(u8, api_key),
            .base_url = try allocator.dupe(u8, "https://api.openai.com/v1"),
        };
        
        // Set OpenAI-specific headers
        try client.http_client.setBearerToken(api_key);
        try client.http_client.setDefaultHeader("OpenAI-Beta", "assistants=v2");
        
        return client;
    }
    
    pub fn deinit(self: *OpenAIClient) void {
        self.http_client.deinit();
        self.http_client.allocator.free(self.api_key);
        self.http_client.allocator.free(self.base_url);
        self.http_client.allocator.destroy(self);
    }
    
    pub fn chatCompletion(self: *OpenAIClient, _: []const ChatMessage, model: []const u8) !HttpResponse {
        const url = try std.fmt.allocPrint(self.http_client.allocator, "{s}/chat/completions", .{self.base_url});
        defer self.http_client.allocator.free(url);
        
        const request_body = try std.fmt.allocPrint(self.http_client.allocator,
            \\{{
            \\  "model": "{s}",
            \\  "max_tokens": 4096,
            \\  "messages": [
            \\    {{
            \\      "role": "user",
            \\      "content": "Hello"
            \\    }}
            \\  ]
            \\}}
        , .{model});
        defer self.http_client.allocator.free(request_body);
        
        return try self.http_client.postJson(url, request_body);
    }
    
    pub fn createEmbedding(self: *OpenAIClient, input: []const u8, model: []const u8) !HttpResponse {
        const url = try std.fmt.allocPrint(self.http_client.allocator, "{s}/embeddings", .{self.base_url});
        defer self.http_client.allocator.free(url);
        
        const request_body = try std.fmt.allocPrint(self.http_client.allocator,
            \\{{
            \\  "model": "{s}",
            \\  "input": "{s}"
            \\}}
        , .{ model, input });
        defer self.http_client.allocator.free(request_body);
        
        return try self.http_client.postJson(url, request_body);
    }
};

pub const ChatMessage = struct {
    role: []const u8,
    content: []const u8,
};

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
    
    pub fn getCopilotToken(self: *CopilotClient) !HttpResponse {
        const url = try std.fmt.allocPrint(self.http_client.allocator, "{s}/token", .{self.base_url});
        defer self.http_client.allocator.free(url);
        
        return try self.http_client.get(url);
    }
};

pub const GitHubClient = struct {
    http_client: *HttpClient,
    token: []const u8,
    base_url: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, token: []const u8) !*GitHubClient {
        var client = try allocator.create(GitHubClient);
        client.* = .{
            .http_client = try HttpClient.init(allocator, runtime),
            .token = try allocator.dupe(u8, token),
            .base_url = try allocator.dupe(u8, "https://api.github.com"),
        };
        
        // Set GitHub-specific headers
        try client.http_client.setBearerToken(token);
        try client.http_client.setDefaultHeader("Accept", "application/vnd.github.v3+json");
        try client.http_client.setDefaultHeader("X-GitHub-Api-Version", "2022-11-28");
        
        return client;
    }
    
    pub fn deinit(self: *GitHubClient) void {
        self.http_client.deinit();
        self.http_client.allocator.free(self.token);
        self.http_client.allocator.free(self.base_url);
        self.http_client.allocator.destroy(self);
    }
    
    pub fn getCopilotToken(self: *GitHubClient) !HttpResponse {
        const url = try std.fmt.allocPrint(self.http_client.allocator, "{s}/copilot_internal/v2/token", .{self.base_url});
        defer self.http_client.allocator.free(url);
        
        return try self.http_client.get(url);
    }
    
    pub fn getUser(self: *GitHubClient) !HttpResponse {
        const url = try std.fmt.allocPrint(self.http_client.allocator, "{s}/user", .{self.base_url});
        defer self.http_client.allocator.free(url);
        
        return try self.http_client.get(url);
    }
    
    pub fn getRepository(self: *GitHubClient, owner: []const u8, repo: []const u8) !HttpResponse {
        const url = try std.fmt.allocPrint(self.http_client.allocator, "{s}/repos/{s}/{s}", .{ self.base_url, owner, repo });
        defer self.http_client.allocator.free(url);
        
        return try self.http_client.get(url);
    }
};