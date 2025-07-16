const std = @import("std");

pub const HttpError = error{
    // Network errors
    NetworkError,
    ConnectionRefused,
    ConnectionTimeout,
    ConnectionReset,
    
    // Request errors
    InvalidUrl,
    InvalidRequest,
    RequestTimeout,
    RequestTooLarge,
    
    // Response errors
    InvalidResponse,
    ResponseTooLarge,
    
    // HTTP status errors
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    TooManyRequests,
    InternalServerError,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
    
    // Client errors
    TooManyRedirects,
    UnsupportedProtocol,
    SSLError,
    CertificateError,
    
    // Pool errors
    PoolExhausted,
    PoolShutdown,
    TooManyConnections,
    
    // Middleware errors
    MiddlewareRejected,
    MiddlewareFailed,
    RetryLimitExceeded,
    TimeoutExceeded,
    
    // JSON/Serialization errors
    JsonParseError,
    JsonSerializeError,
    
    // General errors
    OutOfMemory,
    UnexpectedError,
};

pub const ErrorContext = struct {
    error_type: HttpError,
    status_code: ?u16 = null,
    message: []const u8,
    request_url: []const u8,
    request_method: []const u8,
    timestamp: i64,
    retry_count: u32 = 0,
    duration_ms: ?u64 = null,
    
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, error_type: HttpError, message: []const u8, request_url: []const u8, request_method: []const u8) !ErrorContext {
        return ErrorContext{
            .error_type = error_type,
            .message = try allocator.dupe(u8, message),
            .request_url = try allocator.dupe(u8, request_url),
            .request_method = try allocator.dupe(u8, request_method),
            .timestamp = std.time.milliTimestamp(),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ErrorContext) void {
        self.allocator.free(self.message);
        self.allocator.free(self.request_url);
        self.allocator.free(self.request_method);
    }
    
    pub fn setStatusCode(self: *ErrorContext, code: u16) void {
        self.status_code = code;
    }
    
    pub fn setRetryCount(self: *ErrorContext, count: u32) void {
        self.retry_count = count;
    }
    
    pub fn setDuration(self: *ErrorContext, duration_ms: u64) void {
        self.duration_ms = duration_ms;
    }
    
    pub fn format(self: *ErrorContext, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        
        try writer.print("HttpError: {s}", .{@errorName(self.error_type)});
        
        if (self.status_code) |code| {
            try writer.print(" (HTTP {d})", .{code});
        }
        
        try writer.print(" - {s} {s}", .{ self.request_method, self.request_url });
        
        if (self.message.len > 0) {
            try writer.print(": {s}", .{self.message});
        }
        
        if (self.retry_count > 0) {
            try writer.print(" (after {d} retries)", .{self.retry_count});
        }
        
        if (self.duration_ms) |duration| {
            try writer.print(" [{d}ms]", .{duration});
        }
    }
};

pub const HttpResult = union(enum) {
    success: []const u8, // Response body
    error_context: ErrorContext,
    
    pub fn isSuccess(self: HttpResult) bool {
        return switch (self) {
            .success => true,
            .error_context => false,
        };
    }
    
    pub fn getError(self: HttpResult) ?ErrorContext {
        return switch (self) {
            .success => null,
            .error_context => |ctx| ctx,
        };
    }
    
    pub fn getBody(self: HttpResult) ?[]const u8 {
        return switch (self) {
            .success => |body| body,
            .error_context => null,
        };
    }
};

pub fn mapStatusCodeToError(status_code: u16) HttpError {
    return switch (status_code) {
        400 => HttpError.BadRequest,
        401 => HttpError.Unauthorized,
        403 => HttpError.Forbidden,
        404 => HttpError.NotFound,
        405 => HttpError.MethodNotAllowed,
        408 => HttpError.RequestTimeout,
        429 => HttpError.TooManyRequests,
        500 => HttpError.InternalServerError,
        502 => HttpError.BadGateway,
        503 => HttpError.ServiceUnavailable,
        504 => HttpError.GatewayTimeout,
        else => HttpError.UnexpectedError,
    };
}

pub fn mapSystemError(err: anyerror) HttpError {
    return switch (err) {
        error.OutOfMemory => HttpError.OutOfMemory,
        error.ConnectionRefused => HttpError.ConnectionRefused,
        error.ConnectionTimedOut => HttpError.ConnectionTimeout,
        error.ConnectionResetByPeer => HttpError.ConnectionReset,
        error.NetworkUnreachable => HttpError.NetworkError,
        error.HostUnreachable => HttpError.NetworkError,
        error.InvalidUrl => HttpError.InvalidUrl,
        error.JsonParseError => HttpError.JsonParseError,
        error.TooManyConnections => HttpError.TooManyConnections,
        error.PoolExhausted => HttpError.PoolExhausted,
        error.PoolShutdown => HttpError.PoolShutdown,
        else => HttpError.UnexpectedError,
    };
}

pub const ErrorBuilder = struct {
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) ErrorBuilder {
        return ErrorBuilder{ .allocator = allocator };
    }
    
    pub fn networkError(self: ErrorBuilder, url: []const u8, method: []const u8, message: []const u8) !ErrorContext {
        return ErrorContext.init(self.allocator, HttpError.NetworkError, message, url, method);
    }
    
    pub fn timeoutError(self: ErrorBuilder, url: []const u8, method: []const u8, timeout_ms: u64) !ErrorContext {
        const message = try std.fmt.allocPrint(self.allocator, "Request timed out after {d}ms", .{timeout_ms});
        defer self.allocator.free(message);
        return ErrorContext.init(self.allocator, HttpError.RequestTimeout, message, url, method);
    }
    
    pub fn statusCodeError(self: ErrorBuilder, url: []const u8, method: []const u8, status_code: u16) !ErrorContext {
        const http_error = mapStatusCodeToError(status_code);
        const message = try std.fmt.allocPrint(self.allocator, "HTTP {d} error", .{status_code});
        defer self.allocator.free(message);
        
        var ctx = try ErrorContext.init(self.allocator, http_error, message, url, method);
        ctx.setStatusCode(status_code);
        return ctx;
    }
    
    pub fn retryExhaustedError(self: ErrorBuilder, url: []const u8, method: []const u8, max_retries: u32) !ErrorContext {
        const message = try std.fmt.allocPrint(self.allocator, "Retry limit exceeded after {d} attempts", .{max_retries});
        defer self.allocator.free(message);
        
        var ctx = try ErrorContext.init(self.allocator, HttpError.RetryLimitExceeded, message, url, method);
        ctx.setRetryCount(max_retries);
        return ctx;
    }
};

test "error context creation and formatting" {
    const allocator = std.testing.allocator;
    
    var ctx = try ErrorContext.init(allocator, HttpError.NotFound, "Resource not found", "https://api.example.com/user/123", "GET");
    defer ctx.deinit();
    
    ctx.setStatusCode(404);
    ctx.setDuration(150);
    
    // Test individual fields instead of full formatting
    try std.testing.expectEqual(HttpError.NotFound, ctx.error_type);
    try std.testing.expectEqual(@as(u16, 404), ctx.status_code.?);
    try std.testing.expect(std.mem.eql(u8, ctx.request_method, "GET"));
    try std.testing.expectEqual(@as(u64, 150), ctx.duration_ms.?);
}

test "error mapping" {
    try std.testing.expectEqual(HttpError.NotFound, mapStatusCodeToError(404));
    try std.testing.expectEqual(HttpError.InternalServerError, mapStatusCodeToError(500));
    try std.testing.expectEqual(HttpError.UnexpectedError, mapStatusCodeToError(418)); // I'm a teapot
}

test "error builder" {
    const allocator = std.testing.allocator;
    const builder = ErrorBuilder.init(allocator);
    
    var ctx = try builder.statusCodeError("https://api.example.com", "POST", 401);
    defer ctx.deinit();
    
    try std.testing.expectEqual(HttpError.Unauthorized, ctx.error_type);
    try std.testing.expectEqual(@as(u16, 401), ctx.status_code.?);
}