const std = @import("std");
const http = @import("http.zig");
const zsync = @import("zsync");

pub const MiddlewareError = error{
    MiddlewareRejected,
    MiddlewareFailed,
    RetryLimitExceeded,
    TimeoutExceeded,
};

pub const MiddlewareContext = struct {
    request: *http.HttpRequest,
    response: ?*http.HttpResponse,
    url: []const u8,
    attempt: u32,
    start_time: i64,
    allocator: std.mem.Allocator,
};

pub const MiddlewareResult = union(enum) {
    continue_chain,
    stop_with_response: http.HttpResponse,
    stop_with_error: MiddlewareError,
};

pub const Middleware = struct {
    name: []const u8,
    before_request: ?*const fn (ctx: *MiddlewareContext) MiddlewareResult,
    after_response: ?*const fn (ctx: *MiddlewareContext) MiddlewareResult,
    
    pub fn init(name: []const u8) Middleware {
        return Middleware{
            .name = name,
            .before_request = null,
            .after_response = null,
        };
    }
};

pub const MiddlewareChain = struct {
    middlewares: std.ArrayList(Middleware),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) MiddlewareChain {
        return MiddlewareChain{
            .middlewares = std.ArrayList(Middleware).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *MiddlewareChain) void {
        self.middlewares.deinit();
    }
    
    pub fn add(self: *MiddlewareChain, middleware: Middleware) !void {
        try self.middlewares.append(middleware);
    }
    
    pub fn processRequest(self: *MiddlewareChain, ctx: *MiddlewareContext) !void {
        for (self.middlewares.items) |middleware| {
            if (middleware.before_request) |handler| {
                switch (handler(ctx)) {
                    .continue_chain => continue,
                    .stop_with_response => |response| {
                        ctx.response = try ctx.allocator.create(http.HttpResponse);
                        ctx.response.?.* = response;
                        return;
                    },
                    .stop_with_error => |err| return err,
                }
            }
        }
    }
    
    pub fn processResponse(self: *MiddlewareChain, ctx: *MiddlewareContext) !void {
        var i: usize = self.middlewares.items.len;
        while (i > 0) {
            i -= 1;
            const middleware = self.middlewares.items[i];
            if (middleware.after_response) |handler| {
                switch (handler(ctx)) {
                    .continue_chain => continue,
                    .stop_with_response => |response| {
                        if (ctx.response) |old_response| {
                            old_response.deinit(ctx.allocator);
                            ctx.allocator.destroy(old_response);
                        }
                        ctx.response = try ctx.allocator.create(http.HttpResponse);
                        ctx.response.?.* = response;
                        return;
                    },
                    .stop_with_error => |err| return err,
                }
            }
        }
    }
};

// Built-in middleware implementations
pub const LoggingMiddleware = struct {
    pub fn beforeRequest(ctx: *MiddlewareContext) MiddlewareResult {
        std.debug.print("[HTTP] {s} {s}\n", .{ ctx.request.method.toString(), ctx.url });
        return .continue_chain;
    }
    
    pub fn afterResponse(ctx: *MiddlewareContext) MiddlewareResult {
        if (ctx.response) |response| {
            const duration = std.time.milliTimestamp() - ctx.start_time;
            std.debug.print("[HTTP] {d} - {dms}\n", .{ response.status_code, duration });
        }
        return .continue_chain;
    }
    
    pub fn create() Middleware {
        return Middleware{
            .name = "logging",
            .before_request = beforeRequest,
            .after_response = afterResponse,
        };
    }
};

pub const RetryConfig = struct {
    max_attempts: u32 = 3,
    backoff_strategy: BackoffStrategy = .exponential,
    retry_status_codes: []const u16 = &[_]u16{ 502, 503, 504, 429 },
    base_delay_ms: u64 = 1000,
    max_delay_ms: u64 = 30000,
    
    pub const BackoffStrategy = enum {
        fixed,
        linear,
        exponential,
    };
};

pub const RetryMiddleware = struct {
    config: RetryConfig,
    
    pub fn init(config: RetryConfig) RetryMiddleware {
        return RetryMiddleware{ .config = config };
    }
    
    pub fn afterResponse(self: *RetryMiddleware, ctx: *MiddlewareContext) MiddlewareResult {
        if (ctx.response) |response| {
            if (ctx.attempt >= self.config.max_attempts) {
                return .continue_chain;
            }
            
            // Check if status code should trigger retry
            var should_retry = false;
            for (self.config.retry_status_codes) |code| {
                if (response.status_code == code) {
                    should_retry = true;
                    break;
                }
            }
            
            if (should_retry) {
                const delay_ms = self.calculateDelay(ctx.attempt);
                std.debug.print("[RETRY] Attempt {d}/{d} after {dms}\n", .{ ctx.attempt + 1, self.config.max_attempts, delay_ms });
                
                // Sleep for calculated delay
                std.time.sleep(delay_ms * std.time.ns_per_ms);
                
                // Signal that we want to retry
                return .stop_with_error;
            }
        }
        
        return .continue_chain;
    }
    
    fn calculateDelay(self: *RetryMiddleware, attempt: u32) u64 {
        const base_delay = self.config.base_delay_ms;
        const delay = switch (self.config.backoff_strategy) {
            .fixed => base_delay,
            .linear => base_delay * (attempt + 1),
            .exponential => base_delay * std.math.pow(u64, 2, attempt),
        };
        
        return std.math.min(delay, self.config.max_delay_ms);
    }
    
    pub fn create(config: RetryConfig) Middleware {
        // Note: This is a simplified implementation
        // In a real implementation, you'd need to store the config in a way
        // that can be accessed by the middleware function
        return Middleware{
            .name = "retry",
            .before_request = null,
            .after_response = null, // Would need to bind the config properly
        };
    }
};

pub const AuthMiddleware = struct {
    pub fn beforeRequest(ctx: *MiddlewareContext) MiddlewareResult {
        // This would be customized based on auth requirements
        // For now, just continue
        _ = ctx;
        return .continue_chain;
    }
    
    pub fn create() Middleware {
        return Middleware{
            .name = "auth",
            .before_request = beforeRequest,
            .after_response = null,
        };
    }
};

pub const TimeoutMiddleware = struct {
    timeout_ms: u64,
    
    pub fn init(timeout_ms: u64) TimeoutMiddleware {
        return TimeoutMiddleware{ .timeout_ms = timeout_ms };
    }
    
    pub fn beforeRequest(self: *TimeoutMiddleware, ctx: *MiddlewareContext) MiddlewareResult {
        // Set timeout context
        _ = self;
        ctx.start_time = std.time.milliTimestamp();
        return .continue_chain;
    }
    
    pub fn afterResponse(self: *TimeoutMiddleware, ctx: *MiddlewareContext) MiddlewareResult {
        const elapsed = std.time.milliTimestamp() - ctx.start_time;
        if (elapsed > self.timeout_ms) {
            return .stop_with_error;
        }
        return .continue_chain;
    }
    
    pub fn create(timeout_ms: u64) Middleware {
        // Simplified implementation
        return Middleware{
            .name = "timeout",
            .before_request = null,
            .after_response = null,
        };
    }
};