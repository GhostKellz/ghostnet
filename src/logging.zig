//! Production-ready logging system for ghostnet
//! Provides structured logging with levels, contexts, and performance monitoring

const std = @import("std");
const zsync = @import("zsync");

pub const LogLevel = enum(u8) {
    trace = 0,
    debug = 1,
    info = 2,
    warn = 3,
    err = 4,
    fatal = 5,

    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .trace => "TRACE",
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
            .fatal => "FATAL",
        };
    }
};

pub const LogContext = struct {
    component: []const u8,
    operation: ?[]const u8 = null,
    connection_id: ?[]const u8 = null,
    stream_id: ?u32 = null,
    request_id: ?[]const u8 = null,
};

pub const Logger = struct {
    allocator: std.mem.Allocator,
    level: LogLevel,
    output: std.fs.File,
    mutex: std.Thread.Mutex = .{},
    
    pub fn init(allocator: std.mem.Allocator, level: LogLevel, output: std.fs.File) Logger {
        return .{
            .allocator = allocator,
            .level = level,
            .output = output,
        };
    }
    
    pub fn log(self: *Logger, level: LogLevel, context: LogContext, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(level) < @intFromEnum(self.level)) return;
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const timestamp = std.time.timestamp();
        const thread_id = std.Thread.getCurrentId();
        
        // Format: [TIMESTAMP] [LEVEL] [THREAD] [COMPONENT] [OPERATION] MESSAGE
        self.output.writer().print("[{d}] [{s}] [{d}] [{s}]", .{
            timestamp, level.toString(), thread_id, context.component
        }) catch return;
        
        if (context.operation) |op| {
            self.output.writer().print(" [{s}]", .{op}) catch return;
        }
        
        if (context.connection_id) |conn_id| {
            self.output.writer().print(" [conn:{s}]", .{conn_id}) catch return;
        }
        
        if (context.stream_id) |stream_id| {
            self.output.writer().print(" [stream:{d}]", .{stream_id}) catch return;
        }
        
        if (context.request_id) |req_id| {
            self.output.writer().print(" [req:{s}]", .{req_id}) catch return;
        }
        
        self.output.writer().print(" ", .{}) catch return;
        self.output.writer().print(fmt, args) catch return;
        self.output.writer().print("\n", .{}) catch return;
    }
    
    pub fn trace(self: *Logger, context: LogContext, comptime fmt: []const u8, args: anytype) void {
        self.log(.trace, context, fmt, args);
    }
    
    pub fn debug(self: *Logger, context: LogContext, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, context, fmt, args);
    }
    
    pub fn info(self: *Logger, context: LogContext, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, context, fmt, args);
    }
    
    pub fn warn(self: *Logger, context: LogContext, comptime fmt: []const u8, args: anytype) void {
        self.log(.warn, context, fmt, args);
    }
    
    pub fn err(self: *Logger, context: LogContext, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, context, fmt, args);
    }
    
    pub fn fatal(self: *Logger, context: LogContext, comptime fmt: []const u8, args: anytype) void {
        self.log(.fatal, context, fmt, args);
    }
};

// Global logger instance
var global_logger: ?*Logger = null;

pub fn setGlobalLogger(logger: *Logger) void {
    global_logger = logger;
}

pub fn getGlobalLogger() ?*Logger {
    return global_logger;
}

// Convenience functions for global logging
pub fn trace(context: LogContext, comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |logger| logger.trace(context, fmt, args);
}

pub fn debug(context: LogContext, comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |logger| logger.debug(context, fmt, args);
}

pub fn info(context: LogContext, comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |logger| logger.info(context, fmt, args);
}

pub fn warn(context: LogContext, comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |logger| logger.warn(context, fmt, args);
}

pub fn err(context: LogContext, comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |logger| logger.err(context, fmt, args);
}

pub fn fatal(context: LogContext, comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |logger| logger.fatal(context, fmt, args);
}

// Performance monitoring utilities
pub const PerformanceTimer = struct {
    start_time: i64,
    context: LogContext,
    operation: []const u8,
    
    pub fn start(context: LogContext, operation: []const u8) PerformanceTimer {
        return .{
            .start_time = std.time.nanoTimestamp(),
            .context = context,
            .operation = operation,
        };
    }
    
    pub fn end(self: PerformanceTimer) void {
        const duration_ns = std.time.nanoTimestamp() - self.start_time;
        const duration_ms = @divTrunc(duration_ns, std.time.ns_per_ms);
        
        debug(self.context, "{s} completed in {d}ms", .{ self.operation, duration_ms });
    }
};

pub fn perfTimer(context: LogContext, operation: []const u8) PerformanceTimer {
    return PerformanceTimer.start(context, operation);
}