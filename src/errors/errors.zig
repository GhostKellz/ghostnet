const std = @import("std");

pub const GhostnetError = error{
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NetworkUnreachable,
    HostUnreachable,
    AddressInUse,
    AddressNotAvailable,
    InvalidAddress,
    Timeout,
    TooManyConnections,
    ProtocolError,
    ProtocolNotSupported,
    TransportClosed,
    InvalidState,
    BufferFull,
    BufferEmpty,
    OutOfMemory,
    PermissionDenied,
    FileDescriptorLimit,
    Interrupted,
    WouldBlock,
    InProgress,
    AlreadyConnected,
    NotConnected,
    Shutdown,
    MessageTooLarge,
    InvalidArgument,
    OperationNotSupported,
    PipeBroken,
    Unexpected,
    
    CryptoError,
    HandshakeFailed,
    CertificateInvalid,
    CertificateExpired,
    CertificateRevoked,
    KeyExchangeFailed,
    DecryptionFailed,
    EncryptionFailed,
    AuthenticationFailed,
    
    QuicError,
    QuicStreamLimit,
    QuicFlowControl,
    QuicTransportError,
    QuicApplicationError,
    
    DhtError,
    NodeNotFound,
    RoutingTableFull,
    
    GossipError,
    TopicNotFound,
    MessageDropped,
};

pub const ErrorContext = struct {
    error_type: GhostnetError,
    message: []const u8,
    source: ?[]const u8 = null,
    timestamp: i64,
    additional_info: ?std.json.Value = null,
    
    pub fn init(allocator: std.mem.Allocator, err: GhostnetError, message: []const u8) !ErrorContext {
        return ErrorContext{
            .error_type = err,
            .message = try allocator.dupe(u8, message),
            .timestamp = std.time.timestamp(),
        };
    }
    
    pub fn deinit(self: *ErrorContext, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
        if (self.source) |src| {
            allocator.free(src);
        }
    }
    
    pub fn format(self: ErrorContext, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("GhostnetError.{s}: {s}", .{ @errorName(self.error_type), self.message });
        if (self.source) |src| {
            try writer.print(" (source: {s})", .{src});
        }
    }
};

pub fn mapSystemError(err: anyerror) GhostnetError {
    return switch (err) {
        error.ConnectionRefused => GhostnetError.ConnectionRefused,
        error.NetworkUnreachable => GhostnetError.NetworkUnreachable,
        error.AddressInUse => GhostnetError.AddressInUse,
        error.AddressNotAvailable => GhostnetError.AddressNotAvailable,
        error.PermissionDenied => GhostnetError.PermissionDenied,
        error.FileDescriptorLimit => GhostnetError.FileDescriptorLimit,
        error.ProcessFdQuotaExceeded => GhostnetError.FileDescriptorLimit,
        error.SystemFdQuotaExceeded => GhostnetError.FileDescriptorLimit,
        error.Unexpected => GhostnetError.Unexpected,
        error.OutOfMemory => GhostnetError.OutOfMemory,
        error.WouldBlock => GhostnetError.WouldBlock,
        error.ConnectionResetByPeer => GhostnetError.ConnectionReset,
        error.BrokenPipe => GhostnetError.PipeBroken,
        error.NotOpenForReading => GhostnetError.InvalidState,
        error.NotOpenForWriting => GhostnetError.InvalidState,
        error.OperationAborted => GhostnetError.ConnectionAborted,
        else => GhostnetError.Unexpected,
    };
}

pub fn Result(comptime T: type) type {
    return union(enum) {
        ok: T,
        err: ErrorContext,
        
        pub fn isOk(self: @This()) bool {
            return switch (self) {
                .ok => true,
                .err => false,
            };
        }
        
        pub fn isErr(self: @This()) bool {
            return !self.isOk();
        }
        
        pub fn unwrap(self: @This()) T {
            return switch (self) {
                .ok => |val| val,
                .err => |ctx| {
                    std.debug.panic("Called unwrap on error result: {}", .{ctx});
                },
            };
        }
        
        pub fn unwrapOr(self: @This(), default: T) T {
            return switch (self) {
                .ok => |val| val,
                .err => default,
            };
        }
        
        pub fn mapErr(self: @This(), comptime func: fn (ErrorContext) ErrorContext) @This() {
            return switch (self) {
                .ok => self,
                .err => |ctx| .{ .err = func(ctx) },
            };
        }
    };
}