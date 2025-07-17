const std = @import("std");
const zsync = @import("zsync");

pub const tcp = @import("tcp.zig");
pub const udp = @import("udp.zig");

pub const TransportError = error{
    ConnectionRefused,
    ConnectionReset,
    NetworkUnreachable,
    AddressInUse,
    InvalidAddress,
    Timeout,
    TooManyConnections,
    ProtocolError,
    TransportClosed,
    InvalidState,
    OutOfMemory,
    Unexpected,
    // Additional errors for complete implementation
    ConnectionTimedOut,
    ConnectionAborted,
    InvalidSocket,
    NotListening,
};

pub const Address = union(enum) {
    ipv4: std.net.Ip4Address,
    ipv6: std.net.Ip6Address,
    unix: []const u8,
    custom: []const u8,

    pub fn format(self: Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .ipv4 => |addr| try writer.print("{}", .{addr}),
            .ipv6 => |addr| try writer.print("{}", .{addr}),
            .unix => |path| try writer.print("unix:{s}", .{path}),
            .custom => |addr| try writer.print("{s}", .{addr}),
        }
    }
};

pub const TransportOptions = struct {
    backlog: u31 = 128,
    reuse_address: bool = true,
    reuse_port: bool = false,
    no_delay: bool = true,
    keep_alive: bool = true,
    keepalive_interval: u32 = 60,
    send_buffer_size: u32 = 8192,
    receive_buffer_size: u32 = 8192,
    timeout: u32 = 5000,
    linger: ?u16 = null,
};

pub const Transport = struct {
    const Self = @This();

    pub const VTable = struct {
        bind: *const fn (self: *anyopaque, address: Address, options: TransportOptions) TransportError!void,
        connect: *const fn (self: *anyopaque, address: Address, options: TransportOptions) TransportError!Connection,
        accept: *const fn (self: *anyopaque) TransportError!Connection,
        close: *const fn (self: *anyopaque) void,
        local_address: *const fn (self: *anyopaque) TransportError!Address,
    };

    ptr: *anyopaque,
    vtable: *const VTable,

    pub fn bind(self: Self, address: Address, options: TransportOptions) TransportError!void {
        return self.vtable.bind(self.ptr, address, options);
    }

    pub fn connect(self: Self, address: Address, options: TransportOptions) TransportError!Connection {
        return self.vtable.connect(self.ptr, address, options);
    }

    pub fn accept(self: Self) TransportError!Connection {
        return self.vtable.accept(self.ptr);
    }

    pub fn close(self: Self) void {
        self.vtable.close(self.ptr);
    }

    pub fn localAddress(self: Self) TransportError!Address {
        return self.vtable.local_address(self.ptr);
    }
};

pub const ConnectionState = enum {
    connecting,
    connected,
    closing,
    closed,
};

pub const Connection = struct {
    const Self = @This();

    pub const VTable = struct {
        read: *const fn (self: *anyopaque, buffer: []u8) TransportError!usize,
        write: *const fn (self: *anyopaque, buffer: []const u8) TransportError!usize,
        close: *const fn (self: *anyopaque) void,
        local_address: *const fn (self: *anyopaque) TransportError!Address,
        remote_address: *const fn (self: *anyopaque) TransportError!Address,
        state: *const fn (self: *anyopaque) ConnectionState,
        set_timeout: *const fn (self: *anyopaque, read_timeout: ?u64, write_timeout: ?u64) TransportError!void,
    };

    ptr: *anyopaque,
    vtable: *const VTable,

    pub fn read(self: Self, buffer: []u8) TransportError!usize {
        return self.vtable.read(self.ptr, buffer);
    }

    pub fn write(self: Self, buffer: []const u8) TransportError!usize {
        return self.vtable.write(self.ptr, buffer);
    }

    pub fn close(self: Self) void {
        self.vtable.close(self.ptr);
    }

    pub fn localAddress(self: Self) TransportError!Address {
        return self.vtable.local_address(self.ptr);
    }

    pub fn remoteAddress(self: Self) TransportError!Address {
        return self.vtable.remote_address(self.ptr);
    }

    pub fn state(self: Self) ConnectionState {
        return self.vtable.state(self.ptr);
    }

    pub fn setTimeout(self: Self, read_timeout: ?u64, write_timeout: ?u64) TransportError!void {
        return self.vtable.set_timeout(self.ptr, read_timeout, write_timeout);
    }
};

pub const Stream = struct {
    const Self = @This();

    pub const VTable = struct {
        read_async: *const fn (self: *anyopaque, buffer: []u8) zsync.Future,
        write_async: *const fn (self: *anyopaque, buffer: []const u8) zsync.Future,
        flush_async: *const fn (self: *anyopaque) zsync.Future,
        close_async: *const fn (self: *anyopaque) zsync.Future,
    };

    ptr: *anyopaque,
    vtable: *const VTable,

    pub fn readAsync(self: Self, buffer: []u8) zsync.Future {
        return self.vtable.read_async(self.ptr, buffer);
    }

    pub fn writeAsync(self: Self, buffer: []const u8) zsync.Future {
        return self.vtable.write_async(self.ptr, buffer);
    }

    pub fn flushAsync(self: Self) zsync.Future {
        return self.vtable.flush_async(self.ptr);
    }

    pub fn closeAsync(self: Self) zsync.Future {
        return self.vtable.close_async(self.ptr);
    }
};

pub const Listener = struct {
    const Self = @This();

    pub const VTable = struct {
        accept_async: *const fn (self: *anyopaque) zsync.Future,
        close: *const fn (self: *anyopaque) void,
        local_address: *const fn (self: *anyopaque) TransportError!Address,
    };

    ptr: *anyopaque,
    vtable: *const VTable,

    pub fn acceptAsync(self: Self) zsync.Future {
        return self.vtable.accept_async(self.ptr);
    }

    pub fn close(self: Self) void {
        self.vtable.close(self.ptr);
    }

    pub fn localAddress(self: Self) TransportError!Address {
        return self.vtable.local_address(self.ptr);
    }
};