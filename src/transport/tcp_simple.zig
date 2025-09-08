const std = @import("std");
const transport_mod = @import("transport.zig");
const errors = @import("../errors/errors.zig");

pub const SimpleTcpTransport = struct {
    allocator: std.mem.Allocator,
    listener: ?*SimpleTcpListener,
    
    pub fn init(allocator: std.mem.Allocator) SimpleTcpTransport {
        return .{
            .allocator = allocator,
            .listener = null,
        };
    }
    
    pub fn deinit(self: *SimpleTcpTransport) void {
        if (self.listener) |listener| {
            listener.close();
            self.allocator.destroy(listener);
        }
    }
    
    const vtable = transport_mod.Transport.VTable{
        .bind = bindTransport,
        .connect = connectTransport,
        .accept = acceptTransport,
        .close = closeTransport,
        .local_address = localAddress,
    };
    
    pub fn transport(self: *SimpleTcpTransport) transport_mod.Transport {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }
    
    fn bindTransport(ptr: *anyopaque, address: transport_mod.Address, options: transport_mod.TransportOptions) transport_mod.TransportError!void {
        const self: *SimpleTcpTransport = @ptrCast(@alignCast(ptr));
        
        // Clean up existing listener if any
        if (self.listener) |listener| {
            listener.close();
            self.allocator.destroy(listener);
        }
        
        // Create new listener
        self.listener = self.allocator.create(SimpleTcpListener) catch return error.OutOfMemory;
        errdefer {
            self.allocator.destroy(self.listener.?);
            self.listener = null;
        }
        
        self.listener.?.* = SimpleTcpListener.init(self.allocator);
        try self.listener.?.bind(address, options);
    }
    
    fn connectTransport(ptr: *anyopaque, address: transport_mod.Address, options: transport_mod.TransportOptions) transport_mod.TransportError!transport_mod.Connection {
        const self: *SimpleTcpTransport = @ptrCast(@alignCast(ptr));
        
        const conn = SimpleTcpConnection.connect(self.allocator, address, options) catch |err| {
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.InvalidAddress => error.InvalidAddress,
                error.ConnectionRefused => error.ConnectionRefused,
                error.NetworkUnreachable => error.NetworkUnreachable,
                error.ConnectionTimedOut => error.ConnectionTimedOut,
                else => error.Unexpected,
            };
        };
        
        return conn.connection();
    }
    
    fn acceptTransport(ptr: *anyopaque) transport_mod.TransportError!transport_mod.Connection {
        const self: *SimpleTcpTransport = @ptrCast(@alignCast(ptr));
        
        if (self.listener == null) {
            return error.NotListening;
        }
        
        const conn = self.listener.?.accept() catch |err| {
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.ConnectionAborted => error.ConnectionAborted,
                error.FileDescriptorNotASocket => error.InvalidSocket,
                else => error.Unexpected,
            };
        };
        
        return conn.connection();
    }
    
    fn closeTransport(ptr: *anyopaque) void {
        const self: *SimpleTcpTransport = @ptrCast(@alignCast(ptr));
        
        if (self.listener) |listener| {
            listener.close();
            self.allocator.destroy(listener);
            self.listener = null;
        }
    }
    
    fn localAddress(ptr: *anyopaque) transport_mod.TransportError!transport_mod.Address {
        const self: *SimpleTcpTransport = @ptrCast(@alignCast(ptr));
        
        if (self.listener == null) {
            return error.NotListening;
        }
        
        return self.listener.?.localAddress() catch |err| {
            return switch (err) {
                error.InvalidSocket => error.InvalidSocket,
                error.FileDescriptorNotASocket => error.InvalidSocket,
                else => error.Unexpected,
            };
        };
    }
};

pub const SimpleTcpListener = struct {
    allocator: std.mem.Allocator,
    socket: ?std.net.Server,
    
    pub fn init(allocator: std.mem.Allocator) SimpleTcpListener {
        return .{
            .allocator = allocator,
            .socket = null,
        };
    }
    
    pub fn bind(self: *SimpleTcpListener, address: transport_mod.Address, options: transport_mod.TransportOptions) !void {
        const addr = switch (address) {
            .ipv4 => |a| std.net.Address{ .in = a },
            .ipv6 => |a| std.net.Address{ .in6 = a },
            else => return error.InvalidAddress,
        };
        
        self.socket = try addr.listen(.{
            .reuse_address = options.reuse_address,
            .reuse_port = options.reuse_port,
        });
    }
    
    pub fn accept(self: *SimpleTcpListener) !*SimpleTcpConnection {
        if (self.socket == null) return error.NotListening;
        
        const conn_result = try self.socket.?.accept();
        
        var tcp_conn = try self.allocator.create(SimpleTcpConnection);
        tcp_conn.* = SimpleTcpConnection{
            .allocator = self.allocator,
            .socket = conn_result.stream,
            .state = .connected,
        };
        
        return tcp_conn;
    }
    
    pub fn close(self: *SimpleTcpListener) void {
        if (self.socket) |*socket| {
            socket.deinit();
            self.socket = null;
        }
    }
    
    pub fn localAddress(self: *SimpleTcpListener) !transport_mod.Address {
        if (self.socket == null) return error.NotListening;
        
        const addr = try self.socket.?.listen_address;
        
        return switch (addr) {
            .in => |a| transport_mod.Address{ .ipv4 = a },
            .in6 => |a| transport_mod.Address{ .ipv6 = a },
            else => error.InvalidAddress,
        };
    }
};

pub const SimpleTcpConnection = struct {
    allocator: std.mem.Allocator,
    socket: std.net.Stream,
    state: transport_mod.ConnectionState,
    
    pub fn connect(allocator: std.mem.Allocator, address: transport_mod.Address, options: transport_mod.TransportOptions) !*SimpleTcpConnection {
        const addr = switch (address) {
            .ipv4 => |a| std.net.Address{ .in = a },
            .ipv6 => |a| std.net.Address{ .in6 = a },
            else => return error.InvalidAddress,
        };
        
        var conn = try allocator.create(SimpleTcpConnection);
        errdefer allocator.destroy(conn);
        
        conn.* = .{
            .allocator = allocator,
            .socket = undefined,
            .state = .connecting,
        };
        
        conn.socket = try std.net.tcpConnectToAddress(addr);
        conn.state = .connected;
        
        // Configure socket options using std.posix.setsockopt
        const fd = conn.socket.handle;
        
        if (options.no_delay) {
            const value: c_int = 1;
            try std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, 1, std.mem.asBytes(&value)); // TCP_NODELAY = 1
        }
        if (options.keep_alive) {
            const value: c_int = 1;
            try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, std.mem.asBytes(&value));
        }
        if (options.send_buffer_size > 0) {
            const value: c_int = @intCast(options.send_buffer_size);
            try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&value));
        }
        if (options.receive_buffer_size > 0) {
            const value: c_int = @intCast(options.receive_buffer_size);
            try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&value));
        }
        
        return conn;
    }
    
    pub fn connection(self: *SimpleTcpConnection) transport_mod.Connection {
        return .{
            .ptr = self,
            .vtable = &.{
                .read = read,
                .write = write,
                .flush = flush,
                .close = close,
                .remote_address = remoteAddress,
                .state = getState,
                .set_timeout = setTimeout,
            },
        };
    }
    
    fn read(ptr: *anyopaque, buffer: []u8) transport_mod.TransportError!usize {
        const self: *SimpleTcpConnection = @ptrCast(@alignCast(ptr));
        return self.socket.read(buffer) catch |err| {
            return errors.mapSystemError(err);
        };
    }
    
    fn write(ptr: *anyopaque, buffer: []const u8) transport_mod.TransportError!usize {
        const self: *SimpleTcpConnection = @ptrCast(@alignCast(ptr));
        return self.socket.write(buffer) catch |err| {
            return errors.mapSystemError(err);
        };
    }
    
    fn flush(ptr: *anyopaque) transport_mod.TransportError!void {
        const self: *SimpleTcpConnection = @ptrCast(@alignCast(ptr));
        // TCP doesn't need explicit flushing
        _ = self;
    }
    
    fn close(ptr: *anyopaque) void {
        const self: *SimpleTcpConnection = @ptrCast(@alignCast(ptr));
        self.socket.close();
        self.state = .closed;
    }
    
    fn remoteAddress(ptr: *anyopaque) transport_mod.TransportError!transport_mod.Address {
        const self: *SimpleTcpConnection = @ptrCast(@alignCast(ptr));
        const addr = self.socket.getEndPoint() catch |err| {
            return errors.mapSystemError(err);
        };
        
        return switch (addr) {
            .in => |a| transport_mod.Address{ .ipv4 = a },
            .in6 => |a| transport_mod.Address{ .ipv6 = a },
            else => error.InvalidAddress,
        };
    }
    
    fn getState(ptr: *anyopaque) transport_mod.ConnectionState {
        const self: *SimpleTcpConnection = @ptrCast(@alignCast(ptr));
        return self.state;
    }
    
    fn setTimeout(ptr: *anyopaque, timeout_ms: u32) transport_mod.TransportError!void {
        const self: *SimpleTcpConnection = @ptrCast(@alignCast(ptr));
        
        // Set socket timeout for read/write operations
        const tv = std.posix.timeval{
            .tv_sec = @intCast(timeout_ms / 1000),
            .tv_usec = @intCast((timeout_ms % 1000) * 1000),
        };
        
        const sockfd = self.stream.handle;
        _ = std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
        _ = std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv));
    }
};