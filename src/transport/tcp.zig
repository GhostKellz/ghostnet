const std = @import("std");
const zsync = @import("zsync");
const transport_mod = @import("transport.zig");
const errors = @import("../errors/errors.zig");

pub const TcpTransport = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) TcpTransport {
        return .{
            .allocator = allocator,
            .runtime = runtime,
        };
    }
    
    const vtable = transport_mod.Transport.VTable{
        .bind = bindTransport,
        .connect = connectTransport,
        .accept = acceptTransport,
        .close = closeTransport,
        .local_address = localAddress,
    };
    
    pub fn transport(self: *TcpTransport) transport_mod.Transport {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }
    
    fn bindTransport(ptr: *anyopaque, address: transport_mod.Address, options: transport_mod.TransportOptions) transport_mod.TransportError!void {
        const self: *TcpTransport = @ptrCast(@alignCast(ptr));
        _ = self;
        _ = address;
        _ = options;
        return error.Unexpected;
    }
    
    fn connectTransport(ptr: *anyopaque, address: transport_mod.Address, options: transport_mod.TransportOptions) transport_mod.TransportError!transport_mod.Connection {
        const self: *TcpTransport = @ptrCast(@alignCast(ptr));
        _ = self;
        _ = address;
        _ = options;
        return error.Unexpected;
    }
    
    fn acceptTransport(ptr: *anyopaque) transport_mod.TransportError!transport_mod.Connection {
        const self: *TcpTransport = @ptrCast(@alignCast(ptr));
        _ = self;
        return error.Unexpected;
    }
    
    fn closeTransport(ptr: *anyopaque) void {
        const self: *TcpTransport = @ptrCast(@alignCast(ptr));
        _ = self;
    }
    
    fn localAddress(ptr: *anyopaque) transport_mod.TransportError!transport_mod.Address {
        const self: *TcpTransport = @ptrCast(@alignCast(ptr));
        _ = self;
        return error.Unexpected;
    }
};

pub const TcpListener = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    socket: ?i32,
    options: transport_mod.TransportOptions,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) TcpListener {
        return .{
            .allocator = allocator,
            .runtime = runtime,
            .socket = null,
            .options = undefined,
        };
    }
    
    pub fn bind(self: *TcpListener, address: transport_mod.Address, options: transport_mod.TransportOptions) !void {
        self.options = options;
        
        const addr = switch (address) {
            .ipv4 => |a| std.net.Address{ .in = a },
            .ipv6 => |a| std.net.Address{ .in6 = a },
            else => return error.InvalidAddress,
        };
        
        self.socket = try zsync.net.TcpListener.bind(addr);
        
        if (options.reuse_address) {
            try self.socket.setReuseAddress(true);
        }
        if (options.reuse_port) {
            try self.socket.setReusePort(true);
        }
        
        try self.socket.listen(options.backlog);
    }
    
    pub fn listener(self: *TcpListener) transport_mod.Listener {
        return .{
            .ptr = self,
            .vtable = &.{
                .accept_async = acceptAsync,
                .close = close,
                .local_address = localAddress,
            },
        };
    }
    
    fn acceptAsync(ptr: *anyopaque) zsync.Future {
        const self: *TcpListener = @ptrCast(@alignCast(ptr));
        
        return zsync.Future.init(self.runtime, struct {
            listener: *TcpListener,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport_mod.TransportError!transport_mod.Connection) {
                const conn_result = ctx.listener.socket.acceptAsync() catch |err| {
                    return .{ .ready = transport_mod.TransportError!transport_mod.Connection{ 
                        errors.mapSystemError(err) 
                    }};
                };
                
                switch (conn_result) {
                    .ready => |conn| {
                        var tcp_conn = ctx.listener.allocator.create(TcpConnection) catch {
                            return .{ .ready = transport_mod.TransportError!transport_mod.Connection{ 
                                error.OutOfMemory 
                            }};
                        };
                        
                        tcp_conn.* = TcpConnection{
                            .allocator = ctx.listener.allocator,
                            .runtime = ctx.listener.runtime,
                            .socket = conn,
                            .state = .connected,
                            .options = ctx.listener.options,
                        };
                        
                        return .{ .ready = tcp_conn.connection() };
                    },
                    .pending => return .pending,
                }
            }
        }{ .listener = self });
    }
    
    fn close(ptr: *anyopaque) void {
        const self: *TcpListener = @ptrCast(@alignCast(ptr));
        self.socket.close();
    }
    
    fn localAddress(ptr: *anyopaque) transport_mod.TransportError!transport_mod.Address {
        const self: *TcpListener = @ptrCast(@alignCast(ptr));
        const addr = self.socket.getLocalAddress() catch |err| {
            return errors.mapSystemError(err);
        };
        
        return switch (addr) {
            .in => |a| transport_mod.Address{ .ipv4 = a },
            .in6 => |a| transport_mod.Address{ .ipv6 = a },
            else => error.InvalidAddress,
        };
    }
};

pub const TcpConnection = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    socket: ?std.net.Stream,
    state: transport_mod.ConnectionState,
    options: transport_mod.TransportOptions,
    
    pub fn connect(allocator: std.mem.Allocator, runtime: *zsync.Runtime, address: transport_mod.Address, options: transport_mod.TransportOptions) !*TcpConnection {
        const addr = switch (address) {
            .ipv4 => |a| std.net.Address{ .in = a },
            .ipv6 => |a| std.net.Address{ .in6 = a },
            else => return error.InvalidAddress,
        };
        
        var conn = try allocator.create(TcpConnection);
        errdefer allocator.destroy(conn);
        
        conn.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .socket = null,
            .state = .connecting,
            .options = options,
        };
        
        conn.socket = try std.net.tcpConnectToAddress(addr);
        conn.state = .connected;
        
        if (options.nodelay) {
            try conn.socket.setNoDelay(true);
        }
        if (options.keepalive) {
            try conn.socket.setKeepAlive(true);
        }
        if (options.recv_buffer_size) |size| {
            try conn.socket.setRecvBufferSize(size);
        }
        if (options.send_buffer_size) |size| {
            try conn.socket.setSendBufferSize(size);
        }
        
        return conn;
    }
    
    pub fn connection(self: *TcpConnection) transport_mod.Connection {
        return .{
            .ptr = self,
            .vtable = &.{
                .read = read,
                .write = write,
                .close = close,
                .local_address = localAddress,
                .remote_address = remoteAddress,
                .state = getState,
                .set_timeout = setTimeout,
            },
        };
    }
    
    pub fn stream(self: *TcpConnection) transport_mod.Stream {
        return .{
            .ptr = self,
            .vtable = &.{
                .read_async = readAsync,
                .write_async = writeAsync,
                .flush_async = flushAsync,
                .close_async = closeAsync,
            },
        };
    }
    
    fn read(ptr: *anyopaque, buffer: []u8) transport_mod.TransportError!usize {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        return self.socket.read(buffer) catch |err| {
            return errors.mapSystemError(err);
        };
    }
    
    fn write(ptr: *anyopaque, buffer: []const u8) transport_mod.TransportError!usize {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        return self.socket.write(buffer) catch |err| {
            return errors.mapSystemError(err);
        };
    }
    
    fn readAsync(ptr: *anyopaque, buffer: []u8) zsync.Future {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        
        return zsync.Future.init(self.runtime, struct {
            conn: *TcpConnection,
            buf: []u8,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport_mod.TransportError!usize) {
                const result = ctx.conn.socket.readAsync(ctx.buf) catch |err| {
                    return .{ .ready = transport_mod.TransportError!usize{ 
                        errors.mapSystemError(err) 
                    }};
                };
                
                return switch (result) {
                    .ready => |n| .{ .ready = n },
                    .pending => .pending,
                };
            }
        }{ .conn = self, .buf = buffer });
    }
    
    fn writeAsync(ptr: *anyopaque, buffer: []const u8) zsync.Future {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        
        return zsync.Future.init(self.runtime, struct {
            conn: *TcpConnection,
            buf: []const u8,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport_mod.TransportError!usize) {
                const result = ctx.conn.socket.writeAsync(ctx.buf) catch |err| {
                    return .{ .ready = transport_mod.TransportError!usize{ 
                        errors.mapSystemError(err) 
                    }};
                };
                
                return switch (result) {
                    .ready => |n| .{ .ready = n },
                    .pending => .pending,
                };
            }
        }{ .conn = self, .buf = buffer });
    }
    
    fn flushAsync(ptr: *anyopaque) zsync.Future {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        
        return zsync.Future.init(self.runtime, struct {
            conn: *TcpConnection,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport_mod.TransportError!void) {
                _ = ctx;
                return .{ .ready = {} };
            }
        }{ .conn = self });
    }
    
    fn closeAsync(ptr: *anyopaque) zsync.Future {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        
        return zsync.Future.init(self.runtime, struct {
            conn: *TcpConnection,
            
            pub fn poll(ctx: *@This()) zsync.Poll(void) {
                ctx.conn.state = .closed;
                ctx.conn.socket.close();
                return .{ .ready = {} };
            }
        }{ .conn = self });
    }
    
    fn close(ptr: *anyopaque) void {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        self.state = .closed;
        self.socket.close();
    }
    
    fn localAddress(ptr: *anyopaque) transport_mod.TransportError!transport_mod.Address {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        const addr = self.socket.getLocalAddress() catch |err| {
            return errors.mapSystemError(err);
        };
        
        return switch (addr) {
            .in => |a| transport_mod.Address{ .ipv4 = a },
            .in6 => |a| transport_mod.Address{ .ipv6 = a },
            else => error.InvalidAddress,
        };
    }
    
    fn remoteAddress(ptr: *anyopaque) transport_mod.TransportError!transport_mod.Address {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        const addr = self.socket.getRemoteAddress() catch |err| {
            return errors.mapSystemError(err);
        };
        
        return switch (addr) {
            .in => |a| transport_mod.Address{ .ipv4 = a },
            .in6 => |a| transport_mod.Address{ .ipv6 = a },
            else => error.InvalidAddress,
        };
    }
    
    fn getState(ptr: *anyopaque) transport_mod.ConnectionState {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        return self.state;
    }
    
    fn setTimeout(ptr: *anyopaque, read_timeout: ?u64, write_timeout: ?u64) transport_mod.TransportError!void {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        
        if (read_timeout) |timeout| {
            self.socket.setReadTimeout(timeout) catch |err| {
                return errors.mapSystemError(err);
            };
        }
        
        if (write_timeout) |timeout| {
            self.socket.setWriteTimeout(timeout) catch |err| {
                return errors.mapSystemError(err);
            };
        }
    }
};