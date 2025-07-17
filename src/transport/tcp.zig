const std = @import("std");
const zsync = @import("zsync");
const transport_mod = @import("transport.zig");
const errors = @import("../errors/errors.zig");

pub const TcpTransport = struct {
    allocator: std.mem.Allocator,
    io: zsync.BlockingIo,
    
    pub fn init(allocator: std.mem.Allocator) !TcpTransport {
        return .{
            .allocator = allocator,
            .io = zsync.BlockingIo.init(allocator),
        };
    }
    
    pub fn deinit(self: *TcpTransport) void {
        self.io.deinit();
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
    io: zsync.BlockingIo,
    tcp_listener: ?zsync.TcpListener,
    options: transport_mod.TransportOptions,
    
    pub fn init(allocator: std.mem.Allocator) !TcpListener {
        return .{
            .allocator = allocator,
            .io = zsync.BlockingIo.init(allocator),
            .tcp_listener = null,
            .options = undefined,
        };
    }
    
    pub fn deinit(self: *TcpListener) void {
        if (self.tcp_listener) |tcp_listener| {
            tcp_listener.close();
        }
        self.io.deinit();
    }
    
    pub fn bind(self: *TcpListener, address: transport_mod.Address, options: transport_mod.TransportOptions) !void {
        self.options = options;
        
        const addr = switch (address) {
            .ipv4 => |a| std.net.Address{ .in = a },
            .ipv6 => |a| std.net.Address{ .in6 = a },
            else => return error.InvalidAddress,
        };
        
        // Use zsync TcpListener.bind() directly
        self.tcp_listener = try zsync.TcpListener.bind(addr);
        
        // TODO: Apply socket options based on zsync API capabilities
        // For now, zsync TcpListener handles common options internally
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
    
    fn acceptAsync(ptr: *anyopaque) zsync.Future(transport_mod.TransportError!transport_mod.Connection) {
        const self: *TcpListener = @ptrCast(@alignCast(ptr));
        
        return self.io.async(struct {
            listener: *TcpListener,
            
            pub fn run(ctx: @This()) transport_mod.TransportError!transport_mod.Connection {
                if (ctx.listener.tcp_listener == null) {
                    return error.InvalidAddress;
                }
                
                // Use zsync TcpListener.accept() to get a TcpStream
                const tcp_stream = try ctx.listener.tcp_listener.?.accept();
                
                var tcp_conn = try ctx.listener.allocator.create(TcpConnection);
                errdefer ctx.listener.allocator.destroy(tcp_conn);
                
                tcp_conn.* = try TcpConnection.initFromStream(
                    ctx.listener.allocator,
                    tcp_stream,
                    ctx.listener.options
                );
                
                return tcp_conn.connection();
            }
        }{ .listener = self });
    }
    
    fn close(ptr: *anyopaque) void {
        const self: *TcpListener = @ptrCast(@alignCast(ptr));
        if (self.tcp_listener) |tcp_listener| {
            tcp_listener.close();
            self.tcp_listener = null;
        }
    }
    
    fn localAddress(ptr: *anyopaque) transport_mod.TransportError!transport_mod.Address {
        const self: *TcpListener = @ptrCast(@alignCast(ptr));
        if (self.tcp_listener == null) return error.InvalidAddress;
        
        // Use zsync TcpListener.localAddress() if available
        const addr = self.tcp_listener.?.localAddress() catch |err| {
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
    io: zsync.BlockingIo,
    tcp_stream: zsync.TcpStream,
    state: transport_mod.ConnectionState,
    options: transport_mod.TransportOptions,
    
    pub fn connect(allocator: std.mem.Allocator, address: transport_mod.Address, options: transport_mod.TransportOptions) !*TcpConnection {
        const addr = switch (address) {
            .ipv4 => |a| std.net.Address{ .in = a },
            .ipv6 => |a| std.net.Address{ .in6 = a },
            else => return error.InvalidAddress,
        };
        
        const conn = try allocator.create(TcpConnection);
        errdefer allocator.destroy(conn);
        
        // Use zsync TcpStream.connect() directly
        const tcp_stream = try zsync.TcpStream.connect(addr);
        
        conn.* = .{
            .allocator = allocator,
            .io = zsync.BlockingIo.init(allocator),
            .tcp_stream = tcp_stream,
            .state = .connected,
            .options = options,
        };
        
        return conn;
    }
    
    pub fn initFromStream(allocator: std.mem.Allocator, tcp_stream: zsync.TcpStream, options: transport_mod.TransportOptions) !TcpConnection {
        return .{
            .allocator = allocator,
            .io = try zsync.ThreadPoolIo.init(allocator, .{}),
            .tcp_stream = tcp_stream,
            .state = .connected,
            .options = options,
        };
    }
    
    pub fn deinit(self: *TcpConnection) void {
        self.tcp_stream.close();
        self.io.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn connection(self: *TcpConnection) transport_mod.Connection {
        return .{
            .ptr = self,
            .vtable = &.{
                .read = read,
                .write = write,
                .close = connectionClose,
                .local_address = connectionLocalAddress,
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
        return self.tcp_stream.read(buffer) catch |err| {
            return errors.mapSystemError(err);
        };
    }
    
    fn write(ptr: *anyopaque, buffer: []const u8) transport_mod.TransportError!usize {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        return self.tcp_stream.write(buffer) catch |err| {
            return errors.mapSystemError(err);
        };
    }
    
    fn readAsync(ptr: *anyopaque, buffer: []u8) zsync.Future(transport_mod.TransportError!usize) {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        
        return self.io.async(struct {
            conn: *TcpConnection,
            buf: []u8,
            
            pub fn run(ctx: @This()) transport_mod.TransportError!usize {
                return ctx.conn.tcp_stream.read(ctx.buf) catch |err| {
                    return errors.mapSystemError(err);
                };
            }
        }{ .conn = self, .buf = buffer });
    }
    
    fn writeAsync(ptr: *anyopaque, buffer: []const u8) zsync.Future(transport_mod.TransportError!usize) {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        
        return self.io.async(struct {
            conn: *TcpConnection,
            buf: []const u8,
            
            pub fn run(ctx: @This()) transport_mod.TransportError!usize {
                return ctx.conn.tcp_stream.write(ctx.buf) catch |err| {
                    return errors.mapSystemError(err);
                };
            }
        }{ .conn = self, .buf = buffer });
    }
    
    fn flushAsync(ptr: *anyopaque) zsync.Future(transport_mod.TransportError!void) {
        _ = ptr; // TCP sockets auto-flush, no explicit flush needed
        
        return zsync.Future.ready({});
    }
    
    fn closeAsync(ptr: *anyopaque) zsync.Future(void) {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        
        return self.io.async(struct {
            conn: *TcpConnection,
            
            pub fn run(ctx: @This()) void {
                ctx.conn.state = .closed;
                ctx.conn.tcp_stream.close();
            }
        }{ .conn = self });
    }
    
    fn connectionClose(ptr: *anyopaque) void {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        self.state = .closed;
        self.tcp_stream.close();
    }
    
    fn connectionLocalAddress(ptr: *anyopaque) transport_mod.TransportError!transport_mod.Address {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        const addr = self.tcp_stream.localAddress() catch |err| {
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
        const addr = self.tcp_stream.remoteAddress() catch |err| {
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
    
    fn setTimeout(ptr: *anyopaque, timeout: u64) transport_mod.TransportError!void {
        const self: *TcpConnection = @ptrCast(@alignCast(ptr));
        _ = self;
        _ = timeout;
        // TODO: Implement timeout setting with zsync
        return;
    }
};