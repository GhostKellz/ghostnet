const std = @import("std");
const zsync = @import("zsync");
const transport = @import("transport.zig");
const errors = @import("../errors/errors.zig");

pub const UdpPacket = struct {
    data: []const u8,
    address: transport.Address,
};

pub const UdpSocket = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    socket: ?i32,
    state: transport.ConnectionState,
    options: transport.TransportOptions,
    local_addr: ?transport.Address = null,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) UdpSocket {
        return .{
            .allocator = allocator,
            .runtime = runtime,
            .socket = null,
            .state = .closed,
            .options = undefined,
        };
    }
    
    pub fn bind(self: *UdpSocket, address: transport.Address, options: transport.TransportOptions) !void {
        self.options = options;
        
        const addr = switch (address) {
            .ipv4 => |a| std.net.Address{ .in = a },
            .ipv6 => |a| std.net.Address{ .in6 = a },
            else => return error.InvalidAddress,
        };
        
        self.socket = try zsync.net.UdpSocket.bind(addr);
        self.state = .connected;
        self.local_addr = address;
        
        if (options.reuse_address) {
            try self.socket.setReuseAddress(true);
        }
        if (options.reuse_port) {
            try self.socket.setReusePort(true);
        }
        if (options.recv_buffer_size) |size| {
            try self.socket.setRecvBufferSize(size);
        }
        if (options.send_buffer_size) |size| {
            try self.socket.setSendBufferSize(size);
        }
    }
    
    pub fn connect(self: *UdpSocket, address: transport.Address) !void {
        const addr = switch (address) {
            .ipv4 => |a| std.net.Address{ .in = a },
            .ipv6 => |a| std.net.Address{ .in6 = a },
            else => return error.InvalidAddress,
        };
        
        try self.socket.connect(addr);
        self.state = .connected;
    }
    
    pub fn sendTo(self: *UdpSocket, data: []const u8, address: transport.Address) !usize {
        const addr = switch (address) {
            .ipv4 => |a| std.net.Address{ .in = a },
            .ipv6 => |a| std.net.Address{ .in6 = a },
            else => return error.InvalidAddress,
        };
        
        return self.socket.sendTo(data, addr) catch |err| {
            return errors.mapSystemError(err);
        };
    }
    
    pub fn recvFrom(self: *UdpSocket, buffer: []u8) !UdpPacket {
        const result = self.socket.recvFrom(buffer) catch |err| {
            return errors.mapSystemError(err);
        };
        
        const address = switch (result.addr) {
            .in => |a| transport.Address{ .ipv4 = a },
            .in6 => |a| transport.Address{ .ipv6 = a },
            else => return error.InvalidAddress,
        };
        
        return UdpPacket{
            .data = buffer[0..result.size],
            .address = address,
        };
    }
    
    pub fn sendToAsync(self: *UdpSocket, data: []const u8, address: transport.Address) zsync.Future(transport.TransportError!usize) {
        return zsync.Future(transport.TransportError!usize).init(self.runtime, struct {
            socket: *UdpSocket,
            data: []const u8,
            addr: transport.Address,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport.TransportError!usize) {
                const net_addr = switch (ctx.addr) {
                    .ipv4 => |a| std.net.Address{ .in = a },
                    .ipv6 => |a| std.net.Address{ .in6 = a },
                    else => return .{ .ready = transport.TransportError!usize{ error.InvalidAddress } },
                };
                
                const result = ctx.socket.socket.sendToAsync(ctx.data, net_addr) catch |err| {
                    return .{ .ready = transport.TransportError!usize{ 
                        errors.mapSystemError(err) 
                    }};
                };
                
                return switch (result) {
                    .ready => |n| .{ .ready = n },
                    .pending => .pending,
                };
            }
        }{ .socket = self, .data = data, .addr = address });
    }
    
    pub fn recvFromAsync(self: *UdpSocket, buffer: []u8) zsync.Future(transport.TransportError!UdpPacket) {
        return zsync.Future(transport.TransportError!UdpPacket).init(self.runtime, struct {
            socket: *UdpSocket,
            buf: []u8,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport.TransportError!UdpPacket) {
                const result = ctx.socket.socket.recvFromAsync(ctx.buf) catch |err| {
                    return .{ .ready = transport.TransportError!UdpPacket{ 
                        errors.mapSystemError(err) 
                    }};
                };
                
                switch (result) {
                    .ready => |res| {
                        const address = switch (res.addr) {
                            .in => |a| transport.Address{ .ipv4 = a },
                            .in6 => |a| transport.Address{ .ipv6 = a },
                            else => return .{ .ready = transport.TransportError!UdpPacket{ 
                                error.InvalidAddress 
                            }},
                        };
                        
                        return .{ .ready = UdpPacket{
                            .data = ctx.buf[0..res.size],
                            .address = address,
                        } };
                    },
                    .pending => return .pending,
                }
            }
        }{ .socket = self, .buf = buffer });
    }
    
    pub fn close(self: *UdpSocket) void {
        self.state = .closed;
        self.socket.close();
    }
    
    pub fn localAddress(self: *UdpSocket) transport.TransportError!transport.Address {
        if (self.local_addr) |addr| {
            return addr;
        }
        
        const addr = self.socket.getLocalAddress() catch |err| {
            return errors.mapSystemError(err);
        };
        
        return switch (addr) {
            .in => |a| transport.Address{ .ipv4 = a },
            .in6 => |a| transport.Address{ .ipv6 = a },
            else => error.InvalidAddress,
        };
    }
    
    pub fn connection(self: *UdpSocket) transport.Connection {
        return .{
            .ptr = self,
            .vtable = &.{
                .read = read,
                .write = write,
                .close = closeConnection,
                .local_address = localAddressConnection,
                .remote_address = remoteAddressConnection,
                .state = getState,
                .set_timeout = setTimeout,
            },
        };
    }
    
    pub fn stream(self: *UdpSocket) transport.Stream {
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
    
    fn read(ptr: *anyopaque, buffer: []u8) transport.TransportError!usize {
        const self: *UdpSocket = @ptrCast(@alignCast(ptr));
        return self.socket.recv(buffer) catch |err| {
            return errors.mapSystemError(err);
        };
    }
    
    fn write(ptr: *anyopaque, buffer: []const u8) transport.TransportError!usize {
        const self: *UdpSocket = @ptrCast(@alignCast(ptr));
        return self.socket.send(buffer) catch |err| {
            return errors.mapSystemError(err);
        };
    }
    
    fn readAsync(ptr: *anyopaque, buffer: []u8) zsync.Future(transport.TransportError!usize) {
        const self: *UdpSocket = @ptrCast(@alignCast(ptr));
        
        return zsync.Future(transport.TransportError!usize).init(self.runtime, struct {
            socket: *UdpSocket,
            buf: []u8,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport.TransportError!usize) {
                const result = ctx.socket.socket.recvAsync(ctx.buf) catch |err| {
                    return .{ .ready = transport.TransportError!usize{ 
                        errors.mapSystemError(err) 
                    }};
                };
                
                return switch (result) {
                    .ready => |n| .{ .ready = n },
                    .pending => .pending,
                };
            }
        }{ .socket = self, .buf = buffer });
    }
    
    fn writeAsync(ptr: *anyopaque, buffer: []const u8) zsync.Future(transport.TransportError!usize) {
        const self: *UdpSocket = @ptrCast(@alignCast(ptr));
        
        return zsync.Future(transport.TransportError!usize).init(self.runtime, struct {
            socket: *UdpSocket,
            buf: []const u8,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport.TransportError!usize) {
                const result = ctx.socket.socket.sendAsync(ctx.buf) catch |err| {
                    return .{ .ready = transport.TransportError!usize{ 
                        errors.mapSystemError(err) 
                    }};
                };
                
                return switch (result) {
                    .ready => |n| .{ .ready = n },
                    .pending => .pending,
                };
            }
        }{ .socket = self, .buf = buffer });
    }
    
    fn flushAsync(ptr: *anyopaque) zsync.Future(transport.TransportError!void) {
        const self: *UdpSocket = @ptrCast(@alignCast(ptr));
        
        return zsync.Future(transport.TransportError!void).init(self.runtime, struct {
            socket: *UdpSocket,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport.TransportError!void) {
                _ = ctx;
                return .{ .ready = {} };
            }
        }{ .socket = self });
    }
    
    fn closeAsync(ptr: *anyopaque) zsync.Future(void) {
        const self: *UdpSocket = @ptrCast(@alignCast(ptr));
        
        return zsync.Future(void).init(self.runtime, struct {
            socket: *UdpSocket,
            
            pub fn poll(ctx: *@This()) zsync.Poll(void) {
                ctx.socket.close();
                return .{ .ready = {} };
            }
        }{ .socket = self });
    }
    
    fn closeConnection(ptr: *anyopaque) void {
        const self: *UdpSocket = @ptrCast(@alignCast(ptr));
        self.close();
    }
    
    fn localAddressConnection(ptr: *anyopaque) transport.TransportError!transport.Address {
        const self: *UdpSocket = @ptrCast(@alignCast(ptr));
        return self.localAddress();
    }
    
    fn remoteAddressConnection(ptr: *anyopaque) transport.TransportError!transport.Address {
        const self: *UdpSocket = @ptrCast(@alignCast(ptr));
        
        const addr = self.socket.getRemoteAddress() catch |err| {
            return errors.mapSystemError(err);
        };
        
        return switch (addr) {
            .in => |a| transport.Address{ .ipv4 = a },
            .in6 => |a| transport.Address{ .ipv6 = a },
            else => error.InvalidAddress,
        };
    }
    
    fn getState(ptr: *anyopaque) transport.ConnectionState {
        const self: *UdpSocket = @ptrCast(@alignCast(ptr));
        return self.state;
    }
    
    fn setTimeout(ptr: *anyopaque, read_timeout: ?u64, write_timeout: ?u64) transport.TransportError!void {
        const self: *UdpSocket = @ptrCast(@alignCast(ptr));
        
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