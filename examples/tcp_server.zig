const std = @import("std");
const ghostnet = @import("ghostnet");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const stdout = std.io.getStdOut().writer();
    try stdout.print("👻 ghostnet TCP server example\n", .{});
    
    // This is a working example of how ghostnet will be used
    try stdout.print("Server would bind to port 8080 and accept connections\n", .{});
    try stdout.print("Each connection would be handled asynchronously with zsync\n", .{});
    
    // Example of future usage:
    // var runtime = try ghostnet.zsync.Runtime.init(allocator, .{});
    // defer runtime.deinit();
    // 
    // var listener = try ghostnet.TcpListener.init(allocator, &runtime);
    // try listener.bind(.{ .ipv4 = std.net.Ip4Address.any }, .{
    //     .port = 8080,
    //     .allocator = allocator,
    // });
    // 
    // while (true) {
    //     const conn = try listener.acceptAsync().await();
    //     _ = try ghostnet.zsync.spawn(handleConnection, .{conn});
    // }
}

fn handleConnection(conn: ghostnet.transport.Connection) !void {
    _ = conn;
    // Handle the connection
}