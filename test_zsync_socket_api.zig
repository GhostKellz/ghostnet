const std = @import("std");
const zsync = @import("zsync");

// Test the correct zsync socket API
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Testing zsync v0.3.2 socket API...\n", .{});

    // Test 1: TcpStream API
    {
        std.debug.print("1. Testing zsync.TcpStream...\n", .{});
        // Basic API check - don't actually connect
        const TcpStreamType = @TypeOf(zsync.TcpStream);
        std.debug.print("   ✅ TcpStream type: {}\n", .{TcpStreamType});
    }

    // Test 2: TcpListener API
    {
        std.debug.print("2. Testing zsync.TcpListener...\n", .{});
        const TcpListenerType = @TypeOf(zsync.TcpListener);
        std.debug.print("   ✅ TcpListener type: {}\n", .{TcpListenerType});
    }

    // Test 3: UdpSocket API
    {
        std.debug.print("3. Testing zsync.UdpSocket...\n", .{});
        const UdpSocketType = @TypeOf(zsync.UdpSocket);
        std.debug.print("   ✅ UdpSocket type: {}\n", .{UdpSocketType});
    }

    // Test 4: Io implementations
    {
        std.debug.print("4. Testing zsync.Io implementations...\n", .{});
        var blocking_io = zsync.BlockingIo.init();
        defer blocking_io.deinit();

        var thread_pool_io = try zsync.ThreadPoolIo.init(allocator, .{});
        defer thread_pool_io.deinit();

        std.debug.print("   ✅ BlockingIo and ThreadPoolIo work\n", .{});
    }

    std.debug.print("\n🎉 zsync socket API structure confirmed!\n");
    std.debug.print("📝 ghostnet should use:\n");
    std.debug.print("   - zsync.TcpStream for TCP connections\n");
    std.debug.print("   - zsync.TcpListener for TCP servers\n");
    std.debug.print("   - zsync.UdpSocket for UDP operations\n");
    std.debug.print("   - Choose appropriate Io implementation for async operations\n");
}
