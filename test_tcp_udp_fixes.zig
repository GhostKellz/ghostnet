const std = @import("std");
const testing = std.testing;
const zsync = @import("zsync");
const ghostnet = @import("ghostnet");

test "TCP setTcpNoDelay fix" {
    var runtime = try zsync.Runtime.init(testing.allocator, .{});
    defer runtime.deinit();
    
    // Test TCP connection with nodelay option
    const tcp_options = ghostnet.TransportOptions{
        .nodelay = true,
        .keepalive = false,
        .reuse_address = false,
        .reuse_port = false,
        .recv_buffer_size = null,
        .send_buffer_size = null,
        .allocator = testing.allocator,
    };
    
    // This should not fail due to setTcpNoDelay method missing
    const result = ghostnet.TcpConnection.connect(testing.allocator, runtime, ghostnet.Address{ .ipv4 = std.net.Ip4Address.init([4]u8{127, 0, 0, 1}, 80) }, tcp_options);
    
    // We expect connection to fail (since no server is listening), but not due to setTcpNoDelay
    // Just check that the method compiles and runs
    if (result) |conn| {
        testing.allocator.destroy(conn);
    } else |_| {
        // Connection failed as expected (no server listening)
    }
}

test "UDP sendTo fix - compilation check" {
    // This test only checks that UDP socket types compile correctly
    // and that the sendTo method exists (no actual networking)
    
    const UdpSocketType = ghostnet.UdpSocket;
    
    // Check that the sendTo method exists with the correct signature
    const sendto_fn = @TypeOf(UdpSocketType.sendTo);
    _ = sendto_fn; // Just check that the method exists
    
    // This test passes if the UDP socket types compile without errors
}