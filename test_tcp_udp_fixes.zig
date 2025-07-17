const std = @import("std");
const testing = std.testing;
const zsync = @import("zsync");
const ghostnet = @import("ghostnet");

test "TCP setTcpNoDelay fix" {
    // Use new zsync BlockingIo interface
    var blocking_io = zsync.BlockingIo.init(testing.allocator);
    defer blocking_io.deinit();
    const io = blocking_io.io();
    
    // Test TCP connection with no_delay option
    const tcp_options = ghostnet.TransportOptions{
        .no_delay = true,
        .keep_alive = false,
        .reuse_address = false,
        .reuse_port = false,
        .send_buffer_size = 8192,
        .receive_buffer_size = 8192,
        .timeout = 5000,
    };
    
    // This should not fail due to setTcpNoDelay method missing
    const result = ghostnet.TcpConnection.connect(testing.allocator, io, ghostnet.Address{ .ipv4 = std.net.Ip4Address.init([4]u8{127, 0, 0, 1}, 80) }, tcp_options);
    
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