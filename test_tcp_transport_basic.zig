const std = @import("std");
const testing = std.testing;
const ghostnet = @import("ghostnet");
const zsync = @import("zsync");
const transport_mod = ghostnet.transport;
const tcp = transport_mod.tcp;

test "TCP transport basic functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Use new zsync BlockingIo interface
    var blocking_io = zsync.BlockingIo.init(allocator, 4096);
    defer blocking_io.deinit();
    const io = blocking_io.io();

    // Test transport creation
    var tcp_transport = try tcp.TcpTransport.init(allocator);
    defer tcp_transport.deinit();

    const transport = tcp_transport.transport();

    // Test bind
    const bind_addr = transport_mod.Address{ .ipv4 = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, 0) };
    const options = transport_mod.TransportOptions{
        .reuse_address = true,
        .reuse_port = false,
        .backlog = 128,
        .send_buffer_size = 8192,
        .receive_buffer_size = 8192,
        .keep_alive = false,
        .no_delay = true,
        .timeout = 5000,
    };

    try transport.bind(bind_addr, options);

    // Test local address
    const local_addr = try transport.local_address();

    switch (local_addr) {
        .ipv4 => |addr| {
            std.debug.print("Bound to IPv4 address: {}\n", .{addr});
            try testing.expect(addr.getPort() > 0);
        },
        else => {
            std.debug.print("Unexpected address type\n");
            try testing.expect(false);
        },
    }

    // Test close
    transport.close();

    std.debug.print("TCP transport basic functionality test passed\n");
}

test "TCP transport error handling" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Use new zsync BlockingIo interface
    var blocking_io = zsync.BlockingIo.init(allocator, 4096);
    defer blocking_io.deinit();
    const io = blocking_io.io();

    var tcp_transport = try tcp.TcpTransport.init(allocator);
    defer tcp_transport.deinit();

    const transport = tcp_transport.transport();

    // Test local_address without bind should fail
    const result = transport.local_address();
    try testing.expectError(error.NotListening, result);

    // Test accept without bind should fail
    const accept_result = transport.accept();
    try testing.expectError(error.NotListening, accept_result);

    std.debug.print("TCP transport error handling test passed\n");
}
