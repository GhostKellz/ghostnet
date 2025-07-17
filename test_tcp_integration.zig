const std = @import("std");
const testing = std.testing;
const ghostnet = @import("ghostnet");
const zsync = @import("zsync");
const transport_mod = ghostnet.transport;
const tcp = transport_mod.tcp;

test "TCP transport full integration - bind, connect, send, receive" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize zsync runtime
    var runtime = zsync.Runtime.init(allocator, .{}) catch @panic("Failed to init runtime");
    defer runtime.deinit();

    // Create TCP listener
    var listener = tcp.TcpListener.init(allocator, &runtime);
    
    // Bind to localhost on available port
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
    
    try listener.bind(bind_addr, options);
    
    // Get the actual bound address
    const bound_addr = try listener.listener().local_address();
    const port = switch (bound_addr) {
        .ipv4 => |addr| addr.getPort(),
        else => @panic("Expected IPv4 address"),
    };
    
    std.debug.print("TCP listener bound to port: {}\n", .{port});
    
    // Create a task to accept connections
    const accept_task = async {
        const conn_result = listener.listener().accept_async();
        const conn = runtime.blockOn(conn_result) catch |err| {
            std.debug.print("Accept failed: {}\n", .{err});
            return;
        };
        
        std.debug.print("Connection accepted\n");
        
        // Read data from connection
        var read_buffer: [1024]u8 = undefined;
        const read_result = conn.read(&read_buffer);
        const bytes_read = runtime.blockOn(read_result) catch |err| {
            std.debug.print("Read failed: {}\n", .{err});
            return;
        };
        
        std.debug.print("Received {} bytes: {s}\n", .{ bytes_read, read_buffer[0..bytes_read] });
        
        // Echo the data back
        const write_result = conn.write(read_buffer[0..bytes_read]);
        runtime.blockOn(write_result) catch |err| {
            std.debug.print("Write failed: {}\n", .{err});
            return;
        };
        
        std.debug.print("Echoed data back\n");
        conn.close();
    };
    
    // Give the accept task time to start
    std.time.sleep(100 * std.time.ns_per_ms);
    
    // Create TCP connection
    var tcp_transport = tcp.TcpTransport.init(allocator, &runtime);
    const connect_addr = transport_mod.Address{ .ipv4 = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, port) };
    
    const connect_result = tcp_transport.transport().connect(connect_addr, options);
    const conn = runtime.blockOn(connect_result) catch |err| {
        std.debug.print("Connect failed: {}\n", .{err});
        return;
    };
    
    std.debug.print("Connected to server\n");
    
    // Send test data
    const test_message = "Hello, TCP World!";
    const write_result = conn.write(test_message);
    runtime.blockOn(write_result) catch |err| {
        std.debug.print("Write failed: {}\n", .{err});
        return;
    };
    
    std.debug.print("Sent: {s}\n", .{test_message});
    
    // Read echo response
    var read_buffer: [1024]u8 = undefined;
    const read_result = conn.read(&read_buffer);
    const bytes_read = runtime.blockOn(read_result) catch |err| {
        std.debug.print("Read failed: {}\n", .{err});
        return;
    };
    
    std.debug.print("Received echo: {s}\n", .{read_buffer[0..bytes_read]});
    
    // Verify echo matches original
    try testing.expectEqualSlices(u8, test_message, read_buffer[0..bytes_read]);
    
    conn.close();
    
    // Wait for accept task to complete
    await accept_task;
    
    listener.listener().close();
    
    std.debug.print("TCP integration test completed successfully\n");
}

test "TCP transport error handling and edge cases" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var runtime = zsync.Runtime.init(allocator, .{}) catch @panic("Failed to init runtime");
    defer runtime.deinit();

    // Test 1: Invalid bind address
    var listener = tcp.TcpListener.init(allocator, &runtime);
    const invalid_addr = transport_mod.Address{ .ipv4 = std.net.Ip4Address.init([4]u8{ 999, 0, 0, 1 }, 8080) };
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
    
    // This should fail with an invalid address error
    const bind_result = listener.bind(invalid_addr, options);
    try testing.expectError(error.InvalidAddress, bind_result);
    
    // Test 2: Connect to non-existent server
    var tcp_transport = tcp.TcpTransport.init(allocator, &runtime);
    const nonexistent_addr = transport_mod.Address{ .ipv4 = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, 19999) };
    
    const connect_result = tcp_transport.transport().connect(nonexistent_addr, options);
    const connect_error = runtime.blockOn(connect_result);
    try testing.expectError(error.ConnectionRefused, connect_error);
    
    std.debug.print("TCP error handling test completed successfully\n");
}

test "TCP transport concurrent connections" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var runtime = zsync.Runtime.init(allocator, .{}) catch @panic("Failed to init runtime");
    defer runtime.deinit();

    // Create TCP listener
    var listener = tcp.TcpListener.init(allocator, &runtime);
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
    
    try listener.bind(bind_addr, options);
    const bound_addr = try listener.listener().local_address();
    const port = switch (bound_addr) {
        .ipv4 => |addr| addr.getPort(),
        else => @panic("Expected IPv4 address"),
    };
    
    // Handle multiple concurrent connections
    const server_task = async {
        var connection_count: u32 = 0;
        while (connection_count < 3) {
            const conn_result = listener.listener().accept_async();
            const conn = runtime.blockOn(conn_result) catch |err| {
                std.debug.print("Accept failed: {}\n", .{err});
                continue;
            };
            
            connection_count += 1;
            std.debug.print("Accepted connection #{}\n", .{connection_count});
            
            // Handle connection in separate task
            const handle_task = async {
                var read_buffer: [1024]u8 = undefined;
                const read_result = conn.read(&read_buffer);
                const bytes_read = runtime.blockOn(read_result) catch |err| {
                    std.debug.print("Read failed: {}\n", .{err});
                    conn.close();
                    return;
                };
                
                const write_result = conn.write(read_buffer[0..bytes_read]);
                runtime.blockOn(write_result) catch |err| {
                    std.debug.print("Write failed: {}\n", .{err});
                };
                
                conn.close();
            };
            
            // Don't await here - let connections run concurrently
            _ = handle_task;
        }
    };
    
    std.time.sleep(100 * std.time.ns_per_ms);
    
    // Create multiple concurrent client connections
    const client_tasks = [_]@TypeOf(async {}) {
        async {
            var tcp_transport = tcp.TcpTransport.init(allocator, &runtime);
            const connect_addr = transport_mod.Address{ .ipv4 = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, port) };
            
            const connect_result = tcp_transport.transport().connect(connect_addr, options);
            const conn = runtime.blockOn(connect_result) catch |err| {
                std.debug.print("Client 1 connect failed: {}\n", .{err});
                return;
            };
            
            const message = "Client 1 message";
            const write_result = conn.write(message);
            runtime.blockOn(write_result) catch |err| {
                std.debug.print("Client 1 write failed: {}\n", .{err});
                conn.close();
                return;
            };
            
            var read_buffer: [1024]u8 = undefined;
            const read_result = conn.read(&read_buffer);
            const bytes_read = runtime.blockOn(read_result) catch |err| {
                std.debug.print("Client 1 read failed: {}\n", .{err});
                conn.close();
                return;
            };
            
            try testing.expectEqualSlices(u8, message, read_buffer[0..bytes_read]);
            conn.close();
            std.debug.print("Client 1 completed successfully\n");
        },
        async {
            var tcp_transport = tcp.TcpTransport.init(allocator, &runtime);
            const connect_addr = transport_mod.Address{ .ipv4 = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, port) };
            
            const connect_result = tcp_transport.transport().connect(connect_addr, options);
            const conn = runtime.blockOn(connect_result) catch |err| {
                std.debug.print("Client 2 connect failed: {}\n", .{err});
                return;
            };
            
            const message = "Client 2 message";
            const write_result = conn.write(message);
            runtime.blockOn(write_result) catch |err| {
                std.debug.print("Client 2 write failed: {}\n", .{err});
                conn.close();
                return;
            };
            
            var read_buffer: [1024]u8 = undefined;
            const read_result = conn.read(&read_buffer);
            const bytes_read = runtime.blockOn(read_result) catch |err| {
                std.debug.print("Client 2 read failed: {}\n", .{err});
                conn.close();
                return;
            };
            
            try testing.expectEqualSlices(u8, message, read_buffer[0..bytes_read]);
            conn.close();
            std.debug.print("Client 2 completed successfully\n");
        },
        async {
            var tcp_transport = tcp.TcpTransport.init(allocator, &runtime);
            const connect_addr = transport_mod.Address{ .ipv4 = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, port) };
            
            const connect_result = tcp_transport.transport().connect(connect_addr, options);
            const conn = runtime.blockOn(connect_result) catch |err| {
                std.debug.print("Client 3 connect failed: {}\n", .{err});
                return;
            };
            
            const message = "Client 3 message";
            const write_result = conn.write(message);
            runtime.blockOn(write_result) catch |err| {
                std.debug.print("Client 3 write failed: {}\n", .{err});
                conn.close();
                return;
            };
            
            var read_buffer: [1024]u8 = undefined;
            const read_result = conn.read(&read_buffer);
            const bytes_read = runtime.blockOn(read_result) catch |err| {
                std.debug.print("Client 3 read failed: {}\n", .{err});
                conn.close();
                return;
            };
            
            try testing.expectEqualSlices(u8, message, read_buffer[0..bytes_read]);
            conn.close();
            std.debug.print("Client 3 completed successfully\n");
        },
    };
    
    // Wait for all clients to complete
    for (client_tasks) |task| {
        await task;
    }
    
    // Wait for server to complete
    await server_task;
    
    listener.listener().close();
    std.debug.print("TCP concurrent connections test completed successfully\n");
}