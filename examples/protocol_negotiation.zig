const std = @import("std");
const ghostnet = @import("ghostnet");
const zsync = @import("zsync");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize async runtime
    var runtime = try zsync.Runtime.init(allocator);
    defer runtime.deinit();
    
    std.log.info("Protocol Negotiation Demonstration");
    std.log.info("Testing HTTP/3 → HTTP/2 → HTTP/1.1 fallback chain");
    
    // === Default Protocol Preference (HTTP/3 first) ===
    std.log.info("\n1. Default Protocol Preference (HTTP/3 → HTTP/2 → HTTP/1.1)");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Enable debug logging to see protocol selection
        try client.enableDebugLogging();
        
        std.log.info("Making request with default protocol preference...");
        const response = try client.get("https://www.cloudflare.com/"); // Known to support HTTP/3
        defer response.deinit(allocator);
        
        std.log.info("Response status: {d}", .{response.status_code});
        std.log.info("Protocol used: {s}", .{response.version.toString()});
    }
    
    // === Force HTTP/2 Only ===
    std.log.info("\n2. Force HTTP/2 Only");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Set protocol preference to HTTP/2 only
        try client.setProtocolPreference(&.{.http2});
        
        std.log.info("Making request with HTTP/2 only preference...");
        const response = try client.get("https://http2.github.io/"); // Known HTTP/2 endpoint
        defer response.deinit(allocator);
        
        std.log.info("Response status: {d}", .{response.status_code});
        std.log.info("Protocol used: {s}", .{response.version.toString()});
        
        if (response.version == .http_2_0) {
            std.log.info("✅ Successfully used HTTP/2");
        } else {
            std.log.info("⚠️  Expected HTTP/2 but got {s}", .{response.version.toString()});
        }
    }
    
    // === Force HTTP/1.1 (Legacy) ===
    std.log.info("\n3. Force HTTP/1.1 (Legacy Mode)");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Set protocol preference to HTTP/1.1 only
        try client.setProtocolPreference(&.{.http1_1});
        
        std.log.info("Making request with HTTP/1.1 only preference...");
        const response = try client.get("https://httpbin.org/get");
        defer response.deinit(allocator);
        
        std.log.info("Response status: {d}", .{response.status_code});
        std.log.info("Protocol used: {s}", .{response.version.toString()});
        
        if (response.version == .http_1_1) {
            std.log.info("✅ Successfully used HTTP/1.1");
        } else {
            std.log.info("⚠️  Expected HTTP/1.1 but got {s}", .{response.version.toString()});
        }
    }
    
    // === Custom Fallback Chain ===
    std.log.info("\n4. Custom Fallback Chain (HTTP/2 → HTTP/1.1)");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Custom preference: skip HTTP/3, prefer HTTP/2, fallback to HTTP/1.1
        try client.setProtocolPreference(&.{ .http2, .http1_1 });
        
        std.log.info("Making request with custom fallback chain...");
        const response = try client.get("https://httpbin.org/get");
        defer response.deinit(allocator);
        
        std.log.info("Response status: {d}", .{response.status_code});
        std.log.info("Protocol used: {s}", .{response.version.toString()});
        
        if (response.version == .http_2_0 or response.version == .http_1_1) {
            std.log.info("✅ Used expected protocol from custom chain");
        } else {
            std.log.info("⚠️  Unexpected protocol: {s}", .{response.version.toString()});
        }
    }
    
    // === Protocol Caching Demonstration ===
    std.log.info("\n5. Protocol Caching (Multiple Requests to Same Host)");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        const host = "httpbin.org";
        
        std.log.info("Making multiple requests to {s} to demonstrate protocol caching...", .{host});
        
        for (1..4) |i| {
            const url = try std.fmt.allocPrint(allocator, "https://{s}/uuid?request={d}", .{ host, i });
            defer allocator.free(url);
            
            const start_time = std.time.timestamp();
            const response = try client.get(url);
            defer response.deinit(allocator);
            const end_time = std.time.timestamp();
            
            std.log.info("Request {d}: protocol={s}, time={d}ms, status={d}", 
                .{ i, response.version.toString(), (end_time - start_time) * 1000, response.status_code });
            
            if (i == 1) {
                std.log.info("  (first request - protocol negotiation)");
            } else {
                std.log.info("  (cached protocol - should be faster)");
            }
        }
    }
    
    // === HTTP/2 Multiplexing Demo ===
    std.log.info("\n6. HTTP/2 Multiplexing Demo");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Force HTTP/2 for multiplexing
        try client.setProtocolPreference(&.{.http2});
        
        std.log.info("Testing HTTP/2 multiplexing with concurrent requests...");
        
        var futures = std.ArrayList(zsync.Future(ghostnet.HttpResponse)).init(allocator);
        defer futures.deinit();
        
        const urls = [_][]const u8{
            "https://httpbin.org/delay/1",
            "https://httpbin.org/delay/1", 
            "https://httpbin.org/delay/1",
            "https://httpbin.org/delay/1",
        };
        
        const multiplex_start = std.time.timestamp();
        
        // Start all requests concurrently (should multiplex over single HTTP/2 connection)
        for (urls, 0..) |url, i| {
            std.log.info("Starting multiplexed request {d}...", .{i + 1});
            const future = zsync.spawn(client.get, .{url});
            try futures.append(future);
        }
        
        // Wait for all responses
        for (futures.items, 0..) |future, i| {
            const response = try future.await();
            defer response.deinit(allocator);
            
            std.log.info("Multiplexed request {d} completed: protocol={s}, status={d}", 
                .{ i + 1, response.version.toString(), response.status_code });
        }
        
        const multiplex_end = std.time.timestamp();
        const total_time = multiplex_end - multiplex_start;
        
        std.log.info("All 4 requests completed in {d} seconds", .{total_time});
        std.log.info("Expected: ~1 second (multiplexed) vs ~4 seconds (serial)");
        
        if (total_time < 3) {
            std.log.info("✅ HTTP/2 multiplexing working effectively");
        } else {
            std.log.info("⚠️  Multiplexing may not be working as expected");
        }
    }
    
    // === Protocol Specific Features ===
    std.log.info("\n7. Protocol-Specific Features");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Test server push simulation (HTTP/2)
        try client.setProtocolPreference(&.{.http2});
        
        std.log.info("Testing HTTP/2 specific features...");
        
        // Enable compression (more effective with HTTP/2)
        try client.enableCompression(true);
        
        const response = try client.get("https://httpbin.org/gzip");
        defer response.deinit(allocator);
        
        std.log.info("Compressed response: protocol={s}, status={d}", 
            .{ response.version.toString(), response.status_code });
        
        if (response.getHeader("Content-Encoding")) |encoding| {
            std.log.info("Content-Encoding: {s}", .{encoding});
        }
        
        if (response.body) |body| {
            std.log.info("Response body size: {d} bytes", .{body.len});
        }
    }
    
    // === Error Handling and Fallback ===
    std.log.info("\n8. Error Handling and Protocol Fallback");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Configure protocol fallback on errors
        const protocol_config = ghostnet.ProtocolConfig{
            .preference_order = &.{ .http3, .http2, .http1_1 },
            .fallback_on_error = true,
            .max_retries_per_protocol = 2,
            .connection_timeout = 5000, // 5 seconds
        };
        
        // This would be set internally, shown for demonstration
        std.log.info("Protocol config: fallback_on_error={}, max_retries_per_protocol={d}", 
            .{ protocol_config.fallback_on_error, protocol_config.max_retries_per_protocol });
        
        std.log.info("Testing protocol fallback on connection issues...");
        
        // Try connecting to a potentially problematic endpoint
        const response = client.get("https://httpbin.org/status/200") catch |err| {
            std.log.warn("Request failed even with fallback: {}", .{err});
            return;
        };
        defer response.deinit(allocator);
        
        std.log.info("Final response: protocol={s}, status={d}", 
            .{ response.version.toString(), response.status_code });
    }
    
    std.log.info("\n✅ Protocol negotiation demonstration completed!");
    std.log.info("Key protocol features:");
    std.log.info("  ✓ HTTP/3 (QUIC) - fastest, most secure");
    std.log.info("  ✓ HTTP/2 - multiplexing, server push, compression");
    std.log.info("  ✓ HTTP/1.1 - universal compatibility");
    std.log.info("  ✓ Smart fallback chain");
    std.log.info("  ✓ Protocol caching for performance");
    std.log.info("  ✓ Automatic error recovery");
}