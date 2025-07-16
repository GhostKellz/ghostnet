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
    
    // Configure connection pool for high-performance usage
    const pool_config = ghostnet.PoolConfig{
        .max_connections = 100,
        .max_idle_connections = 20,
        .idle_timeout = 60_000_000_000, // 60 seconds
        .connection_timeout = 30_000_000_000, // 30 seconds
    };
    
    // Create HTTP client with connection pooling
    var client = try ghostnet.HttpClient.initWithPool(allocator, &runtime, pool_config);
    defer client.deinit();
    
    // Enable debug logging to see pool usage
    try client.enableDebugLogging();
    
    // Configure retry policy
    const retry_config = ghostnet.RetryConfig{
        .max_attempts = 3,
        .backoff_strategy = .exponential,
        .retry_status_codes = &[_]u16{502, 503, 504, 429},
    };
    try client.setRetryConfig(retry_config);
    
    std.log.info("Making concurrent requests to demonstrate connection pooling...");
    
    // Make multiple concurrent requests to the same host
    var futures = std.ArrayList(zsync.Future(ghostnet.HttpResponse)).init(allocator);
    defer futures.deinit();
    
    const urls = [_][]const u8{
        "https://httpbin.org/delay/1",
        "https://httpbin.org/delay/2", 
        "https://httpbin.org/uuid",
        "https://httpbin.org/ip",
        "https://httpbin.org/user-agent",
        "https://httpbin.org/headers",
    };
    
    // Start all requests concurrently
    for (urls) |url| {
        const future = zsync.spawn(client.get, .{url});
        try futures.append(future);
    }
    
    // Wait for all responses
    for (futures.items, 0..) |future, i| {
        const response = try future.await();
        defer response.deinit(allocator);
        
        std.log.info("Request {d} completed with status: {d}", .{ i + 1, response.status_code });
        
        if (response.isSuccess()) {
            std.log.info("  ✅ Success");
        } else {
            std.log.info("  ❌ Failed");
        }
    }
    
    std.log.info("All requests completed. Connection pool was reused for efficiency.");
    
    // Demonstrate batch operations
    std.log.info("Testing batch GET operations...");
    
    const batch_urls = [_][]const u8{
        "https://httpbin.org/status/200",
        "https://httpbin.org/status/201",
        "https://httpbin.org/status/202",
    };
    
    const batch_responses = try client.batchGet(&batch_urls);
    defer {
        for (batch_responses) |*response| {
            response.deinit(allocator);
        }
        allocator.free(batch_responses);
    }
    
    for (batch_responses, 0..) |response, i| {
        std.log.info("Batch request {d}: status {d}", .{ i + 1, response.status_code });
    }
}