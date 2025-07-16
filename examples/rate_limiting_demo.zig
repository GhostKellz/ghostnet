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
    
    // Create HTTP client
    var client = try ghostnet.HttpClient.init(allocator, &runtime);
    defer client.deinit();
    
    // Configure rate limiting (2 requests per second, burst of 5)
    client.setRateLimit(2.0, 5);
    
    std.log.info("Rate limiting demo: 2 requests/second with burst of 5");
    std.log.info("Making 10 requests to demonstrate rate limiting...");
    
    const start_time = std.time.timestamp();
    
    // Make 10 requests in quick succession
    for (0..10) |i| {
        const request_start = std.time.timestamp();
        
        const url = try std.fmt.allocPrint(allocator, "https://httpbin.org/delay/0?request={d}", .{i + 1});
        defer allocator.free(url);
        
        std.log.info("Starting request {d}...", .{i + 1});
        
        const response = try client.get(url);
        defer response.deinit(allocator);
        
        const request_end = std.time.timestamp();
        const request_duration = request_end - request_start;
        const total_elapsed = request_end - start_time;
        
        std.log.info("Request {d} completed: status={d}, duration={d}s, total_elapsed={d}s", 
            .{ i + 1, response.status_code, request_duration, total_elapsed });
        
        if (i < 4) {
            std.log.info("  (burst allowance - should be fast)");
        } else {
            std.log.info("  (rate limited - should be throttled)");
        }
    }
    
    const total_time = std.time.timestamp() - start_time;
    std.log.info("All requests completed in {d} seconds", .{total_time});
    std.log.info("Expected time with rate limiting: ~5 seconds (first 5 burst, then 1 every 0.5s)");
    
    // Demonstrate different rate limiting scenarios
    std.log.info("\n--- Testing stricter rate limiting ---");
    
    // More restrictive rate limiting (1 request per 2 seconds)
    client.setRateLimit(0.5, 2);
    std.log.info("New rate limit: 0.5 requests/second (1 request every 2 seconds), burst of 2");
    
    const strict_start = std.time.timestamp();
    
    for (0..3) |i| {
        const request_start = std.time.timestamp();
        
        std.log.info("Starting strict rate limited request {d}...", .{i + 1});
        
        const response = try client.get("https://httpbin.org/uuid");
        defer response.deinit(allocator);
        
        const request_end = std.time.timestamp();
        const request_duration = request_end - request_start;
        const total_elapsed = request_end - strict_start;
        
        std.log.info("Strict request {d} completed: duration={d}s, total_elapsed={d}s", 
            .{ i + 1, request_duration, total_elapsed });
    }
    
    const strict_total = std.time.timestamp() - strict_start;
    std.log.info("Strict rate limiting test completed in {d} seconds", .{strict_total});
    std.log.info("Expected time: ~4 seconds (first 2 burst, then wait 2s for third)");
    
    // Demonstrate rate limiting with retry logic
    std.log.info("\n--- Testing rate limiting with retry logic ---");
    
    // Reset to more reasonable rate limiting for retry demo
    client.setRateLimit(5.0, 10);
    
    // Configure aggressive retry policy to show interaction with rate limiting
    const retry_config = ghostnet.RetryConfig{
        .max_attempts = 3,
        .backoff_strategy = .exponential,
        .base_delay_ms = 500,
        .max_delay_ms = 5000,
        .retry_status_codes = &[_]u16{429, 502, 503, 504}, // Include rate limit status
    };
    try client.setRetryConfig(retry_config);
    
    std.log.info("Testing with retry logic (retries on 429, 502, 503, 504)");
    
    // This URL simulates server-side rate limiting
    const rate_limit_url = "https://httpbin.org/status/429"; // Returns 429 Too Many Requests
    
    const retry_start = std.time.timestamp();
    const retry_response = client.get(rate_limit_url) catch |err| {
        std.log.warn("Request failed after retries: {}", .{err});
        return;
    };
    defer retry_response.deinit(allocator);
    
    const retry_end = std.time.timestamp();
    std.log.info("Retry test completed in {d} seconds with status {d}", .{ retry_end - retry_start, retry_response.status_code });
    
    std.log.info("\n✅ Rate limiting demonstration completed!");
    std.log.info("Key takeaways:");
    std.log.info("  - Client-side rate limiting prevents overwhelming servers");
    std.log.info("  - Burst allowance enables brief peaks in activity");
    std.log.info("  - Retry logic can handle server-side rate limiting (429 errors)");
    std.log.info("  - Exponential backoff prevents retry storms");
}