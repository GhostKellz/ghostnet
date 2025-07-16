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
    
    std.log.info("Authentication methods demonstration");
    
    // === Bearer Token Authentication ===
    std.log.info("\n1. Bearer Token Authentication");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Set bearer token (example token)
        try client.setBearerToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example");
        
        std.log.info("Making request with Bearer token...");
        const response = try client.get("https://httpbin.org/bearer");
        defer response.deinit(allocator);
        
        std.log.info("Response status: {d}", .{response.status_code});
        if (response.body) |body| {
            std.log.info("Response indicates token was sent: {s}", .{body[0..@min(200, body.len)]});
        }
    }
    
    // === Basic Authentication ===
    std.log.info("\n2. Basic Authentication");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Set basic auth credentials
        try client.setBasicAuth("testuser", "testpass123");
        
        std.log.info("Making request with Basic auth...");
        const response = try client.get("https://httpbin.org/basic-auth/testuser/testpass123");
        defer response.deinit(allocator);
        
        std.log.info("Response status: {d}", .{response.status_code});
        if (response.isSuccess()) {
            std.log.info("✅ Basic authentication successful");
        } else {
            std.log.info("❌ Basic authentication failed");
        }
    }
    
    // === API Key Authentication ===
    std.log.info("\n3. API Key Authentication");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Set API key in custom header
        try client.setApiKey("X-API-Key", "secret-api-key-12345");
        
        std.log.info("Making request with API key...");
        const response = try client.get("https://httpbin.org/headers");
        defer response.deinit(allocator);
        
        std.log.info("Response status: {d}", .{response.status_code});
        if (response.body) |body| {
            if (std.mem.indexOf(u8, body, "X-API-Key")) |_| {
                std.log.info("✅ API key header was sent");
            } else {
                std.log.info("❌ API key header not found in response");
            }
        }
    }
    
    // === Custom Headers Authentication ===
    std.log.info("\n4. Custom Headers Authentication");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Set multiple custom headers for authentication
        try client.setDefaultHeader("X-Client-ID", "client-123");
        try client.setDefaultHeader("X-Client-Secret", "secret-456");
        try client.setDefaultHeader("X-Request-ID", "req-789");
        
        std.log.info("Making request with custom auth headers...");
        const response = try client.get("https://httpbin.org/headers");
        defer response.deinit(allocator);
        
        std.log.info("Response status: {d}", .{response.status_code});
        if (response.body) |body| {
            const has_client_id = std.mem.indexOf(u8, body, "X-Client-ID") != null;
            const has_client_secret = std.mem.indexOf(u8, body, "X-Client-Secret") != null;
            const has_request_id = std.mem.indexOf(u8, body, "X-Request-ID") != null;
            
            std.log.info("Custom headers sent: client_id={}, client_secret={}, request_id={}", 
                .{ has_client_id, has_client_secret, has_request_id });
        }
    }
    
    // === Per-Request Headers ===
    std.log.info("\n5. Per-Request Authentication");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Create headers for specific request
        var headers = std.StringHashMap([]const u8).init(allocator);
        defer headers.deinit();
        
        try headers.put("Authorization", "Bearer temp-session-token");
        try headers.put("X-Session-ID", "session-abc123");
        try headers.put("X-CSRF-Token", "csrf-token-xyz");
        
        std.log.info("Making request with per-request auth headers...");
        const response = try client.getWithHeaders("https://httpbin.org/headers", headers);
        defer response.deinit(allocator);
        
        std.log.info("Response status: {d}", .{response.status_code});
        if (response.body) |body| {
            const has_bearer = std.mem.indexOf(u8, body, "Bearer temp-session-token") != null;
            const has_session = std.mem.indexOf(u8, body, "X-Session-ID") != null;
            const has_csrf = std.mem.indexOf(u8, body, "X-CSRF-Token") != null;
            
            std.log.info("Per-request headers sent: bearer={}, session={}, csrf={}", 
                .{ has_bearer, has_session, has_csrf });
        }
    }
    
    // === OAuth 2.0 Simulation ===
    std.log.info("\n6. OAuth 2.0 Simulation");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Step 1: Exchange credentials for token (simulated)
        std.log.info("Step 1: Simulating OAuth token exchange...");
        
        const token_request_body = 
            \\{
            \\  "grant_type": "client_credentials",
            \\  "client_id": "my-app-id",
            \\  "client_secret": "my-app-secret",
            \\  "scope": "read write"
            \\}
        ;
        
        // This would normally be to an OAuth provider's token endpoint
        const token_response = try client.postJson("https://httpbin.org/post", token_request_body);
        defer token_response.deinit(allocator);
        
        std.log.info("Token request status: {d}", .{token_response.status_code});
        
        // Step 2: Use the token for API requests (simulated)
        std.log.info("Step 2: Using OAuth token for API request...");
        
        // In real scenario, you'd parse the token from response
        const simulated_access_token = "oauth2-access-token-xyz123";
        try client.setBearerToken(simulated_access_token);
        
        const api_response = try client.get("https://httpbin.org/bearer");
        defer api_response.deinit(allocator);
        
        std.log.info("API request with OAuth token status: {d}", .{api_response.status_code});
        if (api_response.isSuccess()) {
            std.log.info("✅ OAuth simulation successful");
        }
    }
    
    // === Authentication with Timeout and Retry ===
    std.log.info("\n7. Robust Authentication with Retry Logic");
    {
        var client = try ghostnet.HttpClient.init(allocator, &runtime);
        defer client.deinit();
        
        // Configure retry for auth failures
        const retry_config = ghostnet.RetryConfig{
            .max_attempts = 3,
            .backoff_strategy = .exponential,
            .base_delay_ms = 1000,
            .retry_status_codes = &[_]u16{401, 403, 429, 502, 503, 504},
        };
        try client.setRetryConfig(retry_config);
        
        // Set auth with shorter timeout
        try client.setBearerToken("potentially-expired-token");
        client.setDefaultTimeout(5000); // 5 seconds
        
        std.log.info("Testing authentication with retry logic...");
        
        // This endpoint returns 401 to test retry logic
        const auth_response = client.get("https://httpbin.org/status/401") catch |err| {
            std.log.warn("Authentication failed after retries: {}", .{err});
            return;
        };
        defer auth_response.deinit(allocator);
        
        std.log.info("Final auth response status: {d}", .{auth_response.status_code});
    }
    
    std.log.info("\n✅ Authentication demonstration completed!");
    std.log.info("Key authentication methods:");
    std.log.info("  ✓ Bearer tokens (JWT, OAuth)");
    std.log.info("  ✓ Basic authentication (username/password)");
    std.log.info("  ✓ API keys (custom headers)");
    std.log.info("  ✓ Custom authentication headers");
    std.log.info("  ✓ Per-request authentication");
    std.log.info("  ✓ OAuth 2.0 flow simulation");
    std.log.info("  ✓ Robust retry logic for auth failures");
}