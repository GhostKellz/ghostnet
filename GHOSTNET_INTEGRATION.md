# Ghostnet Integration Guide

This guide demonstrates how to integrate **ghostnet v0.2.0** into your project for robust HTTP client functionality with comprehensive networking capabilities. Suitable for AI services, package managers, web scrapers, and any application requiring reliable HTTP communication.

## Overview

Ghostnet v0.2.0 provides a production-ready HTTP client library designed for modern applications, featuring:

- **Unified HttpClient API** with comprehensive authentication support
- **Protocol Negotiation** (HTTP/3, HTTP/2, HTTP/1.1) with smart fallback
- **Connection Pooling** and advanced middleware system
- **Rate Limiting** and retry logic with exponential backoff
- **Streaming Downloads** with progress tracking and resume capability
- **Rich Error Handling** with detailed context and recovery strategies
- **Concurrent Operations** with HTTP/2 multiplexing and batch requests

## Quick Start

### Basic Setup

```zig
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
    
    // Create HTTP client with connection pooling
    const pool_config = ghostnet.PoolConfig{
        .max_connections = 100,
        .max_idle_connections = 20,
        .idle_timeout = 60_000_000_000, // 60 seconds
        .connection_timeout = 30_000_000_000, // 30 seconds
    };
    
    var client = try ghostnet.HttpClient.initWithPool(allocator, &runtime, pool_config);
    defer client.deinit();
    
    // Enable debug logging
    try client.enableDebugLogging();
    
    // Configure retry policy
    const retry_config = ghostnet.RetryConfig{
        .max_attempts = 3,
        .backoff_strategy = .exponential,
        .retry_status_codes = &[_]u16{502, 503, 504, 429},
    };
    try client.setRetryConfig(retry_config);
}
```

## Common Integration Patterns

### Generic HTTP API Client

```zig
pub const ApiClient = struct {
    http_client: *ghostnet.HttpClient,
    base_url: []const u8,
    api_key: ?[]const u8,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, base_url: []const u8, api_key: ?[]const u8) !*ApiClient {
        var client = try allocator.create(ApiClient);
        client.* = .{
            .http_client = try ghostnet.HttpClient.init(allocator, runtime),
            .base_url = try allocator.dupe(u8, base_url),
            .api_key = if (api_key) |key| try allocator.dupe(u8, key) else null,
        };
        
        // Set API key if provided
        if (api_key) |key| {
            try client.http_client.setApiKey("Authorization", try std.fmt.allocPrint(allocator, "Bearer {s}", .{key}));
        }
        
        return client;
    }
    
    pub fn deinit(self: *ApiClient) void {
        self.http_client.deinit();
        self.http_client.allocator.free(self.base_url);
        if (self.api_key) |key| {
            self.http_client.allocator.free(key);
        }
        self.http_client.allocator.destroy(self);
    }
    
    pub fn makeRequest(self: *ApiClient, endpoint: []const u8, method: ghostnet.HttpMethod, body: ?[]const u8) !ghostnet.HttpResponse {
        const url = try std.fmt.allocPrint(self.http_client.allocator, "{s}{s}", .{ self.base_url, endpoint });
        defer self.http_client.allocator.free(url);
        
        return switch (method) {
            .GET => try self.http_client.get(url),
            .POST => if (body) |b| try self.http_client.postJson(url, b) else error.MissingBody,
            .PUT => if (body) |b| try self.http_client.post(url, b, "application/json") else error.MissingBody,
            .DELETE => try self.http_client.get(url), // Would need actual DELETE method
            else => error.UnsupportedMethod,
        };
    }
};
```

## AI Service Integration

### OpenAI Integration

```zig
// Initialize OpenAI client
const openai_api_key = "your-openai-api-key";
var openai = try ghostnet.OpenAIClient.init(allocator, &runtime, openai_api_key);
defer openai.deinit();

// Chat completion
const messages = [_]ghostnet.ChatMessage{
    .{ .role = "user", .content = "Explain async programming in Zig" },
};

const response = try openai.chatCompletion(&messages, "gpt-4");
defer response.deinit(allocator);

if (response.isSuccess()) {
    const response_json = try response.getJson(OpenAIResponse);
    std.debug.print("OpenAI response: {s}\n", .{response_json.choices[0].message.content});
}

// Create embeddings
const embedding_response = try openai.createEmbedding("Hello world", "text-embedding-ada-002");
defer embedding_response.deinit(allocator);
```

### Claude Integration

```zig
// Initialize Claude client
const claude_api_key = "your-claude-api-key";
var claude = try ghostnet.ClaudeClient.init(allocator, &runtime, claude_api_key);
defer claude.deinit();

// Send single message
const claude_response = try claude.sendMessage("Write a function to parse JSON in Zig", "claude-3-5-sonnet-20241022");
defer claude_response.deinit(allocator);

// Send conversation
const conversation = [_]ghostnet.ChatMessage{
    .{ .role = "user", .content = "What is the best way to handle errors in Zig?" },
    .{ .role = "assistant", .content = "Zig uses explicit error handling with error unions..." },
    .{ .role = "user", .content = "Can you show me an example?" },
};

const conv_response = try claude.sendMessages(&conversation, "claude-3-5-sonnet-20241022");
defer conv_response.deinit(allocator);
```

### GitHub Integration

```zig
// Initialize GitHub client
const github_token = "your-github-token";
var github = try ghostnet.GitHubClient.init(allocator, &runtime, github_token);
defer github.deinit();

// Get Copilot token
const copilot_token_response = try github.getCopilotToken();
defer copilot_token_response.deinit(allocator);

// Get user info
const user_response = try github.getUser();
defer user_response.deinit(allocator);

// Get repository info
const repo_response = try github.getRepository("owner", "repo");
defer repo_response.deinit(allocator);
```

## Advanced Features

### Custom Middleware

```zig
// Create custom authentication middleware
const AuthMiddleware = struct {
    api_key: []const u8,
    
    pub fn beforeRequest(self: *@This(), ctx: *ghostnet.middleware.MiddlewareContext) ghostnet.middleware.MiddlewareResult {
        // Add API key to request headers
        ctx.request.setHeader(ctx.allocator, "X-API-Key", self.api_key) catch {
            return .stop_with_error(.MiddlewareFailed);
        };
        return .continue_chain;
    }
    
    pub fn create(api_key: []const u8) ghostnet.Middleware {
        return ghostnet.Middleware{
            .name = "custom-auth",
            .before_request = beforeRequest,
            .after_response = null,
        };
    }
};

// Add custom middleware to client
const auth_middleware = AuthMiddleware.create("my-api-key");
try client.addMiddleware(auth_middleware);
```

### Error Handling

```zig
// Enhanced error handling with context
const response = client.get("https://api.example.com/data") catch |err| {
    const error_builder = ghostnet.http_errors.ErrorBuilder.init(allocator);
    
    switch (err) {
        error.NetworkError => {
            var ctx = try error_builder.networkError("https://api.example.com/data", "GET", "Network unavailable");
            defer ctx.deinit();
            
            std.debug.print("Network error: {}\n", .{ctx});
            return;
        },
        error.RequestTimeout => {
            var ctx = try error_builder.timeoutError("https://api.example.com/data", "GET", 30000);
            defer ctx.deinit();
            
            std.debug.print("Timeout error: {}\n", .{ctx});
            return;
        },
        else => return err,
    }
};

// Check response status
if (response.isClientError()) {
    std.debug.print("Client error: {d}\n", .{response.status_code});
} else if (response.isServerError()) {
    std.debug.print("Server error: {d}\n", .{response.status_code});
}
```

### JSON Handling

```zig
// Type-safe JSON responses
const ApiResponse = struct {
    success: bool,
    data: []const u8,
    timestamp: i64,
};

const response = try client.get("https://api.example.com/data");
defer response.deinit(allocator);

if (response.isSuccess()) {
    const json_data = try response.getJson(ApiResponse);
    std.debug.print("API returned: {s}\n", .{json_data.data});
}

// Send JSON data
const request_data = .{
    .query = "search term",
    .limit = 10,
};

const json_response = try client.postJsonData("https://api.example.com/search", request_data);
defer json_response.deinit(allocator);
```

### HTTP/2 Support

```zig
// HTTP/2 client for multiplexed requests
const tcp_conn = try ghostnet.TcpConnection.connect(allocator, &runtime, address, options);
var http2_client = try ghostnet.Http2Client.init(allocator, &runtime, tcp_conn.stream());
defer http2_client.deinit();

// Send multiple requests simultaneously
const request1 = try ghostnet.HttpRequest.init(allocator, .GET, "/api/v1/users");
const request2 = try ghostnet.HttpRequest.init(allocator, .GET, "/api/v1/posts");

const response1 = try http2_client.sendRequest(&request1);
const response2 = try http2_client.sendRequest(&request2);
```

## Package Manager Integration Patterns

### Repository Client

```zig
pub const RepositoryClient = struct {
    http_client: *ghostnet.HttpClient,
    base_url: []const u8,
    rate_limiter: ?ghostnet.RateLimiter,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, base_url: []const u8, rate_limit_rps: ?f64) !*RepositoryClient {
        var client = try allocator.create(RepositoryClient);
        client.* = .{
            .http_client = try ghostnet.HttpClient.init(allocator, runtime),
            .base_url = try allocator.dupe(u8, base_url),
            .rate_limiter = if (rate_limit_rps) |rps| ghostnet.RateLimiter.init(rps, 20) else null,
        };
        
        if (rate_limit_rps) |rps| {
            client.http_client.setRateLimit(rps, 20);
        }
        
        return client;
    }
    
    pub fn deinit(self: *RepositoryClient) void {
        self.http_client.deinit();
        self.http_client.allocator.free(self.base_url);
        self.http_client.allocator.destroy(self);
    }
    
    pub fn downloadPackage(self: *RepositoryClient, package_path: []const u8, dest_path: []const u8, progress_callback: ?*const fn (u64, u64) void) !void {
        const url = try std.fmt.allocPrint(self.http_client.allocator, "{s}/{s}", .{ self.base_url, package_path });
        defer self.http_client.allocator.free(url);
        
        const options = ghostnet.HttpClient.DownloadOptions{
            .progress_callback = progress_callback,
            .chunk_size = 32768,
            .resume_partial = true,
        };
        
        try self.http_client.downloadStream(url, dest_path, options);
    }
    
    pub fn batchGetMetadata(self: *RepositoryClient, package_names: []const []const u8) ![]ghostnet.HttpResponse {
        var urls = try self.http_client.allocator.alloc([]const u8, package_names.len);
        defer {
            for (urls) |url| {
                self.http_client.allocator.free(url);
            }
            self.http_client.allocator.free(urls);
        }
        
        for (package_names, 0..) |name, i| {
            urls[i] = try std.fmt.allocPrint(self.http_client.allocator, "{s}/api/packages/{s}", .{ self.base_url, name });
        }
        
        return try self.http_client.batchGet(urls);
    }
};
```

### Web Scraper Pattern

```zig
pub const WebScraper = struct {
    http_client: *ghostnet.HttpClient,
    user_agents: []const []const u8,
    current_ua_index: usize,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) !*WebScraper {
        const user_agents = [_][]const u8{
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        };
        
        var client = try allocator.create(WebScraper);
        client.* = .{
            .http_client = try ghostnet.HttpClient.init(allocator, runtime),
            .user_agents = &user_agents,
            .current_ua_index = 0,
        };
        
        // Configure for web scraping
        try client.http_client.setDefaultTimeout(30000);
        client.http_client.setRateLimit(2.0, 5); // Gentle rate limiting
        
        return client;
    }
    
    pub fn deinit(self: *WebScraper) void {
        self.http_client.deinit();
        self.http_client.allocator.destroy(self);
    }
    
    pub fn scrapeUrl(self: *WebScraper, url: []const u8) !ghostnet.HttpResponse {
        // Rotate user agents
        try self.http_client.setDefaultHeader("User-Agent", self.user_agents[self.current_ua_index]);
        self.current_ua_index = (self.current_ua_index + 1) % self.user_agents.len;
        
        // Add common headers
        try self.http_client.setDefaultHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        try self.http_client.setDefaultHeader("Accept-Language", "en-US,en;q=0.5");
        try self.http_client.setDefaultHeader("Accept-Encoding", "gzip, deflate, br");
        try self.http_client.setDefaultHeader("DNT", "1");
        
        return try self.http_client.get(url);
    }
};
```

## Configuration

### Environment Variables

```zig
// Load configuration from environment
const AIConfig = struct {
    openai_key: []const u8,
    claude_key: []const u8,
    github_token: []const u8,
    
    pub fn fromEnv(allocator: std.mem.Allocator) !AIConfig {
        return AIConfig{
            .openai_key = std.os.getenv("OPENAI_API_KEY") orelse return error.MissingOpenAIKey,
            .claude_key = std.os.getenv("CLAUDE_API_KEY") orelse return error.MissingClaudeKey,
            .github_token = std.os.getenv("GITHUB_TOKEN") orelse return error.MissingGitHubToken,
        };
    }
};
```

### Build Configuration

```zig
// In your build.zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    
    // Add ghostnet dependency
    const ghostnet_dep = b.dependency("ghostnet", .{
        .target = target,
        .optimize = optimize,
    });
    
    const exe = b.addExecutable(.{
        .name = "zeke",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    exe.root_module.addImport("ghostnet", ghostnet_dep.module("ghostnet"));
    
    b.installArtifact(exe);
}
```

## Performance Optimization

### Connection Pooling

```zig
// Optimize for AI service usage
const ai_pool_config = ghostnet.PoolConfig{
    .max_connections = 50,
    .max_idle_connections = 10,
    .idle_timeout = 30_000_000_000, // 30 seconds
    .connection_timeout = 15_000_000_000, // 15 seconds
    .enable_health_checks = true,
    .health_check_interval = 10_000_000_000, // 10 seconds
};

var client = try ghostnet.HttpClient.initWithPool(allocator, &runtime, ai_pool_config);
```

### Concurrent Requests

```zig
// Handle multiple AI requests concurrently
pub fn processMultiplePrompts(zeke: *ZekeAI, prompts: []const []const u8) !void {
    var futures = std.ArrayList(zsync.Future(ghostnet.HttpResponse)).init(zeke.allocator);
    defer futures.deinit();
    
    // Start all requests
    for (prompts) |prompt| {
        const future = zsync.spawn(zeke.openai.chatCompletion, .{
            &[_]ghostnet.ChatMessage{.{ .role = "user", .content = prompt }},
            "gpt-4"
        });
        try futures.append(future);
    }
    
    // Wait for all responses
    for (futures.items) |future| {
        const response = try future.await();
        defer response.deinit(zeke.allocator);
        
        std.debug.print("Response: {s}\\n", .{response.body orelse "No response"});
    }
}
```

## Error Recovery

### Fallback Strategies

```zig
pub fn robustGenerate(zeke: *ZekeAI, prompt: []const u8) ![]const u8 {
    // Try OpenAI first
    if (zeke.openai.chatCompletion(&[_]ghostnet.ChatMessage{
        .{ .role = "user", .content = prompt }
    }, "gpt-4")) |response| {
        return response;
    } else |openai_err| {
        std.debug.print("OpenAI failed: {}, trying Claude\\n", .{openai_err});
        
        // Fallback to Claude
        if (zeke.claude.sendMessage(prompt, "claude-3-5-sonnet-20241022")) |response| {
            return response;
        } else |claude_err| {
            std.debug.print("Claude failed: {}, trying fallback\\n", .{claude_err});
            
            // Final fallback - return error message
            const error_msg = try std.fmt.allocPrint(zeke.allocator, 
                "All AI services failed. OpenAI: {}, Claude: {}", 
                .{openai_err, claude_err});
            return error_msg;
        }
    }
}
```

## Best Practices

1. **Always use connection pooling** for AI services to reduce latency
2. **Implement retry logic** for transient failures
3. **Use structured error handling** with context
4. **Enable debug logging** during development
5. **Set appropriate timeouts** for AI API calls
6. **Use HTTP/2 when possible** for better performance
7. **Implement graceful degradation** with fallback services

## gRPC Support Addition

Since you mentioned crypto projects use gRPC extensively, here's how to add gRPC support:

```zig
// Add to your build.zig dependencies
const grpc_dep = b.dependency("grpc-zig", .{
    .target = target,
    .optimize = optimize,
});

// gRPC client usage
const grpc_client = try ghostnet.GrpcClient.init(allocator, &runtime, "api.example.com:443");
defer grpc_client.deinit();

// Set up TLS for secure gRPC
try grpc_client.setTLSConfig(.{
    .verify_certificates = true,
    .client_cert_path = "client.crt",
    .client_key_path = "client.key",
});

// Make gRPC call
const grpc_response = try grpc_client.call("crypto.API", "GetPrice", request_data);
defer grpc_response.deinit();
```

This integration guide provides everything you need to build a robust AI-powered tool like Zeke using ghostnet's enhanced HTTP client capabilities.