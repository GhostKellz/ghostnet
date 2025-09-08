# GhostNet v0.5.2 API Reference

## Overview

GhostNet is a production-ready, async-native networking framework for Zig, built on zsync and providing comprehensive networking capabilities including HTTP, gRPC, QUIC, WebSockets, WireGuard, and more.

## Core Components

### Transport Layer

```zig
const ghostnet = @import("ghostnet");

// TCP Transport
var tcp_transport = try ghostnet.TcpTransport.init(allocator, runtime);
defer tcp_transport.deinit();

// TCP Listener
var listener = try ghostnet.TcpListener.bind(address, port);
defer listener.deinit();

// TCP Connection
var connection = try listener.accept();
defer connection.close();

// UDP Socket
var udp_socket = try ghostnet.UdpSocket.bind(address, port);
defer udp_socket.close();
```

### HTTP Client

```zig
// Basic HTTP Client
var client = try ghostnet.HttpClient.init(allocator, runtime);
defer client.deinit();

const response = try client.get("https://api.example.com/data");
defer response.deinit();

// With middleware
var middleware_chain = ghostnet.MiddlewareChain.init(allocator);
try middleware_chain.add(ghostnet.middleware.logging());
try middleware_chain.add(ghostnet.middleware.retry(.{ .max_attempts = 3 }));

client.setMiddleware(middleware_chain);
```

### HTTP/2 Client

```zig
var http2_client = try ghostnet.Http2Client.init(allocator, runtime);
defer http2_client.deinit();

const response = try http2_client.request(.{
    .method = .GET,
    .url = "https://example.com/api",
    .headers = headers,
});
```

### gRPC Client

```zig
var grpc_client = try ghostnet.GrpcClient.init(allocator, runtime, "https://api.example.com");
defer grpc_client.deinit();

// Unary call
var context = ghostnet.CallContext.init(allocator, "service.Method");
defer context.deinit();

const response = try grpc_client.unaryCall(&context, request_data);
defer response.deinit();

// Streaming calls
const client_stream = try grpc_client.clientStreamingCall(&context);
try client_stream.sendMessage(data1);
try client_stream.sendMessage(data2);
const response = try client_stream.finishAndReceive();

const server_stream = try grpc_client.serverStreamingCall(&context, request_data);
while (try server_stream.receiveMessage()) |message| {
    // Process streaming response
    defer message.deinit();
}

const bidi_stream = try grpc_client.bidirectionalStreamingCall(&context);
try bidi_stream.sendMessage(data);
const response = try bidi_stream.receiveMessage();
try bidi_stream.close();
```

### QUIC Transport

```zig
var quic_client = try ghostnet.QuicClient.init(allocator, runtime);
defer quic_client.deinit();

const connection = try quic_client.connect("quic.example.com", 443);
defer connection.close();

const stream = try connection.openStream();
defer stream.close();

try stream.write(data);
const response = try stream.read();
```

### WireGuard VPN

```zig
var config = ghostnet.WireGuardConfig{
    .private_key = private_key,
    .peers = &[_]ghostnet.Peer{.{
        .public_key = peer_public_key,
        .endpoint = "vpn.example.com:51820",
        .allowed_ips = &[_][]const u8{"0.0.0.0/0"},
    }},
};

var tunnel = try ghostnet.WireGuardTunnel.create(allocator, config);
defer tunnel.destroy();

try tunnel.start();
defer tunnel.stop();
```

### WebSockets

```zig
var ws_client = try ghostnet.WebSocketClient.connect("wss://api.example.com/ws");
defer ws_client.close();

try ws_client.sendText("Hello, WebSocket!");

while (try ws_client.receive()) |message| {
    switch (message.type) {
        .text => std.debug.print("Received: {s}\n", .{message.data}),
        .binary => std.debug.print("Received binary data\n", .{}),
        .close => break,
    }
}
```

## Error Handling

```zig
// Using Result type for explicit error handling
const result: ghostnet.Result([]u8, ghostnet.GhostnetError) = client.get(url);
if (result.isOk()) {
    const data = result.unwrapOr(&[_]u8{});
    // Process data
} else {
    const error_ctx = result.unwrapErr();
    std.log.err("Request failed: {s}", .{error_ctx.message});
}

// Error context provides detailed information
const ctx = ghostnet.ErrorContext{
    .component = "http_client",
    .operation = "GET /api/data",
    .message = "Connection timeout",
    .details = details_map,
};
```

## Logging System

```zig
// Initialize logger
var logger = ghostnet.Logger.init(allocator, .info, std.io.getStdErr());
ghostnet.logging.setGlobalLogger(&logger);

// Use contextual logging
const log_context = ghostnet.LogContext{
    .component = "http_client",
    .operation = "request",
    .connection_id = "conn_123",
    .request_id = "req_456",
};

logger.info(log_context, "Starting HTTP request to {s}", .{url});
logger.warn(log_context, "Retry attempt {d}/{d}", .{ attempt, max_attempts });
logger.err(log_context, "Request failed: {}", .{error});

// Performance monitoring
var timer = ghostnet.PerformanceTimer.start(log_context, "http_request");
// ... perform operation
timer.end(); // Automatically logs duration
```

## Input Validation

```zig
// Initialize validator
const config = ghostnet.ValidationConfig{
    .max_payload_size = 10 * 1024 * 1024, // 10MB
    .enforce_https = true,
    .allow_private_ips = false,
};
var validator = ghostnet.Validator.init(config);
ghostnet.validation.setGlobalValidator(&validator);

// Validate inputs
try validator.validateUrl("https://example.com/api");
try validator.validatePort(443);
try validator.validateIPv4("192.168.1.1");
try validator.validateHostname("api.example.com");
try validator.validateHeaderName("Authorization");
try validator.validateHeaderValue("Bearer token123");
try validator.validateHttpMethod("POST");
try validator.validatePayloadSize(1024);

// Sanitize strings
const sanitized = try validator.sanitizeString(allocator, user_input);
defer allocator.free(sanitized);
```

## Connection Pooling

```zig
const pool_config = ghostnet.PoolConfig{
    .max_connections = 100,
    .max_idle_connections = 10,
    .idle_timeout = 300_000, // 5 minutes
};

var pool = try ghostnet.ConnectionPool.init(allocator, pool_config);
defer pool.deinit();

const connection = try pool.getConnection("https://api.example.com");
defer pool.releaseConnection(connection);
```

## Async Patterns

```zig
// All operations are async-native using zsync
const ghostnet = @import("ghostnet");

pub fn main() !void {
    var runtime = try ghostnet.zsync.Runtime.init(allocator);
    defer runtime.deinit();

    // Spawn concurrent tasks
    const task1 = runtime.spawn(fetchData, .{"https://api1.example.com"});
    const task2 = runtime.spawn(fetchData, .{"https://api2.example.com"});
    
    const result1 = try task1.await();
    const result2 = try task2.await();
    
    // Process results
}

fn fetchData(url: []const u8) ![]u8 {
    var client = try ghostnet.HttpClient.init(allocator, runtime);
    defer client.deinit();
    
    const response = try client.get(url);
    return response.body;
}
```

## Security Features

GhostNet includes comprehensive security features:

- **Input Validation**: All network inputs are validated and sanitized
- **TLS/SSL**: Full TLS 1.3 support with modern cipher suites  
- **WireGuard**: Complete WireGuard VPN implementation
- **Authentication**: Built-in support for various auth methods
- **Rate Limiting**: Configurable rate limiting and throttling
- **HTTPS Enforcement**: Optional HTTPS-only mode
- **Private IP Filtering**: Configurable private IP address filtering

## Production Readiness

- **Structured Logging**: Comprehensive logging with context and performance monitoring
- **Error Handling**: Rich error context and recovery mechanisms  
- **Memory Safety**: Zero-copy operations where possible, careful memory management
- **Performance**: Async-native design with connection pooling and multiplexing
- **Reliability**: Retry logic, timeout handling, and graceful degradation
- **Monitoring**: Built-in performance metrics and health checks

## Testing

```zig
// Run comprehensive test suite
// zig build test

// Run specific test categories
// zig build test-prod     // Production test suite
// zig build test-tcp      // TCP transport tests  
// zig build test-http     // HTTP client tests
// zig build test-grpc     // gRPC implementation tests
```

## Examples

See the `examples/` directory for complete working examples of:
- TCP echo server
- HTTP client usage
- gRPC service implementation
- WebSocket chat application
- QUIC file transfer
- WireGuard tunnel setup

## Version Compatibility

- **Zig**: 0.16+ required
- **zsync**: v0.5.4+ (async runtime)
- **zcrypto**: v0.8.6+ (cryptography)
- **zquic**: v0.8.4+ (QUIC transport)

This API reference covers the core functionality. For detailed examples and advanced usage, refer to the individual module documentation and the examples directory.