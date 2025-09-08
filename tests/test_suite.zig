//! Comprehensive test suite for ghostnet
//! Tests critical paths, error handling, and API consistency

const std = @import("std");
const testing = std.testing;
const ghostnet = @import("ghostnet");

// Test logging system
test "logging system initialization and usage" {
    var logger = ghostnet.Logger.init(testing.allocator, .info, std.io.getStdErr());
    
    const context = ghostnet.LogContext{
        .component = "test",
        .operation = "test_logging",
    };
    
    logger.info(context, "Test log message: {d}", .{42});
    logger.warn(context, "Test warning message");
    logger.err(context, "Test error message");
    
    // Test performance timer
    var timer = ghostnet.PerformanceTimer.start(context, "test_operation");
    std.time.sleep(1000000); // 1ms
    timer.end();
}

// Test validation system
test "URL validation" {
    const config = ghostnet.ValidationConfig{
        .enforce_https = false,
        .allow_private_ips = true,
    };
    const validator = ghostnet.Validator.init(config);
    
    // Valid URLs
    try validator.validateUrl("http://example.com");
    try validator.validateUrl("https://api.example.com/v1/test");
    try validator.validateUrl("http://localhost:8080/path");
    
    // Invalid URLs
    try testing.expectError(ghostnet.ValidationError.InvalidUrl, validator.validateUrl(""));
    try testing.expectError(ghostnet.ValidationError.InvalidUrl, validator.validateUrl("not-a-url"));
    try testing.expectError(ghostnet.ValidationError.InvalidUrl, validator.validateUrl("ftp://example.com"));
}

test "port validation" {
    const validator = ghostnet.Validator.init(.{});
    
    // Valid ports
    try validator.validatePort(80);
    try validator.validatePort(443);
    try validator.validatePort(8080);
    try validator.validatePort(65535);
    
    // Invalid ports
    try testing.expectError(ghostnet.ValidationError.InvalidPort, validator.validatePort(0));
}

test "IPv4 validation" {
    const config = ghostnet.ValidationConfig{ .allow_private_ips = true };
    const validator = ghostnet.Validator.init(config);
    
    // Valid IPv4
    try validator.validateIPv4("192.168.1.1");
    try validator.validateIPv4("10.0.0.1");
    try validator.validateIPv4("8.8.8.8");
    try validator.validateIPv4("127.0.0.1");
    
    // Invalid IPv4
    try testing.expectError(ghostnet.ValidationError.InvalidIPAddress, validator.validateIPv4("256.1.1.1"));
    try testing.expectError(ghostnet.ValidationError.InvalidIPAddress, validator.validateIPv4("192.168.1"));
    try testing.expectError(ghostnet.ValidationError.InvalidIPAddress, validator.validateIPv4("not.an.ip.address"));
    try testing.expectError(ghostnet.ValidationError.InvalidIPAddress, validator.validateIPv4(""));
}

test "hostname validation" {
    const validator = ghostnet.Validator.init(.{});
    
    // Valid hostnames
    try validator.validateHostname("example.com");
    try validator.validateHostname("api.example.com");
    try validator.validateHostname("test-server.local");
    try validator.validateHostname("localhost");
    
    // Invalid hostnames
    try testing.expectError(ghostnet.ValidationError.InvalidHostname, validator.validateHostname(""));
    try testing.expectError(ghostnet.ValidationError.InvalidHostname, validator.validateHostname("-invalid.com"));
    try testing.expectError(ghostnet.ValidationError.InvalidHostname, validator.validateHostname("invalid-.com"));
    try testing.expectError(ghostnet.ValidationError.InvalidHostname, validator.validateHostname("invalid..com"));
}

test "HTTP header validation" {
    const validator = ghostnet.Validator.init(.{});
    
    // Valid headers
    try validator.validateHeaderName("Content-Type");
    try validator.validateHeaderName("User-Agent");
    try validator.validateHeaderName("Authorization");
    try validator.validateHeaderName("X-Custom-Header");
    
    try validator.validateHeaderValue("application/json");
    try validator.validateHeaderValue("Mozilla/5.0 (compatible; Test)");
    try validator.validateHeaderValue("Bearer token123");
    
    // Invalid headers
    try testing.expectError(ghostnet.ValidationError.InvalidHeaderName, validator.validateHeaderName(""));
    try testing.expectError(ghostnet.ValidationError.InvalidHeaderName, validator.validateHeaderName("Invalid Header"));
    try testing.expectError(ghostnet.ValidationError.InvalidHeaderName, validator.validateHeaderName("Invalid:Header"));
}

test "HTTP method validation" {
    const validator = ghostnet.Validator.init(.{});
    
    // Valid methods
    try validator.validateHttpMethod("GET");
    try validator.validateHttpMethod("POST");
    try validator.validateHttpMethod("PUT");
    try validator.validateHttpMethod("DELETE");
    try validator.validateHttpMethod("HEAD");
    try validator.validateHttpMethod("OPTIONS");
    try validator.validateHttpMethod("PATCH");
    try validator.validateHttpMethod("TRACE");
    try validator.validateHttpMethod("CONNECT");
    
    // Invalid methods
    try testing.expectError(ghostnet.ValidationError.InvalidMethod, validator.validateHttpMethod("INVALID"));
    try testing.expectError(ghostnet.ValidationError.InvalidMethod, validator.validateHttpMethod("get"));
    try testing.expectError(ghostnet.ValidationError.InvalidMethod, validator.validateHttpMethod(""));
}

test "payload size validation" {
    const config = ghostnet.ValidationConfig{ .max_payload_size = 1024 };
    const validator = ghostnet.Validator.init(config);
    
    // Valid sizes
    try validator.validatePayloadSize(0);
    try validator.validatePayloadSize(512);
    try validator.validatePayloadSize(1024);
    
    // Invalid sizes
    try testing.expectError(ghostnet.ValidationError.PayloadTooLarge, validator.validatePayloadSize(1025));
    try testing.expectError(ghostnet.ValidationError.PayloadTooLarge, validator.validatePayloadSize(10000));
}

test "HTTP/2 stream ID validation" {
    const validator = ghostnet.Validator.init(.{});
    
    // Valid stream IDs
    try validator.validateStreamId(1);
    try validator.validateStreamId(100);
    try validator.validateStreamId(0x7FFFFFFF);
    
    // Invalid stream IDs
    try testing.expectError(ghostnet.ValidationError.InvalidStreamId, validator.validateStreamId(0));
    try testing.expectError(ghostnet.ValidationError.InvalidStreamId, validator.validateStreamId(0x80000000));
    try testing.expectError(ghostnet.ValidationError.InvalidStreamId, validator.validateStreamId(0xFFFFFFFF));
}

test "string sanitization" {
    const validator = ghostnet.Validator.init(.{});
    
    const input = "Hello\x00World\x01Test\x7F";
    const sanitized = try validator.sanitizeString(testing.allocator, input);
    defer testing.allocator.free(sanitized);
    
    try testing.expectEqualStrings("Hello?World?Test?", sanitized);
}

// Test error handling system
test "error context and result types" {
    const TestError = error{TestFailure};
    
    // Test successful result
    const success_result: ghostnet.Result(i32, TestError) = .{ .ok = 42 };
    try testing.expect(success_result.isOk());
    try testing.expect(!success_result.isErr());
    try testing.expectEqual(@as(i32, 42), success_result.unwrapOr(0));
    
    // Test error result  
    const error_ctx = ghostnet.ErrorContext{
        .component = "test",
        .operation = "test_error",
        .message = "Test error message",
    };
    const error_result: ghostnet.Result(i32, TestError) = .{ .err = error_ctx };
    try testing.expect(!error_result.isOk());
    try testing.expect(error_result.isErr());
    try testing.expectEqual(@as(i32, 100), error_result.unwrapOr(100));
}

// Test critical path functionality
test "transport layer initialization" {
    // Test that transport layer can be initialized without errors
    const allocator = testing.allocator;
    
    // This is a basic smoke test - in a real scenario we'd test actual network operations
    _ = allocator;
    
    // Test that we can import and reference all transport types
    _ = ghostnet.Transport;
    _ = ghostnet.Connection;
    _ = ghostnet.Stream;
    _ = ghostnet.Listener;
    _ = ghostnet.Address;
    _ = ghostnet.TcpTransport;
    _ = ghostnet.UdpSocket;
}

test "protocol layer accessibility" {
    // Test that all protocol modules are accessible
    _ = ghostnet.HttpClient;
    _ = ghostnet.Http2Client;
    _ = ghostnet.GrpcClient;
    _ = ghostnet.QuicConnection;
    _ = ghostnet.WireGuardTunnel;
    _ = ghostnet.MqttClient;
    _ = ghostnet.NatsClient;
    _ = ghostnet.SseClient;
    _ = ghostnet.WebTransportSession;
}

test "crypto and async runtime accessibility" {
    // Test that external dependencies are properly accessible
    _ = ghostnet.zsync;
    _ = ghostnet.zcrypto;
    _ = ghostnet.zquic;
}

// Integration test for multiple systems
test "integrated logging and validation" {
    const allocator = testing.allocator;
    
    // Setup logging
    var logger = ghostnet.Logger.init(allocator, .debug, std.io.getStdErr());
    ghostnet.logging.setGlobalLogger(&logger);
    
    // Setup validation
    var validator = ghostnet.Validator.init(.{});
    ghostnet.validation.setGlobalValidator(&validator);
    
    // Test integrated usage
    const context = ghostnet.LogContext{
        .component = "integration_test",
        .operation = "validate_and_log",
    };
    
    logger.info(context, "Starting validation test");
    
    try ghostnet.validation.validateUrl("https://example.com/test");
    logger.info(context, "URL validation passed");
    
    try ghostnet.validation.validatePort(8080);
    logger.info(context, "Port validation passed");
    
    logger.info(context, "Integration test completed successfully");
}