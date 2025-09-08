const std = @import("std");
const testing = std.testing;
const ghostnet = @import("ghostnet");

test "basic API accessibility" {
    // Test that all core types are accessible
    _ = ghostnet.Transport;
    _ = ghostnet.TcpTransport;
    _ = ghostnet.HttpClient;
    _ = ghostnet.Logger;
    _ = ghostnet.Validator;
    _ = ghostnet.GrpcClient;
}

test "error handling system" {
    const TestError = error{TestFailure};
    
    // Test successful result
    const success_result: ghostnet.Result(i32, TestError) = .{ .ok = 42 };
    try testing.expect(success_result.isOk());
    try testing.expectEqual(@as(i32, 42), success_result.unwrapOr(0));
}

test "logging system basic functionality" {
    var logger = ghostnet.Logger.init(testing.allocator, .info, std.io.getStdErr());
    
    const context = ghostnet.LogContext{
        .component = "test",
        .operation = "test_logging",
    };
    
    logger.info(context, "Test log message: {d}", .{42});
}

test "validation system basic functionality" {
    const validator = ghostnet.Validator.init(.{});
    
    // Test valid inputs
    try validator.validatePort(8080);
    try validator.validateHttpMethod("GET");
}