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
    
    // Create basic HTTP client
    var client = try ghostnet.HttpClient.init(allocator, &runtime);
    defer client.deinit();
    
    // Set timeout
    client.setDefaultTimeout(10000); // 10 seconds
    
    // Make a simple GET request
    std.log.info("Making GET request to httpbin.org...");
    const response = try client.get("https://httpbin.org/get");
    defer response.deinit(allocator);
    
    std.log.info("Response status: {d}", .{response.status_code});
    if (response.body) |body| {
        std.log.info("Response body: {s}", .{body});
    }
    
    // Make a POST request with JSON data
    std.log.info("Making POST request with JSON...");
    const json_data = 
        \\{
        \\  "message": "Hello from ghostnet!",
        \\  "timestamp": 1234567890
        \\}
    ;
    
    const post_response = try client.postJson("https://httpbin.org/post", json_data);
    defer post_response.deinit(allocator);
    
    std.log.info("POST response status: {d}", .{post_response.status_code});
    if (post_response.body) |body| {
        std.log.info("POST response body length: {d} bytes", .{body.len});
    }
}