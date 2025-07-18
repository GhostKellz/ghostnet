const std = @import("std");
const zsync = @import("zsync");

// Test proper zsync integration for TCP operations
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Testing zsync TCP integration patterns...\n", .{});

    // Test 1: BlockingIo for simple TCP operations
    {
        std.debug.print("1. Testing zsync.BlockingIo...\n", .{});
        var blocking_io = zsync.BlockingIo.init();
        defer blocking_io.deinit();

        std.debug.print("   ✅ BlockingIo initialized successfully\n", .{});
    }

    // Test 2: ThreadPoolIo for concurrent TCP operations
    {
        std.debug.print("2. Testing zsync.ThreadPoolIo...\n", .{});
        var thread_pool_io = try zsync.ThreadPoolIo.init(allocator, .{});
        defer thread_pool_io.deinit();

        std.debug.print("   ✅ ThreadPoolIo initialized successfully\n", .{});
    }

    // Test 3: GreenThreadsIo for high-concurrency TCP operations
    {
        std.debug.print("3. Testing zsync.GreenThreadsIo...\n", .{});
        var green_threads_io = try zsync.GreenThreadsIo.init(allocator, .{});
        defer green_threads_io.deinit();

        std.debug.print("   ✅ GreenThreadsIo initialized successfully\n", .{});
    }

    // Test 4: TCP socket creation with zsync
    {
        std.debug.print("4. Testing TCP socket with zsync...\n", .{});
        var thread_pool_io = try zsync.ThreadPoolIo.init(allocator, .{});
        defer thread_pool_io.deinit();

        // Test basic socket creation (without actual networking)
        const socket = try thread_pool_io.socket(.ipv4, .tcp, .tcp);
        try thread_pool_io.close(socket);

        std.debug.print("   ✅ TCP socket creation successful\n", .{});
    }

    std.debug.print("\n🎉 All zsync TCP integration tests passed!\n");
    std.debug.print("📝 Recommended pattern for ghostnet:\n");
    std.debug.print("   - Use zsync.ThreadPoolIo for most TCP operations\n");
    std.debug.print("   - Use zsync.GreenThreadsIo for high-concurrency scenarios\n");
    std.debug.print("   - Replace zsync.Runtime with appropriate Io implementation\n");
}
