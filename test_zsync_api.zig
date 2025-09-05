const std = @import("std");
const testing = std.testing;
const ghostnet = @import("ghostnet");
const zsync = ghostnet.zsync; // Use zsync through ghostnet

test "zsync v0.3.2 API basic test" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test the new zsync BlockingIo interface
    var blocking_io = zsync.BlockingIo.init(allocator, 4096);
    defer blocking_io.deinit();

    const io = blocking_io.io();

    // This should compile without errors
    std.debug.print("✅ zsync v0.3.2 BlockingIo interface works\n", .{});

    _ = io; // Use the io variable to avoid unused warnings
}

test "zsync Io interface availability" {
    // Test that the new zsync types are available
    const IoType = zsync.Io;
    const FutureType = zsync.Future;

    // Check that key types exist
    _ = IoType;
    _ = FutureType;

    std.debug.print("✅ zsync v0.3.2 types available\n", .{});
}
