const std = @import("std");
const ghostnet = @import("ghostnet");
const zsync = @import("zsync");

const ProgressTracker = struct {
    start_time: i64,
    last_update: i64,
    
    pub fn init() ProgressTracker {
        const now = std.time.timestamp();
        return .{
            .start_time = now,
            .last_update = now,
        };
    }
    
    pub fn onProgress(self: *ProgressTracker, downloaded: u64, total: u64) void {
        const now = std.time.timestamp();
        
        // Update every 500ms
        if (now - self.last_update < 1) return;
        self.last_update = now;
        
        const elapsed = @as(f64, @floatFromInt(now - self.start_time));
        const progress_percent = if (total > 0) @as(f64, @floatFromInt(downloaded)) / @as(f64, @floatFromInt(total)) * 100.0 else 0.0;
        const speed_bps = if (elapsed > 0) @as(f64, @floatFromInt(downloaded)) / elapsed else 0.0;
        const eta_seconds = if (downloaded > 0 and elapsed > 0) 
            (@as(f64, @floatFromInt(total - downloaded)) / @as(f64, @floatFromInt(downloaded))) * elapsed
        else 0.0;
        
        std.log.info("Download: {d:.1}% ({d}/{d} bytes) @ {d:.1} KB/s ETA: {d:.0}s", 
            .{ progress_percent, downloaded, total, speed_bps / 1024.0, eta_seconds });
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize async runtime
    var runtime = try zsync.Runtime.init(allocator);
    defer runtime.deinit();
    
    // Create HTTP client optimized for downloads
    var client = try ghostnet.HttpClient.init(allocator, &runtime);
    defer client.deinit();
    
    // Set longer timeout for large downloads
    client.setDefaultTimeout(300_000); // 5 minutes
    
    // Create download directory
    try std.fs.cwd().makePath("downloads");
    
    std.log.info("Starting file download with progress tracking...");
    
    // Set up progress tracking
    var progress_tracker = ProgressTracker.init();
    
    const progress_callback = struct {
        tracker: *ProgressTracker,
        
        pub fn callback(self: @This()) *const fn (u64, u64) void {
            return struct {
                pub fn onProgress(downloaded: u64, total: u64) void {
                    @fieldParentPtr(@TypeOf(self), "tracker", self.tracker).tracker.onProgress(downloaded, total);
                }
            }.onProgress;
        }
    }{ .tracker = &progress_tracker }.callback();
    
    // Download a sample file
    const download_url = "https://httpbin.org/drip?duration=5&numbytes=1048576"; // 1MB over 5 seconds
    const dest_path = "downloads/sample_file.bin";
    
    const download_options = ghostnet.HttpClient.DownloadOptions{
        .progress_callback = progress_callback,
        .chunk_size = 8192, // 8KB chunks
        .resume_partial = true,
        .verify_checksum = null,
        .max_speed = null, // No speed limit
    };
    
    const start_time = std.time.timestamp();
    
    try client.downloadStream(download_url, dest_path, download_options) catch |err| {
        std.log.err("Download failed: {}", .{err});
        return;
    };
    
    const end_time = std.time.timestamp();
    const total_time = end_time - start_time;
    
    // Get file size
    const file_stat = try std.fs.cwd().statFile(dest_path);
    const file_size = file_stat.size;
    
    std.log.info("✅ Download completed successfully!");
    std.log.info("   File: {s}", .{dest_path});
    std.log.info("   Size: {d} bytes ({d:.2} MB)", .{ file_size, @as(f64, @floatFromInt(file_size)) / 1024.0 / 1024.0 });
    std.log.info("   Time: {d} seconds", .{total_time});
    
    if (total_time > 0) {
        const avg_speed = @as(f64, @floatFromInt(file_size)) / @as(f64, @floatFromInt(total_time));
        std.log.info("   Avg Speed: {d:.1} KB/s", .{avg_speed / 1024.0});
    }
    
    // Demonstrate resume capability by downloading again (should be instant if file exists)
    std.log.info("Testing resume capability...");
    
    const resume_start = std.time.timestamp();
    try client.downloadStream(download_url, dest_path, download_options) catch |err| {
        std.log.err("Resume test failed: {}", .{err});
        return;
    };
    const resume_end = std.time.timestamp();
    
    std.log.info("✅ Resume test completed in {d} seconds (should be fast if file already complete)", .{resume_end - resume_start});
}