# 🌐 Ghostnet v0.2.1 Wishlist - Package Manager Integration

## 🎯 Priority Features for v0.2.1

### 1. **HTTP Client Core API**
**Current Gap**: Basic networking framework but no concrete HTTP client API
```zig
// Desired API for package manager workloads
const client = ghostnet.HttpClient.init(allocator, .{
    .default_timeout = 30_000,
    .max_redirects = 5,
    .user_agent = "reaper/1.1.0",
    .enable_compression = true, // gzip, br, deflate
});

// Simple request/response
const response = try client.get("https://aur.archlinux.org/rpc/v5/info?arg[]=firefox");
defer response.deinit();

// JSON parsing integration
const PackageInfo = struct { name: []const u8, version: []const u8 };
const pkg_info = try response.json(PackageInfo);
```

**Impact**: Foundation for all AUR API interactions

---

### 2. **Connection Pool Management**
**Current Gap**: No connection reuse for repeated AUR API calls
```zig
// Desired API - connection reuse for package manager efficiency
const pool = ghostnet.ConnectionPool.init(allocator, .{
    .max_connections_per_host = 6,
    .keep_alive_timeout = 60_000,
    .connection_timeout = 10_000,
    .enable_http2_multiplexing = true,
});

// Automatic connection reuse
const client = ghostnet.HttpClient.initWithPool(allocator, pool);

// Batch requests to same host reuse connections
const batch_urls = [_][]const u8{
    "https://aur.archlinux.org/rpc/v5/info?arg[]=firefox",
    "https://aur.archlinux.org/rpc/v5/info?arg[]=discord", 
    "https://aur.archlinux.org/rpc/v5/info?arg[]=vscode",
};
const responses = try client.batchGet(batch_urls);
```

**Impact**: 3-5x faster multi-package metadata fetching

---

### 3. **Download Progress & Streaming**
**Current Gap**: No progress callbacks or streaming for large package downloads
```zig
// Desired API - progress tracking for package downloads
const download_opts = ghostnet.DownloadOptions{
    .progress_callback = progressCallback,
    .chunk_size = 8192,
    .resume_partial = true, // Resume interrupted downloads
    .verify_checksum = .sha256,
};

// Stream large files with progress
const file_stream = try client.downloadStream(
    "https://archive.archlinux.org/packages/f/firefox/firefox-120.0-1-x86_64.pkg.tar.zst",
    download_opts
);

// Progress callback for TUI integration  
fn progressCallback(downloaded: u64, total: u64) void {
    const percent = (downloaded * 100) / total;
    phantom_progress.update(percent);
}
```

**Impact**: Professional download experience with resume capability

---

## 🔧 HTTP Protocol Enhancements

### 4. **Smart Protocol Selection**
```zig
// Auto-select best protocol per mirror
const client = ghostnet.HttpClient.init(allocator, .{
    .protocol_preference = .{ .http3, .http2, .http1_1 },
    .fallback_on_error = true,
    .protocol_cache_ttl = 3600_000, // Remember working protocols
});

// Automatic fallback: HTTP/3 → HTTP/2 → HTTP/1.1
const response = try client.get("https://mirror.example.com/package.tar.zst");
```

### 5. **Rate Limiting & Retry Logic**
```zig
// Respect AUR API limits and handle transient failures
const rate_limiter = ghostnet.RateLimiter.init(.{
    .requests_per_second = 10, // AUR API compliance
    .burst_size = 20,
});

const retry_policy = ghostnet.RetryPolicy{
    .max_attempts = 3,
    .backoff = .exponential,
    .base_delay_ms = 1000,
    .retry_on = &.{ .timeout, .connection_reset, .server_error },
};

const client = ghostnet.HttpClient.init(allocator, .{
    .rate_limiter = rate_limiter,
    .retry_policy = retry_policy,
});
```

---

## 🌐 Package Manager Specific Features

### 6. **Mirror Management**
```zig
// Handle multiple package mirrors with failover
const mirror_manager = ghostnet.MirrorManager.init(allocator, .{
    .primary_mirrors = &.{
        "https://archive.archlinux.org",
        "https://mirror.rackspace.com/archlinux",
    },
    .fallback_mirrors = &.{
        "https://mirror.kernel.org/archlinux",
    },
    .health_check_interval = 300_000, // 5 minutes
});

// Automatic failover on mirror errors
const package_url = mirror_manager.getBestMirror("/packages/f/firefox/firefox.pkg.tar.zst");
const response = try client.get(package_url);
```

### 7. **Concurrent Download Coordination**
```zig
// Download multiple packages simultaneously
const download_manager = ghostnet.DownloadManager.init(allocator, .{
    .max_concurrent = 4,
    .bandwidth_limit = null, // No limit by default
    .temp_directory = "/tmp/reaper/downloads",
});

const packages = [_]DownloadRequest{
    .{ .url = "https://...", .dest = "/tmp/firefox.pkg.tar.zst" },
    .{ .url = "https://...", .dest = "/tmp/discord.pkg.tar.zst" },
};

const results = try download_manager.batchDownload(packages);
```

---

## 📊 Expected Improvements for Reaper

- **AUR API Performance**: 5-10x faster metadata fetching via HTTP/2+ multiplexing
- **Download Speed**: HTTP/3 + QUIC for faster package downloads  
- **Reliability**: Smart mirror failover, resume capability
- **Resource Efficiency**: Connection pooling, rate limiting
- **User Experience**: Progress tracking, concurrent downloads

---

## 🔗 ZSync Integration Points

- **Async Coordination**: ghostnet handles HTTP, zsync coordinates tasks
- **Memory Management**: Shared allocators between ghostnet and zsync
- **Error Handling**: ghostnet errors propagate to zsync task cancellation
- **Resource Limits**: Coordinate connection limits with zsync thread pool

---

*These features would make ghostnet the ideal HTTP foundation for modern package managers, with performance comparable to commercial download managers.*