//! Compression support for HTTP and other protocols
//! Implements gzip, deflate, and brotli compression

const std = @import("std");
const zsync = @import("zsync");

/// Compression algorithms
pub const Algorithm = enum {
    none,
    gzip,
    deflate,
    brotli,
    zstd,
    
    pub fn fromString(name: []const u8) ?Algorithm {
        if (std.mem.eql(u8, name, "gzip")) return .gzip;
        if (std.mem.eql(u8, name, "deflate")) return .deflate;
        if (std.mem.eql(u8, name, "br")) return .brotli;
        if (std.mem.eql(u8, name, "zstd")) return .zstd;
        if (std.mem.eql(u8, name, "identity")) return .none;
        return null;
    }
    
    pub fn toString(self: Algorithm) []const u8 {
        return switch (self) {
            .none => "identity",
            .gzip => "gzip",
            .deflate => "deflate", 
            .brotli => "br",
            .zstd => "zstd",
        };
    }
    
    pub fn mimeType(self: Algorithm) []const u8 {
        return switch (self) {
            .none => "application/octet-stream",
            .gzip => "application/gzip",
            .deflate => "application/deflate",
            .brotli => "application/brotli",
            .zstd => "application/zstd",
        };
    }
};

/// Compression level
pub const Level = enum(u8) {
    fastest = 1,
    fast = 2,
    default = 6,
    good = 7,
    best = 9,
    
    pub fn toInt(self: Level) u8 {
        return @intFromEnum(self);
    }
};

/// Compression options
pub const CompressionOptions = struct {
    algorithm: Algorithm = .gzip,
    level: Level = .default,
    window_size: ?u8 = null, // For deflate/gzip
    mem_level: ?u8 = null,   // For deflate/gzip
    strategy: ?u8 = null,    // For deflate/gzip
};

/// Compression result
pub const CompressionResult = struct {
    data: []u8,
    algorithm: Algorithm,
    original_size: usize,
    compressed_size: usize,
    
    pub fn compressionRatio(self: CompressionResult) f64 {
        if (self.original_size == 0) return 0.0;
        return @as(f64, @floatFromInt(self.compressed_size)) / @as(f64, @floatFromInt(self.original_size));
    }
    
    pub fn spaceSaved(self: CompressionResult) usize {
        return self.original_size -| self.compressed_size;
    }
    
    pub fn deinit(self: *CompressionResult, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

/// Content encoding parser for HTTP Accept-Encoding header
pub const ContentEncoding = struct {
    algorithms: std.ArrayList(WeightedAlgorithm),
    allocator: std.mem.Allocator,
    
    const WeightedAlgorithm = struct {
        algorithm: Algorithm,
        quality: f32,
    };
    
    pub fn init(allocator: std.mem.Allocator) ContentEncoding {
        return .{
            .algorithms = std.ArrayList(WeightedAlgorithm).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ContentEncoding) void {
        self.algorithms.deinit();
    }
    
    pub fn parse(allocator: std.mem.Allocator, accept_encoding: []const u8) !ContentEncoding {
        var encoding = ContentEncoding.init(allocator);
        
        var parts = std.mem.split(u8, accept_encoding, ",");
        while (parts.next()) |part| {
            const trimmed = std.mem.trim(u8, part, " \t");
            
            var quality: f32 = 1.0;
            var alg_name = trimmed;
            
            // Check for quality value (q=0.8)
            if (std.mem.indexOf(u8, trimmed, ";")) |semicolon_pos| {
                alg_name = std.mem.trim(u8, trimmed[0..semicolon_pos], " \t");
                const q_part = std.mem.trim(u8, trimmed[semicolon_pos + 1..], " \t");
                
                if (std.mem.startsWith(u8, q_part, "q=")) {
                    quality = std.fmt.parseFloat(f32, q_part[2..]) catch 1.0;
                }
            }
            
            if (Algorithm.fromString(alg_name)) |algorithm| {
                try encoding.algorithms.append(.{
                    .algorithm = algorithm,
                    .quality = quality,
                });
            }
        }
        
        // Sort by quality (highest first)
        std.mem.sort(WeightedAlgorithm, encoding.algorithms.items, {}, struct {
            fn lessThan(context: void, a: WeightedAlgorithm, b: WeightedAlgorithm) bool {
                _ = context;
                return a.quality > b.quality;
            }
        }.lessThan);
        
        return encoding;
    }
    
    pub fn selectBest(self: *ContentEncoding, supported: []const Algorithm) ?Algorithm {
        for (self.algorithms.items) |weighted| {
            for (supported) |alg| {
                if (weighted.algorithm == alg and weighted.quality > 0) {
                    return alg;
                }
            }
        }
        return null;
    }
    
    pub fn accepts(self: *ContentEncoding, algorithm: Algorithm) bool {
        for (self.algorithms.items) |weighted| {
            if (weighted.algorithm == algorithm and weighted.quality > 0) {
                return true;
            }
        }
        return false;
    }
    
    pub fn toString(self: *ContentEncoding, allocator: std.mem.Allocator) ![]u8 {
        if (self.algorithms.items.len == 0) return try allocator.dupe(u8, "identity");
        
        var result = std.ArrayList(u8).init(allocator);
        defer result.deinit();
        
        for (self.algorithms.items, 0..) |weighted, i| {
            if (i > 0) {
                try result.appendSlice(", ");
            }
            
            try result.appendSlice(weighted.algorithm.toString());
            
            if (weighted.quality != 1.0) {
                try result.writer().print(";q={d:.1}", .{weighted.quality});
            }
        }
        
        return result.toOwnedSlice();
    }
};

/// Main compressor implementation
pub const Compressor = struct {
    allocator: std.mem.Allocator,
    options: CompressionOptions,
    
    pub fn init(allocator: std.mem.Allocator, options: CompressionOptions) Compressor {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }
    
    /// Compress data using the configured algorithm
    pub fn compress(self: *Compressor, data: []const u8) !CompressionResult {
        const original_size = data.len;
        
        const compressed_data = switch (self.options.algorithm) {
            .none => try self.allocator.dupe(u8, data),
            .gzip => try self.compressGzip(data),
            .deflate => try self.compressDeflate(data),
            .brotli => try self.compressBrotli(data),
            .zstd => try self.compressZstd(data),
        };
        
        return CompressionResult{
            .data = compressed_data,
            .algorithm = self.options.algorithm,
            .original_size = original_size,
            .compressed_size = compressed_data.len,
        };
    }
    
    /// Decompress data 
    pub fn decompress(self: *Compressor, data: []const u8, algorithm: Algorithm) ![]u8 {
        return switch (algorithm) {
            .none => try self.allocator.dupe(u8, data),
            .gzip => try self.decompressGzip(data),
            .deflate => try self.decompressDeflate(data),
            .brotli => try self.decompressBrotli(data),
            .zstd => try self.decompressZstd(data),
        };
    }
    
    /// Auto-detect compression algorithm from data
    pub fn detectAlgorithm(data: []const u8) Algorithm {
        if (data.len < 3) return .none;
        
        // Gzip magic bytes
        if (data[0] == 0x1f and data[1] == 0x8b) {
            return .gzip;
        }
        
        // Brotli doesn't have reliable magic bytes, but has patterns
        // This is a simplified detection
        if (data.len >= 6) {
            // Check for common brotli patterns (simplified)
            const first_bytes = std.mem.readInt(u32, data[0..4], .little);
            if ((first_bytes & 0xFF) >= 0x81 and (first_bytes & 0xFF) <= 0x8F) {
                return .brotli;
            }
        }
        
        // Zstd magic number
        if (data.len >= 4) {
            const magic = std.mem.readInt(u32, data[0..4], .little);
            if (magic == 0xFD2FB528) {
                return .zstd;
            }
        }
        
        // Try to detect deflate by attempting decompression
        // This is expensive but more reliable
        
        return .none;
    }
    
    /// Gzip compression using std.compress.gzip
    fn compressGzip(self: *Compressor, data: []const u8) ![]u8 {
        var compressed = std.ArrayList(u8).init(self.allocator);
        defer compressed.deinit();
        
        var gzip_stream = try std.compress.gzip.compressor(compressed.writer(), .{
            .level = self.options.level.toInt(),
        });
        defer gzip_stream.deinit();
        
        try gzip_stream.writer().writeAll(data);
        try gzip_stream.finish();
        
        return compressed.toOwnedSlice();
    }
    
    /// Gzip decompression
    fn decompressGzip(self: *Compressor, data: []const u8) ![]u8 {
        var decompressed = std.ArrayList(u8).init(self.allocator);
        defer decompressed.deinit();
        
        var stream = std.io.fixedBufferStream(data);
        var gzip_stream = try std.compress.gzip.decompressor(stream.reader());
        defer gzip_stream.deinit();
        
        try gzip_stream.reader().readAllArrayList(&decompressed, std.math.maxInt(usize));
        
        return decompressed.toOwnedSlice();
    }
    
    /// Deflate compression using std.compress.deflate
    fn compressDeflate(self: *Compressor, data: []const u8) ![]u8 {
        var compressed = std.ArrayList(u8).init(self.allocator);
        defer compressed.deinit();
        
        var deflate_stream = try std.compress.deflate.compressor(compressed.writer(), .{
            .level = self.options.level.toInt(),
        });
        defer deflate_stream.deinit();
        
        try deflate_stream.writer().writeAll(data);
        try deflate_stream.finish();
        
        return compressed.toOwnedSlice();
    }
    
    /// Deflate decompression
    fn decompressDeflate(self: *Compressor, data: []const u8) ![]u8 {
        var decompressed = std.ArrayList(u8).init(self.allocator);
        defer decompressed.deinit();
        
        var stream = std.io.fixedBufferStream(data);
        var deflate_stream = try std.compress.deflate.decompressor(stream.reader(), null);
        defer deflate_stream.deinit();
        
        try deflate_stream.reader().readAllArrayList(&decompressed, std.math.maxInt(usize));
        
        return decompressed.toOwnedSlice();
    }
    
    /// Brotli compression (placeholder - would need brotli library)
    fn compressBrotli(self: *Compressor, data: []const u8) ![]u8 {
        // For now, return identity compression
        // Real implementation would use a brotli library like google/brotli
        std.log.warn("Brotli compression not implemented, using identity", .{});
        return try self.allocator.dupe(u8, data);
    }
    
    /// Brotli decompression (placeholder)
    fn decompressBrotli(self: *Compressor, data: []const u8) ![]u8 {
        // For now, return identity decompression
        std.log.warn("Brotli decompression not implemented, using identity", .{});
        return try self.allocator.dupe(u8, data);
    }
    
    /// Zstd compression (placeholder - would need zstd library)
    fn compressZstd(self: *Compressor, data: []const u8) ![]u8 {
        // For now, return identity compression
        // Real implementation would use zstd library
        std.log.warn("Zstd compression not implemented, using identity", .{});
        return try self.allocator.dupe(u8, data);
    }
    
    /// Zstd decompression (placeholder)
    fn decompressZstd(self: *Compressor, data: []const u8) ![]u8 {
        // For now, return identity decompression
        std.log.warn("Zstd decompression not implemented, using identity", .{});
        return try self.allocator.dupe(u8, data);
    }
};

/// Stream compressor for incremental compression
pub const StreamCompressor = struct {
    allocator: std.mem.Allocator,
    algorithm: Algorithm,
    level: Level,
    state: CompressionState,
    
    const CompressionState = union(Algorithm) {
        none: void,
        gzip: std.compress.gzip.Compressor(std.io.AnyWriter),
        deflate: std.compress.deflate.Compressor(std.io.AnyWriter),
        brotli: void, // Placeholder
        zstd: void,   // Placeholder
    };
    
    pub fn init(allocator: std.mem.Allocator, writer: std.io.AnyWriter, algorithm: Algorithm, level: Level) !StreamCompressor {
        const state = switch (algorithm) {
            .none => CompressionState{ .none = {} },
            .gzip => CompressionState{ .gzip = try std.compress.gzip.compressor(writer, .{
                .level = level.toInt(),
            }) },
            .deflate => CompressionState{ .deflate = try std.compress.deflate.compressor(writer, .{
                .level = level.toInt(),
            }) },
            .brotli => CompressionState{ .brotli = {} },
            .zstd => CompressionState{ .zstd = {} },
        };
        
        return .{
            .allocator = allocator,
            .algorithm = algorithm,
            .level = level,
            .state = state,
        };
    }
    
    pub fn deinit(self: *StreamCompressor) void {
        switch (self.state) {
            .gzip => |*compressor| compressor.deinit(),
            .deflate => |*compressor| compressor.deinit(),
            else => {},
        }
    }
    
    pub fn write(self: *StreamCompressor, data: []const u8) !usize {
        return switch (self.state) {
            .none => data.len, // Identity, assume data was written directly
            .gzip => |*compressor| try compressor.writer().write(data),
            .deflate => |*compressor| try compressor.writer().write(data),
            .brotli => data.len, // Placeholder
            .zstd => data.len,   // Placeholder
        };
    }
    
    pub fn finish(self: *StreamCompressor) !void {
        switch (self.state) {
            .none => {},
            .gzip => |*compressor| try compressor.finish(),
            .deflate => |*compressor| try compressor.finish(),
            .brotli => {}, // Placeholder
            .zstd => {},   // Placeholder
        }
    }
    
    pub fn writer(self: *StreamCompressor) Writer {
        return .{ .context = self };
    }
    
    pub const Writer = std.io.Writer(*StreamCompressor, error{OutOfMemory}, write);
    
    fn write(self: *StreamCompressor, data: []const u8) !usize {
        return self.write(data);
    }
};

/// Stream decompressor for incremental decompression  
pub const StreamDecompressor = struct {
    allocator: std.mem.Allocator,
    algorithm: Algorithm,
    state: DecompressionState,
    
    const DecompressionState = union(Algorithm) {
        none: void,
        gzip: std.compress.gzip.Decompressor(std.io.AnyReader),
        deflate: std.compress.deflate.Decompressor(std.io.AnyReader),
        brotli: void, // Placeholder
        zstd: void,   // Placeholder
    };
    
    pub fn init(allocator: std.mem.Allocator, reader: std.io.AnyReader, algorithm: Algorithm) !StreamDecompressor {
        const state = switch (algorithm) {
            .none => DecompressionState{ .none = {} },
            .gzip => DecompressionState{ .gzip = try std.compress.gzip.decompressor(reader) },
            .deflate => DecompressionState{ .deflate = try std.compress.deflate.decompressor(reader, null) },
            .brotli => DecompressionState{ .brotli = {} },
            .zstd => DecompressionState{ .zstd = {} },
        };
        
        return .{
            .allocator = allocator,
            .algorithm = algorithm,
            .state = state,
        };
    }
    
    pub fn deinit(self: *StreamDecompressor) void {
        switch (self.state) {
            .gzip => |*decompressor| decompressor.deinit(),
            .deflate => |*decompressor| decompressor.deinit(),
            else => {},
        }
    }
    
    pub fn read(self: *StreamDecompressor, buffer: []u8) !usize {
        return switch (self.state) {
            .none => 0, // Identity, assume data was read directly
            .gzip => |*decompressor| try decompressor.reader().read(buffer),
            .deflate => |*decompressor| try decompressor.reader().read(buffer),
            .brotli => 0, // Placeholder
            .zstd => 0,   // Placeholder
        };
    }
    
    pub fn reader(self: *StreamDecompressor) Reader {
        return .{ .context = self };
    }
    
    pub const Reader = std.io.Reader(*StreamDecompressor, error{OutOfMemory}, read);
    
    fn read(self: *StreamDecompressor, buffer: []u8) !usize {
        return self.read(buffer);
    }
};

/// Compression middleware for HTTP
pub const CompressionMiddleware = struct {
    compressor: Compressor,
    supported_algorithms: []const Algorithm,
    min_compress_size: usize,
    compress_types: std.StringHashMap(void),
    
    pub fn init(
        allocator: std.mem.Allocator, 
        supported: []const Algorithm, 
        min_size: usize
    ) !CompressionMiddleware {
        var middleware = CompressionMiddleware{
            .compressor = Compressor.init(allocator, .{}),
            .supported_algorithms = try allocator.dupe(Algorithm, supported),
            .min_compress_size = min_size,
            .compress_types = std.StringHashMap(void).init(allocator),
        };
        
        // Add common compressible content types
        const compressible_types = [_][]const u8{
            "text/plain",
            "text/html",
            "text/css",
            "text/javascript",
            "application/javascript",
            "application/json",
            "application/xml",
            "text/xml",
            "image/svg+xml",
        };
        
        for (compressible_types) |content_type| {
            const owned_type = try allocator.dupe(u8, content_type);
            try middleware.compress_types.put(owned_type, {});
        }
        
        return middleware;
    }
    
    pub fn deinit(self: *CompressionMiddleware) void {
        self.compressor.allocator.free(self.supported_algorithms);
        
        var it = self.compress_types.iterator();
        while (it.next()) |entry| {
            self.compressor.allocator.free(entry.key_ptr.*);
        }
        self.compress_types.deinit();
    }
    
    pub fn shouldCompress(self: *CompressionMiddleware, content_type: ?[]const u8, content_length: usize) bool {
        // Check minimum size
        if (content_length < self.min_compress_size) return false;
        
        // Check content type
        if (content_type) |ct| {
            // Extract main type (before semicolon)
            const main_type = if (std.mem.indexOf(u8, ct, ";")) |pos| ct[0..pos] else ct;
            return self.compress_types.contains(main_type);
        }
        
        return false;
    }
    
    pub fn selectCompression(self: *CompressionMiddleware, accept_encoding: ?[]const u8) ?Algorithm {
        const encoding_header = accept_encoding orelse return null;
        
        var content_encoding = ContentEncoding.parse(self.compressor.allocator, encoding_header) catch return null;
        defer content_encoding.deinit();
        
        return content_encoding.selectBest(self.supported_algorithms);
    }
};