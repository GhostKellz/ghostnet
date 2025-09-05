//! HPACK - HTTP/2 Header Compression
//! RFC 7541 implementation for efficient header compression in HTTP/2

const std = @import("std");

/// HPACK static table entries (RFC 7541 Appendix B)
const StaticTable = struct {
    const Entry = struct {
        name: []const u8,
        value: []const u8,
    };
    
    const static_entries = [_]Entry{
        .{ .name = ":authority", .value = "" },
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":status", .value = "200" },
        .{ .name = ":status", .value = "204" },
        .{ .name = ":status", .value = "206" },
        .{ .name = ":status", .value = "304" },
        .{ .name = ":status", .value = "400" },
        .{ .name = ":status", .value = "404" },
        .{ .name = ":status", .value = "500" },
        .{ .name = "accept-charset", .value = "" },
        .{ .name = "accept-encoding", .value = "gzip, deflate" },
        .{ .name = "accept-language", .value = "" },
        .{ .name = "accept-ranges", .value = "" },
        .{ .name = "accept", .value = "" },
        .{ .name = "access-control-allow-origin", .value = "" },
        .{ .name = "age", .value = "" },
        .{ .name = "allow", .value = "" },
        .{ .name = "authorization", .value = "" },
        .{ .name = "cache-control", .value = "" },
        .{ .name = "content-disposition", .value = "" },
        .{ .name = "content-encoding", .value = "" },
        .{ .name = "content-language", .value = "" },
        .{ .name = "content-length", .value = "" },
        .{ .name = "content-location", .value = "" },
        .{ .name = "content-range", .value = "" },
        .{ .name = "content-type", .value = "" },
        .{ .name = "cookie", .value = "" },
        .{ .name = "date", .value = "" },
        .{ .name = "etag", .value = "" },
        .{ .name = "expect", .value = "" },
        .{ .name = "expires", .value = "" },
        .{ .name = "from", .value = "" },
        .{ .name = "host", .value = "" },
        .{ .name = "if-match", .value = "" },
        .{ .name = "if-modified-since", .value = "" },
        .{ .name = "if-none-match", .value = "" },
        .{ .name = "if-range", .value = "" },
        .{ .name = "if-unmodified-since", .value = "" },
        .{ .name = "last-modified", .value = "" },
        .{ .name = "link", .value = "" },
        .{ .name = "location", .value = "" },
        .{ .name = "max-forwards", .value = "" },
        .{ .name = "proxy-authenticate", .value = "" },
        .{ .name = "proxy-authorization", .value = "" },
        .{ .name = "range", .value = "" },
        .{ .name = "referer", .value = "" },
        .{ .name = "refresh", .value = "" },
        .{ .name = "retry-after", .value = "" },
        .{ .name = "server", .value = "" },
        .{ .name = "set-cookie", .value = "" },
        .{ .name = "strict-transport-security", .value = "" },
        .{ .name = "transfer-encoding", .value = "" },
        .{ .name = "user-agent", .value = "" },
        .{ .name = "vary", .value = "" },
        .{ .name = "via", .value = "" },
        .{ .name = "www-authenticate", .value = "" },
    };
    
    fn get(index: usize) ?Entry {
        if (index == 0 or index > static_entries.len) return null;
        return static_entries[index - 1];
    }
    
    fn find(name: []const u8, value: []const u8) ?usize {
        for (static_entries, 1..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                return i;
            }
        }
        return null;
    }
    
    fn findName(name: []const u8) ?usize {
        for (static_entries, 1..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                return i;
            }
        }
        return null;
    }
};

/// Dynamic table for HPACK compression
pub const DynamicTable = struct {
    entries: std.ArrayList(Entry),
    max_size: usize,
    current_size: usize,
    allocator: std.mem.Allocator,
    
    const Entry = struct {
        name: []u8,
        value: []u8,
        
        fn size(self: Entry) usize {
            return self.name.len + self.value.len + 32; // RFC 7541 overhead
        }
        
        fn deinit(self: Entry, allocator: std.mem.Allocator) void {
            allocator.free(self.name);
            allocator.free(self.value);
        }
    };
    
    pub fn init(allocator: std.mem.Allocator, max_size: usize) DynamicTable {
        return DynamicTable{
            .entries = std.ArrayList(Entry).init(allocator),
            .max_size = max_size,
            .current_size = 0,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *DynamicTable) void {
        for (self.entries.items) |entry| {
            entry.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
    }
    
    pub fn add(self: *DynamicTable, name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);
        
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);
        
        const entry = Entry{
            .name = name_copy,
            .value = value_copy,
        };
        
        const entry_size = entry.size();
        
        // Evict entries if necessary
        while (self.current_size + entry_size > self.max_size and self.entries.items.len > 0) {
            if (self.entries.popOrNull()) |evicted| {
                self.current_size -= evicted.size();
                evicted.deinit(self.allocator);
            }
        }
        
        if (entry_size <= self.max_size) {
            try self.entries.insert(0, entry);
            self.current_size += entry_size;
        } else {
            // Entry too large, don't add it
            entry.deinit(self.allocator);
        }
    }
    
    pub fn get(self: *DynamicTable, index: usize) ?Entry {
        if (index == 0 or index > self.entries.items.len) return null;
        return self.entries.items[index - 1];
    }
    
    pub fn setMaxSize(self: *DynamicTable, new_max_size: usize) void {
        self.max_size = new_max_size;
        
        // Evict entries if current size exceeds new max
        while (self.current_size > self.max_size and self.entries.items.len > 0) {
            const evicted = self.entries.pop();
            self.current_size -= evicted.size();
            evicted.deinit(self.allocator);
        }
    }
};

/// HPACK Encoder/Decoder
pub const Context = struct {
    dynamic_table: DynamicTable,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) Context {
        return Context{
            .dynamic_table = DynamicTable.init(allocator, 4096), // Default size
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Context) void {
        self.dynamic_table.deinit();
    }
    
    /// Encode headers using HPACK
    pub fn encode(self: *Context, headers: []const HeaderField) ![]u8 {
        var output = std.ArrayList(u8).init(self.allocator);
        defer output.deinit(self.allocator);
        
        for (headers) |header| {
            try self.encodeHeader(&output, header.name, header.value);
        }
        
        return output.toOwnedSlice();
    }
    
    /// Decode HPACK-encoded headers
    pub fn decode(self: *Context, data: []const u8) ![]HeaderField {
        var headers = std.ArrayList(HeaderField).init(self.allocator);
        defer headers.deinit(self.allocator);
        
        var i: usize = 0;
        while (i < data.len) {
            const header = try self.decodeHeader(data[i..], &i);
            try headers.append(header);
        }
        
        return headers.toOwnedSlice();
    }
    
    fn encodeHeader(self: *Context, output: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
        // Try to find in static/dynamic tables
        if (StaticTable.find(name, value)) |index| {
            // Indexed Header Field
            try self.encodeInteger(output, index, 7, 0x80);
            return;
        }
        
        if (StaticTable.findName(name)) |name_index| {
            // Literal Header Field with Incremental Indexing — Indexed Name
            try self.encodeInteger(output, name_index, 6, 0x40);
            try self.encodeString(output, value);
            try self.dynamic_table.add(name, value);
            return;
        }
        
        // Check dynamic table
        for (self.dynamic_table.entries.items, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                // Indexed Header Field (dynamic table)
                const index = StaticTable.static_entries.len + i + 1;
                try self.encodeInteger(output, index, 7, 0x80);
                return;
            }
        }
        
        for (self.dynamic_table.entries.items, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                // Literal Header Field with Incremental Indexing — Indexed Name (dynamic)
                const index = StaticTable.static_entries.len + i + 1;
                try self.encodeInteger(output, index, 6, 0x40);
                try self.encodeString(output, value);
                try self.dynamic_table.add(name, value);
                return;
            }
        }
        
        // Literal Header Field with Incremental Indexing — New Name
        try output.append(0x40); // Pattern: 01
        try self.encodeString(output, name);
        try self.encodeString(output, value);
        try self.dynamic_table.add(name, value);
    }
    
    fn decodeHeader(self: *Context, data: []const u8, pos: *usize) !HeaderField {
        if (data.len == 0) return error.InvalidHeader;
        
        const first_byte = data[0];
        
        if ((first_byte & 0x80) != 0) {
            // Indexed Header Field
            const index = try self.decodeInteger(data, pos, 7, 0x80);
            const entry = self.getTableEntry(index) orelse return error.InvalidIndex;
            return HeaderField{
                .name = try self.allocator.dupe(u8, entry.name),
                .value = try self.allocator.dupe(u8, entry.value),
            };
        } else if ((first_byte & 0x40) != 0) {
            // Literal Header Field with Incremental Indexing
            return self.decodeLiteral(data, pos, 6, 0x40, true);
        } else if ((first_byte & 0xF0) == 0) {
            // Literal Header Field without Indexing
            return self.decodeLiteral(data, pos, 4, 0x00, false);
        } else if ((first_byte & 0xF0) == 0x10) {
            // Literal Header Field never Indexed
            return self.decodeLiteral(data, pos, 4, 0x10, false);
        } else if ((first_byte & 0xE0) == 0x20) {
            // Dynamic Table Size Update
            const new_size = try self.decodeInteger(data, pos, 5, 0x20);
            self.dynamic_table.setMaxSize(new_size);
            return self.decodeHeader(data[*pos..], pos); // Continue with next header
        }
        
        return error.InvalidHeader;
    }
    
    fn decodeLiteral(self: *Context, data: []const u8, pos: *usize, prefix: u3, pattern: u8, add_to_table: bool) !HeaderField {
        const name_index = try self.decodeInteger(data, pos, prefix, pattern);
        
        var name: []u8 = undefined;
        if (name_index == 0) {
            // New name
            name = try self.decodeString(data[*pos..], pos);
        } else {
            // Indexed name
            const entry = self.getTableEntry(name_index) orelse return error.InvalidIndex;
            name = try self.allocator.dupe(u8, entry.name);
        }
        
        const value = try self.decodeString(data[*pos..], pos);
        
        if (add_to_table) {
            try self.dynamic_table.add(name, value);
        }
        
        return HeaderField{
            .name = name,
            .value = value,
        };
    }
    
    fn getTableEntry(self: *Context, index: usize) ?StaticTable.Entry {
        if (index <= StaticTable.static_entries.len) {
            return StaticTable.get(index);
        }
        
        const dynamic_index = index - StaticTable.static_entries.len - 1;
        if (dynamic_index < self.dynamic_table.entries.items.len) {
            const entry = self.dynamic_table.entries.items[dynamic_index];
            return StaticTable.Entry{
                .name = entry.name,
                .value = entry.value,
            };
        }
        
        return null;
    }
    
    fn encodeInteger(self: *Context, output: *std.ArrayList(u8), value: usize, prefix: u3, pattern: u8) !void {
        _ = self;
        const max_value = (@as(usize, 1) << prefix) - 1;
        
        if (value < max_value) {
            try output.append(@intCast(pattern | value));
        } else {
            try output.append(@intCast(pattern | max_value));
            var remaining = value - max_value;
            
            while (remaining >= 128) {
                try output.append(@intCast((remaining % 128) + 128));
                remaining /= 128;
            }
            try output.append(@intCast(remaining));
        }
    }
    
    fn decodeInteger(self: *Context, data: []const u8, pos: *usize, prefix: u3, pattern: u8) !usize {
        _ = pattern;
        _ = self;
        if (data.len == 0) return error.InvalidInteger;
        
        const max_value = (@as(usize, 1) << prefix) - 1;
        var value: usize = data[0] & @as(u8, @intCast(max_value));
        pos.* += 1;
        
        if (value < max_value) {
            return value;
        }
        
        var m: usize = 0;
        while (*pos < data.len) {
            const byte = data[*pos];
            pos.* += 1;
            
            value += @as(usize, byte & 127) << @intCast(m);
            m += 7;
            
            if ((byte & 128) == 0) {
                break;
            }
        }
        
        return value;
    }
    
    fn encodeString(self: *Context, output: *std.ArrayList(u8), string: []const u8) !void {
        // Simple implementation - no Huffman coding for now
        try self.encodeInteger(output, string.len, 7, 0x00);
        try output.appendSlice(string);
    }
    
    fn decodeString(self: *Context, data: []const u8, pos: *usize) ![]u8 {
        if (data.len == 0) return error.InvalidString;
        
        const huffman = (data[0] & 0x80) != 0;
        const length = try self.decodeInteger(data, pos, 7, 0x00);
        
        if (*pos + length > data.len) return error.InvalidString;
        
        const string_data = data[*pos..*pos + length];
        pos.* += length;
        
        if (huffman) {
            // TODO: Implement Huffman decoding
            return error.HuffmanNotImplemented;
        } else {
            return self.allocator.dupe(u8, string_data);
        }
    }
};

/// Header field structure
pub const HeaderField = struct {
    name: []u8,
    value: []u8,
    
    pub fn deinit(self: HeaderField, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
    }
};

// Tests
test "HPACK static table lookup" {
    const testing = std.testing;
    
    const entry = StaticTable.get(2);
    try testing.expect(entry != null);
    try testing.expectEqualStrings(entry.?.name, ":method");
    try testing.expectEqualStrings(entry.?.value, "GET");
    
    const index = StaticTable.find(":method", "GET");
    try testing.expect(index == 2);
}

test "HPACK dynamic table" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var table = DynamicTable.init(allocator, 4096);
    defer table.deinit();
    
    try table.add("custom-header", "custom-value");
    
    const entry = table.get(1);
    try testing.expect(entry != null);
    try testing.expectEqualStrings(entry.?.name, "custom-header");
    try testing.expectEqualStrings(entry.?.value, "custom-value");
}

test "HPACK encode/decode simple header" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var context = Context.init(allocator);
    defer context.deinit();
    
    const headers = [_]HeaderField{
        HeaderField{
            .name = try allocator.dupe(u8, ":method"),
            .value = try allocator.dupe(u8, "GET"),
        },
    };
    defer {
        for (headers) |header| {
            header.deinit(allocator);
        }
    }
    
    const encoded = try context.encode(&headers);
    defer allocator.free(encoded);
    
    const decoded = try context.decode(encoded);
    defer {
        for (decoded) |header| {
            header.deinit(allocator);
        }
        allocator.free(decoded);
    }
    
    try testing.expect(decoded.len == 1);
    try testing.expectEqualStrings(decoded[0].name, ":method");
    try testing.expectEqualStrings(decoded[0].value, "GET");
}