const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");
const udp = @import("../transport/udp.zig");
const errors = @import("../errors/errors.zig");

pub const NODE_ID_SIZE = 32; // 256 bits
pub const K_BUCKET_SIZE = 20; // Kademlia constant K
pub const ALPHA = 3; // Concurrency parameter
pub const B = 160; // Number of bits in a NodeID (for 160-bit keys)

pub const NodeID = [NODE_ID_SIZE]u8;

pub const KademliaRpcType = enum(u8) {
    ping = 0x01,
    pong = 0x02,
    find_node = 0x03,
    find_node_response = 0x04,
    find_value = 0x05,
    find_value_response = 0x06,
    store = 0x07,
    store_response = 0x08,
};

pub const KademliaMessage = struct {
    message_type: KademliaRpcType,
    transaction_id: [16]u8,
    sender_id: NodeID,
    target_id: ?NodeID,
    nodes: []NodeContact,
    key: ?[]const u8,
    value: ?[]const u8,
    timestamp: i64,
    
    pub fn init(allocator: std.mem.Allocator, message_type: KademliaRpcType, sender_id: NodeID) !KademliaMessage {
        _ = allocator;
        var transaction_id: [16]u8 = undefined;
        std.crypto.random.bytes(&transaction_id);
        
        return KademliaMessage{
            .message_type = message_type,
            .transaction_id = transaction_id,
            .sender_id = sender_id,
            .target_id = null,
            .nodes = &[_]NodeContact{},
            .key = null,
            .value = null,
            .timestamp = std.time.timestamp(),
        };
    }
    
    pub fn deinit(self: *KademliaMessage, allocator: std.mem.Allocator) void {
        if (self.nodes.len > 0) {
            allocator.free(self.nodes);
        }
        if (self.key) |key| {
            allocator.free(key);
        }
        if (self.value) |value| {
            allocator.free(value);
        }
    }
    
    pub fn serialize(self: *KademliaMessage, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        
        // Header
        try buffer.append(@intFromEnum(self.message_type));
        try buffer.appendSlice(&self.transaction_id);
        try buffer.appendSlice(&self.sender_id);
        
        // Timestamp (8 bytes, big endian)
        const timestamp_u64 = @as(u64, @bitCast(self.timestamp));
        try buffer.append(@intCast(timestamp_u64 >> 56));
        try buffer.append(@intCast((timestamp_u64 >> 48) & 0xFF));
        try buffer.append(@intCast((timestamp_u64 >> 40) & 0xFF));
        try buffer.append(@intCast((timestamp_u64 >> 32) & 0xFF));
        try buffer.append(@intCast((timestamp_u64 >> 24) & 0xFF));
        try buffer.append(@intCast((timestamp_u64 >> 16) & 0xFF));
        try buffer.append(@intCast((timestamp_u64 >> 8) & 0xFF));
        try buffer.append(@intCast(timestamp_u64 & 0xFF));
        
        // Target ID (optional)
        if (self.target_id) |target| {
            try buffer.append(1); // Has target
            try buffer.appendSlice(&target);
        } else {
            try buffer.append(0); // No target
        }
        
        // Nodes count and nodes
        try buffer.append(@intCast(self.nodes.len));
        for (self.nodes) |node| {
            try buffer.appendSlice(&node.id);
            
            // Address serialization
            switch (node.address) {
                .ipv4 => |addr| {
                    try buffer.append(4); // IPv4
                    try buffer.appendSlice(std.mem.asBytes(&addr.sa.addr));
                    try buffer.append(@intCast(addr.sa.port >> 8));
                    try buffer.append(@intCast(addr.sa.port & 0xFF));
                },
                .ipv6 => |addr| {
                    try buffer.append(6); // IPv6
                    try buffer.appendSlice(&addr.sa.addr);
                    try buffer.append(@intCast(addr.sa.port >> 8));
                    try buffer.append(@intCast(addr.sa.port & 0xFF));
                },
                else => {
                    try buffer.append(0); // Unknown
                },
            }
            
            // Last seen timestamp
            const last_seen_u64 = @as(u64, @bitCast(node.last_seen));
            try buffer.append(@intCast(last_seen_u64 >> 56));
            try buffer.append(@intCast((last_seen_u64 >> 48) & 0xFF));
            try buffer.append(@intCast((last_seen_u64 >> 40) & 0xFF));
            try buffer.append(@intCast((last_seen_u64 >> 32) & 0xFF));
            try buffer.append(@intCast((last_seen_u64 >> 24) & 0xFF));
            try buffer.append(@intCast((last_seen_u64 >> 16) & 0xFF));
            try buffer.append(@intCast((last_seen_u64 >> 8) & 0xFF));
            try buffer.append(@intCast(last_seen_u64 & 0xFF));
        }
        
        // Key (optional)
        if (self.key) |key| {
            try buffer.append(@intCast(key.len));
            try buffer.appendSlice(key);
        } else {
            try buffer.append(0);
        }
        
        // Value (optional)
        if (self.value) |value| {
            try buffer.append(@intCast(value.len >> 8));
            try buffer.append(@intCast(value.len & 0xFF));
            try buffer.appendSlice(value);
        } else {
            try buffer.append(0);
            try buffer.append(0);
        }
        
        return buffer.toOwnedSlice();
    }
    
    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !KademliaMessage {
        if (data.len < 57) return error.InvalidMessageLength; // Minimum header size
        
        var offset: usize = 0;
        
        // Message type
        const message_type: KademliaRpcType = @enumFromInt(data[offset]);
        offset += 1;
        
        // Transaction ID
        const transaction_id = data[offset..offset + 16][0..16].*;
        offset += 16;
        
        // Sender ID
        const sender_id = data[offset..offset + 32][0..32].*;
        offset += 32;
        
        // Timestamp
        var timestamp_u64: u64 = 0;
        for (0..8) |i| {
            timestamp_u64 = (timestamp_u64 << 8) | data[offset + i];
        }
        const timestamp = @as(i64, @bitCast(timestamp_u64));
        offset += 8;
        
        // Target ID
        const has_target = data[offset] != 0;
        offset += 1;
        
        var target_id: ?NodeID = null;
        if (has_target) {
            target_id = data[offset..offset + 32][0..32].*;
            offset += 32;
        }
        
        // Nodes
        const nodes_count = data[offset];
        offset += 1;
        
        var nodes = try allocator.alloc(NodeContact, nodes_count);
        for (0..nodes_count) |i| {
            // Node ID
            const node_id = data[offset..offset + 32][0..32].*;
            offset += 32;
            
            // Address
            const addr_type = data[offset];
            offset += 1;
            
            var address: transport.Address = undefined;
            switch (addr_type) {
                4 => { // IPv4
                    const addr_bytes = data[offset..offset + 4][0..4].*;
                    const port = (@as(u16, data[offset + 4]) << 8) | data[offset + 5];
                    address = transport.Address{ .ipv4 = std.net.Ip4Address.init(addr_bytes, port) };
                    offset += 6;
                },
                6 => { // IPv6
                    const addr_bytes = data[offset..offset + 16][0..16].*;
                    const port = (@as(u16, data[offset + 16]) << 8) | data[offset + 17];
                    address = transport.Address{ .ipv6 = std.net.Ipv6Address.init(addr_bytes, port, 0, 0) };
                    offset += 18;
                },
                else => {
                    return error.UnsupportedAddressType;
                },
            }
            
            // Last seen
            var last_seen_u64: u64 = 0;
            for (0..8) |j| {
                last_seen_u64 = (last_seen_u64 << 8) | data[offset + j];
            }
            const last_seen = @as(i64, @bitCast(last_seen_u64));
            offset += 8;
            
            nodes[i] = NodeContact{
                .id = node_id,
                .address = address,
                .last_seen = last_seen,
            };
        }
        
        // Key
        const key_len = data[offset];
        offset += 1;
        
        var key: ?[]const u8 = null;
        if (key_len > 0) {
            key = try allocator.dupe(u8, data[offset..offset + key_len]);
            offset += key_len;
        }
        
        // Value
        const value_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
        offset += 2;
        
        var value: ?[]const u8 = null;
        if (value_len > 0) {
            value = try allocator.dupe(u8, data[offset..offset + value_len]);
        }
        
        return KademliaMessage{
            .message_type = message_type,
            .transaction_id = transaction_id,
            .sender_id = sender_id,
            .target_id = target_id,
            .nodes = nodes,
            .key = key,
            .value = value,
            .timestamp = timestamp,
        };
    }
};

pub const NodeContact = struct {
    id: NodeID,
    address: transport.Address,
    last_seen: i64,
    
    pub fn init(id: NodeID, address: transport.Address) NodeContact {
        return NodeContact{
            .id = id,
            .address = address,
            .last_seen = std.time.timestamp(),
        };
    }
    
    pub fn updateLastSeen(self: *NodeContact) void {
        self.last_seen = std.time.timestamp();
    }
    
    pub fn isStale(self: *NodeContact, timeout: i64) bool {
        return (std.time.timestamp() - self.last_seen) > timeout;
    }
    
    pub fn distanceTo(self: *NodeContact, other_id: NodeID) NodeID {
        return xorDistance(self.id, other_id);
    }
};

pub const KBucket = struct {
    nodes: std.ArrayList(NodeContact),
    max_size: usize,
    
    pub fn init(allocator: std.mem.Allocator, max_size: usize) KBucket {
        return KBucket{
            .nodes = std.ArrayList(NodeContact).init(allocator),
            .max_size = max_size,
        };
    }
    
    pub fn deinit(self: *KBucket) void {
        self.nodes.deinit();
    }
    
    pub fn addNode(self: *KBucket, node: NodeContact) !bool {
        // Check if node already exists
        for (self.nodes.items, 0..) |existing, i| {
            if (std.mem.eql(u8, &existing.id, &node.id)) {
                // Update existing node
                self.nodes.items[i] = node;
                return true;
            }
        }
        
        // Add new node if there's space
        if (self.nodes.items.len < self.max_size) {
            try self.nodes.append(node);
            return true;
        }
        
        // Bucket is full - could implement LRU eviction here
        return false;
    }
    
    pub fn removeNode(self: *KBucket, node_id: NodeID) bool {
        for (self.nodes.items, 0..) |node, i| {
            if (std.mem.eql(u8, &node.id, &node_id)) {
                _ = self.nodes.swapRemove(i);
                return true;
            }
        }
        return false;
    }
    
    pub fn getNode(self: *KBucket, node_id: NodeID) ?NodeContact {
        for (self.nodes.items) |node| {
            if (std.mem.eql(u8, &node.id, &node_id)) {
                return node;
            }
        }
        return null;
    }
    
    pub fn getClosestNodes(self: *KBucket, target_id: NodeID, count: usize) []NodeContact {
        var nodes_with_distance = std.ArrayList(struct { node: NodeContact, distance: NodeID }).init(self.nodes.allocator);
        defer nodes_with_distance.deinit();
        
        // Calculate distances
        for (self.nodes.items) |node| {
            const distance = xorDistance(node.id, target_id);
            nodes_with_distance.append(.{ .node = node, .distance = distance }) catch continue;
        }
        
        // Sort by distance
        std.sort.block(struct { node: NodeContact, distance: NodeID }, nodes_with_distance.items, {}, struct {
            fn lessThan(context: void, a: struct { node: NodeContact, distance: NodeID }, b: struct { node: NodeContact, distance: NodeID }) bool {
                _ = context;
                return isCloser(a.distance, b.distance);
            }
        }.lessThan);
        
        // Return closest nodes
        const result_count = std.math.min(count, nodes_with_distance.items.len);
        const result = self.nodes.allocator.alloc(NodeContact, result_count) catch return &[_]NodeContact{};
        
        for (0..result_count) |i| {
            result[i] = nodes_with_distance.items[i].node;
        }
        
        return result;
    }
    
    pub fn isFull(self: *KBucket) bool {
        return self.nodes.items.len >= self.max_size;
    }
    
    pub fn size(self: *KBucket) usize {
        return self.nodes.items.len;
    }
};

pub const RoutingTable = struct {
    buckets: [160]KBucket, // 160 buckets for 160-bit key space
    node_id: NodeID,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, node_id: NodeID) RoutingTable {
        var table = RoutingTable{
            .buckets = undefined,
            .node_id = node_id,
            .allocator = allocator,
        };
        
        // Initialize buckets
        for (0..160) |i| {
            table.buckets[i] = KBucket.init(allocator, K_BUCKET_SIZE);
        }
        
        return table;
    }
    
    pub fn deinit(self: *RoutingTable) void {
        for (0..160) |i| {
            self.buckets[i].deinit();
        }
    }
    
    pub fn addNode(self: *RoutingTable, node: NodeContact) !void {
        if (std.mem.eql(u8, &node.id, &self.node_id)) {
            return; // Don't add ourselves
        }
        
        const bucket_index = getBucketIndex(self.node_id, node.id);
        _ = try self.buckets[bucket_index].addNode(node);
    }
    
    pub fn removeNode(self: *RoutingTable, node_id: NodeID) void {
        const bucket_index = getBucketIndex(self.node_id, node_id);
        _ = self.buckets[bucket_index].removeNode(node_id);
    }
    
    pub fn findClosestNodes(self: *RoutingTable, target_id: NodeID, count: usize) []NodeContact {
        var all_nodes = std.ArrayList(NodeContact).init(self.allocator);
        defer all_nodes.deinit();
        
        // Collect all nodes from all buckets
        for (self.buckets) |bucket| {
            for (bucket.nodes.items) |node| {
                all_nodes.append(node) catch continue;
            }
        }
        
        // Sort by distance to target
        var nodes_with_distance = std.ArrayList(struct { node: NodeContact, distance: NodeID }).init(self.allocator);
        defer nodes_with_distance.deinit();
        
        for (all_nodes.items) |node| {
            const distance = xorDistance(node.id, target_id);
            nodes_with_distance.append(.{ .node = node, .distance = distance }) catch continue;
        }
        
        std.sort.block(struct { node: NodeContact, distance: NodeID }, nodes_with_distance.items, {}, struct {
            fn lessThan(context: void, a: struct { node: NodeContact, distance: NodeID }, b: struct { node: NodeContact, distance: NodeID }) bool {
                _ = context;
                return isCloser(a.distance, b.distance);
            }
        }.lessThan);
        
        // Return closest nodes
        const result_count = std.math.min(count, nodes_with_distance.items.len);
        const result = self.allocator.alloc(NodeContact, result_count) catch return &[_]NodeContact{};
        
        for (0..result_count) |i| {
            result[i] = nodes_with_distance.items[i].node;
        }
        
        return result;
    }
    
    pub fn getNode(self: *RoutingTable, node_id: NodeID) ?NodeContact {
        const bucket_index = getBucketIndex(self.node_id, node_id);
        return self.buckets[bucket_index].getNode(node_id);
    }
    
    pub fn size(self: *RoutingTable) usize {
        var total: usize = 0;
        for (self.buckets) |bucket| {
            total += bucket.size();
        }
        return total;
    }
};

pub const StorageItem = struct {
    key: []const u8,
    value: []const u8,
    timestamp: i64,
    ttl: i64,
    
    pub fn init(allocator: std.mem.Allocator, key: []const u8, value: []const u8, ttl: i64) !StorageItem {
        return StorageItem{
            .key = try allocator.dupe(u8, key),
            .value = try allocator.dupe(u8, value),
            .timestamp = std.time.timestamp(),
            .ttl = ttl,
        };
    }
    
    pub fn deinit(self: *StorageItem, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }
    
    pub fn isExpired(self: *StorageItem) bool {
        return self.ttl > 0 and (std.time.timestamp() - self.timestamp) > self.ttl;
    }
};

pub const KademliaConfig = struct {
    node_id: NodeID,
    k: usize = K_BUCKET_SIZE,
    alpha: usize = ALPHA,
    rpc_timeout: u64 = 5000, // 5 seconds
    refresh_interval: u64 = 3600000, // 1 hour
    expire_interval: u64 = 86400000, // 24 hours
    storage_max_size: usize = 10000,
    storage_ttl: i64 = 86400, // 24 hours
};

pub const KademliaNode = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    config: KademliaConfig,
    socket: udp.UdpSocket,
    routing_table: RoutingTable,
    storage: std.StringHashMap(StorageItem),
    pending_requests: std.HashMap([16]u8, PendingRequest, TransactionHashContext, 80),
    
    // Statistics
    stats: KademliaStats,
    
    // Control
    running: std.atomic.Value(bool),
    mutex: std.Thread.Mutex,
    
    pub const PendingRequest = struct {
        transaction_id: [16]u8,
        message_type: KademliaRpcType,
        target_id: NodeID,
        timestamp: i64,
        response_future: zsync.Future,
        response: ?KademliaMessage,
        completed: std.atomic.Value(bool),
        
        pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, transaction_id: [16]u8, message_type: KademliaRpcType, target_id: NodeID) PendingRequest {
            _ = allocator;
            return PendingRequest{
                .transaction_id = transaction_id,
                .message_type = message_type,
                .target_id = target_id,
                .timestamp = std.time.timestamp(),
                .response_future = zsync.Future.init(runtime, struct {
                    request: *PendingRequest,
                    
                    pub fn poll(ctx: *@This()) zsync.Poll(?KademliaMessage) {
                        if (ctx.request.completed.load(.seq_cst)) {
                            return .{ .ready = ctx.request.response };
                        }
                        return .pending;
                    }
                }{ .request = undefined }),
                .response = null,
                .completed = std.atomic.Value(bool).init(false),
            };
        }
        
        pub fn complete(self: *PendingRequest, response: ?KademliaMessage) void {
            self.response = response;
            self.completed.store(true, .seq_cst);
        }
    };
    
    pub const TransactionHashContext = struct {
        pub fn hash(self: @This(), key: [16]u8) u64 {
            _ = self;
            return std.hash_map.hashString(std.mem.asBytes(&key));
        }
        
        pub fn eql(self: @This(), a: [16]u8, b: [16]u8) bool {
            _ = self;
            return std.mem.eql(u8, &a, &b);
        }
    };
    
    pub const KademliaStats = struct {
        requests_sent: std.atomic.Value(u64),
        requests_received: std.atomic.Value(u64),
        responses_sent: std.atomic.Value(u64),
        responses_received: std.atomic.Value(u64),
        lookup_operations: std.atomic.Value(u64),
        store_operations: std.atomic.Value(u64),
        nodes_discovered: std.atomic.Value(u64),
        storage_items: std.atomic.Value(u64),
        
        pub fn init() KademliaStats {
            return .{
                .requests_sent = std.atomic.Value(u64).init(0),
                .requests_received = std.atomic.Value(u64).init(0),
                .responses_sent = std.atomic.Value(u64).init(0),
                .responses_received = std.atomic.Value(u64).init(0),
                .lookup_operations = std.atomic.Value(u64).init(0),
                .store_operations = std.atomic.Value(u64).init(0),
                .nodes_discovered = std.atomic.Value(u64).init(0),
                .storage_items = std.atomic.Value(u64).init(0),
            };
        }
    };
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, config: KademliaConfig) !*KademliaNode {
        const node = try allocator.create(KademliaNode);
        node.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .config = config,
            .socket = udp.UdpSocket.init(allocator, runtime),
            .routing_table = RoutingTable.init(allocator, config.node_id),
            .storage = std.StringHashMap(StorageItem).init(allocator),
            .pending_requests = std.HashMap([16]u8, PendingRequest, TransactionHashContext, 80).init(allocator),
            .stats = KademliaStats.init(),
            .running = std.atomic.Value(bool).init(false),
            .mutex = .{},
        };
        
        return node;
    }
    
    pub fn deinit(self: *KademliaNode) void {
        self.stop();
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Clean up storage
        var storage_iter = self.storage.iterator();
        while (storage_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.storage.deinit();
        
        self.routing_table.deinit();
        self.pending_requests.deinit();
        self.socket.close();
        
        self.allocator.destroy(self);
    }
    
    pub fn start(self: *KademliaNode, bind_address: transport.Address) !void {
        try self.socket.bind(bind_address, transport.TransportOptions{ .allocator = self.allocator });
        
        self.running.store(true, .seq_cst);
        
        // Start background tasks
        _ = try self.runtime.spawn(receiveLoop, .{self}, .normal);
        _ = try self.runtime.spawn(maintenanceLoop, .{self}, .normal);
        _ = try self.runtime.spawn(refreshLoop, .{self}, .normal);
    }
    
    pub fn stop(self: *KademliaNode) void {
        self.running.store(false, .seq_cst);
    }
    
    pub fn bootstrap(self: *KademliaNode, bootstrap_nodes: []const NodeContact) !void {
        // Add bootstrap nodes to routing table
        for (bootstrap_nodes) |node| {
            try self.routing_table.addNode(node);
        }
        
        // Perform initial lookup for our own ID to populate routing table
        _ = try self.findNode(self.config.node_id);
    }
    
    pub fn ping(self: *KademliaNode, target: NodeContact) !void {
        var message = try KademliaMessage.init(self.allocator, .ping, self.config.node_id);
        defer message.deinit(self.allocator);
        
        try self.sendMessage(&message, target.address);
    }
    
    pub fn findNode(self: *KademliaNode, target_id: NodeID) ![]NodeContact {
        _ = self.stats.lookup_operations.fetchAdd(1, .seq_cst);
        
        // Start with closest known nodes
        const closest_nodes = self.routing_table.findClosestNodes(target_id, self.config.k);
        defer self.allocator.free(closest_nodes);
        
        // Iterative lookup
        var queried_nodes = std.HashMap(NodeID, void, NodeIDHashContext, 80).init(self.allocator);
        defer queried_nodes.deinit();
        
        var active_queries: usize = 0;
        const max_queries = self.config.alpha;
        
        while (active_queries > 0 or queried_nodes.count() < self.config.k) {
            // Find unqueried nodes to query
            var nodes_to_query = std.ArrayList(NodeContact).init(self.allocator);
            defer nodes_to_query.deinit();
            
            for (closest_nodes) |node| {
                if (!queried_nodes.contains(node.id) and nodes_to_query.items.len < max_queries) {
                    try nodes_to_query.append(node);
                }
            }
            
            if (nodes_to_query.items.len == 0) {
                break;
            }
            
            // Query nodes
            for (nodes_to_query.items) |node| {
                try queried_nodes.put(node.id, {});
                self.queryNodeForFindNode(node, target_id) catch continue;
                active_queries += 1;
            }
            
            // Wait for responses using async futures
            var response_futures = std.ArrayList(zsync.Future).init(self.allocator);
            defer response_futures.deinit();
            
            for (nodes_to_query.items) |node| {
                const future = try self.runtime.spawn(waitForResponse, .{ self, node.id }, .normal);
                try response_futures.append(future);
            }
            
            // Wait for all responses or timeout
            const timeout_ns = self.config.rpc_timeout * 1000000; // Convert to nanoseconds
            for (response_futures.items) |future| {
                _ = self.runtime.awaitTimeout(future, timeout_ns) catch continue;
            }
            
            active_queries = 0; // Reset for next iteration
        }
        
        // Return final closest nodes
        return self.routing_table.findClosestNodes(target_id, self.config.k);
    }
    
    fn queryNodeForFindNode(self: *KademliaNode, node: NodeContact, target_id: NodeID) !void {
        var message = try KademliaMessage.init(self.allocator, .find_node, self.config.node_id);
        defer message.deinit(self.allocator);
        
        message.target_id = target_id;
        
        try self.sendMessage(&message, node.address);
    }
    
    pub fn findValue(self: *KademliaNode, key: []const u8) !?[]const u8 {
        // First check local storage
        if (self.storage.get(key)) |item| {
            if (!item.isExpired()) {
                return try self.allocator.dupe(u8, item.value);
            }
        }
        
        // Calculate target ID from key
        var target_id: NodeID = undefined;
        std.crypto.hash.sha3.Sha3_256.hash(key, &target_id, .{});
        
        // Find closest nodes
        const closest_nodes = try self.findNode(target_id);
        defer self.allocator.free(closest_nodes);
        
        // Query nodes for value
        for (closest_nodes) |node| {
            if (try self.queryNodeForValue(node, key)) |value| {
                return value;
            }
        }
        
        return null;
    }
    
    fn queryNodeForValue(self: *KademliaNode, node: NodeContact, key: []const u8) !?[]const u8 {
        var message = try KademliaMessage.init(self.allocator, .find_value, self.config.node_id);
        defer message.deinit(self.allocator);
        
        message.key = try self.allocator.dupe(u8, key);
        
        try self.sendMessage(&message, node.address);
        
        // Wait for response using async future
        const timeout_ms = self.config.rpc_timeout;
        const response_future = self.waitForResponse(message.transaction_id, timeout_ms);
        
        if (try self.runtime.await(response_future)) |response| {
            if (response.value) |value| {
                return try self.allocator.dupe(u8, value);
            }
        }
        
        return null;
    }
    
    pub fn store(self: *KademliaNode, key: []const u8, value: []const u8) !void {
        _ = self.stats.store_operations.fetchAdd(1, .seq_cst);
        
        // Calculate target ID from key
        var target_id: NodeID = undefined;
        std.crypto.hash.sha3.Sha3_256.hash(key, &target_id, .{});
        
        // Find closest nodes
        const closest_nodes = try self.findNode(target_id);
        defer self.allocator.free(closest_nodes);
        
        // Store on closest nodes
        for (closest_nodes) |node| {
            self.storeOnNode(node, key, value) catch continue;
        }
        
        // Also store locally
        try self.storeLocally(key, value);
    }
    
    fn storeOnNode(self: *KademliaNode, node: NodeContact, key: []const u8, value: []const u8) !void {
        var message = try KademliaMessage.init(self.allocator, .store, self.config.node_id);
        defer message.deinit(self.allocator);
        
        message.key = try self.allocator.dupe(u8, key);
        message.value = try self.allocator.dupe(u8, value);
        
        try self.sendMessage(&message, node.address);
    }
    
    fn storeLocally(self: *KademliaNode, key: []const u8, value: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Remove old item if exists
        if (self.storage.fetchRemove(key)) |kv| {
            kv.value.deinit(self.allocator);
            _ = self.stats.storage_items.fetchSub(1, .seq_cst);
        }
        
        // Check storage limits
        if (self.storage.count() >= self.config.storage_max_size) {
            // Remove oldest item
            self.evictOldestItem();
        }
        
        // Store new item
        const item = try StorageItem.init(self.allocator, key, value, self.config.storage_ttl);
        try self.storage.put(key, item);
        _ = self.stats.storage_items.fetchAdd(1, .seq_cst);
    }
    
    fn evictOldestItem(self: *KademliaNode) void {
        var oldest_key: ?[]const u8 = null;
        var oldest_timestamp: i64 = std.math.maxInt(i64);
        
        var iter = self.storage.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.timestamp < oldest_timestamp) {
                oldest_timestamp = entry.value_ptr.timestamp;
                oldest_key = entry.key_ptr.*;
            }
        }
        
        if (oldest_key) |key| {
            if (self.storage.fetchRemove(key)) |kv| {
                kv.value.deinit(self.allocator);
                _ = self.stats.storage_items.fetchSub(1, .seq_cst);
            }
        }
    }
    
    fn sendMessage(self: *KademliaNode, message: *KademliaMessage, address: transport.Address) !void {
        const data = try message.serialize(self.allocator);
        defer self.allocator.free(data);
        
        _ = try self.socket.sendTo(data, address);
        _ = self.stats.requests_sent.fetchAdd(1, .seq_cst);
    }
    
    fn receiveLoop(self: *KademliaNode) void {
        var buffer: [65536]u8 = undefined;
        
        while (self.running.load(.seq_cst)) {
            const packet = self.socket.recvFromAsync(&buffer) catch continue;
            
            switch (packet) {
                .ready => |result| {
                    if (result) |pkt| {
                        self.handleMessage(pkt.data, pkt.address) catch |err| {
                            std.log.err("Error handling Kademlia message: {}", .{err});
                        };
                    } else |_| {
                        continue;
                    }
                },
                .pending => {
                    // Yield to allow other tasks to run
                    _ = try self.runtime.yield();
                    continue;
                },
            }
        }
    }
    
    fn handleMessage(self: *KademliaNode, data: []const u8, sender_addr: transport.Address) !void {
        var message = KademliaMessage.deserialize(self.allocator, data) catch return;
        defer message.deinit(self.allocator);
        
        // Add sender to routing table
        const sender_contact = NodeContact.init(message.sender_id, sender_addr);
        try self.routing_table.addNode(sender_contact);
        _ = self.stats.nodes_discovered.fetchAdd(1, .seq_cst);
        
        // Check if this is a response to a pending request
        if (self.isResponseMessage(message.message_type)) {
            self.completePendingRequest(message);
        }
        
        switch (message.message_type) {
            .ping => {
                _ = self.stats.requests_received.fetchAdd(1, .seq_cst);
                try self.handlePing(&message, sender_addr);
            },
            .pong => {
                _ = self.stats.responses_received.fetchAdd(1, .seq_cst);
                try self.handlePong(&message, sender_addr);
            },
            .find_node => {
                _ = self.stats.requests_received.fetchAdd(1, .seq_cst);
                try self.handleFindNode(&message, sender_addr);
            },
            .find_node_response => {
                _ = self.stats.responses_received.fetchAdd(1, .seq_cst);
                try self.handleFindNodeResponse(&message, sender_addr);
            },
            .find_value => {
                _ = self.stats.requests_received.fetchAdd(1, .seq_cst);
                try self.handleFindValue(&message, sender_addr);
            },
            .find_value_response => {
                _ = self.stats.responses_received.fetchAdd(1, .seq_cst);
                try self.handleFindValueResponse(&message, sender_addr);
            },
            .store => {
                _ = self.stats.requests_received.fetchAdd(1, .seq_cst);
                try self.handleStore(&message, sender_addr);
            },
            .store_response => {
                _ = self.stats.responses_received.fetchAdd(1, .seq_cst);
                try self.handleStoreResponse(&message, sender_addr);
            },
        }
    }
    
    fn handlePing(self: *KademliaNode, message: *KademliaMessage, sender_addr: transport.Address) !void {
        var response = try KademliaMessage.init(self.allocator, .pong, self.config.node_id);
        defer response.deinit(self.allocator);
        
        response.transaction_id = message.transaction_id;
        
        try self.sendMessage(&response, sender_addr);
        _ = self.stats.responses_sent.fetchAdd(1, .seq_cst);
    }
    
    fn handlePong(self: *KademliaNode, message: *KademliaMessage, sender_addr: transport.Address) !void {
        // Update the node's activity in the routing table
        if (message.sender_id) |sender_id| {
            const node_contact = NodeContact{
                .id = sender_id,
                .address = sender_addr,
                .last_seen = std.time.timestamp(),
                .distance = try self.calculateDistance(self.config.node_id, sender_id),
            };
            
            try self.routing_table.updateNode(node_contact);
            
            // If this is a response to a pending request, complete it
            if (message.transaction_id) |tx_id| {
                if (self.pending_requests.get(tx_id)) |pending_request| {
                    // Mark the request as completed
                    pending_request.completed = true;
                    pending_request.response_time = std.time.timestamp();
                    
                    // Remove from pending requests
                    _ = self.pending_requests.remove(tx_id);
                    
                    // Update node reachability statistics
                    try self.updateNodeReachability(sender_id, true);
                }
            }
        }
    }
    
    fn handleFindNode(self: *KademliaNode, message: *KademliaMessage, sender_addr: transport.Address) !void {
        var response = try KademliaMessage.init(self.allocator, .find_node_response, self.config.node_id);
        defer response.deinit(self.allocator);
        
        response.transaction_id = message.transaction_id;
        
        if (message.target_id) |target_id| {
            response.nodes = self.routing_table.findClosestNodes(target_id, self.config.k);
        }
        
        try self.sendMessage(&response, sender_addr);
        _ = self.stats.responses_sent.fetchAdd(1, .seq_cst);
    }
    
    fn handleFindNodeResponse(self: *KademliaNode, message: *KademliaMessage, sender_addr: transport.Address) !void {
        _ = sender_addr;
        
        // Add returned nodes to routing table
        for (message.nodes) |node| {
            try self.routing_table.addNode(node);
        }
    }
    
    fn handleFindValue(self: *KademliaNode, message: *KademliaMessage, sender_addr: transport.Address) !void {
        var response = try KademliaMessage.init(self.allocator, .find_value_response, self.config.node_id);
        defer response.deinit(self.allocator);
        
        response.transaction_id = message.transaction_id;
        
        if (message.key) |key| {
            if (self.storage.get(key)) |item| {
                if (!item.isExpired()) {
                    response.value = try self.allocator.dupe(u8, item.value);
                }
            }
        }
        
        try self.sendMessage(&response, sender_addr);
        _ = self.stats.responses_sent.fetchAdd(1, .seq_cst);
    }
    
    fn handleFindValueResponse(self: *KademliaNode, message: *KademliaMessage, sender_addr: transport.Address) !void {
        // Update the node's activity in the routing table
        if (message.sender_id) |sender_id| {
            const node_contact = NodeContact{
                .id = sender_id,
                .address = sender_addr,
                .last_seen = std.time.timestamp(),
                .distance = try self.calculateDistance(self.config.node_id, sender_id),
            };
            
            try self.routing_table.updateNode(node_contact);
        }
        
        // Handle the response to a pending find value request
        if (message.transaction_id) |tx_id| {
            if (self.pending_requests.get(tx_id)) |pending_request| {
                // Mark the request as completed
                pending_request.completed = true;
                pending_request.response_time = std.time.timestamp();
                
                // If we got a value, cache it locally
                if (message.value) |value| {
                    if (message.key) |key| {
                        try self.storeLocally(key, value);
                        
                        // Update statistics
                        _ = self.stats.values_found.fetchAdd(1, .seq_cst);
                    }
                } else {
                    // If no value, but we got nodes, add them to routing table
                    if (message.nodes) |nodes| {
                        for (nodes) |node| {
                            try self.routing_table.addNode(node);
                        }
                    }
                }
                
                // Remove from pending requests
                _ = self.pending_requests.remove(tx_id);
                
                // Update node reachability statistics
                if (message.sender_id) |sender_id| {
                    try self.updateNodeReachability(sender_id, true);
                }
            }
        }
    }
    
    fn handleStore(self: *KademliaNode, message: *KademliaMessage, sender_addr: transport.Address) !void {
        if (message.key) |key| {
            if (message.value) |value| {
                try self.storeLocally(key, value);
            }
        }
        
        var response = try KademliaMessage.init(self.allocator, .store_response, self.config.node_id);
        defer response.deinit(self.allocator);
        
        response.transaction_id = message.transaction_id;
        
        try self.sendMessage(&response, sender_addr);
        _ = self.stats.responses_sent.fetchAdd(1, .seq_cst);
    }
    
    fn handleStoreResponse(self: *KademliaNode, message: *KademliaMessage, sender_addr: transport.Address) !void {
        // Update the node's activity in the routing table
        if (message.sender_id) |sender_id| {
            const node_contact = NodeContact{
                .id = sender_id,
                .address = sender_addr,
                .last_seen = std.time.timestamp(),
                .distance = try self.calculateDistance(self.config.node_id, sender_id),
            };
            
            try self.routing_table.updateNode(node_contact);
        }
        
        // Handle the response to a pending store request
        if (message.transaction_id) |tx_id| {
            if (self.pending_requests.get(tx_id)) |pending_request| {
                // Mark the request as completed
                pending_request.completed = true;
                pending_request.response_time = std.time.timestamp();
                
                // Update statistics based on success/failure
                if (message.success) |success| {
                    if (success) {
                        _ = self.stats.stores_successful.fetchAdd(1, .seq_cst);
                    } else {
                        _ = self.stats.stores_failed.fetchAdd(1, .seq_cst);
                    }
                } else {
                    // If success field is not present, assume success
                    _ = self.stats.stores_successful.fetchAdd(1, .seq_cst);
                }
                
                // Remove from pending requests
                _ = self.pending_requests.remove(tx_id);
                
                // Update node reachability statistics
                if (message.sender_id) |sender_id| {
                    try self.updateNodeReachability(sender_id, true);
                }
            }
        }
    }
    
    fn maintenanceLoop(self: *KademliaNode) void {
        while (self.running.load(.seq_cst)) {
            // Use async sleep instead of blocking
            try self.runtime.sleep(60 * 1000); // 1 minute
            
            self.mutex.lock();
            defer self.mutex.unlock();
            
            // Clean up expired storage items
            var keys_to_remove = std.ArrayList([]const u8).init(self.allocator);
            defer keys_to_remove.deinit();
            
            var iter = self.storage.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.isExpired()) {
                    keys_to_remove.append(entry.key_ptr.*) catch continue;
                }
            }
            
            for (keys_to_remove.items) |key| {
                if (self.storage.fetchRemove(key)) |kv| {
                    kv.value.deinit(self.allocator);
                    _ = self.stats.storage_items.fetchSub(1, .seq_cst);
                }
            }
        }
    }
    
    fn refreshLoop(self: *KademliaNode) void {
        while (self.running.load(.seq_cst)) {
            // Use async sleep instead of blocking
            try self.runtime.sleep(self.config.refresh_interval); // Convert to nanoseconds
            
            // Refresh routing table buckets
            self.refreshRoutingTable() catch {};
        }
    }
    
    fn refreshRoutingTable(self: *KademliaNode) !void {
        // Generate random IDs for each bucket and perform lookups
        for (0..160) |i| {
            var random_id: NodeID = undefined;
            std.crypto.random.bytes(&random_id);
            
            // Set bit i to be different from our node ID
            const byte_index = i / 8;
            const bit_index = @as(u3, @intCast(i % 8));
            
            if ((self.config.node_id[byte_index] >> bit_index) & 1 == 0) {
                random_id[byte_index] |= (@as(u8, 1) << bit_index);
            } else {
                random_id[byte_index] &= ~(@as(u8, 1) << bit_index);
            }
            
            // Perform lookup
            const nodes = self.findNode(random_id) catch continue;
            self.allocator.free(nodes);
        }
    }
    
    pub fn getStats(self: *KademliaNode) KademliaStats {
        return self.stats;
    }
    
    pub fn getNodeInfo(self: *KademliaNode) struct {
        node_id: NodeID,
        routing_table_size: usize,
        storage_size: usize,
    } {
        return .{
            .node_id = self.config.node_id,
            .routing_table_size = self.routing_table.size(),
            .storage_size = self.storage.count(),
        };
    }
    
    fn isResponseMessage(self: *KademliaNode, message_type: KademliaRpcType) bool {
        _ = self;
        return switch (message_type) {
            .pong, .find_node_response, .find_value_response, .store_response => true,
            else => false,
        };
    }
    
    fn completePendingRequest(self: *KademliaNode, message: KademliaMessage) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.pending_requests.getPtr(message.transaction_id)) |request| {
            var response_copy = message;
            // Clone the message for the response
            response_copy.nodes = self.allocator.dupe(NodeContact, message.nodes) catch &[_]NodeContact{};
            if (message.key) |key| {
                response_copy.key = self.allocator.dupe(u8, key) catch null;
            }
            if (message.value) |value| {
                response_copy.value = self.allocator.dupe(u8, value) catch null;
            }
            
            request.complete(response_copy);
            _ = self.pending_requests.remove(message.transaction_id);
        }
    }
    
    fn addPendingRequest(self: *KademliaNode, request: PendingRequest) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        try self.pending_requests.put(request.transaction_id, request);
    }
    
    fn waitForResponse(self: *KademliaNode, transaction_id: [16]u8, timeout_ms: u32) zsync.Future {
        return zsync.Future.init(self.runtime, struct {
            node: *KademliaNode,
            transaction_id: [16]u8,
            timeout_ms: u32,
            start_time: i64,
            
            pub fn poll(ctx: *@This()) zsync.Poll(?KademliaMessage) {
                const now = std.time.timestamp();
                if (now - ctx.start_time > ctx.timeout_ms) {
                    return .{ .ready = null }; // Timeout
                }
                
                ctx.node.mutex.lock();
                defer ctx.node.mutex.unlock();
                
                if (ctx.node.pending_requests.get(ctx.transaction_id)) |request| {
                    if (request.completed.load(.seq_cst)) {
                        return .{ .ready = request.response };
                    }
                }
                
                return .pending;
            }
        }{ 
            .node = self, 
            .transaction_id = transaction_id, 
            .timeout_ms = timeout_ms,
            .start_time = std.time.timestamp(),
        });
    }
};

// Utility functions

pub fn generateNodeID() NodeID {
    var id: NodeID = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

pub fn xorDistance(a: NodeID, b: NodeID) NodeID {
    var distance: NodeID = undefined;
    for (0..NODE_ID_SIZE) |i| {
        distance[i] = a[i] ^ b[i];
    }
    return distance;
}

pub fn getBucketIndex(node_id: NodeID, target_id: NodeID) usize {
    const distance = xorDistance(node_id, target_id);
    
    // Find first differing bit
    for (0..NODE_ID_SIZE) |i| {
        if (distance[i] != 0) {
            return (i * 8) + @clz(distance[i]);
        }
    }
    
    return 159; // Should not happen unless IDs are identical
}

pub fn isCloser(a: NodeID, b: NodeID) bool {
    for (0..NODE_ID_SIZE) |i| {
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return false;
}

pub const NodeIDHashContext = struct {
    pub fn hash(self: @This(), key: NodeID) u64 {
        _ = self;
        return std.hash_map.hashString(std.mem.asBytes(&key));
    }
    
    pub fn eql(self: @This(), a: NodeID, b: NodeID) bool {
        _ = self;
        return std.mem.eql(u8, &a, &b);
    }
};