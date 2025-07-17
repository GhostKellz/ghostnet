const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");
const udp = @import("../transport/udp.zig");
const errors = @import("../errors/errors.zig");
const protocol = @import("../protocols/protocol.zig");

pub const GossipMessageType = enum(u8) {
    announce = 0x01,
    subscribe = 0x02,
    unsubscribe = 0x03,
    publish = 0x04,
    heartbeat = 0x05,
    peer_exchange = 0x06,
    topic_list = 0x07,
    anti_entropy = 0x08,
    sync_request = 0x09,
    sync_response = 0x0A,
};

pub const TopicDigest = struct {
    message_count: u32,
    latest_timestamp: i64,
    content_hash: u64,
    
    pub fn serialize(self: TopicDigest, buffer: []u8) void {
        std.mem.writeInt(u32, buffer[0..4], self.message_count, .big);
        std.mem.writeInt(i64, buffer[4..12], self.latest_timestamp, .big);
        std.mem.writeInt(u64, buffer[12..20], self.content_hash, .big);
    }
    
    pub fn deserialize(buffer: []const u8) TopicDigest {
        return TopicDigest{
            .message_count = std.mem.readInt(u32, buffer[0..4], .big),
            .latest_timestamp = std.mem.readInt(i64, buffer[4..12], .big),
            .content_hash = std.mem.readInt(u64, buffer[12..20], .big),
        };
    }
    
    pub fn isDifferent(self: TopicDigest, other: TopicDigest) bool {
        return self.message_count != other.message_count or
               self.latest_timestamp != other.latest_timestamp or
               self.content_hash != other.content_hash;
    }
};

pub const GossipMessage = struct {
    message_type: GossipMessageType,
    sender_id: [16]u8,
    sequence_number: u64,
    timestamp: i64,
    ttl: u16,
    topic: []const u8,
    payload: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, message_type: GossipMessageType, sender_id: [16]u8, topic: []const u8, payload: []const u8) !GossipMessage {
        return GossipMessage{
            .message_type = message_type,
            .sender_id = sender_id,
            .sequence_number = 0,
            .timestamp = std.time.timestamp(),
            .ttl = 5, // Default TTL
            .topic = try allocator.dupe(u8, topic),
            .payload = try allocator.dupe(u8, payload),
        };
    }
    
    pub fn deinit(self: *GossipMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.topic);
        allocator.free(self.payload);
    }
    
    pub fn serialize(self: *GossipMessage, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        
        // Header
        try buffer.append(@intFromEnum(self.message_type));
        try buffer.appendSlice(&self.sender_id);
        
        // Sequence number (8 bytes, big endian)
        try buffer.append(@intCast(self.sequence_number >> 56));
        try buffer.append(@intCast((self.sequence_number >> 48) & 0xFF));
        try buffer.append(@intCast((self.sequence_number >> 40) & 0xFF));
        try buffer.append(@intCast((self.sequence_number >> 32) & 0xFF));
        try buffer.append(@intCast((self.sequence_number >> 24) & 0xFF));
        try buffer.append(@intCast((self.sequence_number >> 16) & 0xFF));
        try buffer.append(@intCast((self.sequence_number >> 8) & 0xFF));
        try buffer.append(@intCast(self.sequence_number & 0xFF));
        
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
        
        // TTL (2 bytes, big endian)
        try buffer.append(@intCast(self.ttl >> 8));
        try buffer.append(@intCast(self.ttl & 0xFF));
        
        // Topic length and topic
        try buffer.append(@intCast(self.topic.len));
        try buffer.appendSlice(self.topic);
        
        // Payload length (4 bytes, big endian)
        try buffer.append(@intCast(self.payload.len >> 24));
        try buffer.append(@intCast((self.payload.len >> 16) & 0xFF));
        try buffer.append(@intCast((self.payload.len >> 8) & 0xFF));
        try buffer.append(@intCast(self.payload.len & 0xFF));
        
        // Payload
        try buffer.appendSlice(self.payload);
        
        return buffer.toOwnedSlice();
    }
    
    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !GossipMessage {
        if (data.len < 35) return error.InvalidMessageLength; // Minimum header size
        
        var offset: usize = 0;
        
        // Message type
        const message_type: GossipMessageType = @enumFromInt(data[offset]);
        offset += 1;
        
        // Sender ID
        const sender_id = data[offset..offset + 16][0..16].*;
        offset += 16;
        
        // Sequence number
        var sequence_number: u64 = 0;
        for (0..8) |i| {
            sequence_number = (sequence_number << 8) | data[offset + i];
        }
        offset += 8;
        
        // Timestamp
        var timestamp_u64: u64 = 0;
        for (0..8) |i| {
            timestamp_u64 = (timestamp_u64 << 8) | data[offset + i];
        }
        const timestamp = @as(i64, @bitCast(timestamp_u64));
        offset += 8;
        
        // TTL
        const ttl = (@as(u16, data[offset]) << 8) | data[offset + 1];
        offset += 2;
        
        // Topic
        const topic_len = data[offset];
        offset += 1;
        
        if (offset + topic_len > data.len) return error.InvalidMessageLength;
        const topic = try allocator.dupe(u8, data[offset..offset + topic_len]);
        offset += topic_len;
        
        // Payload length
        if (offset + 4 > data.len) return error.InvalidMessageLength;
        const payload_len = (@as(u32, data[offset]) << 24) | 
                           (@as(u32, data[offset + 1]) << 16) | 
                           (@as(u32, data[offset + 2]) << 8) | 
                           data[offset + 3];
        offset += 4;
        
        // Payload
        if (offset + payload_len > data.len) return error.InvalidMessageLength;
        const payload = try allocator.dupe(u8, data[offset..offset + payload_len]);
        
        return GossipMessage{
            .message_type = message_type,
            .sender_id = sender_id,
            .sequence_number = sequence_number,
            .timestamp = timestamp,
            .ttl = ttl,
            .topic = topic,
            .payload = payload,
        };
    }
};

pub const GossipPeer = struct {
    id: [16]u8,
    address: transport.Address,
    last_seen: i64,
    topics: std.StringHashMap(void),
    sequence_number: u64,
    heartbeat_failures: u32,
    rtt: f64, // Round-trip time in milliseconds
    bandwidth: f64, // Estimated bandwidth in bytes/sec
    reliability: f64, // Success rate (0.0 to 1.0)
    network_distance: u8, // Estimated network hops
    
    pub fn init(allocator: std.mem.Allocator, id: [16]u8, address: transport.Address) !*GossipPeer {
        const peer = try allocator.create(GossipPeer);
        peer.* = .{
            .id = id,
            .address = address,
            .last_seen = std.time.timestamp(),
            .topics = std.StringHashMap(void).init(allocator),
            .sequence_number = 0,
            .heartbeat_failures = 0,
            .rtt = 100.0, // Default 100ms
            .bandwidth = 1000000.0, // Default 1MB/s
            .reliability = 1.0, // Start with perfect reliability
            .network_distance = 1, // Default to 1 hop
        };
        return peer;
    }
    
    pub fn deinit(self: *GossipPeer, allocator: std.mem.Allocator) void {
        self.topics.deinit();
        allocator.destroy(self);
    }
    
    pub fn addTopic(self: *GossipPeer, topic: []const u8) !void {
        try self.topics.put(topic, {});
    }
    
    pub fn removeTopic(self: *GossipPeer, topic: []const u8) void {
        _ = self.topics.remove(topic);
    }
    
    pub fn hasTopicInterest(self: *GossipPeer, topic: []const u8) bool {
        return self.topics.contains(topic);
    }
    
    pub fn updateLastSeen(self: *GossipPeer) void {
        self.last_seen = std.time.timestamp();
        self.heartbeat_failures = 0;
    }
    
    pub fn isStale(self: *GossipPeer, timeout: i64) bool {
        return (std.time.timestamp() - self.last_seen) > timeout;
    }
    
    pub fn updateNetworkMetrics(self: *GossipPeer, rtt: f64, success: bool) void {
        // Update RTT with exponential moving average
        self.rtt = 0.8 * self.rtt + 0.2 * rtt;
        
        // Update reliability
        if (success) {
            self.reliability = 0.9 * self.reliability + 0.1 * 1.0;
        } else {
            self.reliability = 0.9 * self.reliability + 0.1 * 0.0;
        }
    }
    
    pub fn getNetworkScore(self: *GossipPeer) f64 {
        // Calculate composite network score (higher is better)
        // Factor in reliability, RTT (inverse), and bandwidth
        const rtt_score = 1000.0 / (self.rtt + 1.0); // Inverse RTT
        const bandwidth_score = self.bandwidth / 1000000.0; // Normalize to MB/s
        const distance_penalty = 1.0 / (@as(f64, @floatFromInt(self.network_distance)) + 1.0);
        
        return self.reliability * rtt_score * bandwidth_score * distance_penalty;
    }
};

pub const GossipTopic = struct {
    name: []const u8,
    subscribers: std.ArrayList([16]u8),
    message_cache: std.ArrayList(GossipMessage),
    max_cache_size: usize,
    
    pub fn init(allocator: std.mem.Allocator, name: []const u8, max_cache_size: usize) !*GossipTopic {
        const topic = try allocator.create(GossipTopic);
        topic.* = .{
            .name = try allocator.dupe(u8, name),
            .subscribers = std.ArrayList([16]u8).init(allocator),
            .message_cache = std.ArrayList(GossipMessage).init(allocator),
            .max_cache_size = max_cache_size,
        };
        return topic;
    }
    
    pub fn deinit(self: *GossipTopic, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        self.subscribers.deinit();
        
        for (self.message_cache.items) |*msg| {
            msg.deinit(allocator);
        }
        self.message_cache.deinit();
        
        allocator.destroy(self);
    }
    
    pub fn addSubscriber(self: *GossipTopic, peer_id: [16]u8) !void {
        // Check if already subscribed
        for (self.subscribers.items) |subscriber| {
            if (std.mem.eql(u8, &subscriber, &peer_id)) {
                return;
            }
        }
        
        try self.subscribers.append(peer_id);
    }
    
    pub fn removeSubscriber(self: *GossipTopic, peer_id: [16]u8) void {
        for (self.subscribers.items, 0..) |subscriber, i| {
            if (std.mem.eql(u8, &subscriber, &peer_id)) {
                _ = self.subscribers.swapRemove(i);
                return;
            }
        }
    }
    
    pub fn cacheMessage(self: *GossipTopic, allocator: std.mem.Allocator, message: GossipMessage) !void {
        // Check if we already have this message
        for (self.message_cache.items) |cached_msg| {
            if (std.mem.eql(u8, &cached_msg.sender_id, &message.sender_id) and 
                cached_msg.sequence_number == message.sequence_number) {
                return;
            }
        }
        
        // Add to cache
        try self.message_cache.append(message);
        
        // Evict old messages if cache is full
        while (self.message_cache.items.len > self.max_cache_size) {
            var oldest_msg = self.message_cache.orderedRemove(0);
            oldest_msg.deinit(allocator);
        }
    }
    
    pub fn getRecentMessages(self: *GossipTopic, allocator: std.mem.Allocator, since: i64) ![]GossipMessage {
        var result = std.ArrayList(GossipMessage).init(allocator);
        
        for (self.message_cache.items) |msg| {
            if (msg.timestamp > since) {
                try result.append(msg);
            }
        }
        
        return result.toOwnedSlice();
    }
    
    pub fn getTopicDigest(self: *GossipTopic) TopicDigest {
        var latest_timestamp: i64 = 0;
        var message_count: u32 = 0;
        var hash_accumulator: u64 = 0;
        
        for (self.message_cache.items) |msg| {
            if (msg.timestamp > latest_timestamp) {
                latest_timestamp = msg.timestamp;
            }
            message_count += 1;
            
            // Simple hash of sequence number and timestamp
            hash_accumulator = hash_accumulator ^ msg.sequence_number ^ @as(u64, @bitCast(msg.timestamp));
        }
        
        return TopicDigest{
            .message_count = message_count,
            .latest_timestamp = latest_timestamp,
            .content_hash = hash_accumulator,
        };
    }
};

pub const GossipConfig = struct {
    node_id: [16]u8,
    heartbeat_interval: u64 = 5000, // 5 seconds
    peer_timeout: u64 = 30000, // 30 seconds
    max_peers: usize = 100,
    max_topics: usize = 1000,
    message_cache_size: usize = 100,
    fanout: u8 = 3, // Number of peers to forward messages to
    gossip_interval: u64 = 1000, // 1 second
    anti_entropy_interval: u64 = 10000, // 10 seconds
    max_message_size: usize = 64 * 1024, // 64KB
    enable_encryption: bool = false,
};

pub const GossipNode = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    config: GossipConfig,
    socket: udp.UdpSocket,
    local_address: transport.Address,
    
    // Peer management
    peers: std.HashMap([16]u8, *GossipPeer, PeerHashContext, 80),
    peer_addresses: std.AutoHashMap(transport.Address, [16]u8),
    
    // Topic management
    topics: std.StringHashMap(*GossipTopic),
    subscriptions: std.StringHashMap(void),
    
    // Message tracking
    sequence_counter: std.atomic.Value(u64),
    seen_messages: std.HashMap([24]u8, i64, SeenMessageHashContext, 80), // sender_id + seq_num -> timestamp
    
    // Statistics
    stats: GossipStats,
    
    // Control
    running: std.atomic.Value(bool),
    mutex: std.Thread.Mutex,
    
    pub const PeerHashContext = struct {
        pub fn hash(self: @This(), key: [16]u8) u64 {
            _ = self;
            return std.hash_map.hashString(std.mem.asBytes(&key));
        }
        
        pub fn eql(self: @This(), a: [16]u8, b: [16]u8) bool {
            _ = self;
            return std.mem.eql(u8, &a, &b);
        }
    };
    
    pub const SeenMessageHashContext = struct {
        pub fn hash(self: @This(), key: [24]u8) u64 {
            _ = self;
            return std.hash_map.hashString(std.mem.asBytes(&key));
        }
        
        pub fn eql(self: @This(), a: [24]u8, b: [24]u8) bool {
            _ = self;
            return std.mem.eql(u8, &a, &b);
        }
    };
    
    pub const GossipStats = struct {
        messages_sent: std.atomic.Value(u64),
        messages_received: std.atomic.Value(u64),
        messages_forwarded: std.atomic.Value(u64),
        messages_dropped: std.atomic.Value(u64),
        peers_connected: std.atomic.Value(u32),
        topics_subscribed: std.atomic.Value(u32),
        bytes_sent: std.atomic.Value(u64),
        bytes_received: std.atomic.Value(u64),
        
        pub fn init() GossipStats {
            return .{
                .messages_sent = std.atomic.Value(u64).init(0),
                .messages_received = std.atomic.Value(u64).init(0),
                .messages_forwarded = std.atomic.Value(u64).init(0),
                .messages_dropped = std.atomic.Value(u64).init(0),
                .peers_connected = std.atomic.Value(u32).init(0),
                .topics_subscribed = std.atomic.Value(u32).init(0),
                .bytes_sent = std.atomic.Value(u64).init(0),
                .bytes_received = std.atomic.Value(u64).init(0),
            };
        }
    };
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, config: GossipConfig) !*GossipNode {
        const node = try allocator.create(GossipNode);
        node.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .config = config,
            .socket = udp.UdpSocket.init(allocator, runtime),
            .local_address = undefined,
            .peers = std.HashMap([16]u8, *GossipPeer, PeerHashContext, 80).init(allocator),
            .peer_addresses = std.AutoHashMap(transport.Address, [16]u8).init(allocator),
            .topics = std.StringHashMap(*GossipTopic).init(allocator),
            .subscriptions = std.StringHashMap(void).init(allocator),
            .sequence_counter = std.atomic.Value(u64).init(0),
            .seen_messages = std.HashMap([24]u8, i64, SeenMessageHashContext, 80).init(allocator),
            .stats = GossipStats.init(),
            .running = std.atomic.Value(bool).init(false),
            .mutex = .{},
        };
        
        return node;
    }
    
    pub fn deinit(self: *GossipNode) void {
        self.stop();
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Clean up peers
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
        }
        self.peers.deinit();
        self.peer_addresses.deinit();
        
        // Clean up topics
        var topic_iter = self.topics.iterator();
        while (topic_iter.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
        }
        self.topics.deinit();
        self.subscriptions.deinit();
        
        self.seen_messages.deinit();
        self.socket.close();
        
        self.allocator.destroy(self);
    }
    
    pub fn start(self: *GossipNode, bind_address: transport.Address) !void {
        try self.socket.bind(bind_address, transport.TransportOptions{ .allocator = self.allocator });
        self.local_address = try self.socket.localAddress();
        
        self.running.store(true, .seq_cst);
        
        // Start background tasks
        _ = try self.runtime.spawn(receiveLoop, .{self}, .normal);
        _ = try self.runtime.spawn(heartbeatLoop, .{self}, .normal);
        _ = try self.runtime.spawn(antiEntropyLoop, .{self}, .normal);
        _ = try self.runtime.spawn(peerExchangeLoop, .{self}, .normal);
        _ = try self.runtime.spawn(maintenanceLoop, .{self}, .normal);
    }
    
    pub fn stop(self: *GossipNode) void {
        self.running.store(false, .seq_cst);
    }
    
    pub fn addPeer(self: *GossipNode, peer_id: [16]u8, address: transport.Address) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.peers.count() >= self.config.max_peers) {
            return error.TooManyPeers;
        }
        
        const peer = try GossipPeer.init(self.allocator, peer_id, address);
        try self.peers.put(peer_id, peer);
        try self.peer_addresses.put(address, peer_id);
        
        _ = self.stats.peers_connected.fetchAdd(1, .seq_cst);
        
        // Send announce message
        try self.sendAnnounce(peer);
    }
    
    pub fn removePeer(self: *GossipNode, peer_id: [16]u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.peers.fetchRemove(peer_id)) |kv| {
            _ = self.peer_addresses.remove(kv.value.address);
            kv.value.deinit(self.allocator);
            _ = self.stats.peers_connected.fetchSub(1, .seq_cst);
        }
    }
    
    pub fn subscribe(self: *GossipNode, topic: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.topics.count() >= self.config.max_topics) {
            return error.TooManyTopics;
        }
        
        // Add to subscriptions
        try self.subscriptions.put(topic, {});
        
        // Create topic if it doesn't exist
        if (!self.topics.contains(topic)) {
            const gossip_topic = try GossipTopic.init(self.allocator, topic, self.config.message_cache_size);
            try self.topics.put(topic, gossip_topic);
        }
        
        _ = self.stats.topics_subscribed.fetchAdd(1, .seq_cst);
        
        // Send subscribe message to peers
        try self.broadcastSubscribe(topic);
    }
    
    pub fn unsubscribe(self: *GossipNode, topic: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.subscriptions.remove(topic)) {
            _ = self.stats.topics_subscribed.fetchSub(1, .seq_cst);
            
            // Send unsubscribe message to peers
            self.broadcastUnsubscribe(topic) catch {};
        }
    }
    
    pub fn publish(self: *GossipNode, topic: []const u8, payload: []const u8) !void {
        var message = try GossipMessage.init(self.allocator, .publish, self.config.node_id, topic, payload);
        defer message.deinit(self.allocator);
        
        message.sequence_number = self.sequence_counter.fetchAdd(1, .seq_cst);
        
        try self.forwardMessage(&message);
    }
    
    fn sendAnnounce(self: *GossipNode, peer: *GossipPeer) !void {
        var message = try GossipMessage.init(self.allocator, .announce, self.config.node_id, "", "");
        defer message.deinit(self.allocator);
        
        message.sequence_number = self.sequence_counter.fetchAdd(1, .seq_cst);
        
        try self.sendMessageToPeer(&message, peer);
    }
    
    fn broadcastSubscribe(self: *GossipNode, topic: []const u8) !void {
        var message = try GossipMessage.init(self.allocator, .subscribe, self.config.node_id, topic, "");
        defer message.deinit(self.allocator);
        
        message.sequence_number = self.sequence_counter.fetchAdd(1, .seq_cst);
        
        try self.broadcastMessage(&message);
    }
    
    fn broadcastUnsubscribe(self: *GossipNode, topic: []const u8) !void {
        var message = try GossipMessage.init(self.allocator, .unsubscribe, self.config.node_id, topic, "");
        defer message.deinit(self.allocator);
        
        message.sequence_number = self.sequence_counter.fetchAdd(1, .seq_cst);
        
        try self.broadcastMessage(&message);
    }
    
    fn forwardMessage(self: *GossipNode, message: *GossipMessage) !void {
        // Check if we've already seen this message
        var message_key: [24]u8 = undefined;
        @memcpy(message_key[0..16], &message.sender_id);
        @memcpy(message_key[16..24], std.mem.asBytes(&message.sequence_number));
        
        if (self.seen_messages.contains(message_key)) {
            _ = self.stats.messages_dropped.fetchAdd(1, .seq_cst);
            return;
        }
        
        // Mark as seen
        try self.seen_messages.put(message_key, std.time.timestamp());
        
        // Cache message in topic
        if (self.topics.get(message.topic)) |topic| {
            try topic.cacheMessage(self.allocator, message.*);
        }
        
        // Forward to interested peers
        try self.gossipMessage(message);
        
        _ = self.stats.messages_forwarded.fetchAdd(1, .seq_cst);
    }
    
    fn gossipMessage(self: *GossipNode, message: *GossipMessage) !void {
        // Reduce TTL
        if (message.ttl == 0) {
            _ = self.stats.messages_dropped.fetchAdd(1, .seq_cst);
            return;
        }
        message.ttl -= 1;
        
        // Find peers interested in this topic
        var interested_peers = std.ArrayList(*GossipPeer).init(self.allocator);
        defer interested_peers.deinit();
        
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            const peer = entry.value_ptr.*;
            if (peer.hasTopicInterest(message.topic)) {
                try interested_peers.append(peer);
            }
        }
        
        // Sort peers by network score (best first)
        std.sort.block(*GossipPeer, interested_peers.items, {}, struct {
            fn lessThan(context: void, a: *GossipPeer, b: *GossipPeer) bool {
                _ = context;
                return a.getNetworkScore() > b.getNetworkScore(); // Higher score is better
            }
        }.lessThan);
        
        // Select top peers for gossip with some randomness
        const fanout = std.math.min(self.config.fanout, interested_peers.items.len);
        const best_count = std.math.min(fanout / 2, interested_peers.items.len); // Take top 50%
        const random_count = fanout - best_count; // Random selection for the rest
        
        var i: usize = 0;
        
        // Send to best peers first
        while (i < best_count) {
            const peer = interested_peers.items[i];
            const start_time = std.time.milliTimestamp();
            
            const success = if (self.sendMessageToPeer(message, peer)) |_| true else |_| false;
            const end_time = std.time.milliTimestamp();
            const rtt = @as(f64, @floatFromInt(end_time - start_time));
            
            peer.updateNetworkMetrics(rtt, success);
            i += 1;
        }
        
        // Send to random subset of remaining peers
        var remaining_peers = interested_peers.items[best_count..];
        var j: usize = 0;
        while (j < random_count and remaining_peers.len > 0) {
            const index = std.crypto.random.intRangeAtMost(usize, 0, remaining_peers.len - 1);
            const peer = remaining_peers[index];
            
            const start_time = std.time.milliTimestamp();
            const success = if (self.sendMessageToPeer(message, peer)) |_| true else |_| false;
            const end_time = std.time.milliTimestamp();
            const rtt = @as(f64, @floatFromInt(end_time - start_time));
            
            peer.updateNetworkMetrics(rtt, success);
            
            // Remove selected peer from remaining list
            remaining_peers[index] = remaining_peers[remaining_peers.len - 1];
            remaining_peers = remaining_peers[0..remaining_peers.len - 1];
            j += 1;
        }
    }
    
    fn broadcastMessage(self: *GossipNode, message: *GossipMessage) !void {
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            const peer = entry.value_ptr.*;
            try self.sendMessageToPeer(message, peer);
        }
    }
    
    fn sendMessageToPeer(self: *GossipNode, message: *GossipMessage, peer: *GossipPeer) !void {
        const data = try message.serialize(self.allocator);
        defer self.allocator.free(data);
        
        _ = try self.socket.sendTo(data, peer.address);
        
        _ = self.stats.messages_sent.fetchAdd(1, .seq_cst);
        _ = self.stats.bytes_sent.fetchAdd(data.len, .seq_cst);
    }
    
    fn receiveLoop(self: *GossipNode) void {
        var buffer: [65536]u8 = undefined;
        
        while (self.running.load(.seq_cst)) {
            const packet = self.socket.recvFromAsync(&buffer) catch continue;
            
            switch (packet) {
                .ready => |result| {
                    if (result) |pkt| {
                        self.handleMessage(pkt.data, pkt.address) catch |err| {
                            std.log.err("Error handling gossip message: {}", .{err});
                        };
                    } else |_| {
                        continue;
                    }
                },
                .pending => {
                    const delay_future = self.runtime.sleep(std.time.ns_per_ms);
                    _ = try self.runtime.await(delay_future);
                    continue;
                },
            }
        }
    }
    
    fn handleMessage(self: *GossipNode, data: []const u8, sender_addr: transport.Address) !void {
        var message = GossipMessage.deserialize(self.allocator, data) catch {
            _ = self.stats.messages_dropped.fetchAdd(1, .seq_cst);
            return;
        };
        defer message.deinit(self.allocator);
        
        _ = self.stats.messages_received.fetchAdd(1, .seq_cst);
        _ = self.stats.bytes_received.fetchAdd(data.len, .seq_cst);
        
        // Update peer last seen
        if (self.peer_addresses.get(sender_addr)) |peer_id| {
            if (self.peers.get(peer_id)) |peer| {
                peer.updateLastSeen();
            }
        }
        
        switch (message.message_type) {
            .announce => try self.handleAnnounce(&message, sender_addr),
            .subscribe => try self.handleSubscribe(&message, sender_addr),
            .unsubscribe => try self.handleUnsubscribe(&message, sender_addr),
            .publish => try self.handlePublish(&message, sender_addr),
            .heartbeat => try self.handleHeartbeat(&message, sender_addr),
            .peer_exchange => try self.handlePeerExchange(&message, sender_addr),
            .topic_list => try self.handleTopicList(&message, sender_addr),
            .anti_entropy => try self.handleAntiEntropy(&message, sender_addr),
            .sync_request => try self.handleSyncRequest(&message, sender_addr),
            .sync_response => try self.handleSyncResponse(&message, sender_addr),
        }
    }
    
    fn handleAnnounce(self: *GossipNode, message: *GossipMessage, sender_addr: transport.Address) !void {
        _ = self;
        _ = message;
        _ = sender_addr;
        // Handle peer announcement
    }
    
    fn handleSubscribe(self: *GossipNode, message: *GossipMessage, sender_addr: transport.Address) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.peer_addresses.get(sender_addr)) |peer_id| {
            if (self.peers.get(peer_id)) |peer| {
                try peer.addTopic(message.topic);
                
                // Add to topic subscribers
                if (self.topics.get(message.topic)) |topic| {
                    try topic.addSubscriber(peer_id);
                }
            }
        }
    }
    
    fn handleUnsubscribe(self: *GossipNode, message: *GossipMessage, sender_addr: transport.Address) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.peer_addresses.get(sender_addr)) |peer_id| {
            if (self.peers.get(peer_id)) |peer| {
                peer.removeTopic(message.topic);
                
                // Remove from topic subscribers
                if (self.topics.get(message.topic)) |topic| {
                    topic.removeSubscriber(peer_id);
                }
            }
        }
    }
    
    fn handlePublish(self: *GossipNode, message: *GossipMessage, sender_addr: transport.Address) !void {
        _ = sender_addr;
        
        // Forward message if we haven't seen it and we're interested
        if (self.subscriptions.contains(message.topic)) {
            try self.forwardMessage(message);
        }
    }
    
    fn handleHeartbeat(self: *GossipNode, message: *GossipMessage, sender_addr: transport.Address) !void {
        _ = self;
        _ = message;
        _ = sender_addr;
        // Handle heartbeat
    }
    
    fn handlePeerExchange(self: *GossipNode, message: *GossipMessage, sender_addr: transport.Address) !void {
        // Parse peer exchange payload: each peer is 16 bytes ID + address info
        var offset: usize = 0;
        const payload = message.payload;
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        while (offset + 16 <= payload.len) {
            // Extract peer ID
            const peer_id = payload[offset..offset + 16][0..16].*;
            offset += 16;
            
            // Extract address type and address
            if (offset >= payload.len) break;
            const addr_type = payload[offset];
            offset += 1;
            
            var peer_addr: transport.Address = undefined;
            switch (addr_type) {
                4 => { // IPv4
                    if (offset + 6 > payload.len) break;
                    const addr_bytes = payload[offset..offset + 4][0..4].*;
                    const port = (@as(u16, payload[offset + 4]) << 8) | payload[offset + 5];
                    peer_addr = transport.Address{ .ipv4 = std.net.Ip4Address.init(addr_bytes, port) };
                    offset += 6;
                },
                6 => { // IPv6
                    if (offset + 18 > payload.len) break;
                    const addr_bytes = payload[offset..offset + 16][0..16].*;
                    const port = (@as(u16, payload[offset + 16]) << 8) | payload[offset + 17];
                    peer_addr = transport.Address{ .ipv6 = std.net.Ipv6Address.init(addr_bytes, port, 0, 0) };
                    offset += 18;
                },
                else => break,
            }
            
            // Add peer if we don't already know about it and have capacity
            if (!self.peers.contains(peer_id) and self.peers.count() < self.config.max_peers) {
                const new_peer = try GossipPeer.init(self.allocator, peer_id, peer_addr);
                try self.peers.put(peer_id, new_peer);
                try self.peer_addresses.put(peer_addr, peer_id);
                _ = self.stats.peers_connected.fetchAdd(1, .seq_cst);
            }
        }
        
        // Send our own peer list back if this was a request
        if (self.peer_addresses.get(sender_addr)) |sender_id| {
            try self.sendPeerExchangeResponse(sender_id);
        }
    }
    
    fn handleTopicList(self: *GossipNode, message: *GossipMessage, sender_addr: transport.Address) !void {
        _ = self;
        _ = message;
        _ = sender_addr;
        // Handle topic list
    }
    
    fn handleAntiEntropy(self: *GossipNode, message: *GossipMessage, sender_addr: transport.Address) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.peer_addresses.get(sender_addr)) |peer_id| {
            if (self.peers.get(peer_id)) |peer| {
                // Parse peer's topic digests from payload
                var offset: usize = 0;
                var topics_to_sync = std.ArrayList([]const u8).init(self.allocator);
                defer topics_to_sync.deinit();
                
                while (offset + 20 < message.payload.len) {
                    // Find topic name (terminated by 0 byte)
                    const topic_start = offset;
                    while (offset < message.payload.len and message.payload[offset] != 0) {
                        offset += 1;
                    }
                    
                    if (offset >= message.payload.len) break;
                    
                    const topic_name = message.payload[topic_start..offset];
                    offset += 1; // Skip separator
                    
                    if (offset + 20 > message.payload.len) break;
                    
                    // Parse peer's digest
                    const peer_digest = TopicDigest.deserialize(message.payload[offset..offset + 20]);
                    offset += 20;
                    
                    // Compare with our digest
                    if (self.topics.get(topic_name)) |topic| {
                        const our_digest = topic.getTopicDigest();
                        
                        if (our_digest.isDifferent(peer_digest)) {
                            try topics_to_sync.append(topic_name);
                        }
                    }
                }
                
                // Send sync response with our missing messages
                try self.sendSyncResponse(peer, topics_to_sync.items);
            }
        }
    }
    
    fn sendSyncResponse(self: *GossipNode, peer: *GossipPeer, topics_to_sync: []const []const u8) !void {
        for (topics_to_sync) |topic_name| {
            if (self.topics.get(topic_name)) |topic| {
                // Send recent messages from this topic
                const cutoff_time = std.time.timestamp() - 300; // Last 5 minutes
                const recent_messages = try topic.getRecentMessages(self.allocator, cutoff_time);
                defer self.allocator.free(recent_messages);
                
                for (recent_messages) |recent_msg| {
                    // Create sync message for each recent message
                    var sync_msg = try GossipMessage.init(
                        self.allocator,
                        .sync_response,
                        recent_msg.sender_id,
                        recent_msg.topic,
                        recent_msg.payload
                    );
                    defer sync_msg.deinit(self.allocator);
                    
                    sync_msg.sequence_number = recent_msg.sequence_number;
                    sync_msg.timestamp = recent_msg.timestamp;
                    
                    try self.sendMessageToPeer(&sync_msg, peer);
                }
            }
        }
    }
    
    fn handleSyncRequest(self: *GossipNode, message: *GossipMessage, sender_addr: transport.Address) !void {
        // Extract topic from sync request
        const topic_name = message.topic;
        
        // Find the requesting peer
        var peer_opt: ?*GossipPeer = null;
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            if (std.mem.eql(u8, &entry.value_ptr.address.host, &sender_addr.host) and 
                entry.value_ptr.address.port == sender_addr.port) {
                peer_opt = entry.value_ptr;
                break;
            }
        }
        
        if (peer_opt) |peer| {
            if (self.topics.get(topic_name)) |topic| {
                // Send recent messages from this topic (last 5 minutes)
                const cutoff_time = std.time.timestamp() - 300;
                const recent_messages = try topic.getRecentMessages(self.allocator, cutoff_time);
                defer self.allocator.free(recent_messages);
                
                for (recent_messages) |recent_msg| {
                    // Create sync response message
                    var sync_msg = try GossipMessage.init(
                        self.allocator,
                        .sync_response,
                        recent_msg.sender_id,
                        recent_msg.topic,
                        recent_msg.payload
                    );
                    defer sync_msg.deinit(self.allocator);
                    
                    sync_msg.sequence_number = recent_msg.sequence_number;
                    sync_msg.timestamp = recent_msg.timestamp;
                    
                    try self.sendMessageToPeer(&sync_msg, peer);
                }
            }
        }
        
        // Update sync request statistics
        _ = self.stats.messages_received.fetchAdd(1, .seq_cst);
    }
    
    fn handleSyncResponse(self: *GossipNode, message: *GossipMessage, sender_addr: transport.Address) !void {
        // Process sync response message like a regular publish
        try self.handlePublish(message, sender_addr);
        
        // Update statistics
        _ = self.stats.messages_received.fetchAdd(1, .seq_cst);
    }
    
    fn heartbeatLoop(self: *GossipNode) void {
        while (self.running.load(.seq_cst)) {
            const delay_ns = self.config.heartbeat_interval * std.time.ns_per_ms;
            const delay_future = self.runtime.sleep(delay_ns);
            _ = self.runtime.await(delay_future) catch continue;
            
            self.mutex.lock();
            defer self.mutex.unlock();
            
            // Send heartbeat to all peers
            var peer_iter = self.peers.iterator();
            while (peer_iter.next()) |entry| {
                const peer = entry.value_ptr.*;
                self.sendHeartbeat(peer) catch {};
            }
        }
    }
    
    fn sendHeartbeat(self: *GossipNode, peer: *GossipPeer) !void {
        var message = try GossipMessage.init(self.allocator, .heartbeat, self.config.node_id, "", "");
        defer message.deinit(self.allocator);
        
        message.sequence_number = self.sequence_counter.fetchAdd(1, .seq_cst);
        
        try self.sendMessageToPeer(&message, peer);
    }
    
    fn sendAntiEntropyRequest(self: *GossipNode, peer: *GossipPeer) !void {
        // Create digest of our current topic states
        var digest_payload = std.ArrayList(u8).init(self.allocator);
        defer digest_payload.deinit();
        
        var topic_iter = self.topics.iterator();
        while (topic_iter.next()) |entry| {
            const topic_name = entry.key_ptr.*;
            const topic = entry.value_ptr.*;
            
            // Add topic name
            try digest_payload.appendSlice(topic_name);
            try digest_payload.append(0); // Separator
            
            // Add topic digest (20 bytes)
            const digest = topic.getTopicDigest();
            var digest_buffer: [20]u8 = undefined;
            digest.serialize(&digest_buffer);
            try digest_payload.appendSlice(&digest_buffer);
        }
        
        var message = try GossipMessage.init(self.allocator, .anti_entropy, self.config.node_id, "", digest_payload.items);
        defer message.deinit(self.allocator);
        
        message.sequence_number = self.sequence_counter.fetchAdd(1, .seq_cst);
        
        try self.sendMessageToPeer(&message, peer);
    }
    
    fn sendPeerExchangeResponse(self: *GossipNode, requesting_peer_id: [16]u8) !void {
        // Create payload with up to 10 random peers
        var exchange_payload = std.ArrayList(u8).init(self.allocator);
        defer exchange_payload.deinit();
        
        var peer_count: usize = 0;
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            const peer = entry.value_ptr.*;
            if (peer_count >= 10 or std.mem.eql(u8, &peer.id, &requesting_peer_id)) continue;
            
            // Add peer ID
            try exchange_payload.appendSlice(&peer.id);
            
            // Add address info
            switch (peer.address) {
                .ipv4 => |addr| {
                    try exchange_payload.append(4); // IPv4 type
                    try exchange_payload.appendSlice(std.mem.asBytes(&addr.sa.addr));
                    try exchange_payload.append(@intCast(addr.sa.port >> 8));
                    try exchange_payload.append(@intCast(addr.sa.port & 0xFF));
                },
                .ipv6 => |addr| {
                    try exchange_payload.append(6); // IPv6 type
                    try exchange_payload.appendSlice(&addr.sa.addr);
                    try exchange_payload.append(@intCast(addr.sa.port >> 8));
                    try exchange_payload.append(@intCast(addr.sa.port & 0xFF));
                },
                else => continue,
            }
            
            peer_count += 1;
        }
        
        if (self.peers.get(requesting_peer_id)) |requesting_peer| {
            var message = try GossipMessage.init(self.allocator, .peer_exchange, self.config.node_id, "", exchange_payload.items);
            defer message.deinit(self.allocator);
            
            message.sequence_number = self.sequence_counter.fetchAdd(1, .seq_cst);
            try self.sendMessageToPeer(&message, requesting_peer);
        }
    }
    
    fn initiatePeerExchange(self: *GossipNode) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Select a random peer to exchange with
        if (self.peers.count() == 0) return;
        
        var peer_list = std.ArrayList(*GossipPeer).init(self.allocator);
        defer peer_list.deinit();
        
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            try peer_list.append(entry.value_ptr.*);
        }
        
        if (peer_list.items.len > 0) {
            const random_index = std.crypto.random.intRangeAtMost(usize, 0, peer_list.items.len - 1);
            const peer = peer_list.items[random_index];
            
            var message = try GossipMessage.init(self.allocator, .peer_exchange, self.config.node_id, "", "");
            defer message.deinit(self.allocator);
            
            message.sequence_number = self.sequence_counter.fetchAdd(1, .seq_cst);
            try self.sendMessageToPeer(&message, peer);
        }
    }
    
    fn antiEntropyLoop(self: *GossipNode) void {
        while (self.running.load(.seq_cst)) {
            const delay_ns = self.config.anti_entropy_interval * std.time.ns_per_ms;
            const delay_future = self.runtime.sleep(delay_ns);
            _ = self.runtime.await(delay_future) catch continue;
            
            // Perform anti-entropy with random peers
            self.performAntiEntropy() catch {};
        }
    }
    
    fn peerExchangeLoop(self: *GossipNode) void {
        while (self.running.load(.seq_cst)) {
            const delay_future = self.runtime.sleep(30 * std.time.ns_per_s);
            _ = self.runtime.await(delay_future) catch continue;
            
            // Initiate peer exchange
            self.initiatePeerExchange() catch {};
        }
    }
    
    fn performAntiEntropy(self: *GossipNode) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Select random subset of peers for anti-entropy
        var peers_to_sync = std.ArrayList(*GossipPeer).init(self.allocator);
        defer peers_to_sync.deinit();
        
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            const peer = entry.value_ptr.*;
            if (peers_to_sync.items.len < 3) { // Sync with up to 3 peers
                try peers_to_sync.append(peer);
            }
        }
        
        // For each peer, send anti-entropy message with our topic digests
        for (peers_to_sync.items) |peer| {
            try self.sendAntiEntropyRequest(peer);
        }
    }
    
    fn maintenanceLoop(self: *GossipNode) void {
        while (self.running.load(.seq_cst)) {
            const delay_future = self.runtime.sleep(10 * std.time.ns_per_s);
            _ = self.runtime.await(delay_future) catch continue;
            
            self.mutex.lock();
            defer self.mutex.unlock();
            
            // Remove stale peers
            var stale_peers = std.ArrayList([16]u8).init(self.allocator);
            defer stale_peers.deinit();
            
            var peer_iter = self.peers.iterator();
            while (peer_iter.next()) |entry| {
                const peer = entry.value_ptr.*;
                if (peer.isStale(@intCast(self.config.peer_timeout))) {
                    stale_peers.append(peer.id) catch continue;
                }
            }
            
            for (stale_peers.items) |peer_id| {
                self.removePeer(peer_id);
            }
            
            // Clean up old seen messages
            const cutoff_time = std.time.timestamp() - 300; // 5 minutes
            var keys_to_remove = std.ArrayList([24]u8).init(self.allocator);
            defer keys_to_remove.deinit();
            
            var seen_iter = self.seen_messages.iterator();
            while (seen_iter.next()) |entry| {
                if (entry.value_ptr.* < cutoff_time) {
                    keys_to_remove.append(entry.key_ptr.*) catch continue;
                }
            }
            
            for (keys_to_remove.items) |key| {
                _ = self.seen_messages.remove(key);
            }
        }
    }
    
    pub fn getStats(self: *GossipNode) GossipStats {
        return self.stats;
    }
    
    pub fn getTopics(self: *GossipNode) []const []const u8 {
        var topics = std.ArrayList([]const u8).init(self.allocator);
        
        var iter = self.subscriptions.iterator();
        while (iter.next()) |entry| {
            topics.append(entry.key_ptr.*) catch continue;
        }
        
        return topics.toOwnedSlice() catch &[_][]const u8{};
    }
    
    pub fn getPeers(self: *GossipNode) []const [16]u8 {
        var peers = std.ArrayList([16]u8).init(self.allocator);
        
        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            peers.append(entry.key_ptr.*) catch continue;
        }
        
        return peers.toOwnedSlice() catch &[_][16]u8{};
    }
};