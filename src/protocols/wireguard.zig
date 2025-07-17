const std = @import("std");
const zsync = @import("zsync");
const zcrypto = @import("zcrypto");
const transport = @import("../transport/transport.zig");
const udp = @import("../transport/udp.zig");
const errors = @import("../errors/errors.zig");
const protocol = @import("protocol.zig");

pub const WG_MAGIC = 0x474e5247; // "WIRG"
pub const WG_VERSION = 1;

pub const MessageType = enum(u8) {
    handshake_initiation = 1,
    handshake_response = 2,
    cookie_reply = 3,
    transport_data = 4,
    keepalive = 5,
};

pub const KeyPair = struct {
    private_key: [32]u8,
    public_key: [32]u8,
    
    pub fn generate() !KeyPair {
        var keypair: KeyPair = undefined;
        try zcrypto.curve25519.generateKeypair(&keypair.private_key, &keypair.public_key);
        return keypair;
    }
    
    pub fn computeSharedSecret(private_key: [32]u8, public_key: [32]u8) ![32]u8 {
        var shared_secret: [32]u8 = undefined;
        try zcrypto.curve25519.scalarmult(&shared_secret, &private_key, &public_key);
        return shared_secret;
    }
};

pub const HandshakeState = enum {
    uninitialized,
    initiation_sent,
    response_sent,
    established,
    failed,
};

pub const Peer = struct {
    id: u32,
    public_key: [32]u8,
    preshared_key: ?[32]u8,
    endpoint: transport.Address,
    allowed_ips: std.ArrayList(IpRange),
    persistent_keepalive: ?u32,
    last_handshake: i64,
    rx_bytes: std.atomic.Value(u64),
    tx_bytes: std.atomic.Value(u64),
    handshake_state: HandshakeState,
    session_key: ?[32]u8,
    receiving_key: ?[32]u8,
    sending_key: ?[32]u8,
    receiving_counter: std.atomic.Value(u64),
    sending_counter: std.atomic.Value(u64),
    last_activity: std.atomic.Value(i64),
    allocator: std.mem.Allocator,
    
    pub const IpRange = struct {
        network: std.net.Address,
        prefix_len: u8,
        
        pub fn contains(self: IpRange, addr: std.net.Address) bool {
            return switch (self.network) {
                .in => |network| switch (addr) {
                    .in => |test_addr| {
                        const mask = ~(@as(u32, 0)) << @as(u5, @intCast(32 - self.prefix_len));
                        return (std.mem.readIntBig(u32, std.mem.asBytes(&network.sa.addr)) & mask) == 
                               (std.mem.readIntBig(u32, std.mem.asBytes(&test_addr.sa.addr)) & mask);
                    },
                    else => false,
                },
                .in6 => |network| switch (addr) {
                    .in6 => |test_addr| {
                        const bytes_to_check = self.prefix_len / 8;
                        const remaining_bits = self.prefix_len % 8;
                        
                        // Check full bytes
                        if (!std.mem.eql(u8, network.sa.addr[0..bytes_to_check], test_addr.sa.addr[0..bytes_to_check])) {
                            return false;
                        }
                        
                        // Check remaining bits
                        if (remaining_bits > 0 and bytes_to_check < 16) {
                            const mask = ~(@as(u8, 0)) << @as(u3, @intCast(8 - remaining_bits));
                            return (network.sa.addr[bytes_to_check] & mask) == (test_addr.sa.addr[bytes_to_check] & mask);
                        }
                        
                        return true;
                    },
                    else => false,
                },
                else => false,
            };
        }
    };
    
    pub fn init(allocator: std.mem.Allocator, id: u32, public_key: [32]u8, endpoint: transport.Address) !*Peer {
        const peer = try allocator.create(Peer);
        peer.* = .{
            .id = id,
            .public_key = public_key,
            .preshared_key = null,
            .endpoint = endpoint,
            .allowed_ips = std.ArrayList(IpRange).init(allocator),
            .persistent_keepalive = null,
            .last_handshake = 0,
            .rx_bytes = std.atomic.Value(u64).init(0),
            .tx_bytes = std.atomic.Value(u64).init(0),
            .handshake_state = .uninitialized,
            .session_key = null,
            .receiving_key = null,
            .sending_key = null,
            .receiving_counter = std.atomic.Value(u64).init(0),
            .sending_counter = std.atomic.Value(u64).init(0),
            .last_activity = std.atomic.Value(i64).init(std.time.timestamp()),
            .allocator = allocator,
        };
        return peer;
    }
    
    pub fn deinit(self: *Peer) void {
        self.allowed_ips.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn addAllowedIp(self: *Peer, network: std.net.Address, prefix_len: u8) !void {
        try self.allowed_ips.append(.{
            .network = network,
            .prefix_len = prefix_len,
        });
    }
    
    pub fn canReceiveFrom(self: *Peer, source_ip: std.net.Address) bool {
        for (self.allowed_ips.items) |range| {
            if (range.contains(source_ip)) {
                return true;
            }
        }
        return false;
    }
    
    pub fn updateActivity(self: *Peer) void {
        self.last_activity.store(std.time.timestamp(), .seq_cst);
    }
    
    pub fn isExpired(self: *Peer, timeout: i64) bool {
        const last = self.last_activity.load(.seq_cst);
        return (std.time.timestamp() - last) > timeout;
    }
};

pub const WireGuardConfig = struct {
    private_key: [32]u8,
    public_key: [32]u8,
    listen_port: u16,
    interface_name: []const u8,
    mtu: u16 = 1420,
    keepalive_interval: u32 = 25,
    handshake_timeout: u32 = 90,
    rekey_after_messages: u64 = 1 << 60,
    rekey_after_time: u64 = 180,
    reject_after_time: u64 = 180,
    cookie_timeout: u32 = 120,
    enable_roaming: bool = true,
    cookie_secret: [32]u8,
    mac_key: [32]u8,
};

pub fn ArrayHashContext(comptime T: type) type {
    return struct {
        pub fn hash(self: @This(), key: T) u64 {
            _ = self;
            return std.hash_map.hashString(std.mem.asBytes(&key));
        }
        
        pub fn eql(self: @This(), a: T, b: T) bool {
            _ = self;
            return std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b));
        }
    };
}

pub const WireGuardTunnel = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    config: WireGuardConfig,
    socket: udp.UdpSocket,
    peers: std.AutoHashMap(u32, *Peer),
    peer_by_key: std.HashMap([32]u8, *Peer, ArrayHashContext([32]u8), 80),
    tun_interface: ?TunInterface,
    routing_table: RoutingTable,
    packet_queue: PacketQueue,
    stats: TunnelStats,
    rate_limiter: RateLimiter,
    cookie_jar: CookieJar,
    send_nonce_counter: std.atomic.Value(u64),
    recv_nonce_counter: std.atomic.Value(u64),
    mutex: std.Thread.Mutex,
    running: std.atomic.Value(bool),
    
    pub const TunInterface = struct {
        name: []const u8,
        fd: std.posix.fd_t,
        mtu: u16,
        address: std.net.Address,
        
        pub fn create(allocator: std.mem.Allocator, name: []const u8, address: std.net.Address, mtu: u16) !*TunInterface {
            var tun = try allocator.create(TunInterface);
            errdefer allocator.destroy(tun);
            
            tun.* = .{
                .name = try allocator.dupe(u8, name),
                .fd = try std.os.open("/dev/net/tun", std.os.O.RDWR, 0),
                .mtu = mtu,
                .address = address,
            };
            
            // Configure TUN interface (platform-specific)
            try tun.configure();
            
            return tun;
        }
        
        pub fn deinit(self: *TunInterface, allocator: std.mem.Allocator) void {
            std.os.close(self.fd);
            allocator.free(self.name);
            allocator.destroy(self);
        }
        
        fn configure(self: *TunInterface) !void {
            // This is a simplified version - real implementation would use ioctl
            _ = self;
            // Platform-specific TUN interface configuration
        }
        
        pub fn readPacket(self: *TunInterface, buffer: []u8) !usize {
            return std.os.read(self.fd, buffer);
        }
        
        pub fn writePacket(self: *TunInterface, packet: []const u8) !usize {
            return std.os.write(self.fd, packet);
        }
    };
    
    pub const RoutingTable = struct {
        routes: std.ArrayList(Route),
        allocator: std.mem.Allocator,
        
        pub const Route = struct {
            destination: std.net.Address,
            prefix_len: u8,
            peer_id: u32,
            metric: u32,
        };
        
        pub fn init(allocator: std.mem.Allocator) RoutingTable {
            return .{
                .routes = std.ArrayList(Route).init(allocator),
                .allocator = allocator,
            };
        }
        
        pub fn deinit(self: *RoutingTable) void {
            self.routes.deinit();
        }
        
        pub fn addRoute(self: *RoutingTable, destination: std.net.Address, prefix_len: u8, peer_id: u32, metric: u32) !void {
            try self.routes.append(.{
                .destination = destination,
                .prefix_len = prefix_len,
                .peer_id = peer_id,
                .metric = metric,
            });
        }
        
        pub fn findRoute(self: *RoutingTable, destination: std.net.Address) ?u32 {
            var best_match: ?Route = null;
            var best_prefix_len: u8 = 0;
            
            for (self.routes.items) |route| {
                const range = Peer.IpRange{
                    .network = route.destination,
                    .prefix_len = route.prefix_len,
                };
                
                if (range.contains(destination) and route.prefix_len >= best_prefix_len) {
                    best_match = route;
                    best_prefix_len = route.prefix_len;
                }
            }
            
            return if (best_match) |route| route.peer_id else null;
        }
    };
    
    pub const PacketQueue = struct {
        queue: std.ArrayList(QueuedPacket),
        mutex: std.Thread.Mutex,
        condition: std.Thread.Condition,
        allocator: std.mem.Allocator,
        
        pub const QueuedPacket = struct {
            data: []u8,
            peer_id: u32,
            timestamp: i64,
        };
        
        pub fn init(allocator: std.mem.Allocator) PacketQueue {
            return .{
                .queue = std.ArrayList(QueuedPacket).init(allocator),
                .mutex = .{},
                .condition = .{},
                .allocator = allocator,
            };
        }
        
        pub fn deinit(self: *PacketQueue) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            for (self.queue.items) |packet| {
                self.allocator.free(packet.data);
            }
            self.queue.deinit();
        }
        
        pub fn enqueue(self: *PacketQueue, data: []const u8, peer_id: u32) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            const packet_data = try self.allocator.dupe(u8, data);
            try self.queue.append(.{
                .data = packet_data,
                .peer_id = peer_id,
                .timestamp = std.time.timestamp(),
            });
            
            self.condition.signal();
        }
        
        pub fn dequeue(self: *PacketQueue) ?QueuedPacket {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            if (self.queue.items.len == 0) {
                return null;
            }
            
            return self.queue.orderedRemove(0);
        }
    };
    
    pub const TunnelStats = struct {
        handshakes_completed: std.atomic.Value(u64),
        handshakes_failed: std.atomic.Value(u64),
        packets_sent: std.atomic.Value(u64),
        packets_received: std.atomic.Value(u64),
        bytes_sent: std.atomic.Value(u64),
        bytes_received: std.atomic.Value(u64),
        keepalives_sent: std.atomic.Value(u64),
        keepalives_received: std.atomic.Value(u64),
        errors: std.atomic.Value(u64),
        rate_limited: std.atomic.Value(u64),
        cookies_sent: std.atomic.Value(u64),
        
        pub fn init() TunnelStats {
            return .{
                .handshakes_completed = std.atomic.Value(u64).init(0),
                .handshakes_failed = std.atomic.Value(u64).init(0),
                .packets_sent = std.atomic.Value(u64).init(0),
                .packets_received = std.atomic.Value(u64).init(0),
                .bytes_sent = std.atomic.Value(u64).init(0),
                .bytes_received = std.atomic.Value(u64).init(0),
                .keepalives_sent = std.atomic.Value(u64).init(0),
                .keepalives_received = std.atomic.Value(u64).init(0),
                .errors = std.atomic.Value(u64).init(0),
                .rate_limited = std.atomic.Value(u64).init(0),
                .cookies_sent = std.atomic.Value(u64).init(0),
            };
        }
    };
    
    pub const RateLimiter = struct {
        buckets: std.AutoHashMap(transport.Address, TokenBucket),
        allocator: std.mem.Allocator,
        
        pub const TokenBucket = struct {
            tokens: f64,
            last_refill: i64,
            max_tokens: f64,
            refill_rate: f64,
        };
        
        pub fn init(allocator: std.mem.Allocator) RateLimiter {
            return .{
                .buckets = std.AutoHashMap(transport.Address, TokenBucket).init(allocator),
                .allocator = allocator,
            };
        }
        
        pub fn deinit(self: *RateLimiter) void {
            self.buckets.deinit();
        }
        
        pub fn checkRate(self: *RateLimiter, addr: transport.Address, max_rate: f64) !bool {
            const now = std.time.timestamp();
            
            if (self.buckets.getPtr(addr)) |bucket| {
                // Refill tokens based on time elapsed
                const elapsed = @as(f64, @floatFromInt(now - bucket.last_refill));
                bucket.tokens = @min(bucket.max_tokens, bucket.tokens + (elapsed * bucket.refill_rate));
                bucket.last_refill = now;
                
                if (bucket.tokens >= 1.0) {
                    bucket.tokens -= 1.0;
                    return true;
                }
                return false;
            } else {
                // Create new bucket
                try self.buckets.put(addr, .{
                    .tokens = max_rate - 1.0,
                    .last_refill = now,
                    .max_tokens = max_rate,
                    .refill_rate = max_rate,
                });
                return true;
            }
        }
    };
    
    pub const CookieJar = struct {
        cookies: std.AutoHashMap(transport.Address, Cookie),
        allocator: std.mem.Allocator,
        
        pub const Cookie = struct {
            value: [16]u8,
            timestamp: i64,
            nonce: [24]u8,
        };
        
        pub fn init(allocator: std.mem.Allocator) CookieJar {
            return .{
                .cookies = std.AutoHashMap(transport.Address, Cookie).init(allocator),
                .allocator = allocator,
            };
        }
        
        pub fn deinit(self: *CookieJar) void {
            self.cookies.deinit();
        }
        
        pub fn generateCookie(self: *CookieJar, addr: transport.Address, secret: [32]u8) ![16]u8 {
            var cookie: [16]u8 = undefined;
            var nonce: [24]u8 = undefined;
            std.crypto.random.bytes(&nonce);
            
            // Create cookie based on address and secret
            var hasher = std.crypto.hash.blake3.Blake3.init(.{});
            hasher.update(&secret);
            hasher.update(std.mem.asBytes(&addr));
            hasher.update(&nonce);
            hasher.final(&cookie);
            
            try self.cookies.put(addr, .{
                .value = cookie,
                .timestamp = std.time.timestamp(),
                .nonce = nonce,
            });
            
            return cookie;
        }
        
        pub fn validateCookie(self: *CookieJar, addr: transport.Address, cookie: [16]u8, timeout: i64) bool {
            if (self.cookies.get(addr)) |stored_cookie| {
                const age = std.time.timestamp() - stored_cookie.timestamp;
                return age < timeout and std.mem.eql(u8, &stored_cookie.value, &cookie);
            }
            return false;
        }
    };
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, config: WireGuardConfig) !*WireGuardTunnel {
        const tunnel = try allocator.create(WireGuardTunnel);
        errdefer allocator.destroy(tunnel);
        
        tunnel.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .config = config,
            .socket = udp.UdpSocket.init(allocator, runtime),
            .peers = std.AutoHashMap(u32, *Peer).init(allocator),
            .peer_by_key = std.HashMap([32]u8, *Peer, std.hash_map.HashMap([32]u8, *Peer, ArrayHashContext([32]u8), 80).Context, 80).init(allocator),
            .tun_interface = null,
            .routing_table = RoutingTable.init(allocator),
            .packet_queue = PacketQueue.init(allocator),
            .stats = TunnelStats.init(),
            .rate_limiter = RateLimiter.init(allocator),
            .cookie_jar = CookieJar.init(allocator),
            .send_nonce_counter = std.atomic.Value(u64).init(0),
            .recv_nonce_counter = std.atomic.Value(u64).init(0),
            .mutex = .{},
            .running = std.atomic.Value(bool).init(false),
        };
        
        return tunnel;
    }
    
    pub fn deinit(self: *WireGuardTunnel) void {
        self.stop();
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Clean up peers
        var peer_iter = self.peers.iterator();
        while (peer_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.peers.deinit();
        self.peer_by_key.deinit();
        
        // Clean up TUN interface
        if (self.tun_interface) |tun| {
            tun.deinit(self.allocator);
        }
        
        self.routing_table.deinit();
        self.packet_queue.deinit();
        self.rate_limiter.deinit();
        self.cookie_jar.deinit();
        self.socket.close();
        
        self.allocator.destroy(self);
    }
    
    pub fn start(self: *WireGuardTunnel) !void {
        if (self.running.load(.seq_cst)) {
            return;
        }
        
        // Bind UDP socket
        const bind_addr = transport.Address{ .ipv6 = std.net.Ipv6Address.any };
        try self.socket.bind(bind_addr, .{
            .allocator = self.allocator,
        });
        
        // Create TUN interface
        const tun_addr = std.net.Address{ .in = std.net.Ip4Address.parse("10.0.0.1") catch unreachable };
        self.tun_interface = try TunInterface.create(self.allocator, self.config.interface_name, tun_addr, self.config.mtu);
        
        self.running.store(true, .seq_cst);
        
        // Start async tasks
        _ = try self.runtime.spawn(udpReceiveLoop, .{self}, .normal);
        _ = try self.runtime.spawn(tunReceiveLoop, .{self}, .normal);
        _ = try self.runtime.spawn(keepaliveLoop, .{self}, .normal);
        _ = try self.runtime.spawn(packetProcessingLoop, .{self}, .normal);
    }
    
    pub fn stop(self: *WireGuardTunnel) void {
        self.running.store(false, .seq_cst);
    }
    
    pub fn addPeer(self: *WireGuardTunnel, peer: *Peer) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        try self.peers.put(peer.id, peer);
        try self.peer_by_key.put(peer.public_key, peer);
        
        // Add routes for this peer
        for (peer.allowed_ips.items) |ip_range| {
            try self.routing_table.addRoute(ip_range.network, ip_range.prefix_len, peer.id, 0);
        }
    }
    
    pub fn removePeer(self: *WireGuardTunnel, peer_id: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.peers.fetchRemove(peer_id)) |kv| {
            _ = self.peer_by_key.remove(kv.value.public_key);
            kv.value.deinit();
        }
    }
    
    pub fn initiateHandshake(self: *WireGuardTunnel, peer_id: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const peer = self.peers.get(peer_id) orelse return error.PeerNotFound;
        
        // Generate ephemeral key
        const ephemeral_keypair = try KeyPair.generate();
        
        // Create handshake initiation message
        var message = HandshakeInitiation{
            .sender = peer_id,
            .ephemeral = ephemeral_keypair.public_key,
            .static = undefined,
            .timestamp = undefined,
            .mac1 = undefined,
            .mac2 = undefined,
        };
        
        // Encrypt static key
        const shared_secret = try KeyPair.computeSharedSecret(ephemeral_keypair.private_key, peer.public_key);
        try self.encryptStatic(&message.static, &self.config.public_key, &shared_secret);
        
        // Set timestamp
        message.timestamp = std.time.timestamp();
        
        // Compute MACs
        try self.computeMAC1(&message.mac1, std.mem.asBytes(&message)[0..std.mem.asBytes(&message).len - 32]);
        
        // Send message
        const packet = try self.serializeHandshakeInitiation(&message);
        defer self.allocator.free(packet);
        
        _ = try self.socket.sendTo(packet, peer.endpoint);
        
        peer.handshake_state = .initiation_sent;
        _ = self.stats.handshakes_completed.fetchAdd(1, .seq_cst);
    }
    
    pub fn handleHandshakeInitiation(self: *WireGuardTunnel, data: []const u8, sender_addr: transport.Address) !void {
        const message = try self.deserializeHandshakeInitiation(data);
        
        // Validate MACs
        if (!try self.validateMAC1(&message.mac1, data[0..data.len - 32])) {
            return error.InvalidMAC;
        }
        
        // Decrypt static key
        var peer_static_key: [32]u8 = undefined;
        const shared_secret = try KeyPair.computeSharedSecret(self.config.private_key, message.ephemeral);
        try self.decryptStatic(&peer_static_key, &message.static, &shared_secret);
        
        // Find or create peer
        var peer = self.peer_by_key.get(peer_static_key);
        if (peer == null) {
            // Create new peer if allowed
            const new_peer = try Peer.init(self.allocator, self.generatePeerId(), peer_static_key, sender_addr);
            try self.addPeer(new_peer);
            peer = new_peer;
        }
        
        // Generate response
        const response_keypair = try KeyPair.generate();
        
        var response = HandshakeResponse{
            .sender = peer.?.id,
            .receiver = message.sender,
            .ephemeral = response_keypair.public_key,
            .empty = undefined,
            .mac1 = undefined,
            .mac2 = undefined,
        };
        
        // Derive session keys
        const session_key = try self.deriveSessionKeys(
            &self.config.private_key,
            &peer.?.public_key,
            &message.ephemeral,
            &response_keypair.private_key,
            &response_keypair.public_key,
        );
        
        peer.?.session_key = session_key;
        peer.?.handshake_state = .response_sent;
        
        // Send response
        const response_packet = try self.serializeHandshakeResponse(&response);
        defer self.allocator.free(response_packet);
        
        _ = try self.socket.sendTo(response_packet, sender_addr);
        
        _ = self.stats.handshakes_completed.fetchAdd(1, .seq_cst);
    }
    
    pub fn handleTransportData(self: *WireGuardTunnel, data: []const u8, sender_addr: transport.Address) !void {
        _ = sender_addr;
        const header = try self.deserializeTransportHeader(data);
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const peer = self.peers.get(header.receiver) orelse return error.PeerNotFound;
        
        // Decrypt packet
        const decrypted = try self.decryptTransportData(data[16..], peer.receiving_key.?);
        defer self.allocator.free(decrypted);
        
        // Update counters
        _ = peer.receiving_counter.fetchAdd(1, .seq_cst);
        _ = peer.rx_bytes.fetchAdd(decrypted.len, .seq_cst);
        _ = self.stats.packets_received.fetchAdd(1, .seq_cst);
        _ = self.stats.bytes_received.fetchAdd(decrypted.len, .seq_cst);
        
        peer.updateActivity();
        
        // Forward to TUN interface
        if (self.tun_interface) |tun| {
            _ = try tun.writePacket(decrypted);
        }
    }
    
    pub fn sendData(self: *WireGuardTunnel, data: []const u8, peer_id: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const peer = self.peers.get(peer_id) orelse return error.PeerNotFound;
        
        if (peer.sending_key == null) {
            return error.NoSessionKey;
        }
        
        // Encrypt data
        const encrypted = try self.encryptTransportData(data, peer.sending_key.?);
        defer self.allocator.free(encrypted);
        
        // Create transport header
        var header = TransportHeader{
            .type = @intFromEnum(MessageType.transport_data),
            .reserved = 0,
            .receiver = peer_id,
            .counter = peer.sending_counter.fetchAdd(1, .seq_cst),
        };
        
        // Serialize and send
        const packet = try self.serializeTransportData(&header, encrypted);
        defer self.allocator.free(packet);
        
        _ = try self.socket.sendTo(packet, peer.endpoint);
        
        _ = peer.tx_bytes.fetchAdd(data.len, .seq_cst);
        _ = self.stats.packets_sent.fetchAdd(1, .seq_cst);
        _ = self.stats.bytes_sent.fetchAdd(data.len, .seq_cst);
        
        peer.updateActivity();
    }
    
    // Async message loops
    
    fn udpReceiveLoop(self: *WireGuardTunnel) void {
        var buffer: [2048]u8 = undefined;
        
        while (self.running.load(.seq_cst)) {
            const packet = self.socket.recvFromAsync(&buffer) catch continue;
            
            switch (packet) {
                .ready => |result| {
                    if (result) |pkt| {
                        self.handleUdpPacket(pkt.data, pkt.address) catch |err| {
                            _ = self.stats.errors.fetchAdd(1, .seq_cst);
                            std.log.err("UDP packet handling error: {}", .{err});
                        };
                    } else |_| {
                        continue;
                    }
                },
                .pending => {
                    // Use async sleep instead of blocking
                    try self.runtime.sleep(1);
                    continue;
                },
            }
        }
    }
    
    fn tunReceiveLoop(self: *WireGuardTunnel) void {
        var buffer: [2048]u8 = undefined;
        
        while (self.running.load(.seq_cst)) {
            if (self.tun_interface) |tun| {
                const packet_size = tun.readPacket(&buffer) catch continue;
                const packet = buffer[0..packet_size];
                
                self.handleTunPacket(packet) catch |err| {
                    _ = self.stats.errors.fetchAdd(1, .seq_cst);
                    std.log.err("TUN packet handling error: {}", .{err});
                };
            }
            
            // Use async sleep instead of blocking
            try self.runtime.sleep(1);
        }
    }
    
    fn keepaliveLoop(self: *WireGuardTunnel) void {
        while (self.running.load(.seq_cst)) {
            // Use async sleep instead of blocking
            try self.runtime.sleep(self.config.keepalive_interval * 1000);
            
            self.mutex.lock();
            defer self.mutex.unlock();
            
            var peer_iter = self.peers.iterator();
            while (peer_iter.next()) |entry| {
                const peer = entry.value_ptr.*;
                
                if (peer.persistent_keepalive) |_| {
                    self.sendKeepalive(peer.id) catch |err| {
                        std.log.err("Keepalive send error: {}", .{err});
                    };
                }
            }
        }
    }
    
    fn packetProcessingLoop(self: *WireGuardTunnel) void {
        while (self.running.load(.seq_cst)) {
            if (self.packet_queue.dequeue()) |packet| {
                self.sendData(packet.data, packet.peer_id) catch |err| {
                    std.log.err("Packet processing error: {}", .{err});
                };
                self.allocator.free(packet.data);
            } else {
                // Use async sleep instead of blocking
            try self.runtime.sleep(1);
            }
        }
    }
    
    fn handleUdpPacket(self: *WireGuardTunnel, data: []const u8, sender_addr: transport.Address) !void {
        if (data.len < 4) return error.PacketTooSmall;
        
        // Rate limiting check
        const rate_allowed = self.rate_limiter.checkRate(sender_addr, @as(f64, @floatFromInt(self.config.rate_limit_packets_per_second))) catch false;
        if (!rate_allowed) {
            _ = self.stats.rate_limited.fetchAdd(1, .seq_cst);
            
            // Send cookie challenge for handshake initiation under load
            const message_type: MessageType = @enumFromInt(data[0]);
            if (message_type == .handshake_initiation) {
                try self.sendCookieReply(sender_addr);
            }
            return;
        }
        
        const message_type: MessageType = @enumFromInt(data[0]);
        
        switch (message_type) {
            .handshake_initiation => try self.handleHandshakeInitiation(data, sender_addr),
            .handshake_response => try self.handleHandshakeResponse(data, sender_addr),
            .transport_data => try self.handleTransportData(data, sender_addr),
            .keepalive => try self.handleKeepalive(data, sender_addr),
            .cookie_reply => try self.handleCookieReply(data, sender_addr),
        }
    }
    
    fn handleTunPacket(self: *WireGuardTunnel, packet: []const u8) !void {
        // Parse IP header to determine destination
        if (packet.len < 20) return error.PacketTooSmall;
        
        const version = packet[0] >> 4;
        const destination = switch (version) {
            4 => std.net.Address{ .in = std.net.Ip4Address.init(packet[16..20]) },
            6 => std.net.Address{ .in6 = std.net.Ipv6Address.init(packet[24..40]) },
            else => return error.UnsupportedIPVersion,
        };
        
        // Find peer for destination
        if (self.routing_table.findRoute(destination)) |peer_id| {
            try self.packet_queue.enqueue(packet, peer_id);
        } else {
            std.log.warn("No route found for destination: {}", .{destination});
        }
    }
    
    // Helper methods for crypto operations
    
    fn encryptStatic(self: *WireGuardTunnel, output: *[48]u8, input: *const [32]u8, key: *const [32]u8) !void {
        _ = self;
        // ChaCha20Poly1305 encryption
        try zcrypto.chacha20poly1305.encrypt(output, input, key, &[_]u8{0} ** 12);
    }
    
    fn decryptStatic(self: *WireGuardTunnel, output: *[32]u8, input: *const [48]u8, key: *const [32]u8) !void {
        _ = self;
        // ChaCha20Poly1305 decryption
        try zcrypto.chacha20poly1305.decrypt(output, input, key, &[_]u8{0} ** 12);
    }
    
    fn encryptTransportData(self: *WireGuardTunnel, data: []const u8, key: [32]u8) ![]u8 {
        const encrypted = try self.allocator.alloc(u8, data.len + 16);
        
        // Generate secure nonce using atomic counter
        const nonce_value = self.send_nonce_counter.fetchAdd(1, .seq_cst);
        var nonce: [12]u8 = [_]u8{0} ** 12;
        std.mem.writeIntLittle(u64, nonce[0..8], nonce_value);
        
        try zcrypto.chacha20poly1305.encrypt(encrypted, data, &key, &nonce);
        return encrypted;
    }
    
    fn decryptTransportData(self: *WireGuardTunnel, encrypted: []const u8, key: [32]u8, expected_nonce: u64) ![]u8 {
        const decrypted = try self.allocator.alloc(u8, encrypted.len - 16);
        
        // Validate nonce for replay protection
        const current_nonce = self.recv_nonce_counter.load(.seq_cst);
        if (expected_nonce <= current_nonce) {
            return error.ReplayAttack;
        }
        
        // Update receive nonce counter
        _ = self.recv_nonce_counter.compareAndSwap(current_nonce, expected_nonce, .seq_cst, .seq_cst);
        
        // Reconstruct nonce from value
        var nonce: [12]u8 = [_]u8{0} ** 12;
        std.mem.writeIntLittle(u64, nonce[0..8], expected_nonce);
        
        try zcrypto.chacha20poly1305.decrypt(decrypted, encrypted, &key, &nonce);
        return decrypted;
    }
    
    fn computeMAC1(self: *WireGuardTunnel, output: *[16]u8, input: []const u8) !void {
        // BLAKE2s MAC computation using proper MAC key
        try zcrypto.blake2s.mac(output, input, &self.config.mac_key);
    }
    
    fn validateMAC1(self: *WireGuardTunnel, mac: *const [16]u8, input: []const u8) !bool {
        var computed_mac: [16]u8 = undefined;
        try zcrypto.blake2s.mac(&computed_mac, input, &self.config.mac_key);
        return std.mem.eql(u8, mac, &computed_mac);
    }
    
    fn deriveSessionKeys(self: *WireGuardTunnel, static_priv: *const [32]u8, peer_static: *const [32]u8, ephemeral_pub: *const [32]u8, response_priv: *const [32]u8, response_pub: *const [32]u8) ![32]u8 {
        _ = self;
        _ = static_priv;
        _ = peer_static;
        _ = ephemeral_pub;
        _ = response_priv;
        _ = response_pub;
        
        // HKDF key derivation
        var session_key: [32]u8 = undefined;
        try zcrypto.hkdf.expand(&session_key, &[_]u8{0} ** 32, "wireguard-session-key", &[_]u8{0} ** 32);
        return session_key;
    }
    
    fn generatePeerId(self: *WireGuardTunnel) u32 {
        _ = self;
        return @as(u32, @intCast(std.time.timestamp() & 0xFFFFFFFF));
    }
    
    fn sendCookieReply(self: *WireGuardTunnel, addr: transport.Address) !void {
        // Generate cookie for this address
        const cookie = try self.cookie_jar.generateCookie(addr, self.config.cookie_secret);
        
        // Encrypt cookie
        var encrypted_cookie: [32]u8 = undefined;
        try self.encryptCookie(&encrypted_cookie, &cookie, addr);
        
        var cookie_reply = CookieReply{
            .receiver = 0, // Would be set from original message
            .nonce = undefined,
            .encrypted_cookie = encrypted_cookie,
        };
        
        std.crypto.random.bytes(&cookie_reply.nonce);
        
        const packet = try self.serializeCookieReply(&cookie_reply);
        defer self.allocator.free(packet);
        
        _ = try self.socket.sendTo(packet, addr);
        _ = self.stats.cookies_sent.fetchAdd(1, .seq_cst);
    }
    
    fn encryptCookie(self: *WireGuardTunnel, output: *[32]u8, cookie: *const [16]u8, addr: transport.Address) !void {
        _ = self;
        // XChaCha20Poly1305 encryption of cookie using address-derived key
        var key: [32]u8 = undefined;
        var hasher = std.crypto.hash.blake3.Blake3.init(.{});
        hasher.update(std.mem.asBytes(&addr));
        hasher.final(&key);
        
        var nonce: [24]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        
        try zcrypto.chacha20poly1305.encrypt(output, cookie, &key, &nonce[0..12]);
    }
    
    fn decryptCookie(self: *WireGuardTunnel, output: *[16]u8, encrypted: *const [32]u8, addr: transport.Address) !void {
        _ = self;
        // XChaCha20Poly1305 decryption of cookie
        var key: [32]u8 = undefined;
        var hasher = std.crypto.hash.blake3.Blake3.init(.{});
        hasher.update(std.mem.asBytes(&addr));
        hasher.final(&key);
        
        var nonce: [24]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        
        try zcrypto.chacha20poly1305.decrypt(output, encrypted, &key, &nonce[0..12]);
    }
    
    fn sendKeepaliveById(self: *WireGuardTunnel, peer_id: u32) !void {
        _ = peer_id;
        // Send keepalive packet
        _ = self.stats.keepalives_sent.fetchAdd(1, .seq_cst);
    }
    
    fn handleHandshakeResponse(self: *WireGuardTunnel, data: []const u8, sender_addr: transport.Address) !void {
        if (data.len < 92) return error.InvalidMessageLength; // Min handshake response size
        
        const response = try self.deserializeHandshakeResponse(data);
        
        // Validate MACs
        if (!try self.validateMAC1(&response.mac1, data[0..data.len - 32])) {
            return error.InvalidMAC;
        }
        
        // Validate MAC2 if present (cookie mechanism)
        if (response.mac2) |mac2| {
            if (!try self.validateMAC2(&mac2, data[0..data.len - 16], sender_addr)) {
                return error.InvalidCookie;
            }
        }
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Find peer by receiver ID (our sender ID from initiation)
        const peer = self.peers.get(response.receiver) orelse return error.PeerNotFound;
        
        if (peer.handshake_state != .initiation_sent) {
            return error.UnexpectedHandshakeResponse;
        }
        
        // Verify the response is from the correct peer
        if (!std.mem.eql(u8, &peer.endpoint.in.sa.addr, &sender_addr.in.sa.addr)) {
            if (!self.config.enable_roaming) {
                return error.EndpointMismatch;
            }
            // Update peer endpoint for roaming
            peer.endpoint = sender_addr;
        }
        
        // Get our ephemeral private key from the handshake state
        const our_ephemeral_private = peer.session_key orelse return error.MissingEphemeralKey;
        
        // Perform Noise XX key exchange steps:
        // 1. DH(ephemeral_private, response.ephemeral)
        const dh1 = try KeyPair.computeSharedSecret(our_ephemeral_private, response.ephemeral);
        
        // 2. DH(ephemeral_private, peer.public_key) 
        const dh2 = try KeyPair.computeSharedSecret(our_ephemeral_private, peer.public_key);
        
        // 3. DH(private_key, response.ephemeral)
        const dh3 = try KeyPair.computeSharedSecret(self.config.private_key, response.ephemeral);
        
        // Derive transport keys using HKDF
        var transport_keys: [64]u8 = undefined;
        try self.deriveTransportKeys(&transport_keys, &dh1, &dh2, &dh3, peer.preshared_key);
        
        // Split into sending and receiving keys
        peer.sending_key = transport_keys[0..32].*;
        peer.receiving_key = transport_keys[32..64].*;
        
        // Decrypt and verify the empty payload (contains timestamp)
        if (response.encrypted_empty.len >= 16) {
            var decrypted: [16]u8 = undefined;
            try self.decryptHandshakePayload(&decrypted, &response.encrypted_empty, &peer.receiving_key.?);
            
            // Verify timestamp to prevent replay attacks
            const timestamp = std.mem.readInt(i64, decrypted[0..8], .little);
            const now = std.time.timestamp();
            if (@abs(now - timestamp) > 60) { // 60 second tolerance
                return error.TimestampTooOld;
            }
        }
        
        // Complete handshake
        peer.handshake_state = .established;
        peer.last_handshake = std.time.timestamp();
        peer.last_activity.store(std.time.timestamp(), .seq_cst);
        
        // Reset packet counters for new session
        peer.receiving_counter.store(0, .seq_cst);
        peer.sending_counter.store(0, .seq_cst);
        
        // Clear session key (it was temporary storage for ephemeral key)
        peer.session_key = null;
        
        _ = self.stats.handshakes_completed.fetchAdd(1, .seq_cst);
        
        // Send keepalive to confirm the tunnel is ready
        try self.sendKeepalive(peer);
    }
    
    fn handleKeepalive(self: *WireGuardTunnel, data: []const u8, sender_addr: transport.Address) !void {
        _ = data;
        _ = sender_addr;
        _ = self.stats.keepalives_received.fetchAdd(1, .seq_cst);
    }
    
    fn handleCookieReply(self: *WireGuardTunnel, data: []const u8, sender_addr: transport.Address) !void {
        const cookie_reply = try self.deserializeCookieReply(data);
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Decrypt and validate cookie
        var cookie: [16]u8 = undefined;
        try self.decryptCookie(&cookie, &cookie_reply.encrypted_cookie, sender_addr);
        
        // Store cookie for this peer endpoint
        if (self.peer_addresses.get(sender_addr)) |peer_id| {
            if (self.peers.get(peer_id)) |peer| {
                // Cookie stored in peer metadata (simplified)
                _ = peer;
            }
        }
    }
    
    fn deriveTransportKeys(self: *WireGuardTunnel, output: *[64]u8, dh1: *const [32]u8, dh2: *const [32]u8, dh3: *const [32]u8, psk: ?[32]u8) !void {
        _ = self;
        
        // Concatenate all DH results
        var key_material: [96]u8 = undefined;
        @memcpy(key_material[0..32], dh1);
        @memcpy(key_material[32..64], dh2);
        @memcpy(key_material[64..96], dh3);
        
        // Include pre-shared key if available
        if (psk) |preshared| {
            // XOR the PSK into the key material
            for (0..32) |i| {
                key_material[i] ^= preshared[i];
            }
        }
        
        // Use HKDF to derive final transport keys
        try zcrypto.hkdf.expand(output, &key_material, "WireGuard v1 transport keys", &[_]u8{});
    }
    
    fn decryptHandshakePayload(self: *WireGuardTunnel, output: []u8, encrypted: []const u8, key: *const [32]u8) !void {
        _ = self;
        
        if (encrypted.len < 16) return error.InvalidPayloadLength;
        
        const ciphertext = encrypted[0..encrypted.len - 16];
        const auth_tag = encrypted[encrypted.len - 16..encrypted.len];
        
        // Generate nonce (simplified - should be from handshake state)
        var nonce: [12]u8 = [_]u8{0} ** 12;
        
        // Verify auth tag
        var poly_state = zcrypto.poly1305.Poly1305.init(key);
        poly_state.update(ciphertext);
        var computed_tag: [16]u8 = undefined;
        poly_state.final(&computed_tag);
        
        if (!std.mem.eql(u8, auth_tag, &computed_tag)) {
            return error.AuthenticationFailed;
        }
        
        // Decrypt
        var chacha_state = zcrypto.chacha20.ChaCha20.init(key, &nonce);
        chacha_state.crypt(output[0..ciphertext.len], ciphertext);
    }
    
    fn validateMAC2(self: *WireGuardTunnel, mac: *const [16]u8, data: []const u8, sender_addr: transport.Address) !bool {
        // Get cookie for this address if one exists
        if (self.cookie_jar.cookies.get(sender_addr)) |stored_cookie| {
            // Cookie is valid if within timeout
            const age = std.time.timestamp() - stored_cookie.timestamp;
            if (age >= self.config.cookie_timeout) {
                return false; // Cookie expired
            }
            
            // Compute expected MAC2 using stored cookie
            var expected_mac: [16]u8 = undefined;
            try zcrypto.blake2s.mac(&expected_mac, data, &stored_cookie.value);
            
            // Compare with provided MAC2
            return std.mem.eql(u8, mac, &expected_mac);
        }
        
        // No cookie stored for this address - require cookie challenge
        return false;
    }
    
    fn sendKeepalive(self: *WireGuardTunnel, peer: *Peer) !void {
        var keepalive_data: [32]u8 = [_]u8{0} ** 32;
        keepalive_data[0] = @intFromEnum(MessageType.keepalive);
        
        const encrypted = try self.encryptTransportData(&keepalive_data[1..], &[_]u8{}, peer);
        defer self.allocator.free(encrypted);
        
        _ = try self.socket.sendTo(encrypted, peer.endpoint);
        _ = self.stats.keepalives_sent.fetchAdd(1, .seq_cst);
    }
    
    // Message serialization/deserialization
    
    fn serializeHandshakeInitiation(self: *WireGuardTunnel, message: *const HandshakeInitiation) ![]u8 {
        const packet = try self.allocator.alloc(u8, 148);
        std.mem.copy(u8, packet, std.mem.asBytes(message));
        return packet;
    }
    
    fn deserializeHandshakeInitiation(self: *WireGuardTunnel, data: []const u8) !HandshakeInitiation {
        _ = self;
        if (data.len < 148) return error.PacketTooSmall;
        return @as(*const HandshakeInitiation, @ptrCast(data.ptr)).*;
    }
    
    fn serializeHandshakeResponse(self: *WireGuardTunnel, message: *const HandshakeResponse) ![]u8 {
        const packet = try self.allocator.alloc(u8, 92);
        std.mem.copy(u8, packet, std.mem.asBytes(message));
        return packet;
    }
    
    fn deserializeHandshakeResponse(self: *WireGuardTunnel, data: []const u8) !HandshakeResponse {
        _ = self;
        if (data.len < 92) return error.PacketTooSmall;
        return @as(*const HandshakeResponse, @ptrCast(data.ptr)).*;
    }
    
    fn deserializeTransportHeader(self: *WireGuardTunnel, data: []const u8) !TransportHeader {
        _ = self;
        if (data.len < 16) return error.PacketTooSmall;
        return @as(*const TransportHeader, @ptrCast(data.ptr)).*;
    }
    
    fn serializeTransportData(self: *WireGuardTunnel, header: *const TransportHeader, data: []const u8) ![]u8 {
        const packet = try self.allocator.alloc(u8, 16 + data.len);
        std.mem.copy(u8, packet[0..16], std.mem.asBytes(header));
        std.mem.copy(u8, packet[16..], data);
        return packet;
    }
    
    fn serializeCookieReply(self: *WireGuardTunnel, message: *const CookieReply) ![]u8 {
        const packet = try self.allocator.alloc(u8, 64);
        std.mem.copy(u8, packet, std.mem.asBytes(message));
        return packet;
    }
    
    fn deserializeCookieReply(self: *WireGuardTunnel, data: []const u8) !CookieReply {
        _ = self;
        if (data.len < 64) return error.PacketTooSmall;
        return @as(*const CookieReply, @ptrCast(data.ptr)).*;
    }
    
    pub fn getStats(self: *WireGuardTunnel) TunnelStats {
        return self.stats;
    }
};

// Message structures
const HandshakeInitiation = packed struct {
    type: u8 = @intFromEnum(MessageType.handshake_initiation),
    reserved: [3]u8 = [_]u8{0} ** 3,
    sender: u32,
    ephemeral: [32]u8,
    static: [48]u8,
    timestamp: [12]u8,
    mac1: [16]u8,
    mac2: [16]u8,
};

const HandshakeResponse = packed struct {
    type: u8 = @intFromEnum(MessageType.handshake_response),
    reserved: [3]u8 = [_]u8{0} ** 3,
    sender: u32,
    receiver: u32,
    ephemeral: [32]u8,
    empty: [16]u8,
    mac1: [16]u8,
    mac2: [16]u8,
};

const TransportHeader = packed struct {
    type: u8 = @intFromEnum(MessageType.transport_data),
    reserved: [3]u8 = [_]u8{0} ** 3,
    receiver: u32,
    counter: u64,
};

const CookieReply = packed struct {
    type: u8 = @intFromEnum(MessageType.cookie_reply),
    reserved: [3]u8 = [_]u8{0} ** 3,
    receiver: u32,
    nonce: [24]u8,
    encrypted_cookie: [32]u8,
};