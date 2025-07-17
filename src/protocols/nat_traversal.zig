const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");
const udp = @import("../transport/udp.zig");
const errors = @import("../errors/errors.zig");

pub const StunMessageType = enum(u16) {
    binding_request = 0x0001,
    binding_response = 0x0101,
    binding_error_response = 0x0111,
    binding_indication = 0x0011,
    allocate_request = 0x0003,
    allocate_response = 0x0103,
    allocate_error_response = 0x0113,
    refresh_request = 0x0004,
    refresh_response = 0x0104,
    send_indication = 0x0016,
    data_indication = 0x0017,
    channel_bind_request = 0x0009,
    channel_bind_response = 0x0109,
};

pub const StunAttributeType = enum(u16) {
    mapped_address = 0x0001,
    username = 0x0006,
    message_integrity = 0x0008,
    error_code = 0x0009,
    unknown_attributes = 0x000A,
    realm = 0x0014,
    nonce = 0x0015,
    xor_mapped_address = 0x0020,
    software = 0x8022,
    alternate_server = 0x8023,
    fingerprint = 0x8028,
    lifetime = 0x000D,
    data = 0x0013,
    xor_peer_address = 0x0012,
    channel_number = 0x000C,
};

pub const StunHeader = packed struct {
    message_type: u16,
    message_length: u16,
    magic_cookie: u32 = 0x2112A442,
    transaction_id: [12]u8,
};

pub const StunAttribute = struct {
    attribute_type: StunAttributeType,
    length: u16,
    value: []const u8,
};

pub const StunMessage = struct {
    header: StunHeader,
    attributes: std.ArrayList(StunAttribute),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, message_type: StunMessageType) !StunMessage {
        var transaction_id: [12]u8 = undefined;
        std.crypto.random.bytes(&transaction_id);
        
        return StunMessage{
            .header = StunHeader{
                .message_type = @intFromEnum(message_type),
                .message_length = 0,
                .transaction_id = transaction_id,
            },
            .attributes = std.ArrayList(StunAttribute).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *StunMessage) void {
        for (self.attributes.items) |attr| {
            self.allocator.free(attr.value);
        }
        self.attributes.deinit();
    }
    
    pub fn addAttribute(self: *StunMessage, attr_type: StunAttributeType, value: []const u8) !void {
        const attr_value = try self.allocator.dupe(u8, value);
        try self.attributes.append(.{
            .attribute_type = attr_type,
            .length = @intCast(value.len),
            .value = attr_value,
        });
        
        // Update message length
        self.header.message_length += 4 + @as(u16, @intCast(value.len));
        // Add padding to 4-byte boundary
        const padding = (4 - (value.len % 4)) % 4;
        self.header.message_length += @intCast(padding);
    }
    
    pub fn serialize(self: *StunMessage) ![]u8 {
        const total_size = 20 + self.header.message_length;
        var buffer = try self.allocator.alloc(u8, total_size);
        var offset: usize = 0;
        
        // Header
        std.mem.writeIntBig(u16, buffer[offset..offset+2], self.header.message_type);
        offset += 2;
        std.mem.writeIntBig(u16, buffer[offset..offset+2], self.header.message_length);
        offset += 2;
        std.mem.writeIntBig(u32, buffer[offset..offset+4], self.header.magic_cookie);
        offset += 4;
        @memcpy(buffer[offset..offset+12], &self.header.transaction_id);
        offset += 12;
        
        // Attributes
        for (self.attributes.items) |attr| {
            std.mem.writeIntBig(u16, buffer[offset..offset+2], @intFromEnum(attr.attribute_type));
            offset += 2;
            std.mem.writeIntBig(u16, buffer[offset..offset+2], attr.length);
            offset += 2;
            @memcpy(buffer[offset..offset+attr.value.len], attr.value);
            offset += attr.value.len;
            
            // Add padding
            const padding = (4 - (attr.value.len % 4)) % 4;
            @memset(buffer[offset..offset+padding], 0);
            offset += padding;
        }
        
        return buffer;
    }
    
    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !StunMessage {
        if (data.len < 20) return error.InvalidMessage;
        
        var message = StunMessage{
            .header = StunHeader{
                .message_type = std.mem.readIntBig(u16, data[0..2]),
                .message_length = std.mem.readIntBig(u16, data[2..4]),
                .magic_cookie = std.mem.readIntBig(u32, data[4..8]),
                .transaction_id = data[8..20][0..12].*,
            },
            .attributes = std.ArrayList(StunAttribute).init(allocator),
            .allocator = allocator,
        };
        
        if (message.header.magic_cookie != 0x2112A442) {
            return error.InvalidMagicCookie;
        }
        
        // Parse attributes
        var offset: usize = 20;
        while (offset < data.len and offset < 20 + message.header.message_length) {
            if (offset + 4 > data.len) break;
            
            const attr_type: StunAttributeType = @enumFromInt(std.mem.readIntBig(u16, data[offset..offset+2]));
            const attr_length = std.mem.readIntBig(u16, data[offset+2..offset+4]);
            offset += 4;
            
            if (offset + attr_length > data.len) break;
            
            const attr_value = try allocator.dupe(u8, data[offset..offset+attr_length]);
            try message.attributes.append(.{
                .attribute_type = attr_type,
                .length = attr_length,
                .value = attr_value,
            });
            
            offset += attr_length;
            // Skip padding
            const padding = (4 - (attr_length % 4)) % 4;
            offset += padding;
        }
        
        return message;
    }
};

pub const StunClient = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    socket: udp.UdpSocket,
    server_address: transport.Address,
    local_address: ?transport.Address,
    mapped_address: ?transport.Address,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, server_address: transport.Address) StunClient {
        return .{
            .allocator = allocator,
            .runtime = runtime,
            .socket = udp.UdpSocket.init(allocator, runtime),
            .server_address = server_address,
            .local_address = null,
            .mapped_address = null,
        };
    }
    
    pub fn deinit(self: *StunClient) void {
        self.socket.close();
    }
    
    pub fn discoverNatType(self: *StunClient) !transport.Address {
        // Bind to local port
        const bind_addr = transport.Address{ .ipv4 = std.net.Ip4Address.any };
        try self.socket.bind(bind_addr, .{ .allocator = self.allocator });
        self.local_address = try self.socket.localAddress();
        
        // Send binding request
        var request = try StunMessage.init(self.allocator, .binding_request);
        defer request.deinit();
        
        const request_data = try request.serialize();
        defer self.allocator.free(request_data);
        
        _ = try self.socket.sendTo(request_data, self.server_address);
        
        // Wait for response
        var response_buffer: [1024]u8 = undefined;
        const response = try self.socket.recvFrom(&response_buffer);
        
        var response_msg = try StunMessage.deserialize(self.allocator, response.data);
        defer response_msg.deinit();
        
        // Extract mapped address
        for (response_msg.attributes.items) |attr| {
            switch (attr.attribute_type) {
                .xor_mapped_address => {
                    self.mapped_address = try self.parseXorMappedAddress(attr.value);
                    return self.mapped_address.?;
                },
                .mapped_address => {
                    self.mapped_address = try self.parseMappedAddress(attr.value);
                    return self.mapped_address.?;
                },
                else => continue,
            }
        }
        
        return error.NoMappedAddress;
    }
    
    fn parseXorMappedAddress(self: *StunClient, data: []const u8) !transport.Address {
        if (data.len < 8) return error.InvalidAttribute;
        
        const family = std.mem.readIntBig(u16, data[1..3]);
        const port = std.mem.readIntBig(u16, data[2..4]) ^ 0x2112; // XOR with magic cookie
        
        switch (family) {
            0x01 => { // IPv4
                if (data.len < 8) return error.InvalidAttribute;
                var addr_bytes: [4]u8 = undefined;
                @memcpy(&addr_bytes, data[4..8]);
                
                // XOR with magic cookie
                const magic_bytes = std.mem.asBytes(&@as(u32, 0x2112A442));
                for (0..4) |i| {
                    addr_bytes[i] ^= magic_bytes[i];
                }
                
                return transport.Address{ .ipv4 = std.net.Ip4Address.init(addr_bytes, port) };
            },
            0x02 => { // IPv6
                if (data.len < 20) return error.InvalidAttribute;
                var addr_bytes: [16]u8 = undefined;
                @memcpy(&addr_bytes, data[4..20]);
                
                // XOR with magic cookie + transaction ID
                const magic_bytes = std.mem.asBytes(&@as(u32, 0x2112A442));
                for (0..4) |i| {
                    addr_bytes[i] ^= magic_bytes[i];
                }
                for (0..12) |i| {
                    addr_bytes[i + 4] ^= self.socket.transaction_id[i];
                }
                
                return transport.Address{ .ipv6 = std.net.Ipv6Address.init(addr_bytes, port, 0, 0) };
            },
            else => return error.UnsupportedAddressFamily,
        }
    }
    
    fn parseMappedAddress(self: *StunClient, data: []const u8) !transport.Address {
        _ = self;
        if (data.len < 8) return error.InvalidAttribute;
        
        const family = std.mem.readIntBig(u16, data[1..3]);
        const port = std.mem.readIntBig(u16, data[2..4]);
        
        switch (family) {
            0x01 => { // IPv4
                const addr_bytes = data[4..8][0..4].*;
                return transport.Address{ .ipv4 = std.net.Ip4Address.init(addr_bytes, port) };
            },
            0x02 => { // IPv6
                if (data.len < 20) return error.InvalidAttribute;
                const addr_bytes = data[4..20][0..16].*;
                return transport.Address{ .ipv6 = std.net.Ipv6Address.init(addr_bytes, port, 0, 0) };
            },
            else => return error.UnsupportedAddressFamily,
        }
    }
};

pub const TurnClient = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    socket: udp.UdpSocket,
    server_address: transport.Address,
    username: []const u8,
    password: []const u8,
    realm: ?[]const u8,
    nonce: ?[]const u8,
    relay_address: ?transport.Address,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, server_address: transport.Address, username: []const u8, password: []const u8) TurnClient {
        return .{
            .allocator = allocator,
            .runtime = runtime,
            .socket = udp.UdpSocket.init(allocator, runtime),
            .server_address = server_address,
            .username = username,
            .password = password,
            .realm = null,
            .nonce = null,
            .relay_address = null,
        };
    }
    
    pub fn deinit(self: *TurnClient) void {
        if (self.realm) |realm| self.allocator.free(realm);
        if (self.nonce) |nonce| self.allocator.free(nonce);
        self.socket.close();
    }
    
    pub fn allocateRelay(self: *TurnClient) !transport.Address {
        // Bind local socket
        const bind_addr = transport.Address{ .ipv4 = std.net.Ip4Address.any };
        try self.socket.bind(bind_addr, .{ .allocator = self.allocator });
        
        // Send allocate request
        var request = try StunMessage.init(self.allocator, .allocate_request);
        defer request.deinit();
        
        // Add requested transport (UDP)
        const transport_udp = [_]u8{17}; // UDP protocol number
        try request.addAttribute(.requested_transport, &transport_udp);
        
        // Add lifetime
        const lifetime_bytes = std.mem.asBytes(&@as(u32, 600)); // 10 minutes
        try request.addAttribute(.lifetime, lifetime_bytes);
        
        const request_data = try request.serialize();
        defer self.allocator.free(request_data);
        
        _ = try self.socket.sendTo(request_data, self.server_address);
        
        // Wait for response
        var response_buffer: [1024]u8 = undefined;
        const response = try self.socket.recvFrom(&response_buffer);
        
        var response_msg = try StunMessage.deserialize(self.allocator, response.data);
        defer response_msg.deinit();
        
        // Check if authentication is required
        if (@as(StunMessageType, @enumFromInt(response_msg.header.message_type)) == .allocate_error_response) {
            // Extract realm and nonce for authentication
            for (response_msg.attributes.items) |attr| {
                switch (attr.attribute_type) {
                    .realm => {
                        if (self.realm) |old_realm| self.allocator.free(old_realm);
                        self.realm = try self.allocator.dupe(u8, attr.value);
                    },
                    .nonce => {
                        if (self.nonce) |old_nonce| self.allocator.free(old_nonce);
                        self.nonce = try self.allocator.dupe(u8, attr.value);
                    },
                    else => continue,
                }
            }
            
            // Retry with authentication
            return try self.allocateWithAuth();
        }
        
        // Extract relay address from successful response
        for (response_msg.attributes.items) |attr| {
            switch (attr.attribute_type) {
                .xor_mapped_address => {
                    self.relay_address = try self.parseXorRelayAddress(attr.value);
                    return self.relay_address.?;
                },
                else => continue,
            }
        }
        
        return error.NoRelayAddress;
    }
    
    fn allocateWithAuth(self: *TurnClient) !transport.Address {
        var request = try StunMessage.init(self.allocator, .allocate_request);
        defer request.deinit();
        
        // Add username
        try request.addAttribute(.username, self.username);
        
        // Add realm if available
        if (self.realm) |realm| {
            try request.addAttribute(.realm, realm);
        }
        
        // Add nonce if available
        if (self.nonce) |nonce| {
            try request.addAttribute(.nonce, nonce);
        }
        
        // Add requested transport
        const transport_udp = [_]u8{17};
        try request.addAttribute(.requested_transport, &transport_udp);
        
        // Add lifetime
        const lifetime_bytes = std.mem.asBytes(&@as(u32, 600));
        try request.addAttribute(.lifetime, lifetime_bytes);
        
        // Calculate message integrity
        const integrity = try self.calculateMessageIntegrity(&request);
        try request.addAttribute(.message_integrity, &integrity);
        
        const request_data = try request.serialize();
        defer self.allocator.free(request_data);
        
        _ = try self.socket.sendTo(request_data, self.server_address);
        
        // Wait for response
        var response_buffer: [1024]u8 = undefined;
        const response = try self.socket.recvFrom(&response_buffer);
        
        var response_msg = try StunMessage.deserialize(self.allocator, response.data);
        defer response_msg.deinit();
        
        // Extract relay address
        for (response_msg.attributes.items) |attr| {
            switch (attr.attribute_type) {
                .xor_mapped_address => {
                    self.relay_address = try self.parseXorRelayAddress(attr.value);
                    return self.relay_address.?;
                },
                else => continue,
            }
        }
        
        return error.AllocationFailed;
    }
    
    fn calculateMessageIntegrity(self: *TurnClient, message: *StunMessage) ![20]u8 {
        // HMAC-SHA1 calculation for message integrity
        var key_material: [1024]u8 = undefined;
        var key_len: usize = 0;
        
        // Create key from username:realm:password
        @memcpy(key_material[key_len..key_len + self.username.len], self.username);
        key_len += self.username.len;
        key_material[key_len] = ':';
        key_len += 1;
        
        if (self.realm) |realm| {
            @memcpy(key_material[key_len..key_len + realm.len], realm);
            key_len += realm.len;
        }
        
        key_material[key_len] = ':';
        key_len += 1;
        @memcpy(key_material[key_len..key_len + self.password.len], self.password);
        key_len += self.password.len;
        
        // Hash the key material
        var md5_key: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(key_material[0..key_len], &md5_key, .{});
        
        // Serialize message without integrity attribute
        const message_data = try message.serialize();
        defer self.allocator.free(message_data);
        
        // Calculate HMAC-SHA1
        var integrity: [20]u8 = undefined;
        std.crypto.auth.hmac.sha1.Hmac.create(&integrity, message_data, &md5_key);
        
        return integrity;
    }
    
    fn parseXorRelayAddress(self: *TurnClient, data: []const u8) !transport.Address {
        _ = self;
        if (data.len < 8) return error.InvalidAttribute;
        
        const family = std.mem.readIntBig(u16, data[1..3]);
        const port = std.mem.readIntBig(u16, data[2..4]) ^ 0x2112;
        
        switch (family) {
            0x01 => { // IPv4
                var addr_bytes: [4]u8 = undefined;
                @memcpy(&addr_bytes, data[4..8]);
                
                // XOR with magic cookie
                const magic_bytes = std.mem.asBytes(&@as(u32, 0x2112A442));
                for (0..4) |i| {
                    addr_bytes[i] ^= magic_bytes[i];
                }
                
                return transport.Address{ .ipv4 = std.net.Ip4Address.init(addr_bytes, port) };
            },
            else => return error.UnsupportedAddressFamily,
        }
    }
    
    pub fn sendData(self: *TurnClient, data: []const u8, peer_address: transport.Address) !void {
        if (self.relay_address == null) return error.NoRelayAllocated;
        
        var request = try StunMessage.init(self.allocator, .send_indication);
        defer request.deinit();
        
        // Add peer address
        const peer_addr_data = try self.encodeXorPeerAddress(peer_address);
        defer self.allocator.free(peer_addr_data);
        try request.addAttribute(.xor_peer_address, peer_addr_data);
        
        // Add data
        try request.addAttribute(.data, data);
        
        const request_data = try request.serialize();
        defer self.allocator.free(request_data);
        
        _ = try self.socket.sendTo(request_data, self.server_address);
    }
    
    fn encodeXorPeerAddress(self: *TurnClient, address: transport.Address) ![]u8 {
        _ = self;
        var buffer = std.ArrayList(u8).init(self.allocator);
        
        switch (address) {
            .ipv4 => |addr| {
                try buffer.append(0); // Reserved
                try buffer.append(0x01); // IPv4 family
                
                const port = addr.sa.port ^ 0x2112;
                try buffer.append(@intCast(port >> 8));
                try buffer.append(@intCast(port & 0xFF));
                
                // XOR address with magic cookie
                const magic_bytes = std.mem.asBytes(&@as(u32, 0x2112A442));
                for (0..4) |i| {
                    try buffer.append(addr.sa.addr[i] ^ magic_bytes[i]);
                }
            },
            else => return error.UnsupportedAddressFamily,
        }
        
        return buffer.toOwnedSlice();
    }
};

pub const NatTraversal = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    stun_client: ?StunClient,
    turn_client: ?TurnClient,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) NatTraversal {
        return .{
            .allocator = allocator,
            .runtime = runtime,
            .stun_client = null,
            .turn_client = null,
        };
    }
    
    pub fn deinit(self: *NatTraversal) void {
        if (self.stun_client) |*client| client.deinit();
        if (self.turn_client) |*client| client.deinit();
    }
    
    pub fn discoverPublicAddress(self: *NatTraversal, stun_server: transport.Address) !transport.Address {
        self.stun_client = StunClient.init(self.allocator, self.runtime, stun_server);
        return try self.stun_client.?.discoverNatType();
    }
    
    pub fn allocateTurnRelay(self: *NatTraversal, turn_server: transport.Address, username: []const u8, password: []const u8) !transport.Address {
        self.turn_client = TurnClient.init(self.allocator, self.runtime, turn_server, username, password);
        return try self.turn_client.?.allocateRelay();
    }
    
    pub fn sendViaTurn(self: *NatTraversal, data: []const u8, peer_address: transport.Address) !void {
        if (self.turn_client) |*client| {
            try client.sendData(data, peer_address);
        } else {
            return error.NoTurnClient;
        }
    }
};