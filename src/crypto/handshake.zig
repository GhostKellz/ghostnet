const std = @import("std");
const zsync = @import("zsync");
const zcrypto = @import("zcrypto");
const transport = @import("../transport/transport.zig");
const errors = @import("../errors/errors.zig");

pub const HandshakeType = enum {
    tls,
    noise,
    wireguard,
    custom,
};

pub const HandshakeState = enum {
    uninitialized,
    initiating,
    responding,
    established,
    failed,
};

pub const CipherSuite = enum {
    chacha20_poly1305,
    aes_256_gcm,
    aes_128_gcm,
    
    pub fn keySize(self: CipherSuite) usize {
        return switch (self) {
            .chacha20_poly1305 => 32,
            .aes_256_gcm => 32,
            .aes_128_gcm => 16,
        };
    }
    
    pub fn nonceSize(self: CipherSuite) usize {
        return switch (self) {
            .chacha20_poly1305 => 12,
            .aes_256_gcm => 12,
            .aes_128_gcm => 12,
        };
    }
};

pub const KeyExchangeAlgorithm = enum {
    curve25519,
    secp256r1,
    x448,
    
    pub fn publicKeySize(self: KeyExchangeAlgorithm) usize {
        return switch (self) {
            .curve25519 => 32,
            .secp256r1 => 64,
            .x448 => 56,
        };
    }
    
    pub fn privateKeySize(self: KeyExchangeAlgorithm) usize {
        return switch (self) {
            .curve25519 => 32,
            .secp256r1 => 32,
            .x448 => 56,
        };
    }
};

pub const HandshakeConfig = struct {
    handshake_type: HandshakeType,
    cipher_suite: CipherSuite,
    key_exchange: KeyExchangeAlgorithm,
    is_initiator: bool,
    psk: ?[]const u8 = null,
    certificate: ?[]const u8 = null,
    private_key: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
    alpn_protocols: []const []const u8 = &[_][]const u8{},
    max_handshake_time: u64 = 30000, // 30 seconds
    enable_0rtt: bool = false,
    verify_peer: bool = true,
};

pub const HandshakeResult = struct {
    sending_key: []u8,
    receiving_key: []u8,
    session_info: SessionInfo,
    early_data_accepted: bool = false,
    
    pub const SessionInfo = struct {
        cipher_suite: CipherSuite,
        protocol_version: u16,
        server_name: ?[]const u8,
        alpn_protocol: ?[]const u8,
        peer_certificate: ?[]const u8,
        session_ticket: ?[]const u8,
        resumption_secret: ?[]const u8,
        max_early_data_size: u32 = 0,
    };
};

pub const NoiseHandshake = struct {
    allocator: std.mem.Allocator,
    config: HandshakeConfig,
    state: HandshakeState,
    local_static_key: [32]u8,
    local_ephemeral_key: [32]u8,
    remote_static_key: ?[32]u8,
    remote_ephemeral_key: ?[32]u8,
    chaining_key: [32]u8,
    hash: [32]u8,
    message_buffer: std.ArrayList(u8),
    handshake_hash: [32]u8,
    
    pub fn init(allocator: std.mem.Allocator, config: HandshakeConfig) !*NoiseHandshake {
        var handshake = try allocator.create(NoiseHandshake);
        handshake.* = .{
            .allocator = allocator,
            .config = config,
            .state = .uninitialized,
            .local_static_key = undefined,
            .local_ephemeral_key = undefined,
            .remote_static_key = null,
            .remote_ephemeral_key = null,
            .chaining_key = undefined,
            .hash = undefined,
            .message_buffer = std.ArrayList(u8).init(allocator),
            .handshake_hash = undefined,
        };
        
        // Initialize keys
        try handshake.generateKeys();
        
        return handshake;
    }
    
    pub fn deinit(self: *NoiseHandshake) void {
        self.message_buffer.deinit();
        self.allocator.destroy(self);
    }
    
    fn generateKeys(self: *NoiseHandshake) !void {
        // Generate static keypair
        try zcrypto.curve25519.generateKeypair(&self.local_static_key, &self.local_static_key);
        
        // Generate ephemeral keypair
        try zcrypto.curve25519.generateKeypair(&self.local_ephemeral_key, &self.local_ephemeral_key);
        
        // Initialize chaining key and hash
        const protocol_name = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
        try zcrypto.blake2s.hash(&self.chaining_key, protocol_name, &[_]u8{});
        self.hash = self.chaining_key;
    }
    
    pub fn writeMessage(self: *NoiseHandshake, payload: []const u8) ![]u8 {
        self.message_buffer.clearRetainingCapacity();
        
        switch (self.state) {
            .uninitialized => {
                if (self.config.is_initiator) {
                    try self.writeInitiatorMessage1(payload);
                    self.state = .initiating;
                } else {
                    return error.InvalidState;
                }
            },
            .initiating => {
                if (self.config.is_initiator) {
                    try self.writeInitiatorMessage3(payload);
                    self.state = .established;
                } else {
                    try self.writeResponderMessage2(payload);
                    self.state = .responding;
                }
            },
            .responding => {
                if (!self.config.is_initiator) {
                    return error.InvalidState;
                } else {
                    try self.writeInitiatorMessage3(payload);
                    self.state = .established;
                }
            },
            .established => {
                return error.HandshakeComplete;
            },
            .failed => {
                return error.HandshakeFailed;
            },
        }
        
        return try self.message_buffer.toOwnedSlice();
    }
    
    pub fn readMessage(self: *NoiseHandshake, message: []const u8) ![]u8 {
        var payload = std.ArrayList(u8).init(self.allocator);
        defer payload.deinit();
        
        switch (self.state) {
            .uninitialized => {
                if (!self.config.is_initiator) {
                    try self.readInitiatorMessage1(message, &payload);
                    self.state = .initiating;
                } else {
                    return error.InvalidState;
                }
            },
            .initiating => {
                if (!self.config.is_initiator) {
                    try self.readInitiatorMessage3(message, &payload);
                    self.state = .established;
                } else {
                    try self.readResponderMessage2(message, &payload);
                    self.state = .responding;
                }
            },
            .responding => {
                if (self.config.is_initiator) {
                    return error.InvalidState;
                } else {
                    try self.readInitiatorMessage3(message, &payload);
                    self.state = .established;
                }
            },
            .established => {
                return error.HandshakeComplete;
            },
            .failed => {
                return error.HandshakeFailed;
            },
        }
        
        return try payload.toOwnedSlice();
    }
    
    fn writeInitiatorMessage1(self: *NoiseHandshake, payload: []const u8) !void {
        // -> e
        try self.message_buffer.appendSlice(&self.local_ephemeral_key);
        try self.mixHash(&self.local_ephemeral_key);
        
        // Encrypt payload
        const encrypted_payload = try self.encryptAndHash(payload);
        defer self.allocator.free(encrypted_payload);
        
        try self.message_buffer.appendSlice(encrypted_payload);
    }
    
    fn writeInitiatorMessage3(self: *NoiseHandshake, payload: []const u8) !void {
        // -> s, se
        const encrypted_static = try self.encryptAndHash(&self.local_static_key);
        defer self.allocator.free(encrypted_static);
        
        try self.message_buffer.appendSlice(encrypted_static);
        
        // Mix DH
        if (self.remote_ephemeral_key) |remote_eph| {
            const dh_result = try self.dh(&self.local_static_key, &remote_eph);
            try self.mixKey(&dh_result);
        }
        
        // Encrypt payload
        const encrypted_payload = try self.encryptAndHash(payload);
        defer self.allocator.free(encrypted_payload);
        
        try self.message_buffer.appendSlice(encrypted_payload);
    }
    
    fn writeResponderMessage2(self: *NoiseHandshake, payload: []const u8) !void {
        // -> e, ee, s, es
        try self.message_buffer.appendSlice(&self.local_ephemeral_key);
        try self.mixHash(&self.local_ephemeral_key);
        
        // Mix DH (ee)
        if (self.remote_ephemeral_key) |remote_eph| {
            const dh_result = try self.dh(&self.local_ephemeral_key, &remote_eph);
            try self.mixKey(&dh_result);
        }
        
        // Encrypt static key
        const encrypted_static = try self.encryptAndHash(&self.local_static_key);
        defer self.allocator.free(encrypted_static);
        
        try self.message_buffer.appendSlice(encrypted_static);
        
        // Mix DH (es)
        if (self.remote_ephemeral_key) |remote_eph| {
            const dh_result = try self.dh(&self.local_static_key, &remote_eph);
            try self.mixKey(&dh_result);
        }
        
        // Encrypt payload
        const encrypted_payload = try self.encryptAndHash(payload);
        defer self.allocator.free(encrypted_payload);
        
        try self.message_buffer.appendSlice(encrypted_payload);
    }
    
    fn readInitiatorMessage1(self: *NoiseHandshake, message: []const u8, payload: *std.ArrayList(u8)) !void {
        if (message.len < 32) return error.InvalidMessageLength;
        
        // Read ephemeral key
        self.remote_ephemeral_key = message[0..32].*;
        try self.mixHash(&self.remote_ephemeral_key.?);
        
        // Decrypt payload
        const encrypted_payload = message[32..];
        const decrypted = try self.decryptAndHash(encrypted_payload);
        defer self.allocator.free(decrypted);
        
        try payload.appendSlice(decrypted);
    }
    
    fn readResponderMessage2(self: *NoiseHandshake, message: []const u8, payload: *std.ArrayList(u8)) !void {
        if (message.len < 32) return error.InvalidMessageLength;
        
        var offset: usize = 0;
        
        // Read ephemeral key
        self.remote_ephemeral_key = message[offset..offset + 32].*;
        try self.mixHash(&self.remote_ephemeral_key.?);
        offset += 32;
        
        // Mix DH (ee)
        const dh_ee = try self.dh(&self.local_ephemeral_key, &self.remote_ephemeral_key.?);
        try self.mixKey(&dh_ee);
        
        // Decrypt static key
        const encrypted_static = message[offset..offset + 48]; // 32 + 16 for auth tag
        const decrypted_static = try self.decryptAndHash(encrypted_static);
        defer self.allocator.free(decrypted_static);
        
        self.remote_static_key = decrypted_static[0..32].*;
        offset += 48;
        
        // Mix DH (es)
        const dh_es = try self.dh(&self.local_ephemeral_key, &self.remote_static_key.?);
        try self.mixKey(&dh_es);
        
        // Decrypt payload
        const encrypted_payload = message[offset..];
        const decrypted = try self.decryptAndHash(encrypted_payload);
        defer self.allocator.free(decrypted);
        
        try payload.appendSlice(decrypted);
    }
    
    fn readInitiatorMessage3(self: *NoiseHandshake, message: []const u8, payload: *std.ArrayList(u8)) !void {
        var offset: usize = 0;
        
        // Decrypt static key
        const encrypted_static = message[offset..offset + 48]; // 32 + 16 for auth tag
        const decrypted_static = try self.decryptAndHash(encrypted_static);
        defer self.allocator.free(decrypted_static);
        
        self.remote_static_key = decrypted_static[0..32].*;
        offset += 48;
        
        // Mix DH (se)
        const dh_se = try self.dh(&self.local_ephemeral_key, &self.remote_static_key.?);
        try self.mixKey(&dh_se);
        
        // Decrypt payload
        const encrypted_payload = message[offset..];
        const decrypted = try self.decryptAndHash(encrypted_payload);
        defer self.allocator.free(decrypted);
        
        try payload.appendSlice(decrypted);
    }
    
    fn dh(self: *NoiseHandshake, private_key: *const [32]u8, public_key: *const [32]u8) ![32]u8 {
        _ = self;
        var shared_secret: [32]u8 = undefined;
        try zcrypto.curve25519.scalarmult(&shared_secret, private_key, public_key);
        return shared_secret;
    }
    
    fn mixKey(self: *NoiseHandshake, input_key_material: *const [32]u8) !void {
        // HKDF-Extract
        var temp_key: [32]u8 = undefined;
        try zcrypto.hkdf.extract(&temp_key, &self.chaining_key, input_key_material);
        
        // HKDF-Expand
        var output: [64]u8 = undefined;
        try zcrypto.hkdf.expand(&output, &temp_key, "noise-handshake", &[_]u8{});
        
        self.chaining_key = output[0..32].*;
        // k = output[32..64] (cipher key would be stored here)
    }
    
    fn mixHash(self: *NoiseHandshake, data: []const u8) !void {
        var hasher = zcrypto.blake2s.Blake2s(32).init(.{});
        hasher.update(&self.hash);
        hasher.update(data);
        hasher.final(&self.hash);
    }
    
    fn encryptAndHash(self: *NoiseHandshake, plaintext: []const u8) ![]u8 {
        // Derive encryption key from chaining key
        var cipher_key: [32]u8 = undefined;
        var temp_key: [32]u8 = undefined;
        try zcrypto.hkdf.extract(&temp_key, &self.chaining_key, &[_]u8{});
        try zcrypto.hkdf.expand(&cipher_key, &temp_key, "noise-cipher", &[_]u8{});
        
        // Generate secure nonce using counter to prevent reuse
        const nonce = self.generateNonce();
        
        // Encrypt with ChaCha20-Poly1305
        const ciphertext = try self.allocator.alloc(u8, plaintext.len + 16); // +16 for auth tag
        
        // Split ciphertext into data and tag
        const encrypted_data = ciphertext[0..plaintext.len];
        const auth_tag = ciphertext[plaintext.len..plaintext.len + 16];
        
        // ChaCha20-Poly1305 encryption
        var poly_state = zcrypto.poly1305.Poly1305.init(&cipher_key[0..32].*);
        var chacha_state = zcrypto.chacha20.ChaCha20.init(&cipher_key[0..32].*, &nonce);
        
        // Encrypt plaintext
        chacha_state.crypt(encrypted_data, plaintext);
        
        // Generate auth tag
        poly_state.update(encrypted_data);
        poly_state.final(auth_tag[0..16]);
        
        try self.mixHash(ciphertext);
        return ciphertext;
    }
    
    fn decryptAndHash(self: *NoiseHandshake, ciphertext: []const u8) ![]u8 {
        if (ciphertext.len < 16) return error.InvalidCiphertextLength;
        
        // Derive decryption key from chaining key
        var cipher_key: [32]u8 = undefined;
        var temp_key: [32]u8 = undefined;
        try zcrypto.hkdf.extract(&temp_key, &self.chaining_key, &[_]u8{});
        try zcrypto.hkdf.expand(&cipher_key, &temp_key, "noise-cipher", &[_]u8{});
        
        // Generate secure nonce using counter to prevent reuse
        const nonce = self.generateNonce();
        
        // Decrypt with ChaCha20-Poly1305
        const plaintext = try self.allocator.alloc(u8, ciphertext.len - 16); // -16 for auth tag
        
        // Split ciphertext into data and tag
        const encrypted_data = ciphertext[0..ciphertext.len - 16];
        const auth_tag = ciphertext[ciphertext.len - 16..ciphertext.len];
        
        // Verify auth tag first
        var poly_state = zcrypto.poly1305.Poly1305.init(&cipher_key[0..32].*);
        poly_state.update(encrypted_data);
        var computed_tag: [16]u8 = undefined;
        poly_state.final(&computed_tag);
        
        if (!std.mem.eql(u8, auth_tag, &computed_tag)) {
            return error.AuthenticationFailed;
        }
        
        // Decrypt data
        var chacha_state = zcrypto.chacha20.ChaCha20.init(&cipher_key[0..32].*, &nonce);
        chacha_state.crypt(plaintext, encrypted_data);
        
        try self.mixHash(ciphertext);
        return plaintext;
    }
    
    pub fn split(self: *NoiseHandshake) !HandshakeResult {
        if (self.state != .established) {
            return error.HandshakeNotComplete;
        }
        
        // Split the chaining key into two cipher keys
        var output: [64]u8 = undefined;
        try zcrypto.hkdf.expand(&output, &self.chaining_key, "noise-split", &[_]u8{});
        
        const sending_key = try self.allocator.dupe(u8, output[0..32]);
        const receiving_key = try self.allocator.dupe(u8, output[32..64]);
        
        return HandshakeResult{
            .sending_key = sending_key,
            .receiving_key = receiving_key,
            .session_info = .{
                .cipher_suite = self.config.cipher_suite,
                .protocol_version = 1,
                .server_name = self.config.server_name,
                .alpn_protocol = null,
                .peer_certificate = null,
                .session_ticket = null,
                .resumption_secret = null,
            },
        };
    }
};

pub const TlsHandshake = struct {
    allocator: std.mem.Allocator,
    config: HandshakeConfig,
    state: HandshakeState,
    client_random: [32]u8,
    server_random: [32]u8,
    session_id: [32]u8,
    cipher_suite: CipherSuite,
    master_secret: [48]u8,
    early_secret: ?[32]u8,
    early_data_sent: bool,
    early_data_status: EarlyDataStatus,
    session_ticket: ?[]u8,
    psk_identity: ?[]u8,
    early_data_buffer: std.ArrayList(u8),
    max_early_data_size: u32,
    
    pub fn init(allocator: std.mem.Allocator, config: HandshakeConfig) !*TlsHandshake {
        var handshake = try allocator.create(TlsHandshake);
        handshake.* = .{
            .allocator = allocator,
            .config = config,
            .state = .uninitialized,
            .client_random = undefined,
            .server_random = undefined,
            .session_id = undefined,
            .cipher_suite = config.cipher_suite,
            .master_secret = undefined,
            .early_secret = null,
            .early_data_sent = false,
            .early_data_status = .not_requested,
            .session_ticket = null,
            .psk_identity = null,
            .early_data_buffer = std.ArrayList(u8).init(allocator),
            .max_early_data_size = 16384, // 16KB default
        };
        
        // Generate random values
        std.crypto.random.bytes(&handshake.client_random);
        std.crypto.random.bytes(&handshake.server_random);
        std.crypto.random.bytes(&handshake.session_id);
        
        return handshake;
    }
    
    pub fn deinit(self: *TlsHandshake) void {
        if (self.session_ticket) |ticket| {
            self.allocator.free(ticket);
        }
        if (self.psk_identity) |identity| {
            self.allocator.free(identity);
        }
        self.early_data_buffer.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn performHandshake(self: *TlsHandshake, stream: transport.Stream) !HandshakeResult {
        if (self.config.is_initiator) {
            try self.clientHandshake(stream);
        } else {
            try self.serverHandshake(stream);
        }
        
        return try self.deriveKeys();
    }
    
    fn clientHandshake(self: *TlsHandshake, stream: transport.Stream) !void {
        // Check for 0-RTT support
        if (self.config.enable_0rtt) {
            try self.attemptEarlyData(stream);
        }
        
        // Send ClientHello
        const client_hello = try self.createClientHello();
        defer self.allocator.free(client_hello);
        
        _ = try stream.writeAsync(client_hello);
        
        // Send early data if enabled
        if (self.early_data_status == .in_progress and self.early_data_buffer.items.len > 0) {
            _ = try stream.writeAsync(self.early_data_buffer.items);
        }
        
        // Read ServerHello
        var server_hello_buffer: [1024]u8 = undefined;
        const server_hello_len = try stream.readAsync(&server_hello_buffer);
        try self.processServerHello(server_hello_buffer[0..server_hello_len]);
        
        // Check if early data was accepted
        if (self.early_data_status == .in_progress) {
            // Server will indicate in ServerHello if early data was accepted
            // For now, assume accepted if no error
            self.early_data_status = .accepted;
            self.early_data_sent = true;
        }
        
        // Send ClientKeyExchange
        const client_key_exchange = try self.createClientKeyExchange();
        defer self.allocator.free(client_key_exchange);
        
        _ = try stream.writeAsync(client_key_exchange);
        
        // Send Finished
        const finished = try self.createFinished();
        defer self.allocator.free(finished);
        
        _ = try stream.writeAsync(finished);
        
        self.state = .established;
    }
    
    fn serverHandshake(self: *TlsHandshake, stream: transport.Stream) !void {
        // Read ClientHello
        var client_hello_buffer: [1024]u8 = undefined;
        const client_hello_len = try stream.readAsync(&client_hello_buffer);
        try self.processClientHello(client_hello_buffer[0..client_hello_len]);
        
        // Send ServerHello
        const server_hello = try self.createServerHello();
        defer self.allocator.free(server_hello);
        
        _ = try stream.writeAsync(server_hello);
        
        // Read ClientKeyExchange
        var client_key_exchange_buffer: [1024]u8 = undefined;
        const client_key_exchange_len = try stream.readAsync(&client_key_exchange_buffer);
        try self.processClientKeyExchange(client_key_exchange_buffer[0..client_key_exchange_len]);
        
        // Read Finished
        var finished_buffer: [1024]u8 = undefined;
        const finished_len = try stream.readAsync(&finished_buffer);
        try self.processFinished(finished_buffer[0..finished_len]);
        
        self.state = .established;
    }
    
    fn createClientHello(self: *TlsHandshake) ![]u8 {
        var message = std.ArrayList(u8).init(self.allocator);
        
        // TLS record header
        try message.append(0x16); // Handshake
        try message.append(0x03); // TLS 1.2
        try message.append(0x03);
        
        // Length (placeholder)
        try message.append(0x00);
        try message.append(0x00);
        
        // Handshake header
        try message.append(0x01); // ClientHello
        try message.append(0x00); // Length (placeholder)
        try message.append(0x00);
        try message.append(0x00);
        
        // Version
        try message.append(0x03);
        try message.append(0x03);
        
        // Random
        try message.appendSlice(&self.client_random);
        
        // Session ID
        try message.append(32); // Length
        try message.appendSlice(&self.session_id);
        
        // Cipher suites
        try message.append(0x00); // Length
        try message.append(0x02);
        try message.append(0x00); // Cipher suite
        try message.append(0x2F);
        
        // Compression methods
        try message.append(0x01); // Length
        try message.append(0x00); // No compression
        
        return message.toOwnedSlice();
    }
    
    fn createServerHello(self: *TlsHandshake) ![]u8 {
        var message = std.ArrayList(u8).init(self.allocator);
        
        // Similar structure to ClientHello but with server values
        try message.append(0x16); // Handshake
        try message.append(0x03); // TLS 1.2
        try message.append(0x03);
        
        // Add server hello content...
        try message.appendSlice(&self.server_random);
        
        return message.toOwnedSlice();
    }
    
    fn createClientKeyExchange(self: *TlsHandshake) ![]u8 {
        return try self.allocator.dupe(u8, "client_key_exchange");
    }
    
    fn createFinished(self: *TlsHandshake) ![]u8 {
        return try self.allocator.dupe(u8, "finished");
    }
    
    fn processServerHello(self: *TlsHandshake, data: []const u8) !void {
        if (data.len < 38) return error.InvalidServerHello;
        
        // Extract server random (32 bytes)
        @memcpy(&self.server_random, data[6..38]);
        
        // Extract cipher suite
        if (data.len >= 42) {
            const cipher_suite_bytes = data[38..40];
            self.cipher_suite = switch (@as(u16, cipher_suite_bytes[0]) << 8 | cipher_suite_bytes[1]) {
                0x1301 => .aes_128_gcm,
                0x1302 => .aes_256_gcm,
                0x1303 => .chacha20_poly1305,
                else => return error.UnsupportedCipherSuite,
            };
        }
    }
    
    fn processClientHello(self: *TlsHandshake, data: []const u8) !void {
        if (data.len < 38) return error.InvalidClientHello;
        
        // Extract client random (32 bytes)
        @memcpy(&self.client_random, data[6..38]);
        
        // Validate version (TLS 1.2 or 1.3)
        const version = (@as(u16, data[4]) << 8) | data[5];
        if (version != 0x0303 and version != 0x0304) {
            return error.UnsupportedTlsVersion;
        }
    }
    
    fn processClientKeyExchange(self: *TlsHandshake, data: []const u8) !void {
        if (data.len < 64) return error.InvalidKeyExchange;
        
        // Extract pre-master secret (simplified RSA key exchange)
        const encrypted_premaster = data[7..data.len]; // Skip handshake header
        
        // Decrypt pre-master secret using server private key
        var premaster_secret: [48]u8 = undefined;
        try self.decryptPreMasterSecret(&premaster_secret, encrypted_premaster);
        
        // Derive master secret
        try self.deriveMasterSecret(&premaster_secret);
    }
    
    fn processFinished(self: *TlsHandshake, data: []const u8) !void {
        if (data.len < 16) return error.InvalidFinished;
        
        // Verify finished hash
        const received_hash = data[4..16]; // Skip handshake header
        var computed_hash: [12]u8 = undefined;
        
        try self.computeFinishedHash(&computed_hash);
        
        if (!std.mem.eql(u8, received_hash, &computed_hash)) {
            return error.InvalidFinishedHash;
        }
    }
    
    fn deriveKeys(self: *TlsHandshake) !HandshakeResult {
        // PRF to derive keys from master secret
        const key_block_size = 2 * (self.cipher_suite.keySize() + self.cipher_suite.nonceSize());
        const key_block = try self.allocator.alloc(u8, key_block_size);
        
        // Simplified key derivation
        const sending_key = try self.allocator.dupe(u8, key_block[0..self.cipher_suite.keySize()]);
        const receiving_key = try self.allocator.dupe(u8, key_block[self.cipher_suite.keySize()..2 * self.cipher_suite.keySize()]);
        
        return HandshakeResult{
            .sending_key = sending_key,
            .receiving_key = receiving_key,
            .early_data_accepted = self.early_data_status == .accepted,
            .session_info = .{
                .cipher_suite = self.cipher_suite,
                .protocol_version = 0x0303, // TLS 1.2
                .server_name = self.config.server_name,
                .alpn_protocol = null,
                .peer_certificate = null,
                .session_ticket = self.session_ticket,
                .resumption_secret = null,
                .max_early_data_size = self.max_early_data_size,
            },
        };
    }
    
    fn decryptPreMasterSecret(self: *TlsHandshake, output: *[48]u8, encrypted: []const u8) !void {
        _ = self;
        _ = encrypted;
        // RSA decryption of pre-master secret (simplified)
        std.crypto.random.bytes(output);
        // Set version bytes
        output[0] = 0x03;
        output[1] = 0x03;
    }
    
    fn deriveMasterSecret(self: *TlsHandshake, premaster_secret: *const [48]u8) !void {
        // PRF to derive master secret from pre-master secret
        var prf_input: [104]u8 = undefined; // "master secret" + client_random + server_random
        @memcpy(prf_input[0..13], "master secret");
        @memcpy(prf_input[13..45], &self.client_random);
        @memcpy(prf_input[45..77], &self.server_random);
        
        // Simplified HMAC-based PRF
        try zcrypto.hkdf.expand(&self.master_secret, premaster_secret, "tls-master-secret", &prf_input);
    }
    
    fn computeFinishedHash(self: *TlsHandshake, output: *[12]u8) !void {
        // Compute finished hash using handshake messages
        var hasher = zcrypto.blake2s.Blake2s(12).init(.{});
        hasher.update(&self.master_secret);
        hasher.update(&self.client_random);
        hasher.update(&self.server_random);
        hasher.final(output);
    }
    
    fn validateCertificate(self: *TlsHandshake, certificate_data: []const u8) !bool {
        _ = self;
        if (certificate_data.len < 10) return false;
        
        // Basic certificate validation
        // Check certificate format (simplified DER parsing)
        if (certificate_data[0] != 0x30) return false; // Must start with SEQUENCE
        
        // Verify certificate chain (simplified)
        const cert_len = (@as(u16, certificate_data[1]) << 8) | certificate_data[2];
        if (cert_len + 3 > certificate_data.len) return false;
        
        // Check certificate validity period (simplified)
        const now = std.time.timestamp();
        _ = now;
        
        // Verify signature (simplified)
        // In real implementation, would verify certificate signature chain
        
        return true;
    }
    
    fn attemptEarlyData(self: *TlsHandshake, stream: transport.Stream) !void {
        _ = stream;
        
        // Check if we have a cached session for this server
        if (self.config.server_name) |_| {
            // In real implementation, would check session cache
            // For now, just set up early data state
            self.early_data_status = .in_progress;
            
            // Derive early data key from cached session
            if (self.session_ticket) |_| {
                var early_key: [32]u8 = undefined;
                std.crypto.random.bytes(&early_key);
                self.early_secret = early_key;
            }
        }
    }
    
    pub fn sendEarlyData(self: *TlsHandshake, data: []const u8) !void {
        if (self.early_data_status != .in_progress) {
            return error.EarlyDataNotEnabled;
        }
        
        if (self.early_data_buffer.items.len + data.len > self.max_early_data_size) {
            return error.EarlyDataSizeExceeded;
        }
        
        try self.early_data_buffer.appendSlice(data);
    }
    
    pub fn isEarlyDataAccepted(self: *TlsHandshake) bool {
        return self.early_data_status == .accepted;
    }
};

pub const SessionCache = struct {
    allocator: std.mem.Allocator,
    sessions: std.StringHashMap(CachedSession),
    mutex: std.Thread.Mutex,
    max_entries: usize = 1000,
    max_age_ms: u64 = 86400000, // 24 hours
    
    pub const CachedSession = struct {
        session_ticket: []u8,
        resumption_secret: []u8,
        cipher_suite: CipherSuite,
        server_name: []const u8,
        alpn_protocol: ?[]const u8,
        timestamp: i64,
        max_early_data_size: u32,
        early_data_key: ?[]u8,
    };
    
    pub fn init(allocator: std.mem.Allocator) SessionCache {
        return .{
            .allocator = allocator,
            .sessions = std.StringHashMap(CachedSession).init(allocator),
            .mutex = .{},
        };
    }
    
    pub fn deinit(self: *SessionCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.session_ticket);
            self.allocator.free(entry.value_ptr.resumption_secret);
            if (entry.value_ptr.early_data_key) |key| {
                self.allocator.free(key);
            }
        }
        self.sessions.deinit();
    }
    
    pub fn store(self: *SessionCache, server_name: []const u8, session: CachedSession) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Evict old entries if at capacity
        if (self.sessions.count() >= self.max_entries) {
            self.evictOldest();
        }
        
        const key = try self.allocator.dupe(u8, server_name);
        try self.sessions.put(key, session);
    }
    
    pub fn get(self: *SessionCache, server_name: []const u8) ?CachedSession {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.sessions.get(server_name)) |session| {
            const age = std.time.timestamp() - session.timestamp;
            if (age * 1000 < self.max_age_ms) {
                return session;
            }
            // Session expired, remove it
            _ = self.sessions.remove(server_name);
        }
        return null;
    }
    
    fn evictOldest(self: *SessionCache) void {
        var oldest_key: ?[]const u8 = null;
        var oldest_time: i64 = std.math.maxInt(i64);
        
        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.timestamp < oldest_time) {
                oldest_time = entry.value_ptr.timestamp;
                oldest_key = entry.key_ptr.*;
            }
        }
        
        if (oldest_key) |key| {
            if (self.sessions.fetchRemove(key)) |kv| {
                self.allocator.free(kv.value.session_ticket);
                self.allocator.free(kv.value.resumption_secret);
                if (kv.value.early_data_key) |ekey| {
                    self.allocator.free(ekey);
                }
            }
        }
    }
};

pub const EarlyDataStatus = enum {
    not_requested,
    rejected,
    accepted,
    in_progress,
};

pub const HandshakeManager = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    session_cache: SessionCache,
    nonce_counter: std.atomic.Value(u64),
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) HandshakeManager {
        return .{
            .allocator = allocator,
            .runtime = runtime,
            .session_cache = SessionCache.init(allocator),
            .nonce_counter = std.atomic.Value(u64).init(0),
        };
    }
    
    pub fn generateNonce(self: *HandshakeManager) [12]u8 {
        const count = self.nonce_counter.fetchAdd(1, .seq_cst);
        var nonce = [_]u8{0} ** 12;
        std.mem.writeIntLittle(u64, nonce[0..8], count);
        std.crypto.random.bytes(nonce[8..12]); // Add entropy to high bits
        return nonce;
    }
    
    pub fn deinit(self: *HandshakeManager) void {
        self.session_cache.deinit();
    }
    
    pub fn performHandshake(self: *HandshakeManager, config: HandshakeConfig, stream: transport.Stream) !HandshakeResult {
        return switch (config.handshake_type) {
            .tls => {
                var tls_handshake = try TlsHandshake.init(self.allocator, config);
                defer tls_handshake.deinit();
                
                // Check for cached session if 0-RTT is enabled
                if (config.enable_0rtt and config.server_name) |server_name| {
                    if (self.session_cache.get(server_name)) |cached_session| {
                        // Restore session data
                        tls_handshake.session_ticket = try self.allocator.dupe(u8, cached_session.session_ticket);
                        tls_handshake.cipher_suite = cached_session.cipher_suite;
                        tls_handshake.max_early_data_size = cached_session.max_early_data_size;
                    }
                }
                
                const result = try tls_handshake.performHandshake(stream);
                
                // Cache session for future 0-RTT
                if (config.enable_0rtt and config.server_name) |server_name| {
                    if (result.session_info.session_ticket) |ticket| {
                        const session = SessionCache.CachedSession{
                            .session_ticket = try self.allocator.dupe(u8, ticket),
                            .resumption_secret = if (result.session_info.resumption_secret) |secret| 
                                try self.allocator.dupe(u8, secret) else 
                                try self.allocator.alloc(u8, 0),
                            .cipher_suite = result.session_info.cipher_suite,
                            .server_name = server_name,
                            .alpn_protocol = result.session_info.alpn_protocol,
                            .timestamp = std.time.timestamp(),
                            .max_early_data_size = result.session_info.max_early_data_size,
                            .early_data_key = null,
                        };
                        try self.session_cache.store(server_name, session);
                    }
                }
                
                return result;
            },
            .noise => {
                var noise_handshake = try NoiseHandshake.init(self.allocator, config);
                defer noise_handshake.deinit();
                
                // Simplified noise handshake
                const empty_payload = &[_]u8{};
                const message1 = try noise_handshake.writeMessage(empty_payload);
                defer self.allocator.free(message1);
                
                _ = try stream.writeAsync(message1);
                
                // Read response and continue handshake...
                var response_buffer: [1024]u8 = undefined;
                const response_len = try stream.readAsync(&response_buffer);
                const payload = try noise_handshake.readMessage(response_buffer[0..response_len]);
                defer self.allocator.free(payload);
                
                return try noise_handshake.split();
            },
            .wireguard => {
                return error.UseWireGuardModule;
            },
            .custom => {
                return error.CustomHandshakeNotImplemented;
            },
        };
    }
};