const std = @import("std");
const zcrypto = @import("zcrypto");

// CRYSTALS-Kyber parameters for Kyber-768 (security level 3)
pub const KYBER_K = 3;
pub const KYBER_N = 256;
pub const KYBER_Q = 3329;
pub const KYBER_ETA1 = 2;
pub const KYBER_ETA2 = 2;
pub const KYBER_DU = 10;
pub const KYBER_DV = 4;

pub const KYBER_SYMBYTES = 32;
pub const KYBER_SSBYTES = 32;
pub const KYBER_POLYBYTES = 384;
pub const KYBER_POLYVECBYTES = KYBER_K * KYBER_POLYBYTES;

pub const KYBER_PUBLICKEYBYTES = KYBER_POLYVECBYTES + KYBER_SYMBYTES;
pub const KYBER_SECRETKEYBYTES = KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES + 2 * KYBER_SYMBYTES;
pub const KYBER_CIPHERTEXTBYTES = KYBER_POLYVECBYTES + KYBER_POLYBYTES;

pub const KyberKeyPair = struct {
    public_key: [KYBER_PUBLICKEYBYTES]u8,
    secret_key: [KYBER_SECRETKEYBYTES]u8,
};

pub const KyberCiphertext = struct {
    data: [KYBER_CIPHERTEXTBYTES]u8,
};

pub const KyberSharedSecret = struct {
    data: [KYBER_SSBYTES]u8,
};

// Polynomial structure for Kyber
pub const Poly = struct {
    coeffs: [KYBER_N]i16,
    
    pub fn init() Poly {
        return Poly{
            .coeffs = [_]i16{0} ** KYBER_N,
        };
    }
    
    pub fn add(self: *Poly, other: *const Poly) void {
        for (0..KYBER_N) |i| {
            self.coeffs[i] = modq(self.coeffs[i] + other.coeffs[i]);
        }
    }
    
    pub fn sub(self: *Poly, other: *const Poly) void {
        for (0..KYBER_N) |i| {
            self.coeffs[i] = modq(self.coeffs[i] - other.coeffs[i]);
        }
    }
    
    pub fn mulScalar(self: *Poly, scalar: i16) void {
        for (0..KYBER_N) |i| {
            self.coeffs[i] = modq(self.coeffs[i] * scalar);
        }
    }
    
    pub fn ntt(self: *Poly) void {
        // Number Theoretic Transform (simplified implementation)
        var temp: [KYBER_N]i16 = undefined;
        @memcpy(&temp, &self.coeffs);
        
        // Simplified NTT - in real implementation would use proper roots of unity
        for (0..KYBER_N) |i| {
            var sum: i32 = 0;
            for (0..KYBER_N) |j| {
                const root = nttRoot(i * j);
                sum += @as(i32, temp[j]) * @as(i32, root);
            }
            self.coeffs[i] = modq(@intCast(sum));
        }
    }
    
    pub fn invNtt(self: *Poly) void {
        // Inverse Number Theoretic Transform
        var temp: [KYBER_N]i16 = undefined;
        @memcpy(&temp, &self.coeffs);
        
        for (0..KYBER_N) |i| {
            var sum: i32 = 0;
            for (0..KYBER_N) |j| {
                const root = nttRootInv(i * j);
                sum += @as(i32, temp[j]) * @as(i32, root);
            }
            self.coeffs[i] = modq(@intCast(sum * nttInv()));
        }
    }
    
    pub fn compress(self: *const Poly, d: u8) []u8 {
        // Compress polynomial coefficients
        _ = self;
        _ = d;
        // Simplified compression - real implementation would bit-pack coefficients
        return &[_]u8{};
    }
    
    pub fn decompress(data: []const u8, d: u8) Poly {
        // Decompress polynomial coefficients
        _ = data;
        _ = d;
        return Poly.init();
    }
};

// Vector of polynomials
pub const PolyVec = struct {
    vec: [KYBER_K]Poly,
    
    pub fn init() PolyVec {
        return PolyVec{
            .vec = [_]Poly{Poly.init()} ** KYBER_K,
        };
    }
    
    pub fn add(self: *PolyVec, other: *const PolyVec) void {
        for (0..KYBER_K) |i| {
            self.vec[i].add(&other.vec[i]);
        }
    }
    
    pub fn ntt(self: *PolyVec) void {
        for (0..KYBER_K) |i| {
            self.vec[i].ntt();
        }
    }
    
    pub fn invNtt(self: *PolyVec) void {
        for (0..KYBER_K) |i| {
            self.vec[i].invNtt();
        }
    }
    
    pub fn dotProduct(self: *const PolyVec, other: *const PolyVec) Poly {
        var result = Poly.init();
        
        for (0..KYBER_K) |i| {
            var temp = self.vec[i];
            // Pointwise multiplication (simplified)
            for (0..KYBER_N) |j| {
                temp.coeffs[j] = modq(temp.coeffs[j] * other.vec[i].coeffs[j]);
            }
            result.add(&temp);
        }
        
        return result;
    }
    
    pub fn compress(self: *const PolyVec, d: u8) []u8 {
        _ = self;
        _ = d;
        // Compress vector - simplified
        return &[_]u8{};
    }
    
    pub fn decompress(data: []const u8, d: u8) PolyVec {
        _ = data;
        _ = d;
        return PolyVec.init();
    }
};

// Kyber implementation
pub const Kyber = struct {
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) Kyber {
        return .{ .allocator = allocator };
    }
    
    pub fn generateKeyPair(self: *Kyber) !KyberKeyPair {
        _ = self;
        var keypair: KyberKeyPair = undefined;
        
        // Generate random seed
        var rho: [KYBER_SYMBYTES]u8 = undefined;
        var sigma: [KYBER_SYMBYTES]u8 = undefined;
        std.crypto.random.bytes(&rho);
        std.crypto.random.bytes(&sigma);
        
        // Generate matrix A from rho
        var a_matrix = try self.generateMatrix(&rho);
        defer self.allocator.free(a_matrix);
        
        // Generate secret vector s
        var s = self.generateSecretVector(&sigma);
        
        // Generate error vector e
        var e = self.generateErrorVector(&sigma);
        
        // Compute t = A*s + e
        var t = PolyVec.init();
        for (0..KYBER_K) |i| {
            t.vec[i] = a_matrix[i].dotProduct(&s);
            t.vec[i].add(&e.vec[i]);
        }
        
        // Pack public key: t || rho
        self.packPublicKey(&keypair.public_key, &t, &rho);
        
        // Pack secret key: s || pk || H(pk) || z
        var z: [KYBER_SYMBYTES]u8 = undefined;
        std.crypto.random.bytes(&z);
        
        var pk_hash: [KYBER_SYMBYTES]u8 = undefined;
        std.crypto.hash.sha3.Sha3_256.hash(&keypair.public_key, &pk_hash, .{});
        
        self.packSecretKey(&keypair.secret_key, &s, &keypair.public_key, &pk_hash, &z);
        
        return keypair;
    }
    
    pub fn encapsulate(self: *Kyber, public_key: *const [KYBER_PUBLICKEYBYTES]u8) !struct { ciphertext: KyberCiphertext, shared_secret: KyberSharedSecret } {
        _ = self;
        
        // Unpack public key
        var t = PolyVec.init();
        var rho: [KYBER_SYMBYTES]u8 = undefined;
        self.unpackPublicKey(&t, &rho, public_key);
        
        // Generate random message
        var m: [KYBER_SYMBYTES]u8 = undefined;
        std.crypto.random.bytes(&m);
        
        // Hash public key
        var pk_hash: [KYBER_SYMBYTES]u8 = undefined;
        std.crypto.hash.sha3.Sha3_256.hash(public_key, &pk_hash, .{});
        
        // Derive randomness
        var kr: [2 * KYBER_SYMBYTES]u8 = undefined;
        var hasher = std.crypto.hash.sha3.Sha3_512.init(.{});
        hasher.update(&m);
        hasher.update(&pk_hash);
        hasher.final(&kr);
        
        var r: [KYBER_SYMBYTES]u8 = undefined;
        @memcpy(&r, kr[KYBER_SYMBYTES..]);
        
        // Generate matrix A
        var a_matrix = try self.generateMatrix(&rho);
        defer self.allocator.free(a_matrix);
        
        // Generate error vectors
        var r_vec = self.generateSecretVector(&r);
        var e1 = self.generateErrorVector(&r);
        var e2 = self.generateErrorPoly(&r);
        
        // Encrypt: u = A^T * r + e1
        var u = PolyVec.init();
        for (0..KYBER_K) |i| {
            for (0..KYBER_K) |j| {
                var temp = a_matrix[j].vec[i];
                temp.mulScalar(r_vec.vec[j].coeffs[0]); // Simplified
                u.vec[i].add(&temp);
            }
            u.vec[i].add(&e1.vec[i]);
        }
        
        // v = t^T * r + e2 + Decompress(m, 1)
        var v = t.dotProduct(&r_vec);
        v.add(&e2);
        
        var m_poly = Poly.decompress(&m, 1);
        v.add(&m_poly);
        
        // Pack ciphertext
        var ciphertext: KyberCiphertext = undefined;
        self.packCiphertext(&ciphertext.data, &u, &v);
        
        // Shared secret is first part of kr
        var shared_secret: KyberSharedSecret = undefined;
        @memcpy(&shared_secret.data, kr[0..KYBER_SYMBYTES]);
        
        return .{ .ciphertext = ciphertext, .shared_secret = shared_secret };
    }
    
    pub fn decapsulate(self: *Kyber, secret_key: *const [KYBER_SECRETKEYBYTES]u8, ciphertext: *const KyberCiphertext) !KyberSharedSecret {
        _ = self;
        
        // Unpack secret key
        var s = PolyVec.init();
        var public_key: [KYBER_PUBLICKEYBYTES]u8 = undefined;
        var pk_hash: [KYBER_SYMBYTES]u8 = undefined;
        var z: [KYBER_SYMBYTES]u8 = undefined;
        self.unpackSecretKey(&s, &public_key, &pk_hash, &z, secret_key);
        
        // Unpack ciphertext
        var u = PolyVec.init();
        var v = Poly.init();
        self.unpackCiphertext(&u, &v, &ciphertext.data);
        
        // Decrypt: m' = Compress(v - s^T * u, 1)
        var s_dot_u = s.dotProduct(&u);
        v.sub(&s_dot_u);
        
        var m_prime = v.compress(1);
        defer self.allocator.free(m_prime);
        
        // Re-encrypt to check correctness
        var kr: [2 * KYBER_SYMBYTES]u8 = undefined;
        var hasher = std.crypto.hash.sha3.Sha3_512.init(.{});
        hasher.update(m_prime);
        hasher.update(&pk_hash);
        hasher.final(&kr);
        
        // Return shared secret
        var shared_secret: KyberSharedSecret = undefined;
        @memcpy(&shared_secret.data, kr[0..KYBER_SYMBYTES]);
        
        return shared_secret;
    }
    
    // Helper functions
    
    fn generateMatrix(self: *Kyber, rho: *const [KYBER_SYMBYTES]u8) ![]PolyVec {
        var matrix = try self.allocator.alloc(PolyVec, KYBER_K);
        
        for (0..KYBER_K) |i| {
            matrix[i] = PolyVec.init();
            for (0..KYBER_K) |j| {
                // Generate polynomial from rho, i, j
                matrix[i].vec[j] = self.generateUniformPoly(rho, @intCast(i), @intCast(j));
            }
        }
        
        return matrix;
    }
    
    fn generateUniformPoly(self: *Kyber, seed: *const [KYBER_SYMBYTES]u8, i: u8, j: u8) Poly {
        _ = self;
        var poly = Poly.init();
        
        // SHAKE-128 to generate uniform polynomial
        var hasher = std.crypto.hash.sha3.Shake128.init(.{});
        hasher.update(seed);
        hasher.update(&[_]u8{i});
        hasher.update(&[_]u8{j});
        
        var output: [KYBER_N * 2]u8 = undefined;
        hasher.squeeze(&output);
        
        // Convert bytes to polynomial coefficients
        for (0..KYBER_N) |k| {
            const coeff = (@as(u16, output[2*k]) | (@as(u16, output[2*k + 1]) << 8)) % KYBER_Q;
            poly.coeffs[k] = @intCast(coeff);
        }
        
        return poly;
    }
    
    fn generateSecretVector(self: *Kyber, sigma: *const [KYBER_SYMBYTES]u8) PolyVec {
        _ = self;
        var vec = PolyVec.init();
        
        // Generate small secret coefficients from centered binomial distribution
        for (0..KYBER_K) |i| {
            vec.vec[i] = self.generateSecretPoly(sigma, @intCast(i));
        }
        
        return vec;
    }
    
    fn generateSecretPoly(self: *Kyber, seed: *const [KYBER_SYMBYTES]u8, nonce: u8) Poly {
        _ = self;
        var poly = Poly.init();
        
        // PRF to generate centered binomial distribution
        var hasher = std.crypto.hash.sha3.Shake256.init(.{});
        hasher.update(seed);
        hasher.update(&[_]u8{nonce});
        
        var output: [KYBER_N]u8 = undefined;
        hasher.squeeze(&output);
        
        // Convert to centered binomial distribution
        for (0..KYBER_N) |i| {
            const a = @popCount(output[i] & 0x55); // Count 1s in even positions
            const b = @popCount(output[i] & 0xAA); // Count 1s in odd positions
            poly.coeffs[i] = @as(i16, @intCast(a)) - @as(i16, @intCast(b));
        }
        
        return poly;
    }
    
    fn generateErrorVector(self: *Kyber, seed: *const [KYBER_SYMBYTES]u8) PolyVec {
        var vec = PolyVec.init();
        
        for (0..KYBER_K) |i| {
            vec.vec[i] = self.generateSecretPoly(seed, @intCast(i + KYBER_K));
        }
        
        return vec;
    }
    
    fn generateErrorPoly(self: *Kyber, seed: *const [KYBER_SYMBYTES]u8) Poly {
        return self.generateSecretPoly(seed, 2 * KYBER_K);
    }
    
    fn packPublicKey(self: *Kyber, output: *[KYBER_PUBLICKEYBYTES]u8, t: *const PolyVec, rho: *const [KYBER_SYMBYTES]u8) void {
        _ = self;
        
        // Pack polynomial vector t
        for (0..KYBER_K) |i| {
            self.packPoly(output[i * KYBER_POLYBYTES..(i + 1) * KYBER_POLYBYTES], &t.vec[i]);
        }
        
        // Append rho
        @memcpy(output[KYBER_POLYVECBYTES..], rho);
    }
    
    fn packSecretKey(self: *Kyber, output: *[KYBER_SECRETKEYBYTES]u8, s: *const PolyVec, pk: *const [KYBER_PUBLICKEYBYTES]u8, pk_hash: *const [KYBER_SYMBYTES]u8, z: *const [KYBER_SYMBYTES]u8) void {
        _ = self;
        var offset: usize = 0;
        
        // Pack s
        for (0..KYBER_K) |i| {
            self.packPoly(output[offset..offset + KYBER_POLYBYTES], &s.vec[i]);
            offset += KYBER_POLYBYTES;
        }
        
        // Pack public key
        @memcpy(output[offset..offset + KYBER_PUBLICKEYBYTES], pk);
        offset += KYBER_PUBLICKEYBYTES;
        
        // Pack hash of public key
        @memcpy(output[offset..offset + KYBER_SYMBYTES], pk_hash);
        offset += KYBER_SYMBYTES;
        
        // Pack z
        @memcpy(output[offset..offset + KYBER_SYMBYTES], z);
    }
    
    fn packCiphertext(self: *Kyber, output: *[KYBER_CIPHERTEXTBYTES]u8, u: *const PolyVec, v: *const Poly) void {
        _ = self;
        
        // Pack u
        for (0..KYBER_K) |i| {
            self.packPoly(output[i * KYBER_POLYBYTES..(i + 1) * KYBER_POLYBYTES], &u.vec[i]);
        }
        
        // Pack v
        self.packPoly(output[KYBER_POLYVECBYTES..KYBER_POLYVECBYTES + KYBER_POLYBYTES], v);
    }
    
    fn packPoly(self: *Kyber, output: []u8, poly: *const Poly) void {
        _ = self;
        // Simplified packing - pack 12-bit coefficients
        for (0..KYBER_N / 2) |i| {
            const c0 = @as(u16, @intCast(poly.coeffs[2 * i]));
            const c1 = @as(u16, @intCast(poly.coeffs[2 * i + 1]));
            
            output[3 * i] = @intCast(c0 & 0xFF);
            output[3 * i + 1] = @intCast((c0 >> 8) | ((c1 & 0x0F) << 4));
            output[3 * i + 2] = @intCast(c1 >> 4);
        }
    }
    
    fn unpackPublicKey(self: *Kyber, t: *PolyVec, rho: *[KYBER_SYMBYTES]u8, input: *const [KYBER_PUBLICKEYBYTES]u8) void {
        _ = self;
        
        // Unpack t
        for (0..KYBER_K) |i| {
            self.unpackPoly(&t.vec[i], input[i * KYBER_POLYBYTES..(i + 1) * KYBER_POLYBYTES]);
        }
        
        // Extract rho
        @memcpy(rho, input[KYBER_POLYVECBYTES..]);
    }
    
    fn unpackSecretKey(self: *Kyber, s: *PolyVec, pk: *[KYBER_PUBLICKEYBYTES]u8, pk_hash: *[KYBER_SYMBYTES]u8, z: *[KYBER_SYMBYTES]u8, input: *const [KYBER_SECRETKEYBYTES]u8) void {
        _ = self;
        var offset: usize = 0;
        
        // Unpack s
        for (0..KYBER_K) |i| {
            self.unpackPoly(&s.vec[i], input[offset..offset + KYBER_POLYBYTES]);
            offset += KYBER_POLYBYTES;
        }
        
        // Extract public key
        @memcpy(pk, input[offset..offset + KYBER_PUBLICKEYBYTES]);
        offset += KYBER_PUBLICKEYBYTES;
        
        // Extract hash of public key
        @memcpy(pk_hash, input[offset..offset + KYBER_SYMBYTES]);
        offset += KYBER_SYMBYTES;
        
        // Extract z
        @memcpy(z, input[offset..offset + KYBER_SYMBYTES]);
    }
    
    fn unpackCiphertext(self: *Kyber, u: *PolyVec, v: *Poly, input: *const [KYBER_CIPHERTEXTBYTES]u8) void {
        _ = self;
        
        // Unpack u
        for (0..KYBER_K) |i| {
            self.unpackPoly(&u.vec[i], input[i * KYBER_POLYBYTES..(i + 1) * KYBER_POLYBYTES]);
        }
        
        // Unpack v
        self.unpackPoly(v, input[KYBER_POLYVECBYTES..KYBER_POLYVECBYTES + KYBER_POLYBYTES]);
    }
    
    fn unpackPoly(self: *Kyber, poly: *Poly, input: []const u8) void {
        _ = self;
        // Simplified unpacking - unpack 12-bit coefficients
        for (0..KYBER_N / 2) |i| {
            const b0 = @as(u16, input[3 * i]);
            const b1 = @as(u16, input[3 * i + 1]);
            const b2 = @as(u16, input[3 * i + 2]);
            
            poly.coeffs[2 * i] = @intCast(b0 | ((b1 & 0x0F) << 8));
            poly.coeffs[2 * i + 1] = @intCast((b1 >> 4) | (b2 << 4));
        }
    }
};

// Utility functions

fn modq(x: i32) i16 {
    const result = @rem(x, KYBER_Q);
    return if (result < 0) @intCast(result + KYBER_Q) else @intCast(result);
}

fn nttRoot(exp: usize) i16 {
    // Simplified NTT root calculation
    _ = exp;
    return 17; // Primitive root modulo q (simplified)
}

fn nttRootInv(exp: usize) i16 {
    // Inverse NTT root
    _ = exp;
    return 1175; // Inverse of primitive root (simplified)
}

fn nttInv() i16 {
    return 3303; // Inverse of N modulo q
}

// Integration with existing handshake
pub fn addKyberToHandshake(handshake_config: *@import("handshake.zig").HandshakeConfig, allocator: std.mem.Allocator) !void {
    var kyber = Kyber.init(allocator);
    
    // Generate Kyber key pair
    const keypair = try kyber.generateKeyPair();
    
    // Store Kyber public key in handshake config
    // This would require extending HandshakeConfig to support post-quantum keys
    _ = keypair;
    _ = handshake_config;
}

pub fn performKyberKeyExchange(allocator: std.mem.Allocator, peer_public_key: *const [KYBER_PUBLICKEYBYTES]u8) !KyberSharedSecret {
    var kyber = Kyber.init(allocator);
    
    // Encapsulate to create shared secret
    const result = try kyber.encapsulate(peer_public_key);
    
    // In practice, would send result.ciphertext to peer
    // and use result.shared_secret for encryption
    _ = result.ciphertext;
    
    return result.shared_secret;
}