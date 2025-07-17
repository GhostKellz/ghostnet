# GhostNet Integration Guide: ZQUIC + zsync

**A complete integration guide for building network applications on the GhostNet framework using ZQUIC's post-quantum QUIC transport and zsync's async runtime.**

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Core Components](#core-components)
- [Integration Examples](#integration-examples)
- [Best Practices](#best-practices)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)

---

## Overview

GhostNet is a comprehensive network framework that combines:
- **ZQUIC**: Post-quantum QUIC transport with HTTP/3 support
- **zsync**: Modern async runtime for Zig applications
- **GhostBridge**: gRPC-over-QUIC service mesh

This integration enables building secure, high-performance network applications with post-quantum cryptography.

### Key Features
- ✅ Post-quantum cryptography (ML-KEM-768, SLH-DSA-128f)
- ✅ HTTP/3 and gRPC-over-QUIC support
- ✅ Async/await programming model
- ✅ Service mesh capabilities
- ✅ FFI bindings for Rust integration

---

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GhostNet      │    │      ZQUIC      │    │     zsync       │
│   Framework     │◄──►│  Transport      │◄──►│   Runtime       │
│                 │    │                 │    │                 │
│ • Service Mesh  │    │ • Post-Quantum  │    │ • Async Tasks   │
│ • Load Balancer │    │ • HTTP/3        │    │ • Cooperative   │
│ • Discovery     │    │ • gRPC/QUIC     │    │ • Zero-Copy     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Runtime Models

Choose the appropriate execution model based on your workload:

| Model | Best For | Use Case |
|-------|----------|----------|
| `zsync.BlockingIo` | CPU-intensive | Cryptographic operations |
| `zsync.ThreadPoolIo` | Mixed workloads | Database operations |
| `zsync.GreenThreadsIo` | High concurrency | QUIC servers |
| `zsync.StacklessIo` | WASM deployment | Edge computing |

---

## Quick Start

### 1. Project Setup

```zig
// build.zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Add dependencies
    const zquic_dep = b.dependency("zquic", .{
        .target = target,
        .optimize = optimize,
    });
    
    const zsync_dep = b.dependency("zsync", .{
        .target = target,
        .optimize = optimize,
    });

    // Create your application
    const exe = b.addExecutable(.{
        .name = "ghostnet-app",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = zquic_dep.module("zquic") },
                .{ .name = "zsync", .module = zsync_dep.module("zsync") },
            },
        }),
    });

    b.installArtifact(exe);
}
```

### 2. Basic Application

```zig
// src/main.zig
const std = @import("std");
const zquic = @import("zquic");
const zsync = @import("zsync");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize zsync runtime
    const runtime = try zsync.init(allocator);
    defer runtime.deinit();

    // Run async application
    try zsync.run(asyncMain, .{allocator});
}

fn asyncMain(allocator: std.mem.Allocator) !void {
    std.log.info("🚀 GhostNet application starting...");
    
    // Create QUIC server
    const config = zquic.ServerConfig{
        .address = "0.0.0.0",
        .port = 8443,
        .max_connections = 1000,
        .enable_post_quantum = true,
    };
    
    var server = try zquic.Server.init(allocator, config);
    defer server.deinit();
    
    // Start accepting connections
    _ = try zsync.spawn(acceptConnections, .{&server});
    
    // Keep server running
    try zsync.sleep(std.time.ns_per_hour); // 1 hour
}

fn acceptConnections(server: *zquic.Server) !void {
    const io = zsync.GreenThreadsIo{};
    
    while (true) {
        const connection = try server.accept();
        _ = try zsync.spawn(handleConnection, .{connection});
    }
}

fn handleConnection(connection: *zquic.Connection) !void {
    defer connection.deinit();
    
    std.log.info("🔗 New connection from {}", .{connection.peer_addr});
    
    // Handle connection events
    while (connection.isActive()) {
        try connection.processEvents();
        try zsync.sleep(1); // 1ms processing interval
    }
}
```

---

## Core Components

### 1. ZQUIC Server with zsync

```zig
// src/quic_server.zig
const std = @import("std");
const zquic = @import("zquic");
const zsync = @import("zsync");

pub const GhostNetServer = struct {
    allocator: std.mem.Allocator,
    config: zquic.ServerConfig,
    server: *zquic.Server,
    connections: std.ArrayList(*zquic.Connection),
    running: std.atomic.Value(bool),
    
    pub fn init(allocator: std.mem.Allocator, config: zquic.ServerConfig) !*GhostNetServer {
        const self = try allocator.create(GhostNetServer);
        self.* = GhostNetServer{
            .allocator = allocator,
            .config = config,
            .server = try zquic.Server.init(allocator, config),
            .connections = std.ArrayList(*zquic.Connection).init(allocator),
            .running = std.atomic.Value(bool).init(false),
        };
        return self;
    }
    
    pub fn deinit(self: *GhostNetServer) void {
        self.stop();
        
        // Clean up connections
        for (self.connections.items) |conn| {
            conn.deinit();
        }
        self.connections.deinit();
        
        self.server.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn start(self: *GhostNetServer) !void {
        self.running.store(true, .release);
        
        // Start connection acceptor
        _ = try zsync.spawn(connectionAcceptor, .{self});
        
        // Start connection manager
        _ = try zsync.spawn(connectionManager, .{self});
        
        std.log.info("🌟 GhostNet server started on {s}:{d}", .{ self.config.address, self.config.port });
    }
    
    pub fn stop(self: *GhostNetServer) void {
        self.running.store(false, .release);
        std.log.info("🛑 GhostNet server stopped");
    }
    
    fn connectionAcceptor(self: *GhostNetServer) !void {
        const io = zsync.GreenThreadsIo{};
        
        while (self.running.load(.acquire)) {
            // Accept new connections
            var future = io.async(acceptNextConnection, .{self});
            defer future.cancel(io) catch {};
            
            if (future.await(io)) |connection| {
                // Add to connection list
                try self.connections.append(connection);
                
                // Spawn connection handler
                _ = try zsync.spawn(handleConnection, .{connection});
            } else |_| {
                // Handle accept errors
                try zsync.sleep(100); // Brief pause on error
            }
        }
    }
    
    fn connectionManager(self: *GhostNetServer) !void {
        while (self.running.load(.acquire)) {
            // Clean up closed connections
            var i: usize = 0;
            while (i < self.connections.items.len) {
                const conn = self.connections.items[i];
                if (!conn.isActive()) {
                    conn.deinit();
                    _ = self.connections.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
            
            // Update connection statistics
            self.updateStats();
            
            try zsync.sleep(1000); // 1 second cleanup interval
        }
    }
    
    fn acceptNextConnection(self: *GhostNetServer) !*zquic.Connection {
        return try self.server.accept();
    }
    
    fn handleConnection(connection: *zquic.Connection) !void {
        defer connection.deinit();
        
        std.log.info("🔗 Handling connection from {}", .{connection.peer_addr});
        
        while (connection.isActive()) {
            try connection.processEvents();
            try zsync.sleep(1); // 1ms processing interval
        }
        
        std.log.info("💔 Connection closed");
    }
    
    fn updateStats(self: *GhostNetServer) void {
        const active_count = self.connections.items.len;
        std.log.debug("📊 Active connections: {d}", .{active_count});
    }
};
```

### 2. GhostBridge Service Integration

```zig
// src/ghostbridge_client.zig
const std = @import("std");
const zquic = @import("zquic");
const zsync = @import("zsync");

pub const GhostBridgeClient = struct {
    allocator: std.mem.Allocator,
    bridge: *zquic.GhostBridge,
    connections: std.HashMap([]const u8, *zquic.GrpcConnection, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    
    pub fn init(allocator: std.mem.Allocator, config: zquic.GhostBridgeConfig) !*GhostBridgeClient {
        const self = try allocator.create(GhostBridgeClient);
        self.* = GhostBridgeClient{
            .allocator = allocator,
            .bridge = try zquic.GhostBridge.init(allocator, config),
            .connections = std.HashMap([]const u8, *zquic.GrpcConnection, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
        return self;
    }
    
    pub fn deinit(self: *GhostBridgeClient) void {
        // Clean up connections
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.connections.deinit();
        
        self.bridge.deinit();
        self.allocator.destroy(self);
    }
    
    /// Connect to a service (ghostd, walletd, etc.)
    pub fn connectToService(self: *GhostBridgeClient, service_name: []const u8) !*zquic.GrpcConnection {
        const io = zsync.GreenThreadsIo{};
        
        // Check if connection already exists
        if (self.connections.get(service_name)) |existing| {
            return existing;
        }
        
        // Create new connection
        var future = io.async(establishConnection, .{ self.bridge, service_name });
        defer future.cancel(io) catch {};
        
        const connection = try future.await(io);
        
        // Cache the connection
        const owned_name = try self.allocator.dupe(u8, service_name);
        try self.connections.put(owned_name, connection);
        
        return connection;
    }
    
    /// Send a gRPC request to a service
    pub fn sendRequest(self: *GhostBridgeClient, service_name: []const u8, method: []const u8, request_data: []const u8) !zquic.GrpcResponse {
        const connection = try self.connectToService(service_name);
        
        const io = zsync.GreenThreadsIo{};
        
        // Create method info
        const grpc_method = try zquic.GrpcMethod.init(self.allocator, service_name, method);
        defer grpc_method.deinit(self.allocator);
        
        // Send request
        var future = io.async(sendUnaryRequest, .{ connection, grpc_method, request_data });
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }
    
    /// Example: Call ghostd blockchain methods
    pub fn callGhostd(self: *GhostBridgeClient, method: []const u8, request_data: []const u8) !zquic.GrpcResponse {
        return self.sendRequest("ghostd.blockchain.service", method, request_data);
    }
    
    /// Example: Call walletd wallet methods
    pub fn callWalletd(self: *GhostBridgeClient, method: []const u8, request_data: []const u8) !zquic.GrpcResponse {
        return self.sendRequest("walletd.wallet.service", method, request_data);
    }
    
    fn establishConnection(bridge: *zquic.GhostBridge, service_name: []const u8) !*zquic.GrpcConnection {
        return try bridge.createConnection(service_name);
    }
    
    fn sendUnaryRequest(connection: *zquic.GrpcConnection, method: zquic.GrpcMethod, request_data: []const u8) !zquic.GrpcResponse {
        return try connection.sendUnaryRequest(method, request_data);
    }
};
```

### 3. Post-Quantum Crypto Integration

```zig
// src/crypto_service.zig
const std = @import("std");
const zquic = @import("zquic");
const zsync = @import("zsync");

pub const CryptoService = struct {
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) !*CryptoService {
        const self = try allocator.create(CryptoService);
        self.* = CryptoService{
            .allocator = allocator,
        };
        return self;
    }
    
    pub fn deinit(self: *CryptoService) void {
        self.allocator.destroy(self);
    }
    
    /// Generate ML-KEM-768 key pair asynchronously
    pub fn generateMLKemKeyPair(self: *CryptoService) !struct { public_key: []u8, private_key: []u8 } {
        const io = zsync.BlockingIo{}; // Use blocking I/O for crypto operations
        
        var future = io.async(generateMLKemKeyPairWorker, .{self});
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }
    
    /// Sign data with SLH-DSA-128f asynchronously
    pub fn signWithSLHDSA(self: *CryptoService, private_key: []const u8, message: []const u8) ![]u8 {
        const io = zsync.BlockingIo{};
        
        var future = io.async(signWithSLHDSAWorker, .{ self, private_key, message });
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }
    
    /// Verify SLH-DSA-128f signature asynchronously
    pub fn verifySLHDSA(self: *CryptoService, public_key: []const u8, message: []const u8, signature: []const u8) !bool {
        const io = zsync.BlockingIo{};
        
        var future = io.async(verifySLHDSAWorker, .{ self, public_key, message, signature });
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }
    
    fn generateMLKemKeyPairWorker(self: *CryptoService) !struct { public_key: []u8, private_key: []u8 } {
        // Yield to allow other tasks to run
        defer zsync.yieldNow();
        
        // Allocate key storage
        const public_key = try self.allocator.alloc(u8, zquic.crypto.ML_KEM_768_PUBLIC_KEY_SIZE);
        const private_key = try self.allocator.alloc(u8, zquic.crypto.ML_KEM_768_PRIVATE_KEY_SIZE);
        
        // Generate keys using ZQUIC crypto
        const result = zquic.crypto.mlkem768KeyPair(public_key.ptr, private_key.ptr);
        if (result != 0) {
            return error.CryptoError;
        }
        
        return .{ .public_key = public_key, .private_key = private_key };
    }
    
    fn signWithSLHDSAWorker(self: *CryptoService, private_key: []const u8, message: []const u8) ![]u8 {
        defer zsync.yieldNow();
        
        const signature = try self.allocator.alloc(u8, zquic.crypto.SLH_DSA_128F_SIGNATURE_SIZE);
        
        const result = zquic.crypto.slhdsa128fSign(private_key.ptr, message.ptr, message.len, signature.ptr);
        if (result != 0) {
            return error.CryptoError;
        }
        
        return signature;
    }
    
    fn verifySLHDSAWorker(self: *CryptoService, public_key: []const u8, message: []const u8, signature: []const u8) !bool {
        defer zsync.yieldNow();
        
        const result = zquic.crypto.slhdsa128fVerify(public_key.ptr, message.ptr, message.len, signature.ptr);
        return result == 0;
    }
};
```

---

## Integration Examples

### 1. Complete GhostNet Application

```zig
// src/ghostnet_app.zig
const std = @import("std");
const zquic = @import("zquic");
const zsync = @import("zsync");

pub const GhostNetApp = struct {
    allocator: std.mem.Allocator,
    server: *GhostNetServer,
    bridge_client: *GhostBridgeClient,
    crypto_service: *CryptoService,
    
    pub fn init(allocator: std.mem.Allocator) !*GhostNetApp {
        const self = try allocator.create(GhostNetApp);
        
        // Server configuration
        const server_config = zquic.ServerConfig{
            .address = "0.0.0.0",
            .port = 8443,
            .max_connections = 1000,
            .enable_post_quantum = true,
            .cert_path = "ghostnet.pem",
            .key_path = "ghostnet.key",
        };
        
        // GhostBridge configuration
        const bridge_config = zquic.GhostBridgeConfig{
            .address = "127.0.0.1",
            .port = 50051,
            .max_connections = 500,
            .enable_post_quantum = true,
        };
        
        self.* = GhostNetApp{
            .allocator = allocator,
            .server = try GhostNetServer.init(allocator, server_config),
            .bridge_client = try GhostBridgeClient.init(allocator, bridge_config),
            .crypto_service = try CryptoService.init(allocator),
        };
        
        return self;
    }
    
    pub fn deinit(self: *GhostNetApp) void {
        self.server.deinit();
        self.bridge_client.deinit();
        self.crypto_service.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn run(self: *GhostNetApp) !void {
        std.log.info("🚀 Starting GhostNet application...");
        
        // Start server
        try self.server.start();
        
        // Spawn service handlers
        _ = try zsync.spawn(handleBlockchainOperations, .{self});
        _ = try zsync.spawn(handleWalletOperations, .{self});
        _ = try zsync.spawn(handleCryptoOperations, .{self});
        
        // Keep running
        while (true) {
            try zsync.sleep(10000); // 10 seconds
            self.logStats();
        }
    }
    
    fn handleBlockchainOperations(self: *GhostNetApp) !void {
        while (true) {
            // Example: Query blockchain state
            const request_data = "{}"; // JSON request
            const response = try self.bridge_client.callGhostd("GetBlockchainInfo", request_data);
            defer response.deinit(self.allocator);
            
            std.log.info("📊 Blockchain info: {s}", .{response.body});
            
            try zsync.sleep(30000); // 30 seconds between queries
        }
    }
    
    fn handleWalletOperations(self: *GhostNetApp) !void {
        while (true) {
            // Example: Check wallet balance
            const request_data = "{\"address\":\"ghost1...\"}";
            const response = try self.bridge_client.callWalletd("GetBalance", request_data);
            defer response.deinit(self.allocator);
            
            std.log.info("💰 Wallet balance: {s}", .{response.body});
            
            try zsync.sleep(60000); // 60 seconds between queries
        }
    }
    
    fn handleCryptoOperations(self: *GhostNetApp) !void {
        while (true) {
            // Example: Generate new key pair
            const keypair = try self.crypto_service.generateMLKemKeyPair();
            defer self.allocator.free(keypair.public_key);
            defer self.allocator.free(keypair.private_key);
            
            std.log.info("🔐 Generated new ML-KEM key pair");
            
            try zsync.sleep(300000); // 5 minutes between generations
        }
    }
    
    fn logStats(self: *GhostNetApp) void {
        std.log.info("📈 GhostNet application running - connections: {d}", .{self.server.connections.items.len});
    }
};
```

### 2. Rust FFI Integration

```rust
// bindings/rust/examples/ghostnet_integration.rs
use zquic_sys::*;
use std::ffi::{CString, CStr};
use std::ptr;

struct GhostNetClient {
    bridge: *mut GhostBridge,
    connections: std::collections::HashMap<String, *mut GrpcConnection>,
}

impl GhostNetClient {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let config = GhostBridgeConfig {
            address: CString::new("127.0.0.1")?.into_raw(),
            port: 50051,
            max_connections: 1000,
            cert_path: ptr::null(),
            key_path: ptr::null(),
            enable_compression: true,
            enable_post_quantum: true,
        };
        
        let bridge = unsafe { ghostbridge_init(&config) };
        if bridge.is_null() {
            return Err("Failed to initialize GhostBridge".into());
        }
        
        Ok(GhostNetClient {
            bridge,
            connections: std::collections::HashMap::new(),
        })
    }
    
    pub fn connect_to_service(&mut self, service_name: &str) -> Result<*mut GrpcConnection, Box<dyn std::error::Error>> {
        // Check if connection already exists
        if let Some(&connection) = self.connections.get(service_name) {
            return Ok(connection);
        }
        
        // Create new connection
        let service_cstr = CString::new(service_name)?;
        let connection = unsafe { ghostbridge_create_grpc_connection(self.bridge, service_cstr.as_ptr()) };
        
        if connection.is_null() {
            return Err("Failed to create gRPC connection".into());
        }
        
        self.connections.insert(service_name.to_string(), connection);
        Ok(connection)
    }
    
    pub fn call_ghostd(&mut self, method: &str, request_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let connection = self.connect_to_service("ghostd.blockchain.service")?;
        
        let method_cstr = CString::new(method)?;
        let response = unsafe {
            ghostbridge_call_method(
                connection,
                method_cstr.as_ptr(),
                request_data.as_ptr(),
                request_data.len(),
            )
        };
        
        if response.is_null() {
            return Err("Failed to call method".into());
        }
        
        // Extract response data (simplified)
        let result = Vec::new(); // Would extract actual response data
        
        unsafe {
            ghostbridge_free_grpc_response(response);
        }
        
        Ok(result)
    }
}

impl Drop for GhostNetClient {
    fn drop(&mut self) {
        // Clean up connections
        for (_, &connection) in &self.connections {
            unsafe {
                ghostbridge_close_grpc_connection(connection);
            }
        }
        
        unsafe {
            ghostbridge_destroy(self.bridge);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 GhostNet Rust Client Example");
    
    let mut client = GhostNetClient::new()?;
    
    // Example blockchain operations
    tokio::spawn(async move {
        loop {
            match client.call_ghostd("GetBlockchainInfo", b"{}") {
                Ok(response) => {
                    println!("📊 Blockchain info: {} bytes", response.len());
                }
                Err(e) => {
                    eprintln!("❌ Error calling ghostd: {}", e);
                }
            }
            
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    });
    
    // Keep client running
    tokio::signal::ctrl_c().await?;
    println!("🛑 Shutting down GhostNet client");
    
    Ok(())
}
```

---

## Best Practices

### 1. Error Handling

```zig
// Use proper error handling with zsync
fn robustNetworkOperation(client: *GhostBridgeClient) !void {
    const io = zsync.GreenThreadsIo{};
    
    var retries: u32 = 0;
    const max_retries = 3;
    
    while (retries < max_retries) {
        var future = io.async(performNetworkCall, .{client});
        defer future.cancel(io) catch {};
        
        if (future.await(io)) |result| {
            // Success
            return result;
        } else |err| switch (err) {
            error.NetworkTimeout => {
                retries += 1;
                try zsync.sleep(1000 * retries); // Exponential backoff
                continue;
            },
            else => return err,
        }
    }
    
    return error.MaxRetriesExceeded;
}
```

### 2. Resource Management

```zig
// Always use defer for cleanup
fn safeResourceUsage(allocator: std.mem.Allocator) !void {
    const app = try GhostNetApp.init(allocator);
    defer app.deinit(); // Guaranteed cleanup
    
    const keypair = try app.crypto_service.generateMLKemKeyPair();
    defer allocator.free(keypair.public_key);
    defer allocator.free(keypair.private_key);
    
    // Use resources...
}
```

### 3. Performance Optimization

```zig
// Use connection pooling
pub const ConnectionPool = struct {
    connections: std.ArrayList(*zquic.GrpcConnection),
    available: zsync.bounded(*zquic.GrpcConnection, 100),
    
    pub fn acquire(self: *ConnectionPool) !*zquic.GrpcConnection {
        if (self.available.tryReceive()) |conn| {
            return conn;
        }
        
        // Create new connection if none available
        return try self.createNewConnection();
    }
    
    pub fn release(self: *ConnectionPool, conn: *zquic.GrpcConnection) void {
        self.available.send(conn) catch {
            // Pool is full, close connection
            conn.deinit();
        };
    }
};
```

---

## Performance Tuning

### 1. Runtime Selection

```zig
// Choose runtime based on workload
const ServerRuntime = switch (build_mode) {
    .Debug => zsync.GreenThreadsIo,
    .ReleaseFast => zsync.StacklessIo,
    .ReleaseSafe => zsync.ThreadPoolIo,
    .ReleaseSmall => zsync.BlockingIo,
};
```

### 2. Buffer Management

```zig
// Use pre-allocated buffers
pub const BufferPool = struct {
    buffers: zsync.bounded([]u8, 1000),
    allocator: std.mem.Allocator,
    
    pub fn getBuffer(self: *BufferPool) ![]u8 {
        if (self.buffers.tryReceive()) |buf| {
            return buf;
        }
        
        // Allocate new buffer
        return try self.allocator.alloc(u8, 8192);
    }
    
    pub fn returnBuffer(self: *BufferPool, buffer: []u8) void {
        self.buffers.send(buffer) catch {
            // Pool is full, deallocate
            self.allocator.free(buffer);
        };
    }
};
```

### 3. Batch Operations

```zig
// Process multiple operations together
fn batchRequests(client: *GhostBridgeClient, requests: []Request) ![]Response {
    var responses = try std.ArrayList(Response).initCapacity(client.allocator, requests.len);
    defer responses.deinit();
    
    // Process in batches of 10
    var i: usize = 0;
    while (i < requests.len) {
        const batch_end = @min(i + 10, requests.len);
        const batch = requests[i..batch_end];
        
        // Process batch concurrently
        var futures = std.ArrayList(zsync.Future(Response)).init(client.allocator);
        defer futures.deinit();
        
        for (batch) |request| {
            const future = zsync.spawn(processRequest, .{ client, request });
            try futures.append(future);
        }
        
        // Await all futures
        for (futures.items) |future| {
            const response = try future.await();
            try responses.append(response);
        }
        
        i = batch_end;
    }
    
    return responses.toOwnedSlice();
}
```

---

## Troubleshooting

### Common Issues

1. **Connection Timeouts**
```zig
// Increase timeout values
const config = zquic.ServerConfig{
    .idle_timeout_ms = 60000, // 60 seconds
    .request_timeout_ms = 30000, // 30 seconds
};
```

2. **Memory Leaks**
```zig
// Always check for proper cleanup
fn debugMemoryUsage(allocator: std.mem.Allocator) void {
    const info = allocator.info();
    std.log.debug("Memory usage: {} bytes allocated", .{info.total_allocated});
}
```

3. **Performance Issues**
```zig
// Use profiling to identify bottlenecks
fn profileOperation(operation: anytype) !void {
    const start = std.time.nanoTimestamp();
    try operation();
    const duration = std.time.nanoTimestamp() - start;
    
    std.log.info("Operation took {} nanoseconds", .{duration});
}
```

### Debug Logging

```zig
// Enable debug logging
pub const log_level: std.log.Level = .debug;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    const timestamp = std.time.timestamp();
    std.debug.print("[{}] {s}: " ++ format ++ "\n", .{ timestamp, @tagName(scope) } ++ args);
}
```

---

This integration guide provides a comprehensive foundation for building GhostNet applications with ZQUIC and zsync. The examples demonstrate real-world usage patterns and best practices for production deployment.

For additional examples and updates, check the repository's `examples/` directory and documentation.