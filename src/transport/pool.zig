const std = @import("std");
const zsync = @import("zsync");
const transport = @import("transport.zig");
const errors = @import("../errors/errors.zig");

pub const PoolConfig = struct {
    max_connections: usize = 100,
    max_idle_connections: usize = 10,
    idle_timeout: u64 = 60_000_000_000, // 60 seconds in nanoseconds
    connection_timeout: u64 = 30_000_000_000, // 30 seconds
    max_retries: u32 = 3,
    retry_delay: u64 = 1_000_000_000, // 1 second
    enable_health_checks: bool = true,
    health_check_interval: u64 = 30_000_000_000, // 30 seconds
};

pub const ConnectionInfo = struct {
    connection: transport.Connection,
    address: transport.Address,
    created_at: i64,
    last_used_at: i64,
    use_count: u64,
    is_healthy: bool,
    id: u64,
};

pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    config: PoolConfig,
    connections: std.ArrayList(ConnectionInfo),
    idle_connections: std.ArrayList(*ConnectionInfo),
    active_connections: std.HashMap(u64, *ConnectionInfo, std.hash_map.AutoContext(u64), 80),
    address_pools: std.StringHashMap(std.ArrayList(*ConnectionInfo)),
    mutex: std.Thread.Mutex,
    next_id: std.atomic.Value(u64),
    stats: PoolStats,
    shutdown: std.atomic.Value(bool),
    
    pub const PoolStats = struct {
        total_created: std.atomic.Value(u64),
        total_destroyed: std.atomic.Value(u64),
        current_active: std.atomic.Value(u32),
        current_idle: std.atomic.Value(u32),
        failed_connections: std.atomic.Value(u64),
        successful_connections: std.atomic.Value(u64),
    };
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, config: PoolConfig) !*ConnectionPool {
        const pool = try allocator.create(ConnectionPool);
        errdefer allocator.destroy(pool);
        
        pool.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .config = config,
            .connections = std.ArrayList(ConnectionInfo).init(allocator),
            .idle_connections = std.ArrayList(*ConnectionInfo).init(allocator),
            .active_connections = std.HashMap(u64, *ConnectionInfo, std.hash_map.AutoContext(u64), 80).init(allocator),
            .address_pools = std.StringHashMap(std.ArrayList(*ConnectionInfo)).init(allocator),
            .mutex = .{},
            .next_id = std.atomic.Value(u64).init(0),
            .stats = .{
                .total_created = std.atomic.Value(u64).init(0),
                .total_destroyed = std.atomic.Value(u64).init(0),
                .current_active = std.atomic.Value(u32).init(0),
                .current_idle = std.atomic.Value(u32).init(0),
                .failed_connections = std.atomic.Value(u64).init(0),
                .successful_connections = std.atomic.Value(u64).init(0),
            },
            .shutdown = std.atomic.Value(bool).init(false),
        };
        
        if (config.enable_health_checks) {
            _ = try pool.runtime.spawn(healthCheckLoop, .{pool});
        }
        
        return pool;
    }
    
    pub fn deinit(self: *ConnectionPool) void {
        self.shutdown.store(true, .SeqCst);
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Close all connections
        for (self.connections.items) |*conn_info| {
            conn_info.connection.close();
        }
        
        // Clean up collections
        self.connections.deinit();
        self.idle_connections.deinit();
        self.active_connections.deinit();
        
        var iter = self.address_pools.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.address_pools.deinit();
        
        self.allocator.destroy(self);
    }
    
    pub fn acquire(self: *ConnectionPool, address: transport.Address, options: transport.TransportOptions) !transport.Connection {
        if (self.shutdown.load(.SeqCst)) {
            return error.PoolShutdown;
        }
        
        // Try to get an idle connection first
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            if (self.idle_connections.items.len > 0) {
                var i: usize = self.idle_connections.items.len;
                while (i > 0) {
                    i -= 1;
                    const conn_info = self.idle_connections.items[i];
                    
                    // Check if connection is still valid
                    if (self.isConnectionValid(conn_info)) {
                        // Move from idle to active
                        _ = self.idle_connections.orderedRemove(i);
                        try self.active_connections.put(conn_info.id, conn_info);
                        
                        conn_info.last_used_at = std.time.timestamp();
                        conn_info.use_count += 1;
                        
                        _ = self.stats.current_idle.fetchSub(1, .SeqCst);
                        _ = self.stats.current_active.fetchAdd(1, .SeqCst);
                        _ = self.stats.successful_connections.fetchAdd(1, .SeqCst);
                        
                        return conn_info.connection;
                    } else {
                        // Remove invalid connection
                        _ = self.idle_connections.orderedRemove(i);
                        self.destroyConnection(conn_info);
                    }
                }
            }
        }
        
        // Create new connection if under limit
        if (self.connections.items.len < self.config.max_connections) {
            return self.createConnection(address, options);
        }
        
        return error.PoolExhausted;
    }
    
    pub fn acquireAsync(self: *ConnectionPool, address: transport.Address, options: transport.TransportOptions) zsync.Future(transport.TransportError!transport.Connection) {
        return zsync.Future(transport.TransportError!transport.Connection).init(self.runtime, struct {
            pool: *ConnectionPool,
            addr: transport.Address,
            opts: transport.TransportOptions,
            retry_count: u32 = 0,
            
            pub fn poll(ctx: *@This()) zsync.Poll(transport.TransportError!transport.Connection) {
                if (ctx.pool.shutdown.load(.SeqCst)) {
                    return .{ .ready = transport.TransportError!transport.Connection{ error.TransportClosed } };
                }
                
                // Try to acquire synchronously first
                if (ctx.pool.acquire(ctx.addr, ctx.opts)) |conn| {
                    return .{ .ready = conn };
                } else |err| switch (err) {
                    error.PoolExhausted => {
                        if (ctx.retry_count < ctx.pool.config.max_retries) {
                            ctx.retry_count += 1;
                            return .pending;
                        }
                        return .{ .ready = transport.TransportError!transport.Connection{ error.TooManyConnections } };
                    },
                    else => return .{ .ready = transport.TransportError!transport.Connection{ errors.mapSystemError(err) } },
                }
            }
        }{ .pool = self, .addr = address, .opts = options });
    }
    
    pub fn release(self: *ConnectionPool, connection: transport.Connection) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Find connection in active pool
        var iter = self.active_connections.iterator();
        while (iter.next()) |entry| {
            if (@intFromPtr(entry.value_ptr.*.connection.ptr) == @intFromPtr(connection.ptr)) {
                const conn_info = entry.value_ptr.*;
                
                // Check if we should keep it
                if (self.idle_connections.items.len < self.config.max_idle_connections and
                    conn_info.is_healthy and
                    self.isConnectionValid(conn_info))
                {
                    // Move to idle pool
                    _ = self.active_connections.remove(entry.key_ptr.*);
                    self.idle_connections.append(conn_info) catch {
                        self.destroyConnection(conn_info);
                        return;
                    };
                    
                    _ = self.stats.current_active.fetchSub(1, .SeqCst);
                    _ = self.stats.current_idle.fetchAdd(1, .SeqCst);
                } else {
                    // Destroy connection
                    _ = self.active_connections.remove(entry.key_ptr.*);
                    self.destroyConnection(conn_info);
                }
                return;
            }
        }
    }
    
    fn createConnection(self: *ConnectionPool, address: transport.Address, options: transport.TransportOptions) !transport.Connection {
        // This is a simplified version - in reality would create based on address type
        const conn_info = try self.allocator.create(ConnectionInfo);
        errdefer self.allocator.destroy(conn_info);
        
        // For now, assume TCP
        var tcp_conn = try @import("tcp.zig").TcpConnection.connect(
            self.allocator,
            self.runtime,
            address,
            options
        );
        
        const now = std.time.timestamp();
        conn_info.* = .{
            .connection = tcp_conn.connection(),
            .address = address,
            .created_at = now,
            .last_used_at = now,
            .use_count = 1,
            .is_healthy = true,
            .id = self.next_id.fetchAdd(1, .SeqCst),
        };
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        try self.connections.append(conn_info.*);
        try self.active_connections.put(conn_info.id, conn_info);
        
        _ = self.stats.total_created.fetchAdd(1, .SeqCst);
        _ = self.stats.current_active.fetchAdd(1, .SeqCst);
        _ = self.stats.successful_connections.fetchAdd(1, .SeqCst);
        
        return conn_info.connection;
    }
    
    fn destroyConnection(self: *ConnectionPool, conn_info: *ConnectionInfo) void {
        conn_info.connection.close();
        _ = self.stats.total_destroyed.fetchAdd(1, .SeqCst);
        _ = self.stats.current_idle.fetchSub(1, .SeqCst);
    }
    
    fn isConnectionValid(self: *ConnectionPool, conn_info: *ConnectionInfo) bool {
        const now = std.time.timestamp();
        const idle_time: u64 = @as(u64, @intCast(now - conn_info.last_used_at)) * 1_000_000_000;
        
        if (idle_time > self.config.idle_timeout) {
            return false;
        }
        
        if (conn_info.connection.state() != .connected) {
            return false;
        }
        
        return conn_info.is_healthy;
    }
    
    fn healthCheckLoop(pool: *ConnectionPool) void {
        while (!pool.shutdown.load(.SeqCst)) {
            std.time.sleep(pool.config.health_check_interval);
            
            pool.mutex.lock();
            defer pool.mutex.unlock();
            
            // Check idle connections
            var i: usize = pool.idle_connections.items.len;
            while (i > 0) {
                i -= 1;
                const conn_info = pool.idle_connections.items[i];
                
                if (!pool.isConnectionValid(conn_info)) {
                    _ = pool.idle_connections.orderedRemove(i);
                    pool.destroyConnection(conn_info);
                }
            }
        }
    }
    
    pub fn getStats(self: *ConnectionPool) PoolStats {
        return .{
            .total_created = std.atomic.Value(u64).init(self.stats.total_created.load(.SeqCst)),
            .total_destroyed = std.atomic.Value(u64).init(self.stats.total_destroyed.load(.SeqCst)),
            .current_active = std.atomic.Value(u32).init(self.stats.current_active.load(.SeqCst)),
            .current_idle = std.atomic.Value(u32).init(self.stats.current_idle.load(.SeqCst)),
            .failed_connections = std.atomic.Value(u64).init(self.stats.failed_connections.load(.SeqCst)),
            .successful_connections = std.atomic.Value(u64).init(self.stats.successful_connections.load(.SeqCst)),
        };
    }
};