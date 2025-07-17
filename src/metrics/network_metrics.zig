const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");

pub const MetricType = enum {
    counter,
    gauge,
    histogram,
    summary,
};

pub const Metric = struct {
    name: []const u8,
    metric_type: MetricType,
    value: std.atomic.Value(u64),
    labels: std.StringHashMap([]const u8),
    timestamp: std.atomic.Value(i64),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, name: []const u8, metric_type: MetricType) !*Metric {
        const metric = try allocator.create(Metric);
        metric.* = .{
            .name = try allocator.dupe(u8, name),
            .metric_type = metric_type,
            .value = std.atomic.Value(u64).init(0),
            .labels = std.StringHashMap([]const u8).init(allocator),
            .timestamp = std.atomic.Value(i64).init(std.time.timestamp()),
            .allocator = allocator,
        };
        return metric;
    }
    
    pub fn deinit(self: *Metric) void {
        self.allocator.free(self.name);
        var iter = self.labels.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.labels.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn addLabel(self: *Metric, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.labels.put(key_copy, value_copy);
    }
    
    pub fn increment(self: *Metric) void {
        _ = self.value.fetchAdd(1, .seq_cst);
        self.timestamp.store(std.time.timestamp(), .seq_cst);
    }
    
    pub fn incrementBy(self: *Metric, amount: u64) void {
        _ = self.value.fetchAdd(amount, .seq_cst);
        self.timestamp.store(std.time.timestamp(), .seq_cst);
    }
    
    pub fn set(self: *Metric, value: u64) void {
        self.value.store(value, .seq_cst);
        self.timestamp.store(std.time.timestamp(), .seq_cst);
    }
    
    pub fn get(self: *Metric) u64 {
        return self.value.load(.seq_cst);
    }
};

pub const Histogram = struct {
    buckets: []f64,
    counts: []std.atomic.Value(u64),
    sum: std.atomic.Value(u64),
    count: std.atomic.Value(u64),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, buckets: []const f64) !*Histogram {
        const hist = try allocator.create(Histogram);
        hist.* = .{
            .buckets = try allocator.dupe(f64, buckets),
            .counts = try allocator.alloc(std.atomic.Value(u64), buckets.len),
            .sum = std.atomic.Value(u64).init(0),
            .count = std.atomic.Value(u64).init(0),
            .allocator = allocator,
        };
        
        for (hist.counts) |*count| {
            count.* = std.atomic.Value(u64).init(0);
        }
        
        return hist;
    }
    
    pub fn deinit(self: *Histogram) void {
        self.allocator.free(self.buckets);
        self.allocator.free(self.counts);
        self.allocator.destroy(self);
    }
    
    pub fn observe(self: *Histogram, value: f64) void {
        _ = self.count.fetchAdd(1, .seq_cst);
        _ = self.sum.fetchAdd(@intFromFloat(value), .seq_cst);
        
        for (self.buckets, 0..) |bucket, i| {
            if (value <= bucket) {
                _ = self.counts[i].fetchAdd(1, .seq_cst);
            }
        }
    }
};

pub const NetworkMetrics = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    metrics: std.StringHashMap(*Metric),
    histograms: std.StringHashMap(*Histogram),
    
    // Protocol-specific metrics
    tcp_connections: *Metric,
    udp_packets: *Metric,
    quic_connections: *Metric,
    gossip_messages: *Metric,
    kademlia_lookups: *Metric,
    wireguard_handshakes: *Metric,
    
    // Performance metrics
    bytes_sent: *Metric,
    bytes_received: *Metric,
    packets_sent: *Metric,
    packets_received: *Metric,
    connection_errors: *Metric,
    timeout_errors: *Metric,
    
    // Latency histograms
    rtt_histogram: *Histogram,
    handshake_duration_histogram: *Histogram,
    message_latency_histogram: *Histogram,
    
    // Memory and resource metrics
    memory_usage: *Metric,
    active_connections: *Metric,
    cpu_usage: *Metric,
    
    mutex: std.Thread.Mutex,
    collection_interval: u64,
    running: std.atomic.Value(bool),
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) !*NetworkMetrics {
        const metrics_system = try allocator.create(NetworkMetrics);
        errdefer allocator.destroy(metrics_system);
        
        metrics_system.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .metrics = std.StringHashMap(*Metric).init(allocator),
            .histograms = std.StringHashMap(*Histogram).init(allocator),
            .tcp_connections = try Metric.init(allocator, "tcp_connections_total", .counter),
            .udp_packets = try Metric.init(allocator, "udp_packets_total", .counter),
            .quic_connections = try Metric.init(allocator, "quic_connections_total", .counter),
            .gossip_messages = try Metric.init(allocator, "gossip_messages_total", .counter),
            .kademlia_lookups = try Metric.init(allocator, "kademlia_lookups_total", .counter),
            .wireguard_handshakes = try Metric.init(allocator, "wireguard_handshakes_total", .counter),
            .bytes_sent = try Metric.init(allocator, "network_bytes_sent_total", .counter),
            .bytes_received = try Metric.init(allocator, "network_bytes_received_total", .counter),
            .packets_sent = try Metric.init(allocator, "network_packets_sent_total", .counter),
            .packets_received = try Metric.init(allocator, "network_packets_received_total", .counter),
            .connection_errors = try Metric.init(allocator, "connection_errors_total", .counter),
            .timeout_errors = try Metric.init(allocator, "timeout_errors_total", .counter),
            .memory_usage = try Metric.init(allocator, "memory_usage_bytes", .gauge),
            .active_connections = try Metric.init(allocator, "active_connections", .gauge),
            .cpu_usage = try Metric.init(allocator, "cpu_usage_percent", .gauge),
            .rtt_histogram = try createLatencyHistogram(allocator),
            .handshake_duration_histogram = try createDurationHistogram(allocator),
            .message_latency_histogram = try createLatencyHistogram(allocator),
            .mutex = .{},
            .collection_interval = 5000, // 5 seconds
            .running = std.atomic.Value(bool).init(false),
        };
        
        // Register all metrics
        try metrics_system.registerMetric(metrics_system.tcp_connections);
        try metrics_system.registerMetric(metrics_system.udp_packets);
        try metrics_system.registerMetric(metrics_system.quic_connections);
        try metrics_system.registerMetric(metrics_system.gossip_messages);
        try metrics_system.registerMetric(metrics_system.kademlia_lookups);
        try metrics_system.registerMetric(metrics_system.wireguard_handshakes);
        try metrics_system.registerMetric(metrics_system.bytes_sent);
        try metrics_system.registerMetric(metrics_system.bytes_received);
        try metrics_system.registerMetric(metrics_system.packets_sent);
        try metrics_system.registerMetric(metrics_system.packets_received);
        try metrics_system.registerMetric(metrics_system.connection_errors);
        try metrics_system.registerMetric(metrics_system.timeout_errors);
        try metrics_system.registerMetric(metrics_system.memory_usage);
        try metrics_system.registerMetric(metrics_system.active_connections);
        try metrics_system.registerMetric(metrics_system.cpu_usage);
        
        try metrics_system.registerHistogram("rtt_seconds", metrics_system.rtt_histogram);
        try metrics_system.registerHistogram("handshake_duration_seconds", metrics_system.handshake_duration_histogram);
        try metrics_system.registerHistogram("message_latency_seconds", metrics_system.message_latency_histogram);
        
        return metrics_system;
    }
    
    pub fn deinit(self: *NetworkMetrics) void {
        self.stop();
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Clean up metrics
        var metric_iter = self.metrics.iterator();
        while (metric_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.metrics.deinit();
        
        // Clean up histograms
        var hist_iter = self.histograms.iterator();
        while (hist_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.histograms.deinit();
        
        // Clean up individual metrics that aren't in the main maps
        self.tcp_connections.deinit();
        self.udp_packets.deinit();
        self.quic_connections.deinit();
        self.gossip_messages.deinit();
        self.kademlia_lookups.deinit();
        self.wireguard_handshakes.deinit();
        self.bytes_sent.deinit();
        self.bytes_received.deinit();
        self.packets_sent.deinit();
        self.packets_received.deinit();
        self.connection_errors.deinit();
        self.timeout_errors.deinit();
        self.memory_usage.deinit();
        self.active_connections.deinit();
        self.cpu_usage.deinit();
        
        self.rtt_histogram.deinit();
        self.handshake_duration_histogram.deinit();
        self.message_latency_histogram.deinit();
        
        self.allocator.destroy(self);
    }
    
    pub fn start(self: *NetworkMetrics) !void {
        self.running.store(true, .seq_cst);
        
        // Start metrics collection loop
        _ = try self.runtime.spawn(collectionLoop, .{self}, .normal);
        _ = try self.runtime.spawn(systemMetricsLoop, .{self}, .normal);
    }
    
    pub fn stop(self: *NetworkMetrics) void {
        self.running.store(false, .seq_cst);
    }
    
    fn registerMetric(self: *NetworkMetrics, metric: *Metric) !void {
        try self.metrics.put(metric.name, metric);
    }
    
    fn registerHistogram(self: *NetworkMetrics, name: []const u8, histogram: *Histogram) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        try self.histograms.put(name_copy, histogram);
    }
    
    pub fn recordTcpConnection(self: *NetworkMetrics) void {
        self.tcp_connections.increment();
    }
    
    pub fn recordUdpPacket(self: *NetworkMetrics, bytes: u64) void {
        self.udp_packets.increment();
        self.bytes_sent.incrementBy(bytes);
        self.packets_sent.increment();
    }
    
    pub fn recordQuicConnection(self: *NetworkMetrics) void {
        self.quic_connections.increment();
    }
    
    pub fn recordGossipMessage(self: *NetworkMetrics, bytes: u64) void {
        self.gossip_messages.increment();
        self.bytes_sent.incrementBy(bytes);
    }
    
    pub fn recordKademliaLookup(self: *NetworkMetrics) void {
        self.kademlia_lookups.increment();
    }
    
    pub fn recordWireguardHandshake(self: *NetworkMetrics, duration_ms: f64) void {
        self.wireguard_handshakes.increment();
        self.handshake_duration_histogram.observe(duration_ms / 1000.0); // Convert to seconds
    }
    
    pub fn recordRtt(self: *NetworkMetrics, rtt_ms: f64) void {
        self.rtt_histogram.observe(rtt_ms / 1000.0); // Convert to seconds
    }
    
    pub fn recordMessageLatency(self: *NetworkMetrics, latency_ms: f64) void {
        self.message_latency_histogram.observe(latency_ms / 1000.0);
    }
    
    pub fn recordConnectionError(self: *NetworkMetrics, error_type: []const u8) void {
        self.connection_errors.increment();
        
        // Create labeled metric for specific error type
        var labeled_metric = Metric.init(self.allocator, "connection_errors_by_type", .counter) catch return;
        defer labeled_metric.deinit();
        
        labeled_metric.addLabel("error_type", error_type) catch {};
        labeled_metric.increment();
    }
    
    pub fn recordBytesReceived(self: *NetworkMetrics, bytes: u64) void {
        self.bytes_received.incrementBy(bytes);
        self.packets_received.increment();
    }
    
    pub fn updateActiveConnections(self: *NetworkMetrics, count: u64) void {
        self.active_connections.set(count);
    }
    
    pub fn exportPrometheus(self: *NetworkMetrics, writer: std.io.AnyWriter) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Export metrics in Prometheus format
        var metric_iter = self.metrics.iterator();
        while (metric_iter.next()) |entry| {
            const metric = entry.value_ptr.*;
            
            try writer.print("# HELP {} {}\n", .{ metric.name, metric.name });
            try writer.print("# TYPE {} {}\n", .{ metric.name, @tagName(metric.metric_type) });
            
            // Write labels if any
            if (metric.labels.count() > 0) {
                try writer.print("{}{{", .{metric.name});
                var label_iter = metric.labels.iterator();
                var first = true;
                while (label_iter.next()) |label| {
                    if (!first) try writer.print(",");
                    try writer.print("{}=\"{}\"", .{ label.key_ptr.*, label.value_ptr.* });
                    first = false;
                }
                try writer.print("}} {}\n", .{metric.get()});
            } else {
                try writer.print("{} {}\n", .{ metric.name, metric.get() });
            }
        }
        
        // Export histograms
        var hist_iter = self.histograms.iterator();
        while (hist_iter.next()) |entry| {
            const name = entry.key_ptr.*;
            const histogram = entry.value_ptr.*;
            
            try writer.print("# HELP {} {}\n", .{ name, name });
            try writer.print("# TYPE {} histogram\n", .{name});
            
            // Export buckets
            for (histogram.buckets, 0..) |bucket, i| {
                try writer.print("{}_bucket{{le=\"{}\"}} {}\n", .{ name, bucket, histogram.counts[i].load(.seq_cst) });
            }
            
            try writer.print("{}_sum {}\n", .{ name, histogram.sum.load(.seq_cst) });
            try writer.print("{}_count {}\n", .{ name, histogram.count.load(.seq_cst) });
        }
    }
    
    pub fn exportJson(self: *NetworkMetrics, writer: std.io.AnyWriter) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        try writer.writeAll("{");
        try writer.writeAll("\"metrics\":{");
        
        var metric_iter = self.metrics.iterator();
        var first_metric = true;
        while (metric_iter.next()) |entry| {
            if (!first_metric) try writer.writeAll(",");
            const metric = entry.value_ptr.*;
            try writer.print("\"{}\":{{\"value\":{},\"type\":\"{}\",\"timestamp\":{}}}", .{ 
                metric.name, 
                metric.get(), 
                @tagName(metric.metric_type),
                metric.timestamp.load(.seq_cst)
            });
            first_metric = false;
        }
        
        try writer.writeAll("},\"histograms\":{");
        
        var hist_iter = self.histograms.iterator();
        var first_hist = true;
        while (hist_iter.next()) |entry| {
            if (!first_hist) try writer.writeAll(",");
            const name = entry.key_ptr.*;
            const histogram = entry.value_ptr.*;
            
            try writer.print("\"{}\":{{\"buckets\":[", .{name});
            for (histogram.buckets, 0..) |bucket, i| {
                if (i > 0) try writer.writeAll(",");
                try writer.print("{{\"le\":{},\"count\":{}}}", .{ bucket, histogram.counts[i].load(.seq_cst) });
            }
            try writer.print("],\"sum\":{},\"count\":{}}}", .{ histogram.sum.load(.seq_cst), histogram.count.load(.seq_cst) });
            first_hist = false;
        }
        
        try writer.writeAll("}}");
    }
    
    fn collectionLoop(self: *NetworkMetrics) void {
        while (self.running.load(.seq_cst)) {
            std.time.sleep(self.collection_interval * 1000000); // Convert to nanoseconds
            
            // Collect network interface statistics
            self.collectNetworkStats() catch |err| {
                std.log.err("Error collecting network stats: {}", .{err});
            };
        }
    }
    
    fn systemMetricsLoop(self: *NetworkMetrics) void {
        while (self.running.load(.seq_cst)) {
            std.time.sleep(1000000000); // 1 second
            
            // Collect system metrics
            self.collectSystemMetrics() catch |err| {
                std.log.err("Error collecting system metrics: {}", .{err});
            };
        }
    }
    
    fn collectNetworkStats(self: *NetworkMetrics) !void {
        // Collect from /proc/net/dev on Linux
        if (std.fs.cwd().openFile("/proc/net/dev", .{})) |file| {
            defer file.close();
            
            var buf_reader = std.io.bufferedReader(file.reader());
            var in_stream = buf_reader.reader();
            
            var buf: [1024]u8 = undefined;
            while (try in_stream.readUntilDelimiterOrEof(buf[0..], '\n')) |line| {
                if (std.mem.indexOf(u8, line, "eth0") != null or std.mem.indexOf(u8, line, "wlan0") != null) {
                    // Parse network interface statistics
                    var fields = std.mem.split(u8, line, " ");
                    var field_count: usize = 0;
                    var rx_bytes: u64 = 0;
                    var tx_bytes: u64 = 0;
                    
                    while (fields.next()) |field| {
                        if (field.len == 0) continue;
                        field_count += 1;
                        
                        if (field_count == 2) { // RX bytes
                            rx_bytes = std.fmt.parseInt(u64, field, 10) catch 0;
                        } else if (field_count == 10) { // TX bytes
                            tx_bytes = std.fmt.parseInt(u64, field, 10) catch 0;
                            break;
                        }
                    }
                    
                    // Update metrics (simplified - would track deltas)
                    self.bytes_received.set(rx_bytes);
                    self.bytes_sent.set(tx_bytes);
                }
            }
        } else |_| {
            // Fallback for non-Linux systems
        }
    }
    
    fn collectSystemMetrics(self: *NetworkMetrics) !void {
        // Collect memory usage
        if (std.fs.cwd().openFile("/proc/meminfo", .{})) |file| {
            defer file.close();
            
            var buf_reader = std.io.bufferedReader(file.reader());
            var in_stream = buf_reader.reader();
            
            var buf: [256]u8 = undefined;
            while (try in_stream.readUntilDelimiterOrEof(buf[0..], '\n')) |line| {
                if (std.mem.startsWith(u8, line, "MemAvailable:")) {
                    var fields = std.mem.split(u8, line, " ");
                    _ = fields.next(); // Skip "MemAvailable:"
                    
                    while (fields.next()) |field| {
                        if (field.len > 0) {
                            const mem_kb = std.fmt.parseInt(u64, field, 10) catch 0;
                            self.memory_usage.set(mem_kb * 1024); // Convert to bytes
                            break;
                        }
                    }
                    break;
                }
            }
        } else |_| {
            // Fallback for non-Linux systems
            const mem_usage = std.heap.page_allocator.total_allocated();
            self.memory_usage.set(mem_usage);
        }
        
        // Collect CPU usage (simplified)
        if (std.fs.cwd().openFile("/proc/loadavg", .{})) |file| {
            defer file.close();
            
            var buf: [64]u8 = undefined;
            if (try file.readAll(&buf)) |bytes_read| {
                var fields = std.mem.split(u8, buf[0..bytes_read], " ");
                if (fields.next()) |load1| {
                    const cpu_load = std.fmt.parseFloat(f64, load1) catch 0.0;
                    self.cpu_usage.set(@intFromFloat(cpu_load * 100.0));
                }
            }
        } else |_| {
            // Fallback - set to 0
            self.cpu_usage.set(0);
        }
    }
    
    pub fn getMetricsSummary(self: *NetworkMetrics) struct {
        total_bytes_sent: u64,
        total_bytes_received: u64,
        total_packets_sent: u64,
        total_packets_received: u64,
        active_connections: u64,
        error_rate: f64,
        avg_rtt_ms: f64,
        memory_usage_mb: f64,
        cpu_usage_percent: f64,
    } {
        const total_packets = self.packets_sent.get() + self.packets_received.get();
        const error_rate = if (total_packets > 0) 
            @as(f64, @floatFromInt(self.connection_errors.get())) / @as(f64, @floatFromInt(total_packets))
        else 0.0;
        
        // Calculate average RTT from histogram (simplified)
        const avg_rtt = if (self.rtt_histogram.count.load(.seq_cst) > 0)
            @as(f64, @floatFromInt(self.rtt_histogram.sum.load(.seq_cst))) / @as(f64, @floatFromInt(self.rtt_histogram.count.load(.seq_cst))) * 1000.0
        else 0.0;
        
        return .{
            .total_bytes_sent = self.bytes_sent.get(),
            .total_bytes_received = self.bytes_received.get(),
            .total_packets_sent = self.packets_sent.get(),
            .total_packets_received = self.packets_received.get(),
            .active_connections = self.active_connections.get(),
            .error_rate = error_rate,
            .avg_rtt_ms = avg_rtt,
            .memory_usage_mb = @as(f64, @floatFromInt(self.memory_usage.get())) / (1024.0 * 1024.0),
            .cpu_usage_percent = @as(f64, @floatFromInt(self.cpu_usage.get())),
        };
    }
};

fn createLatencyHistogram(allocator: std.mem.Allocator) !*Histogram {
    const buckets = [_]f64{ 0.001, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0 };
    return try Histogram.init(allocator, &buckets);
}

fn createDurationHistogram(allocator: std.mem.Allocator) !*Histogram {
    const buckets = [_]f64{ 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0 };
    return try Histogram.init(allocator, &buckets);
}