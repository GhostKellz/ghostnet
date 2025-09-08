//! MQTT - Message Queuing Telemetry Transport
//! Lightweight publish/subscribe messaging protocol for IoT and telemetry

const std = @import("std");
const zsync = @import("zsync");
const transport = @import("../transport/transport.zig");
const tcp = @import("../transport/tcp.zig");
const errors = @import("../errors/errors.zig");

/// MQTT protocol version
pub const ProtocolVersion = enum(u8) {
    v3_1 = 3,
    v3_1_1 = 4,
    v5_0 = 5,
};

/// MQTT message types
pub const MessageType = enum(u4) {
    CONNECT = 1,
    CONNACK = 2,
    PUBLISH = 3,
    PUBACK = 4,
    PUBREC = 5,
    PUBREL = 6,
    PUBCOMP = 7,
    SUBSCRIBE = 8,
    SUBACK = 9,
    UNSUBSCRIBE = 10,
    UNSUBACK = 11,
    PINGREQ = 12,
    PINGRESP = 13,
    DISCONNECT = 14,
    AUTH = 15, // MQTT v5.0 only
};

/// MQTT Quality of Service levels
pub const QoS = enum(u2) {
    at_most_once = 0,
    at_least_once = 1,
    exactly_once = 2,
};

/// MQTT connection options
pub const ConnectOptions = struct {
    client_id: []const u8,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    keep_alive: u16 = 60,
    clean_session: bool = true,
    will_topic: ?[]const u8 = null,
    will_message: ?[]const u8 = null,
    will_qos: QoS = .at_most_once,
    will_retain: bool = false,
    protocol_version: ProtocolVersion = .v3_1_1,
};

/// MQTT message
pub const Message = struct {
    topic: []const u8,
    payload: []const u8,
    qos: QoS,
    retain: bool,
    duplicate: bool = false,
    
    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        allocator.free(self.topic);
        allocator.free(self.payload);
    }
};

/// MQTT packet header
const FixedHeader = struct {
    message_type: MessageType,
    dup: bool,
    qos: QoS,
    retain: bool,
    remaining_length: u32,
    
    fn encode(self: FixedHeader, writer: anytype) !void {
        const first_byte = (@intFromEnum(self.message_type) << 4) |
            (@as(u8, if (self.dup) 1 else 0) << 3) |
            (@as(u8, @intFromEnum(self.qos)) << 1) |
            @as(u8, if (self.retain) 1 else 0);
        
        try writer.writeByte(first_byte);
        try encodeRemainingLength(writer, self.remaining_length);
    }
    
    fn decode(reader: anytype) !FixedHeader {
        const first_byte = try reader.readByte();
        const message_type = @as(MessageType, @enumFromInt((first_byte >> 4) & 0xF));
        const dup = (first_byte & 0x08) != 0;
        const qos = @as(QoS, @enumFromInt((first_byte >> 1) & 0x03));
        const retain = (first_byte & 0x01) != 0;
        
        const remaining_length = try decodeRemainingLength(reader);
        
        return FixedHeader{
            .message_type = message_type,
            .dup = dup,
            .qos = qos,
            .retain = retain,
            .remaining_length = remaining_length,
        };
    }
};

fn encodeRemainingLength(writer: anytype, length: u32) !void {
    var len = length;
    while (len > 127) {
        try writer.writeByte(@intCast((len & 0x7F) | 0x80));
        len >>= 7;
    }
    try writer.writeByte(@intCast(len & 0x7F));
}

fn decodeRemainingLength(reader: anytype) !u32 {
    var length: u32 = 0;
    var multiplier: u32 = 1;
    var byte: u8 = 0;
    
    while (true) {
        byte = try reader.readByte();
        length += (byte & 0x7F) * multiplier;
        
        if ((byte & 0x80) == 0) break;
        
        multiplier *= 128;
        if (multiplier > 128 * 128 * 128) {
            return error.InvalidRemainingLength;
        }
    }
    
    return length;
}

fn encodeString(writer: anytype, string: []const u8) !void {
    try writer.writeInt(u16, @intCast(string.len), .big);
    try writer.writeAll(string);
}

fn decodeString(reader: anytype, allocator: std.mem.Allocator) ![]u8 {
    const length = try reader.readInt(u16, .big);
    var string = try allocator.alloc(u8, length);
    _ = try reader.readAll(string);
    return string;
}

/// MQTT client for pub/sub messaging
pub const MqttClient = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    connection: ?transport.Connection,
    options: ConnectOptions,
    connected: bool,
    packet_id: u16,
    subscriptions: std.StringHashMap(QoS),
    message_handlers: std.StringHashMap(*const fn (Message) void),
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, options: ConnectOptions) !*MqttClient {
        var client = try allocator.create(MqttClient);
        client.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .connection = null,
            .options = options,
            .connected = false,
            .packet_id = 1,
            .subscriptions = std.StringHashMap(QoS).init(allocator),
            .message_handlers = std.StringHashMap(*const fn (Message) void).init(allocator),
        };
        return client;
    }
    
    pub fn deinit(self: *MqttClient) void {
        if (self.connected) {
            self.disconnect() catch {};
        }
        
        var sub_it = self.subscriptions.iterator();
        while (sub_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.subscriptions.deinit();
        
        var handler_it = self.message_handlers.iterator();
        while (handler_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.message_handlers.deinit();
        
        self.allocator.destroy(self);
    }
    
    pub fn connect(self: *MqttClient, address: transport.Address, port: u16) !void {
        // Create TCP connection
        var tcp_transport = try tcp.TcpTransport.init(self.allocator, self.runtime);
        defer tcp_transport.deinit();
        
        const tcp_address = switch (address) {
            .ipv4 => |addr| transport.Address{ .ipv4 = std.net.Ip4Address.init(.{ addr.host[0], addr.host[1], addr.host[2], addr.host[3] }, port) },
            .ipv6 => |addr| transport.Address{ .ipv6 = std.net.Ip6Address.init(addr.host, port, 0, 0) },
            else => return error.InvalidAddress,
        };
        
        self.connection = try tcp_transport.connectAsync(tcp_address, .{}).get();
        
        // Send CONNECT packet
        try self.sendConnect();
        
        // Wait for CONNACK
        const connack = try self.receiveConnack();
        if (connack != 0) {
            return error.ConnectionRefused;
        }
        
        self.connected = true;
        
        // Start message processing loop
        _ = zsync.spawn(self.messageLoop, .{});
    }
    
    pub fn disconnect(self: *MqttClient) !void {
        if (!self.connected) return;
        
        // Send DISCONNECT packet
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        const header = FixedHeader{
            .message_type = .DISCONNECT,
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .remaining_length = 0,
        };
        
        try header.encode(buffer.writer());
        
        if (self.connection) |conn| {
            _ = try conn.writeAsync(buffer.items).get();
            conn.close();
            self.connection = null;
        }
        
        self.connected = false;
    }
    
    pub fn publish(self: *MqttClient, topic: []const u8, payload: []const u8, qos: QoS, retain: bool) !void {
        if (!self.connected) return error.NotConnected;
        
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        // Calculate remaining length
        const remaining_length = 2 + topic.len + // Topic length + topic
            (if (qos != .at_most_once) 2 else 0) + // Packet ID for QoS > 0
            payload.len; // Payload
        
        const header = FixedHeader{
            .message_type = .PUBLISH,
            .dup = false,
            .qos = qos,
            .retain = retain,
            .remaining_length = @intCast(remaining_length),
        };
        
        try header.encode(buffer.writer());
        try encodeString(buffer.writer(), topic);
        
        // Add packet ID for QoS > 0
        if (qos != .at_most_once) {
            try buffer.writer().writeInt(u16, self.packet_id, .big);
            self.packet_id += 1;
        }
        
        try buffer.writer().writeAll(payload);
        
        if (self.connection) |conn| {
            _ = try conn.writeAsync(buffer.items).get();
        }
    }
    
    pub fn subscribe(self: *MqttClient, topic: []const u8, qos: QoS, handler: *const fn (Message) void) !void {
        if (!self.connected) return error.NotConnected;
        
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        const remaining_length = 2 + // Packet ID
            2 + topic.len + 1; // Topic filter length + topic + QoS
        
        const header = FixedHeader{
            .message_type = .SUBSCRIBE,
            .dup = false,
            .qos = .at_least_once, // SUBSCRIBE must use QoS 1
            .retain = false,
            .remaining_length = @intCast(remaining_length),
        };
        
        try header.encode(buffer.writer());
        try buffer.writer().writeInt(u16, self.packet_id, .big);
        self.packet_id += 1;
        
        try encodeString(buffer.writer(), topic);
        try buffer.writer().writeByte(@intFromEnum(qos));
        
        // Store subscription
        const owned_topic = try self.allocator.dupe(u8, topic);
        try self.subscriptions.put(owned_topic, qos);
        try self.message_handlers.put(owned_topic, handler);
        
        if (self.connection) |conn| {
            _ = try conn.writeAsync(buffer.items).get();
        }
    }
    
    pub fn unsubscribe(self: *MqttClient, topic: []const u8) !void {
        if (!self.connected) return error.NotConnected;
        
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        const remaining_length = 2 + // Packet ID
            2 + topic.len; // Topic filter length + topic
        
        const header = FixedHeader{
            .message_type = .UNSUBSCRIBE,
            .dup = false,
            .qos = .at_least_once, // UNSUBSCRIBE must use QoS 1
            .retain = false,
            .remaining_length = @intCast(remaining_length),
        };
        
        try header.encode(buffer.writer());
        try buffer.writer().writeInt(u16, self.packet_id, .big);
        self.packet_id += 1;
        
        try encodeString(buffer.writer(), topic);
        
        // Remove subscription
        if (self.subscriptions.fetchRemove(topic)) |entry| {
            self.allocator.free(entry.key);
        }
        if (self.message_handlers.fetchRemove(topic)) |entry| {
            self.allocator.free(entry.key);
        }
        
        if (self.connection) |conn| {
            _ = try conn.writeAsync(buffer.items).get();
        }
    }
    
    fn sendConnect(self: *MqttClient) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        // Protocol name and version
        const protocol_name = switch (self.options.protocol_version) {
            .v3_1 => "MQIsdp",
            .v3_1_1 => "MQTT",
            .v5_0 => "MQTT",
        };
        
        var payload_length: u32 = 2 + self.options.client_id.len;
        
        if (self.options.will_topic) |will_topic| {
            payload_length += 2 + will_topic.len;
            if (self.options.will_message) |will_message| {
                payload_length += 2 + will_message.len;
            }
        }
        
        if (self.options.username) |username| {
            payload_length += 2 + username.len;
            if (self.options.password) |password| {
                payload_length += 2 + password.len;
            }
        }
        
        const remaining_length = 2 + protocol_name.len + // Protocol name
            1 + // Protocol version
            1 + // Connect flags
            2 + // Keep alive
            payload_length;
        
        const header = FixedHeader{
            .message_type = .CONNECT,
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .remaining_length = @intCast(remaining_length),
        };
        
        try header.encode(buffer.writer());
        try encodeString(buffer.writer(), protocol_name);
        try buffer.writer().writeByte(@intFromEnum(self.options.protocol_version));
        
        // Connect flags
        var flags: u8 = 0;
        if (self.options.clean_session) flags |= 0x02;
        if (self.options.will_topic != null) {
            flags |= 0x04;
            flags |= (@as(u8, @intFromEnum(self.options.will_qos)) << 3);
            if (self.options.will_retain) flags |= 0x20;
        }
        if (self.options.password != null) flags |= 0x40;
        if (self.options.username != null) flags |= 0x80;
        
        try buffer.writer().writeByte(flags);
        try buffer.writer().writeInt(u16, self.options.keep_alive, .big);
        
        // Payload
        try encodeString(buffer.writer(), self.options.client_id);
        
        if (self.options.will_topic) |will_topic| {
            try encodeString(buffer.writer(), will_topic);
            if (self.options.will_message) |will_message| {
                try encodeString(buffer.writer(), will_message);
            }
        }
        
        if (self.options.username) |username| {
            try encodeString(buffer.writer(), username);
            if (self.options.password) |password| {
                try encodeString(buffer.writer(), password);
            }
        }
        
        if (self.connection) |conn| {
            _ = try conn.writeAsync(buffer.items).get();
        }
    }
    
    fn receiveConnack(self: *MqttClient) !u8 {
        var buffer: [4]u8 = undefined;
        
        if (self.connection) |conn| {
            _ = try conn.readAsync(&buffer).get();
        }
        
        const header = FixedHeader{
            .message_type = @enumFromInt((buffer[0] >> 4) & 0xF),
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .remaining_length = buffer[1],
        };
        
        if (header.message_type != .CONNACK or header.remaining_length != 2) {
            return error.InvalidConnack;
        }
        
        // buffer[2] is session present flag, buffer[3] is return code
        return buffer[3];
    }
    
    fn messageLoop(self: *MqttClient) void {
        while (self.connected) {
            self.processMessage() catch |err| switch (err) {
                error.ConnectionClosed => break,
                else => continue,
            };
        }
    }
    
    fn processMessage(self: *MqttClient) !void {
        if (self.connection == null) return error.ConnectionClosed;
        
        var header_buffer: [1]u8 = undefined;
        _ = try self.connection.?.readAsync(&header_buffer).get();
        
        const message_type = @as(MessageType, @enumFromInt((header_buffer[0] >> 4) & 0xF));
        
        switch (message_type) {
            .PUBLISH => try self.handlePublish(),
            .PINGREQ => try self.handlePingRequest(),
            .PINGRESP => {}, // Ping response, nothing to do
            else => {}, // Other message types not implemented
        }
    }
    
    fn handlePublish(self: *MqttClient) !void {
        // Read remaining length
        const remaining_length = try self.readRemainingLength();
        
        // Read variable header and payload
        var data = try self.allocator.alloc(u8, remaining_length);
        defer self.allocator.free(data);
        
        if (self.connection) |conn| {
            _ = try conn.readAsync(data).get();
        }
        
        var stream = std.io.fixedBufferStream(data);
        
        // Read topic
        const topic = try decodeString(stream.reader(), self.allocator);
        defer self.allocator.free(topic);
        
        // Read packet ID if QoS > 0 (we'd need to parse the fixed header properly)
        // For simplicity, assuming QoS 0 messages
        
        // Remaining data is payload
        const payload_start = stream.pos;
        const payload = data[payload_start..];
        
        // Find matching handler
        var handler_it = self.message_handlers.iterator();
        while (handler_it.next()) |entry| {
            if (self.topicMatches(entry.key_ptr.*, topic)) {
                const message = Message{
                    .topic = topic,
                    .payload = payload,
                    .qos = .at_most_once, // Simplified
                    .retain = false,
                    .duplicate = false,
                };
                
                entry.value_ptr.*(message);
                break;
            }
        }
    }
    
    fn handlePingRequest(self: *MqttClient) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        const header = FixedHeader{
            .message_type = .PINGRESP,
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .remaining_length = 0,
        };
        
        try header.encode(buffer.writer());
        
        if (self.connection) |conn| {
            _ = try conn.writeAsync(buffer.items).get();
        }
    }
    
    fn readRemainingLength(self: *MqttClient) !u32 {
        var length: u32 = 0;
        var multiplier: u32 = 1;
        var byte_buffer: [1]u8 = undefined;
        
        while (true) {
            if (self.connection) |conn| {
                _ = try conn.readAsync(&byte_buffer).get();
            }
            
            const byte = byte_buffer[0];
            length += (byte & 0x7F) * multiplier;
            
            if ((byte & 0x80) == 0) break;
            
            multiplier *= 128;
            if (multiplier > 128 * 128 * 128) {
                return error.InvalidRemainingLength;
            }
        }
        
        return length;
    }
    
    fn topicMatches(self: *MqttClient, pattern: []const u8, topic: []const u8) bool {
        _ = self;
        // Simplified topic matching - exact match only
        // Full implementation would support wildcards (+ and #)
        return std.mem.eql(u8, pattern, topic);
    }
};

/// MQTT broker for message routing
pub const MqttBroker = struct {
    allocator: std.mem.Allocator,
    runtime: *zsync.Runtime,
    listener: ?transport.Listener,
    clients: std.ArrayList(*ClientSession),
    subscriptions: std.StringHashMap(std.ArrayList(*ClientSession)),
    running: bool,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) !*MqttBroker {
        var broker = try allocator.create(MqttBroker);
        broker.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .listener = null,
            .clients = std.ArrayList(*ClientSession).init(allocator),
            .subscriptions = std.StringHashMap(std.ArrayList(*ClientSession)).init(allocator),
            .running = false,
        };
        return broker;
    }
    
    pub fn deinit(self: *MqttBroker) void {
        if (self.running) {
            self.stop();
        }
        
        for (self.clients.items) |client| {
            client.deinit();
            self.allocator.destroy(client);
        }
        self.clients.deinit();
        
        var sub_it = self.subscriptions.iterator();
        while (sub_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.subscriptions.deinit();
        
        self.allocator.destroy(self);
    }
    
    pub fn listen(self: *MqttBroker, address: transport.Address, port: u16) !void {
        var tcp_transport = try tcp.TcpTransport.init(self.allocator, self.runtime);
        defer tcp_transport.deinit();
        
        var tcp_listener = try tcp.TcpListener.init(self.allocator, self.runtime);
        
        const tcp_address = switch (address) {
            .ipv4 => |addr| transport.Address{ .ipv4 = std.net.Ip4Address.init(.{ addr.host[0], addr.host[1], addr.host[2], addr.host[3] }, port) },
            .ipv6 => |addr| transport.Address{ .ipv6 = std.net.Ip6Address.init(addr.host, port, 0, 0) },
            else => return error.InvalidAddress,
        };
        
        try tcp_listener.bind(tcp_address, .{});
        self.listener = tcp_listener.listener();
        self.running = true;
        
        while (self.running) {
            const connection = self.listener.?.acceptAsync().get() catch continue;
            
            const client_session = try ClientSession.init(self.allocator, connection, self);
            try self.clients.append(client_session);
            
            _ = zsync.spawn(client_session.handle, .{});
        }
    }
    
    pub fn stop(self: *MqttBroker) void {
        self.running = false;
        if (self.listener) |listener| {
            listener.close();
        }
    }
    
    fn addSubscription(self: *MqttBroker, topic: []const u8, client: *ClientSession) !void {
        if (self.subscriptions.getPtr(topic)) |clients| {
            try clients.append(client);
        } else {
            var clients = std.ArrayList(*ClientSession).init(self.allocator);
            try clients.append(client);
            const owned_topic = try self.allocator.dupe(u8, topic);
            try self.subscriptions.put(owned_topic, clients);
        }
    }
    
    fn removeSubscription(self: *MqttBroker, topic: []const u8, client: *ClientSession) void {
        if (self.subscriptions.getPtr(topic)) |clients| {
            for (clients.items, 0..) |c, i| {
                if (c == client) {
                    _ = clients.orderedRemove(i);
                    break;
                }
            }
        }
    }
    
    fn publishMessage(self: *MqttBroker, topic: []const u8, payload: []const u8, qos: QoS, retain: bool) !void {
        if (self.subscriptions.get(topic)) |clients| {
            for (clients.items) |client| {
                try client.sendPublish(topic, payload, qos, retain);
            }
        }
    }
};

/// Client session for broker
const ClientSession = struct {
    allocator: std.mem.Allocator,
    connection: transport.Connection,
    broker: *MqttBroker,
    client_id: ?[]u8,
    subscriptions: std.StringHashMap(QoS),
    
    fn init(allocator: std.mem.Allocator, connection: transport.Connection, broker: *MqttBroker) !*ClientSession {
        var session = try allocator.create(ClientSession);
        session.* = .{
            .allocator = allocator,
            .connection = connection,
            .broker = broker,
            .client_id = null,
            .subscriptions = std.StringHashMap(QoS).init(allocator),
        };
        return session;
    }
    
    fn deinit(self: *ClientSession) void {
        if (self.client_id) |client_id| {
            self.allocator.free(client_id);
        }
        
        var sub_it = self.subscriptions.iterator();
        while (sub_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.subscriptions.deinit();
        
        self.connection.close();
    }
    
    fn handle(self: *ClientSession) void {
        while (true) {
            self.processMessage() catch break;
        }
        
        self.deinit();
    }
    
    fn processMessage(self: *ClientSession) !void {
        // Similar to client implementation but handles broker-side logic
        // This is a simplified version - full implementation would handle
        // CONNECT, PUBLISH, SUBSCRIBE, UNSUBSCRIBE, DISCONNECT, etc.
        _ = self;
        return error.NotImplemented;
    }
    
    fn sendPublish(self: *ClientSession, topic: []const u8, payload: []const u8, qos: QoS, retain: bool) !void {
        _ = self;
        _ = topic;
        _ = payload;
        _ = qos;
        _ = retain;
        // Implementation would format and send PUBLISH packet
        return error.NotImplemented;
    }
};