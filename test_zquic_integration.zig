const std = @import("std");
const testing = std.testing;
const ghostnet = @import("ghostnet");
const zsync = @import("zsync");

test "zquic integration - config validation" {
    const config = ghostnet.QuicConfig{
        .max_streams = 1000,
        .max_stream_data = 1024 * 1024,
        .max_connection_data = 10 * 1024 * 1024,
        .idle_timeout = 30000,
        .keep_alive_interval = 5000,
        .max_ack_delay = 25,
        .ack_delay_exponent = 3,
        .max_packet_size = 1200,
        .initial_rtt = 100,
        .congestion_window = 10,
        .enable_0rtt = false,
        .enable_migration = true,
        .certificate_file = null,
        .private_key_file = null,
        .alpn_protocols = &[_][]const u8{"h3"},
    };

    // Test that config fields are accessible and correct
    try testing.expect(config.max_streams == 1000);
    try testing.expect(config.max_stream_data == 1024 * 1024);
    try testing.expect(config.idle_timeout == 30000);
    try testing.expect(config.enable_0rtt == false);
    try testing.expect(config.enable_migration == true);
    try testing.expect(config.alpn_protocols.len == 1);
    try testing.expect(std.mem.eql(u8, config.alpn_protocols[0], "h3"));
}

test "zquic integration - quic types exist" {
    // Test that all QUIC types are properly exported
    const QuicConnection = ghostnet.QuicConnection;
    const QuicConfig = ghostnet.QuicConfig;
    const QuicStream = ghostnet.QuicStream;
    const QuicServer = ghostnet.QuicServer;
    const QuicClient = ghostnet.QuicClient;
    
    // Basic type assertions
    try testing.expect(@TypeOf(QuicConnection) == type);
    try testing.expect(@TypeOf(QuicConfig) == type);
    try testing.expect(@TypeOf(QuicStream) == type);
    try testing.expect(@TypeOf(QuicServer) == type);
    try testing.expect(@TypeOf(QuicClient) == type);
}

test "zquic integration - transport types exist" {
    // Test that transport types are properly exported
    const Address = ghostnet.transport.Address;
    const Connection = ghostnet.transport.Connection;
    const Transport = ghostnet.transport.Transport;
    
    // Basic type assertions
    try testing.expect(@TypeOf(Address) == type);
    try testing.expect(@TypeOf(Connection) == type);
    try testing.expect(@TypeOf(Transport) == type);
}