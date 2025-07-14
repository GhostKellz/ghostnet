const std = @import("std");

pub const transport = @import("transport/transport.zig");
pub const tcp = @import("transport/tcp.zig");
pub const udp = @import("transport/udp.zig");
pub const pool = @import("transport/pool.zig");
pub const errors = @import("errors/errors.zig");
pub const protocols = @import("protocols/protocol.zig");
pub const quic = @import("protocols/quic.zig");
pub const wireguard = @import("protocols/wireguard.zig");
pub const websocket = @import("protocols/websocket.zig");
pub const http = @import("protocols/http.zig");
pub const handshake = @import("crypto/handshake.zig");
pub const gossip = @import("p2p/gossip.zig");
pub const kademlia = @import("p2p/kademlia.zig");
pub const mdns = @import("p2p/mdns.zig");

pub const zsync = @import("zsync");
pub const zcrypto = @import("zcrypto");
pub const zquic = @import("zquic");

pub const Transport = transport.Transport;
pub const Connection = transport.Connection;
pub const Stream = transport.Stream;
pub const Listener = transport.Listener;
pub const Address = transport.Address;
pub const TransportOptions = transport.TransportOptions;
pub const TransportError = transport.TransportError;

pub const TcpTransport = tcp.TcpTransport;
pub const TcpListener = tcp.TcpListener;
pub const TcpConnection = tcp.TcpConnection;

pub const UdpSocket = udp.UdpSocket;
pub const UdpPacket = udp.UdpPacket;

pub const ConnectionPool = pool.ConnectionPool;
pub const PoolConfig = pool.PoolConfig;

pub const ProtocolRegistry = protocols.ProtocolRegistry;
pub const ProtocolHandler = protocols.ProtocolHandler;
pub const Message = protocols.Message;

pub const QuicConnection = quic.QuicConnection;
pub const QuicServer = quic.QuicServer;
pub const QuicClient = quic.QuicClient;
pub const QuicStream = quic.QuicStream;

pub const WireGuardTunnel = wireguard.WireGuardTunnel;
pub const WireGuardConfig = wireguard.WireGuardConfig;
pub const Peer = wireguard.Peer;

pub const GhostnetError = errors.GhostnetError;
pub const ErrorContext = errors.ErrorContext;
pub const Result = errors.Result;

test {
    std.testing.refAllDecls(@This());
}