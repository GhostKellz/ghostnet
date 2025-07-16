🛠️ ghostnet v0.1.0 TODO

A focused checklist for launching ghostnet – the async-native, next-gen Zig networking framework.
🚩 MVP Milestones

Async Core Foundation & etc

TCP/UDP async socket abstraction (zsync-powered)

Runtime/init, unified error model

Connection pool and stream traits

    Allocator integration

Protocol Integrations

QUIC transport (minimal client/server)

WireGuard VPN (skeleton, handshake, basic crypto)

TLS/Noise handshake module (pluggable for streams)

    WebSockets async framing

Mesh & P2P

Gossip protocol (async pubsub, simple topic join)

Kademlia DHT (basic node lookup/announce)

    mDNS/ICE for local peer discovery

Crypto Integration

zcrypto handshake and secure key exchange

In-stream encryption/decryption

    PKI for node identity

Plug-in Protocols

Minimal MQTT and CoAP skeletons (show plug-in path)

    Async RPC stub

Dev UX

Complete build.zig, versioned modules, Zig 0.15+ only

100% zsync async/await pattern for all network ops

Allocator/arena management

Examples: minimal TCP, QUIC, gossip node

    First real-world mesh demo (local network pubsub)

Docs & Demos

MVP README updates (examples, protocol table)

Inline Zig doc comments for all pub APIs

        Demo video/gif: live mesh + pubsub

🧠 Design/Architecture

Core transport traits/interfaces

Protocol registration system

Message/event bus async plumbing

Packet/frame structure (zero-copy support)

    Error propagation patterns

🌟 Stretch Goals

Multipath TCP demo

Benchmarks: throughput, connection scaling

WASM/stackless async minimal build

QUIC/HTTP3 echo server example

    VPN mesh relay proof-of-concept

Focus on clean, idiomatic Zig and next-gen async. Ship the core MVP, then iterate on protocol and mesh extensibility!

