# 👻 ghostnet

[![Platform: Zig v0.15+](https://img.shields.io/badge/zig-v0.15%2B-f7a41d?logo=zig\&logoColor=white)](https://ziglang.org/)
[![Async by zsync](https://img.shields.io/badge/async-zsync%20runtime-blue?logo=zig\&logoColor=white)](https://github.com/ghostkellz/zsync)
[![Next-Gen Networking](https://img.shields.io/badge/next--gen-networking-informational)]()
[![QUIC-Ready](https://img.shields.io/badge/transport-QUIC-green?logo=quic)]()
[![WireGuard-Ready](https://img.shields.io/badge/vpn-wireguard-critical)]()
[![Crypto-Native](https://img.shields.io/badge/crypto-zcrypto-important?logo=keybase)]()

---

> **ghostnet** is the async-native, next-gen networking framework for Zig.
> Peer-to-peer, mesh, VPN, and secure communication for the modern era—built on [zsync](https://github.com/ghostkellz/zsync) and the latest Zig async/await model.

---

## 🚀 Features

* **Fully Async Networking**: All sockets, streams, protocols, and messaging use zsync for high-performance, colorblind async.
* **Multi-Protocol, Extensible Core:**

  * **TCP/UDP** (advanced options, zero-copy, NAT)
  * **QUIC** (secure, multiplexed)
  * **WireGuard** (async VPN, NAT traversal)
  * **TLS 1.3/Noise** (secure streams, handshake)
  * **WebSockets** (async message streaming)
  * **HTTP/1.1, HTTP/2, HTTP/3**
  * **Multipath TCP** (resilient failover, link aggregation)
* **Mesh, P2P, and Gossip:**

  * **Gossip protocols** (async pubsub, real-time messaging)
  * **Kademlia DHT** (decentralized lookup)
  * **mDNS/STUN/TURN/ICE** (peer and service discovery, NAT traversal)
* **Crypto-Native:**

  * [zcrypto](https://github.com/ghostkellz/zcrypto) integration for all encryption, Noise, PKI, key exchange
* **Plug-in Friendly:**

  * Easily add MQTT, CoAP, SRTP, Cap’n Proto, or custom protocols
  * Async RPC and message buses
* **Dev-First:**

  * Zig v0.15+ codebase, no C glue, fully type-safe, modern error handling

---

## 🌐 Protocol & Module Roadmap

**Transports**

* TCP, UDP
* QUIC
* WebSockets
* Multipath TCP

**Security**

* TLS 1.3
* WireGuard (ghostwire)
* Noise Protocol

**P2P & Mesh**

* Gossip pubsub
* Kademlia DHT
* mDNS
* STUN/TURN/ICE

**Web**

* HTTP/1.1, HTTP/2, HTTP/3 (over QUIC)

**IoT/Advanced (future):**

* CoAP, MQTT, SRTP/DTLS, Cap’n Proto

---

## 🏗️ Example: Minimal Async TCP Listener

```zig
const ghostnet = @import("ghostnet");

// Create async TCP listener (IPv4/6)
var listener = try ghostnet.TcpListener.init(.{ .address = "::", .port = 8000 }, allocator);
while (true) {
    var conn = try listener.acceptAsync();
    _ = try ghostnet.spawn(handleConnection, .{conn});
}
```

---

## 🔌 Extending ghostnet

* **Protocols:** Implement `ghostnet.Protocol`, register in the runtime
* **Transports:** Add a new transport, async all the way
* **Gossip:** Use built-in or custom pubsub for distributed messaging

---

## 🚧 Coming Soon

* More advanced QUIC, WireGuard, and HTTP3 examples
* Complete Mesh networking demo with live gossip
* Zero-copy packet path, full zcrypto handshake flows
* Benchmarks: async vs sync, throughput, and latency

---

## 🌟 Vision

`ghostnet` is the definitive async-native networking platform for Zig — supporting:

* Secure VPN, mesh, and P2P
* Real-time messaging and gossip
* Modern web and IoT protocols
* Direct crypto and blockchain integration

*Powering the next wave of decentralized, privacy-first, high-performance networks in Zig.*

