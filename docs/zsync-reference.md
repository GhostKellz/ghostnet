# zsync Async Runtime Reference

## Core Design Philosophy
- Inspired by Tokio, optimized for Zig's zero-cost abstractions and manual memory control
- Modular async runtime for event-driven applications

## Key Architectural Components

### 1. Task Executor
- Supports spawn, yield, await operations
- Configurable per-core event loop

### 2. Networking Primitives
- Non-blocking I/O for TCP, UDP, with planned QUIC support
- Integrates with Zig's native async/await mechanisms
- Waker API integrates with Zig's async/await and `@asyncCall`

### 3. Example Async Pattern
```zig
try zsync.runtime.run(async {
    const tcp = try zsync.net.TcpStream.connect("127.0.0.1", 8080);
    try tcp.writeAll("ping");
    const buf = try tcp.readAll();
    std.debug.print("received: {}\n", .{buf});
});
```

### 4. Unique Features
- Composable futures with polling capabilities
- Pluggable I/O backends (epoll, kqueue, planned io_uring)
- Channel system with Sender/Receiver patterns

## Integration Notes for ghostnet
- Use zsync.runtime for the core event loop
- Leverage zsync.net primitives for base TCP/UDP implementation
- Build protocol layers on top of zsync's async I/O
- Use channel system for internal message passing between components