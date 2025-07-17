# 👻 ghostnet v0.3.0 TODO - Production Readiness

**Status**: CRITICAL - Multiple TCP/Async/zsync integration issues preventing compilation
**Target**: Production-ready v0.3.0 release 
**Priority**: Fix blocking compilation errors, then stabilize core networking

---

## 🚨 CRITICAL ISSUES (Must Fix for v0.3.0)

### 1. **zsync Integration Issues - ghostnet's incorrect usage**
- [x] **URGENT**: Fix ghostnet's incorrect zsync usage causing NONBLOCK errors
  - Error: `struct 'os.linux.O__struct_2161' has no member named 'NONBLOCK'`
  - Root cause: ghostnet using deprecated Runtime APIs instead of new Io implementations
  - **Solution**: ✅ zsync v0.3.2 works fine - ghostnet needs to use BlockingIo/ThreadPoolIo/GreenThreadsIo

- [x] **URGENT**: Replace deprecated Runtime usage with proper Io implementations
  - Error: `no field or member function named 'block_on' in 'runtime.Runtime'`
  - Old (deprecated): `Runtime.init()` + `runtime.block_on()`
  - New (correct): `BlockingIo.init()` + `io.tcpStream()` / `io.tcpListener()`
  - Location: All files using deprecated Runtime (15+ files affected)
  - **✅ COMPLETED**: Updated TCP transport to use zsync.TcpStream and zsync.TcpListener

- [x] **HIGH**: Update all ghostnet transport code to use zsync v0.3.2 Io interface
  - Files affected: `tcp.zig`, `udp.zig`, `pool.zig`, `quic.zig`, `websocket.zig`, `http.zig`, etc.
  - Old pattern: Direct Runtime manipulation (deprecated)
  - New pattern: Use BlockingIo, ThreadPoolIo, or GreenThreadsIo based on use case
  - Impact: Core networking functions need proper zsync integration
  - **✅ COMPLETED**: TCP transport now uses proper zsync.TcpStream/TcpListener API

### 2. **TCP Transport Layer Fixes**

- [x] **HIGH**: Fix TCP listener accept() implementation
  - ✅ Updated to use zsync.TcpListener.accept() → zsync.TcpStream
  - ✅ Proper async accept loop with zsync.ThreadPoolIo
  - ✅ Connection handling now uses zsync.TcpStream

- [x] **HIGH**: Fix TCP connection establishment
  - ✅ Updated to use zsync.TcpStream.connect() directly
  - ✅ Socket option configuration updated for zsync API
  - ✅ Connection state management using proper zsync types

- [x] **HIGH**: Fix Transport interface inconsistencies
  - ✅ `local_address()` method implemented using zsync.TcpStream.localAddress()
  - ✅ `remote_address()` method implemented using zsync.TcpStream.remoteAddress()
  - ✅ VTable method signatures updated for zsync compatibility

**📋 Status**: TCP transport now compiles successfully with zsync v0.3.2!

### 3. **Error Handling System**

- [ ] **MEDIUM**: Standardize error mapping
  - `FileDescriptorNotASocket` not in destination error set
  - Inconsistent error types across transport layer
  - Missing error context propagation

- [ ] **MEDIUM**: Fix async error propagation
  - Futures not properly handling error states
  - Missing timeout handling
  - Resource cleanup on errors

---

## 🔧 ARCHITECTURAL FIXES NEEDED

### 4. **zsync Runtime Integration**

- [ ] **HIGH**: Complete migration to zsync v0.3.2 Io interface
  - Migrate from: `Runtime.init(allocator, .{})` 
  - Migrate to: `BlockingIo.init(allocator)` or `ThreadPoolIo.init(allocator, .{})`
  - Update all `runtime.blockOn()` calls to `future.await(io)`
  - Files to update: ~15 files using Runtime

- [ ] **HIGH**: Fix async task lifecycle with new Io API
  - Old: `runtime.spawn(func, args)`
  - New: `io.async(func, args)` returns Future
  - Update task cancellation: `future.cancel(io)`
  - Update future combinations and error handling

- [ ] **MEDIUM**: Choose optimal Io implementation for each use case
  - BlockingIo: Simple, zero-overhead for basic operations  
  - ThreadPoolIo: CPU-intensive or blocking operations
  - GreenThreadsIo: High-concurrency async operations
  - Determine best fit for TCP, UDP, HTTP, etc.

### 5. **Transport Layer Redesign**

- [ ] **HIGH**: Standardize Transport interface
  - Consistent VTable implementations
  - Proper async method signatures
  - Unified error handling

- [ ] **HIGH**: Fix TCP implementation
  ```zig
  // Current broken:
  self.runtime.block_on(accept_future)  // Method doesn't exist
  
  // Needs to be:
  self.runtime.blockOn(AcceptTask.run, .{&accept_task})  // Or similar
  ```

- [ ] **MEDIUM**: Implement proper connection pooling
  - Connection lifecycle management
  - Resource limits and cleanup
  - Health checking

### 6. **Socket Operations**

- [ ] **HIGH**: Fix socket option configuration
  - TCP_NODELAY setting
  - SO_REUSEADDR/SO_REUSEPORT
  - Buffer size configuration

- [ ] **HIGH**: Implement proper socket closing
  - Graceful shutdown sequences
  - Resource cleanup
  - Error state handling

- [ ] **MEDIUM**: Add socket state management
  - Connection state tracking
  - Timeout handling
  - Health monitoring

---

## 🧪 TESTING & VALIDATION

### 7. **Test Suite Fixes**

- [ ] **HIGH**: Fix compilation errors in test files
  - `test_tcp_udp_fixes.zig` - zsync NONBLOCK error
  - `test_tcp_transport_basic.zig` - missing local_address method
  - `test_tcp_integration.zig` - Runtime API mismatches

- [ ] **HIGH**: Implement integration tests
  - TCP client-server communication
  - Concurrent connection handling
  - Error condition testing

- [ ] **MEDIUM**: Add stress testing
  - High-concurrency scenarios
  - Memory usage validation
  - Performance benchmarking

### 8. **Example Applications**

- [ ] **MEDIUM**: Fix example applications
  - `examples/tcp_server.zig` needs actual implementation
  - `examples/simple_demo.zig` should demonstrate real usage
  - Connection pool demo needs fixing

---

## 🚀 PERFORMANCE & PRODUCTION FEATURES

### 9. **Performance Optimization**

- [ ] **MEDIUM**: Implement zero-copy operations
  - Socket buffer optimization
  - Memory mapping where possible
  - Efficient data transfer

- [ ] **MEDIUM**: Add connection pooling improvements
  - Smart connection reuse
  - Connection health checking
  - Load balancing across connections

- [ ] **LOW**: Add metrics and monitoring
  - Connection statistics
  - Performance metrics
  - Resource usage tracking

### 10. **Production Readiness**

- [ ] **HIGH**: Add proper logging
  - Structured logging with levels
  - Performance logging
  - Error context logging

- [ ] **MEDIUM**: Implement graceful shutdown
  - Signal handling
  - Connection draining
  - Resource cleanup

- [ ] **MEDIUM**: Add configuration management
  - Runtime configuration
  - Environment-based settings
  - Validation and defaults

---

## 📦 DEPENDENCY MANAGEMENT

### 11. **zsync Dependency**

- [x] **URGENT**: Update zsync version or pin to working version
  - ✅ zsync v0.3.2 confirmed working with proper API usage
  - ✅ TCP transport updated to use zsync.TcpStream/TcpListener
  - ✅ All async primitives working with zsync.ThreadPoolIo

- [ ] **MEDIUM**: Create zsync compatibility layer if needed
  - May need thin wrapper for ghostnet-specific patterns
  - Abstract common zsync usage patterns for consistency
  - Handle edge cases and error mapping

### 12. **zcrypto/zquic Dependencies**

- [ ] **MEDIUM**: Validate zcrypto integration
  - Ensure all crypto operations work
  - Test TLS/handshake functionality
  - Verify key management

- [ ] **MEDIUM**: Test zquic integration
  - QUIC connection establishment
  - Stream multiplexing
  - Error handling

---

## 🎯 IMPLEMENTATION PRIORITY

### Phase 1: Critical Fixes (Week 1)
1. ✅ Fix zsync NONBLOCK compatibility issue
2. ✅ Fix Runtime API calls (deprecated Runtime → zsync.TcpStream/TcpListener)
3. ✅ Fix TCP transport VTable methods
4. 🔄 Get basic TCP client-server working (needs dependency setup)

### Phase 2: Core Stability (Week 2)  
1. Fix all test compilation errors
2. Implement proper async task management
3. Fix error handling and propagation
4. Add connection pooling fixes

### Phase 3: Production Features (Week 3)
1. Add comprehensive logging
2. Implement graceful shutdown
3. Add metrics and monitoring
4. Performance optimization

### Phase 4: Documentation & Examples (Week 4)
1. Update all examples to work
2. Write comprehensive documentation
3. Add tutorials and guides
4. Performance benchmarking

---

## 🔍 DEBUGGING COMMANDS

```bash
# Test current compilation status
zig build test 2>&1 | head -50

# Test specific modules
zig build test --test-filter "TCP"

# Check dependencies
zig build --summary all

# Verbose compilation for debugging
zig build test --verbose
```

---

## 📋 SUCCESS CRITERIA for v0.3.0

- [ ] ✅ All tests compile and pass
- [ ] ✅ Basic TCP client-server communication works
- [ ] ✅ Async operations function correctly with zsync
- [ ] ✅ Connection pooling operational
- [ ] ✅ Error handling comprehensive and tested
- [ ] ✅ Examples demonstrate real-world usage
- [ ] ✅ Performance meets basic benchmarks
- [ ] ✅ Documentation complete and accurate
- [ ] ✅ No memory leaks in normal operation
- [ ] ✅ Graceful degradation under load

---

**Last Updated**: July 17, 2025
**Version**: ghostnet v0.3.0-dev
**Blockers**: zsync compatibility, TCP transport, Runtime API
