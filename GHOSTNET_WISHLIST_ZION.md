# GhostNet Wishlist for Zion

## Current Networking Needs
- HTTP/HTTPS requests to multiple registries (GitHub, Zigistry, Zeppelin)
- Parallel downloads with connection pooling
- Package verification via cryptographic signatures

## Desired Features

### 1. Advanced HTTP Client
- HTTP/2 and HTTP/3 support for faster registry communication
- Smart retry logic with exponential backoff
- Connection pooling with registry-specific optimizations

### 2. Resilient Download Management
- Multipath connections for large packages
- Resume capability for interrupted downloads
- Automatic mirror fallback for failed registry connections

## Impact
- 2x+ faster package downloads via HTTP/2 multiplexing
- More reliable package management in poor network conditions  
- Better registry availability through smart fallback mechanisms