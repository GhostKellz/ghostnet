//! gRPC - High Performance, Open Source Universal RPC Framework
//! Implementation over HTTP/2 with protobuf serialization

const std = @import("std");
const zsync = @import("zsync");
const http2 = @import("http2.zig");
const hpack = @import("hpack.zig");
const transport = @import("../transport/transport.zig");
const errors = @import("../errors/errors.zig");

/// gRPC status codes (RFC 6838)
pub const StatusCode = enum(u32) {
    OK = 0,
    CANCELLED = 1,
    UNKNOWN = 2,
    INVALID_ARGUMENT = 3,
    DEADLINE_EXCEEDED = 4,
    NOT_FOUND = 5,
    ALREADY_EXISTS = 6,
    PERMISSION_DENIED = 7,
    RESOURCE_EXHAUSTED = 8,
    FAILED_PRECONDITION = 9,
    ABORTED = 10,
    OUT_OF_RANGE = 11,
    UNIMPLEMENTED = 12,
    INTERNAL = 13,
    UNAVAILABLE = 14,
    DATA_LOSS = 15,
    UNAUTHENTICATED = 16,
};

/// gRPC method types
pub const MethodType = enum {
    unary,
    client_streaming,
    server_streaming,
    bidirectional_streaming,
};

/// gRPC message frame
pub const MessageFrame = struct {
    compressed: bool,
    length: u32,
    data: []const u8,
    
    pub fn encode(self: MessageFrame, allocator: std.mem.Allocator) ![]u8 {
        var frame = try allocator.alloc(u8, 5 + self.data.len);
        frame[0] = if (self.compressed) 1 else 0;
        std.mem.writeInt(u32, frame[1..5], self.length, .big);
        @memcpy(frame[5..], self.data);
        return frame;
    }
    
    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !MessageFrame {
        if (data.len < 5) return error.InvalidFrameSize;
        
        const compressed = data[0] != 0;
        const length = std.mem.readInt(u32, data[1..5], .big);
        
        if (data.len < 5 + length) return error.InsufficientData;
        
        const message_data = try allocator.dupe(u8, data[5..5 + length]);
        
        return MessageFrame{
            .compressed = compressed,
            .length = length,
            .data = message_data,
        };
    }
};

/// gRPC metadata (headers)
pub const Metadata = struct {
    headers: std.StringHashMap([]const u8),
    
    pub fn init(allocator: std.mem.Allocator) Metadata {
        return .{
            .headers = std.StringHashMap([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *Metadata) void {
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            self.headers.allocator.free(entry.key_ptr.*);
            self.headers.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
    }
    
    pub fn set(self: *Metadata, key: []const u8, value: []const u8) !void {
        const owned_key = try self.headers.allocator.dupe(u8, key);
        const owned_value = try self.headers.allocator.dupe(u8, value);
        try self.headers.put(owned_key, owned_value);
    }
    
    pub fn get(self: *Metadata, key: []const u8) ?[]const u8 {
        return self.headers.get(key);
    }
};

/// gRPC call context
pub const CallContext = struct {
    method: []const u8,
    timeout: ?u64, // milliseconds
    metadata: Metadata,
    compression: bool,
    
    pub fn init(allocator: std.mem.Allocator, method: []const u8) CallContext {
        return .{
            .method = method,
            .timeout = null,
            .metadata = Metadata.init(allocator),
            .compression = false,
        };
    }
    
    pub fn deinit(self: *CallContext) void {
        self.metadata.deinit();
    }
};

/// gRPC client for making RPC calls
pub const GrpcClient = struct {
    allocator: std.mem.Allocator,
    http2_client: http2.Http2Client,
    base_url: []const u8,
    default_metadata: Metadata,
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime, base_url: []const u8) !*GrpcClient {
        var client = try allocator.create(GrpcClient);
        client.* = .{
            .allocator = allocator,
            .http2_client = try http2.Http2Client.init(allocator, runtime),
            .base_url = try allocator.dupe(u8, base_url),
            .default_metadata = Metadata.init(allocator),
        };
        
        // Set default gRPC headers
        try client.default_metadata.set("content-type", "application/grpc");
        try client.default_metadata.set("te", "trailers");
        try client.default_metadata.set("grpc-accept-encoding", "identity,deflate,gzip");
        
        return client;
    }
    
    pub fn deinit(self: *GrpcClient) void {
        self.http2_client.deinit();
        self.allocator.free(self.base_url);
        self.default_metadata.deinit();
        self.allocator.destroy(self);
    }
    
    /// Make a unary gRPC call
    pub fn unaryCall(
        self: *GrpcClient, 
        context: *CallContext, 
        request_data: []const u8
    ) zsync.Future(errors.GhostnetError!GrpcResponse) {
        return self.runtime.async(struct {
            client: *GrpcClient,
            ctx: *CallContext,
            data: []const u8,
            
            pub fn run(args: @This()) errors.GhostnetError!GrpcResponse {
                const full_url = try std.fmt.allocPrint(args.client.allocator, "{s}/{s}", .{ args.client.base_url, args.ctx.method });
                defer args.client.allocator.free(full_url);
                
                // Create message frame
                const frame = MessageFrame{
                    .compressed = args.ctx.compression,
                    .length = @intCast(args.data.len),
                    .data = args.data,
                };
                
                const encoded_frame = try frame.encode(args.client.allocator);
                defer args.client.allocator.free(encoded_frame);
                
                // Prepare headers
                var headers = std.StringHashMap([]const u8).init(args.client.allocator);
                defer {
                    var it = headers.iterator();
                    while (it.next()) |entry| {
                        args.client.allocator.free(entry.key_ptr.*);
                        args.client.allocator.free(entry.value_ptr.*);
                    }
                    headers.deinit();
                }
                
                // Add default headers
                var default_it = args.client.default_metadata.headers.iterator();
                while (default_it.next()) |entry| {
                    const key = try args.client.allocator.dupe(u8, entry.key_ptr.*);
                    const value = try args.client.allocator.dupe(u8, entry.value_ptr.*);
                    try headers.put(key, value);
                }
                
                // Add context headers
                var ctx_it = args.ctx.metadata.headers.iterator();
                while (ctx_it.next()) |entry| {
                    const key = try args.client.allocator.dupe(u8, entry.key_ptr.*);
                    const value = try args.client.allocator.dupe(u8, entry.value_ptr.*);
                    try headers.put(key, value);
                }
                
                // Add timeout header
                if (args.ctx.timeout) |timeout| {
                    const timeout_str = try std.fmt.allocPrint(args.client.allocator, "{d}m", .{timeout});
                    try headers.put(try args.client.allocator.dupe(u8, "grpc-timeout"), timeout_str);
                }
                
                // Make HTTP/2 request
                const response = try args.client.http2_client.post(full_url, encoded_frame, headers);
                
                return GrpcResponse{
                    .status_code = try args.extractGrpcStatus(response.headers),
                    .message = response.body,
                    .metadata = try args.extractGrpcMetadata(response.headers),
                };
            }
            
            fn extractGrpcStatus(self: @This(), headers: std.StringHashMap([]const u8)) !StatusCode {
                if (headers.get("grpc-status")) |status_str| {
                    const status_int = try std.fmt.parseInt(u32, status_str, 10);
                    return @enumFromInt(status_int);
                }
                return .OK;
            }
            
            fn extractGrpcMetadata(self: @This(), headers: std.StringHashMap([]const u8)) !Metadata {
                var metadata = Metadata.init(self.client.allocator);
                
                var it = headers.iterator();
                while (it.next()) |entry| {
                    if (std.mem.startsWith(u8, entry.key_ptr.*, "grpc-")) {
                        try metadata.set(entry.key_ptr.*, entry.value_ptr.*);
                    }
                }
                
                return metadata;
            }
        }{ .client = self, .ctx = context, .data = request_data });
    }
    
    /// Start a client streaming call
    pub fn clientStreamingCall(self: *GrpcClient, context: *CallContext) !GrpcClientStream {
        return GrpcClientStream.init(self.allocator, &self.http2_client, context);
    }
    
    /// Start a server streaming call  
    pub fn serverStreamingCall(
        self: *GrpcClient, 
        context: *CallContext, 
        request_data: []const u8
    ) !GrpcServerStream {
        return GrpcServerStream.init(self.allocator, &self.http2_client, context, request_data);
    }
    
    /// Start a bidirectional streaming call
    pub fn bidirectionalStreamingCall(self: *GrpcClient, context: *CallContext) !GrpcBidirectionalStream {
        return GrpcBidirectionalStream.init(self.allocator, &self.http2_client, context);
    }
};

/// gRPC response
pub const GrpcResponse = struct {
    status_code: StatusCode,
    message: []const u8,
    metadata: Metadata,
    
    pub fn deinit(self: *GrpcResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
        self.metadata.deinit();
    }
};

/// Client streaming interface
pub const GrpcClientStream = struct {
    allocator: std.mem.Allocator,
    http2_client: *http2.Http2Client,
    context: *CallContext,
    stream_id: u32,
    
    pub fn init(allocator: std.mem.Allocator, http2_client: *http2.Http2Client, context: *CallContext) !GrpcClientStream {
        // Start HTTP/2 stream
        const stream_id = try http2_client.startStream();
        
        return .{
            .allocator = allocator,
            .http2_client = http2_client,
            .context = context,
            .stream_id = stream_id,
        };
    }
    
    pub fn sendMessage(self: *GrpcClientStream, data: []const u8) !void {
        const frame = MessageFrame{
            .compressed = self.context.compression,
            .length = @intCast(data.len),
            .data = data,
        };
        
        const encoded_frame = try frame.encode(self.allocator);
        defer self.allocator.free(encoded_frame);
        
        try self.http2_client.sendData(self.stream_id, encoded_frame, false);
    }
    
    pub fn finishAndReceive(self: *GrpcClientStream) !GrpcResponse {
        try self.http2_client.sendData(self.stream_id, &[_]u8{}, true); // End stream
        
        // Wait for response
        const response_data = try self.http2_client.receiveData(self.stream_id);
        
        return GrpcResponse{
            .status_code = .OK,
            .message = response_data,
            .metadata = Metadata.init(self.allocator),
        };
    }
};

/// Server streaming interface  
pub const GrpcServerStream = struct {
    allocator: std.mem.Allocator,
    http2_client: *http2.Http2Client,
    context: *CallContext,
    stream_id: u32,
    
    pub fn init(
        allocator: std.mem.Allocator, 
        http2_client: *http2.Http2Client, 
        context: *CallContext, 
        request_data: []const u8
    ) !GrpcServerStream {
        const stream_id = try http2_client.startStream();
        
        // Send initial request
        const frame = MessageFrame{
            .compressed = context.compression,
            .length = @intCast(request_data.len),
            .data = request_data,
        };
        
        const encoded_frame = try frame.encode(allocator);
        defer allocator.free(encoded_frame);
        
        try http2_client.sendData(stream_id, encoded_frame, true);
        
        return .{
            .allocator = allocator,
            .http2_client = http2_client,
            .context = context,
            .stream_id = stream_id,
        };
    }
    
    pub fn receiveMessage(self: *GrpcServerStream) !?GrpcResponse {
        const data = self.http2_client.receiveData(self.stream_id) catch |err| switch (err) {
            error.StreamClosed => return null,
            else => return err,
        };
        
        if (data.len == 0) return null;
        
        return GrpcResponse{
            .status_code = .OK,
            .message = data,
            .metadata = Metadata.init(self.allocator),
        };
    }
};

/// Bidirectional streaming interface
pub const GrpcBidirectionalStream = struct {
    allocator: std.mem.Allocator,
    http2_client: *http2.Http2Client,
    context: *CallContext,
    stream_id: u32,
    
    pub fn init(allocator: std.mem.Allocator, http2_client: *http2.Http2Client, context: *CallContext) !GrpcBidirectionalStream {
        const stream_id = try http2_client.startStream();
        
        return .{
            .allocator = allocator,
            .http2_client = http2_client,
            .context = context,
            .stream_id = stream_id,
        };
    }
    
    pub fn sendMessage(self: *GrpcBidirectionalStream, data: []const u8) !void {
        const frame = MessageFrame{
            .compressed = self.context.compression,
            .length = @intCast(data.len),
            .data = data,
        };
        
        const encoded_frame = try frame.encode(self.allocator);
        defer self.allocator.free(encoded_frame);
        
        try self.http2_client.sendData(self.stream_id, encoded_frame, false);
    }
    
    pub fn receiveMessage(self: *GrpcBidirectionalStream) !?GrpcResponse {
        const data = self.http2_client.receiveData(self.stream_id) catch |err| switch (err) {
            error.StreamClosed => return null,
            else => return err,
        };
        
        if (data.len == 0) return null;
        
        return GrpcResponse{
            .status_code = .OK,
            .message = data,
            .metadata = Metadata.init(self.allocator),
        };
    }
    
    pub fn close(self: *GrpcBidirectionalStream) !void {
        try self.http2_client.sendData(self.stream_id, &[_]u8{}, true);
    }
};

/// gRPC server for handling RPC calls
pub const GrpcServer = struct {
    allocator: std.mem.Allocator,
    http2_server: http2.Http2Server,
    services: std.StringHashMap(*ServiceDescriptor),
    
    pub fn init(allocator: std.mem.Allocator, runtime: *zsync.Runtime) !*GrpcServer {
        var server = try allocator.create(GrpcServer);
        server.* = .{
            .allocator = allocator,
            .http2_server = try http2.Http2Server.init(allocator, runtime),
            .services = std.StringHashMap(*ServiceDescriptor).init(allocator),
        };
        return server;
    }
    
    pub fn deinit(self: *GrpcServer) void {
        var it = self.services.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.services.deinit();
        self.http2_server.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn registerService(self: *GrpcServer, service: *ServiceDescriptor) !void {
        const service_name = try self.allocator.dupe(u8, service.name);
        try self.services.put(service_name, service);
    }
    
    pub fn serve(self: *GrpcServer, address: transport.Address, port: u16) !void {
        try self.http2_server.bind(address, port);
        try self.http2_server.listen();
        
        while (true) {
            const connection = try self.http2_server.accept();
            _ = zsync.spawn(self.handleConnection, .{connection});
        }
    }
    
    fn handleConnection(self: *GrpcServer, connection: http2.Http2Connection) void {
        while (true) {
            const request = connection.receiveRequest() catch |err| switch (err) {
                error.ConnectionClosed => break,
                else => continue,
            };
            
            _ = zsync.spawn(self.handleRequest, .{ connection, request });
        }
    }
    
    fn handleRequest(self: *GrpcServer, connection: http2.Http2Connection, request: http2.Http2Request) void {
        // Parse gRPC method from path
        const method_parts = std.mem.split(u8, request.path, "/");
        if (method_parts.next() == null) return; // Skip empty first part
        
        const service_name = method_parts.next() orelse return;
        const method_name = method_parts.next() orelse return;
        
        // Find service
        const service = self.services.get(service_name) orelse {
            self.sendError(connection, request.stream_id, .NOT_FOUND) catch {};
            return;
        };
        
        // Find method
        const method = service.getMethod(method_name) orelse {
            self.sendError(connection, request.stream_id, .UNIMPLEMENTED) catch {};
            return;
        };
        
        // Handle based on method type
        switch (method.method_type) {
            .unary => self.handleUnaryMethod(connection, request, method) catch {},
            .client_streaming => self.handleClientStreamingMethod(connection, request, method) catch {},
            .server_streaming => self.handleServerStreamingMethod(connection, request, method) catch {},
            .bidirectional_streaming => self.handleBidirectionalStreamingMethod(connection, request, method) catch {},
        }
    }
    
    fn handleUnaryMethod(self: *GrpcServer, connection: http2.Http2Connection, request: http2.Http2Request, method: *MethodDescriptor) !void {
        // Decode message frame
        const frame = try MessageFrame.decode(request.body, self.allocator);
        defer self.allocator.free(frame.data);
        
        // Call handler
        const response_data = try method.handler(frame.data);
        defer self.allocator.free(response_data);
        
        // Encode response frame
        const response_frame = MessageFrame{
            .compressed = false,
            .length = @intCast(response_data.len),
            .data = response_data,
        };
        
        const encoded_response = try response_frame.encode(self.allocator);
        defer self.allocator.free(encoded_response);
        
        // Send response
        try connection.sendResponse(request.stream_id, .{
            .status_code = 200,
            .headers = std.StringHashMap([]const u8).init(self.allocator),
            .body = encoded_response,
        });
        
        // Send trailers with gRPC status
        var trailers = std.StringHashMap([]const u8).init(self.allocator);
        defer trailers.deinit();
        
        try trailers.put("grpc-status", "0");
        try connection.sendTrailers(request.stream_id, trailers);
    }
    
    fn handleClientStreamingMethod(self: *GrpcServer, connection: http2.Http2Connection, request: http2.Http2Request, method: *MethodDescriptor) !void {
        // TODO: Implement client streaming
        try self.sendError(connection, request.stream_id, .UNIMPLEMENTED);
    }
    
    fn handleServerStreamingMethod(self: *GrpcServer, connection: http2.Http2Connection, request: http2.Http2Request, method: *MethodDescriptor) !void {
        // TODO: Implement server streaming  
        try self.sendError(connection, request.stream_id, .UNIMPLEMENTED);
    }
    
    fn handleBidirectionalStreamingMethod(self: *GrpcServer, connection: http2.Http2Connection, request: http2.Http2Request, method: *MethodDescriptor) !void {
        // TODO: Implement bidirectional streaming
        try self.sendError(connection, request.stream_id, .UNIMPLEMENTED);
    }
    
    fn sendError(self: *GrpcServer, connection: http2.Http2Connection, stream_id: u32, status: StatusCode) !void {
        var headers = std.StringHashMap([]const u8).init(self.allocator);
        defer headers.deinit();
        
        const status_str = try std.fmt.allocPrint(self.allocator, "{d}", .{@intFromEnum(status)});
        defer self.allocator.free(status_str);
        
        try headers.put("grpc-status", status_str);
        
        try connection.sendResponse(stream_id, .{
            .status_code = 200,
            .headers = headers,
            .body = &[_]u8{},
        });
    }
};

/// Service descriptor for gRPC services
pub const ServiceDescriptor = struct {
    name: []const u8,
    methods: std.StringHashMap(*MethodDescriptor),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, name: []const u8) !*ServiceDescriptor {
        var service = try allocator.create(ServiceDescriptor);
        service.* = .{
            .name = try allocator.dupe(u8, name),
            .methods = std.StringHashMap(*MethodDescriptor).init(allocator),
            .allocator = allocator,
        };
        return service;
    }
    
    pub fn deinit(self: *ServiceDescriptor) void {
        var it = self.methods.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.methods.deinit();
        self.allocator.free(self.name);
    }
    
    pub fn addMethod(self: *ServiceDescriptor, method: *MethodDescriptor) !void {
        const method_name = try self.allocator.dupe(u8, method.name);
        try self.methods.put(method_name, method);
    }
    
    pub fn getMethod(self: *ServiceDescriptor, name: []const u8) ?*MethodDescriptor {
        return self.methods.get(name);
    }
};

/// Method descriptor for gRPC methods
pub const MethodDescriptor = struct {
    name: []const u8,
    method_type: MethodType,
    handler: *const fn ([]const u8) anyerror![]u8,
    allocator: std.mem.Allocator,
    
    pub fn init(
        allocator: std.mem.Allocator, 
        name: []const u8, 
        method_type: MethodType, 
        handler: *const fn ([]const u8) anyerror![]u8
    ) !*MethodDescriptor {
        var method = try allocator.create(MethodDescriptor);
        method.* = .{
            .name = try allocator.dupe(u8, name),
            .method_type = method_type,
            .handler = handler,
            .allocator = allocator,
        };
        return method;
    }
    
    pub fn deinit(self: *MethodDescriptor) void {
        self.allocator.free(self.name);
    }
};