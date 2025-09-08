//! Input validation and sanitization utilities for ghostnet
//! Provides comprehensive validation for network inputs, URLs, and protocol parameters

const std = @import("std");
const logging = @import("logging.zig");

pub const ValidationError = error{
    InvalidUrl,
    InvalidPort,
    InvalidIPAddress,
    InvalidHostname,
    InvalidProtocolVersion,
    InvalidHeaderName,
    InvalidHeaderValue,
    InvalidContentType,
    InvalidMethod,
    PayloadTooLarge,
    InvalidStreamId,
    InvalidFrameType,
    InvalidCompressionLevel,
    SecurityViolation,
};

pub const ValidationConfig = struct {
    max_url_length: usize = 2048,
    max_header_name_length: usize = 64,
    max_header_value_length: usize = 8192,
    max_payload_size: usize = 10 * 1024 * 1024, // 10MB default
    allow_private_ips: bool = false,
    enforce_https: bool = false,
};

pub const Validator = struct {
    config: ValidationConfig,
    
    pub fn init(config: ValidationConfig) Validator {
        return .{ .config = config };
    }
    
    /// Validate URL format and security constraints
    pub fn validateUrl(self: *const Validator, url: []const u8) ValidationError!void {
        if (url.len == 0 or url.len > self.config.max_url_length) {
            logging.warn(.{ .component = "validator", .operation = "validateUrl" }, 
                "URL length invalid: {d}", .{url.len});
            return ValidationError.InvalidUrl;
        }
        
        // Check for basic URL structure
        if (!std.mem.startsWith(u8, url, "http://") and !std.mem.startsWith(u8, url, "https://")) {
            logging.warn(.{ .component = "validator", .operation = "validateUrl" }, 
                "URL missing protocol: {s}", .{url});
            return ValidationError.InvalidUrl;
        }
        
        // Enforce HTTPS if required
        if (self.config.enforce_https and !std.mem.startsWith(u8, url, "https://")) {
            logging.warn(.{ .component = "validator", .operation = "validateUrl" }, 
                "HTTPS required but got HTTP: {s}", .{url});
            return ValidationError.SecurityViolation;
        }
        
        // Basic checks for suspicious characters
        for (url) |char| {
            if (char < 32 or char > 126) {
                if (char != '%') { // Allow URL encoding
                    logging.warn(.{ .component = "validator", .operation = "validateUrl" }, 
                        "URL contains invalid character: {d}", .{char});
                    return ValidationError.InvalidUrl;
                }
            }
        }
    }
    
    /// Validate port number
    pub fn validatePort(self: *const Validator, port: u16) ValidationError!void {
        _ = self;
        if (port == 0) {
            logging.warn(.{ .component = "validator", .operation = "validatePort" }, 
                "Port cannot be zero");
            return ValidationError.InvalidPort;
        }
        
        // Warn about privileged ports
        if (port < 1024) {
            logging.warn(.{ .component = "validator", .operation = "validatePort" }, 
                "Using privileged port: {d}", .{port});
        }
    }
    
    /// Validate IPv4 address format
    pub fn validateIPv4(self: *const Validator, ip: []const u8) ValidationError!void {
        var parts = std.mem.split(u8, ip, ".");
        var part_count: u8 = 0;
        
        while (parts.next()) |part| {
            part_count += 1;
            if (part_count > 4) return ValidationError.InvalidIPAddress;
            
            const num = std.fmt.parseInt(u8, part, 10) catch {
                return ValidationError.InvalidIPAddress;
            };
            
            // Check for private IP ranges if not allowed
            if (!self.config.allow_private_ips and part_count == 1) {
                if (num == 10 or num == 172 or num == 192) {
                    logging.warn(.{ .component = "validator", .operation = "validateIPv4" }, 
                        "Private IP address not allowed: {s}", .{ip});
                    return ValidationError.SecurityViolation;
                }
            }
        }
        
        if (part_count != 4) {
            return ValidationError.InvalidIPAddress;
        }
    }
    
    /// Validate hostname format
    pub fn validateHostname(self: *const Validator, hostname: []const u8) ValidationError!void {
        _ = self;
        if (hostname.len == 0 or hostname.len > 253) {
            return ValidationError.InvalidHostname;
        }
        
        var labels = std.mem.split(u8, hostname, ".");
        var label_count: u8 = 0;
        
        while (labels.next()) |label| {
            label_count += 1;
            if (label.len == 0 or label.len > 63) {
                return ValidationError.InvalidHostname;
            }
            
            // Check label characters
            for (label, 0..) |char, i| {
                if (!std.ascii.isAlphanumeric(char) and char != '-') {
                    return ValidationError.InvalidHostname;
                }
                
                // Labels cannot start or end with hyphen
                if (char == '-' and (i == 0 or i == label.len - 1)) {
                    return ValidationError.InvalidHostname;
                }
            }
        }
        
        if (label_count == 0) {
            return ValidationError.InvalidHostname;
        }
    }
    
    /// Validate HTTP header name
    pub fn validateHeaderName(self: *const Validator, name: []const u8) ValidationError!void {
        if (name.len == 0 or name.len > self.config.max_header_name_length) {
            return ValidationError.InvalidHeaderName;
        }
        
        for (name) |char| {
            // RFC 7230: header names are tokens
            if (!std.ascii.isAlphanumeric(char) and 
                char != '-' and char != '_' and char != '.') {
                return ValidationError.InvalidHeaderName;
            }
        }
    }
    
    /// Validate HTTP header value
    pub fn validateHeaderValue(self: *const Validator, value: []const u8) ValidationError!void {
        if (value.len > self.config.max_header_value_length) {
            return ValidationError.InvalidHeaderValue;
        }
        
        for (value) |char| {
            // Basic printable ASCII check
            if (char < 32 or char > 126) {
                if (char != '\t') { // Allow tab
                    return ValidationError.InvalidHeaderValue;
                }
            }
        }
    }
    
    /// Validate payload size
    pub fn validatePayloadSize(self: *const Validator, size: usize) ValidationError!void {
        if (size > self.config.max_payload_size) {
            logging.warn(.{ .component = "validator", .operation = "validatePayloadSize" }, 
                "Payload too large: {d} bytes (max: {d})", .{ size, self.config.max_payload_size });
            return ValidationError.PayloadTooLarge;
        }
    }
    
    /// Validate HTTP/2 stream ID
    pub fn validateStreamId(self: *const Validator, stream_id: u32) ValidationError!void {
        _ = self;
        if (stream_id == 0 or stream_id >= 0x80000000) {
            return ValidationError.InvalidStreamId;
        }
    }
    
    /// Validate HTTP method
    pub fn validateHttpMethod(self: *const Validator, method: []const u8) ValidationError!void {
        _ = self;
        const valid_methods = &[_][]const u8{
            "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
        };
        
        for (valid_methods) |valid_method| {
            if (std.mem.eql(u8, method, valid_method)) {
                return;
            }
        }
        
        logging.warn(.{ .component = "validator", .operation = "validateHttpMethod" }, 
            "Invalid HTTP method: {s}", .{method});
        return ValidationError.InvalidMethod;
    }
    
    /// Sanitize string by removing or escaping dangerous characters
    pub fn sanitizeString(self: *const Validator, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        _ = self;
        var result = std.ArrayList(u8).init(allocator);
        defer result.deinit();
        
        for (input) |char| {
            if (char >= 32 and char <= 126) {
                try result.append(char);
            } else {
                // Replace with safe character or escape sequence
                try result.appendSlice("?");
            }
        }
        
        return result.toOwnedSlice();
    }
};

// Global validator instance
var global_validator: ?*Validator = null;

pub fn setGlobalValidator(validator: *Validator) void {
    global_validator = validator;
}

pub fn getGlobalValidator() ?*Validator {
    return global_validator;
}

// Convenience functions for global validation
pub fn validateUrl(url: []const u8) ValidationError!void {
    if (global_validator) |validator| return validator.validateUrl(url);
}

pub fn validatePort(port: u16) ValidationError!void {
    if (global_validator) |validator| return validator.validatePort(port);
}

pub fn validateIPv4(ip: []const u8) ValidationError!void {
    if (global_validator) |validator| return validator.validateIPv4(ip);
}

pub fn validateHostname(hostname: []const u8) ValidationError!void {
    if (global_validator) |validator| return validator.validateHostname(hostname);
}