const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Using debug.print for Zig 0.15 compatibility
    std.debug.print("👻 ghostnet v0.1.0 Demo\n", .{});
    std.debug.print("======================\n\n", .{});
    
    // Demo TCP echo server (conceptual)
    std.debug.print("🔧 TCP Echo Server Example:\n", .{});
    std.debug.print("```zig\n", .{});
    std.debug.print("const ghostnet = @import(\"ghostnet\");\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("var runtime = try ghostnet.zsync.Runtime.init(allocator, .{{}});\n", .{});
    std.debug.print("var listener = try ghostnet.TcpListener.init(allocator, &runtime);\n", .{});
    std.debug.print("try listener.bind(.{{ .ipv4 = std.net.Ip4Address.any }}, .{{\n", .{});
    std.debug.print("    .port = 8080,\n", .{});
    std.debug.print("    .allocator = allocator,\n", .{});
    std.debug.print("}});\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("while (true) {{\n", .{});
    std.debug.print("    const conn = try listener.acceptAsync().await();\n", .{});
    std.debug.print("    _ = try ghostnet.zsync.spawn(handleConnection, .{{conn}});\n", .{});
    std.debug.print("}}\n", .{});
    std.debug.print("```\n\n", .{});
    
    // Demo WebSocket client (conceptual)
    std.debug.print("🌐 WebSocket Client Example:\n", .{});
    std.debug.print("```zig\n", .{});
    std.debug.print("var ws_client = try ghostnet.websocket.WebSocketClient.init(allocator, &runtime, ws_config);\n", .{});
    std.debug.print("var ws_conn = try ws_client.connect(\"ws://localhost:8080/chat\");\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("const message = try ghostnet.websocket.WebSocketMessage.text(allocator, \"Hello, WebSocket!\");\n", .{});
    std.debug.print("try ws_conn.sendMessage(message);\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("const response = try ws_conn.receiveMessage();\n", .{});
    std.debug.print("std.debug.print(\"Received: {{s}}\\n\", .{{response.payload}});\n", .{});
    std.debug.print("```\n\n", .{});
    
    // Demo gossip protocol (conceptual)
    std.debug.print("📡 Gossip Protocol Example:\n", .{});
    std.debug.print("```zig\n", .{});
    std.debug.print("var gossip_node = try ghostnet.gossip.GossipNode.init(allocator, &runtime, gossip_config);\n", .{});
    std.debug.print("try gossip_node.start(.{{ .ipv4 = std.net.Ip4Address.any }});\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("try gossip_node.subscribe(\"chat\");\n", .{});
    std.debug.print("try gossip_node.publish(\"chat\", \"Hello, mesh network!\");\n", .{});
    std.debug.print("```\n\n", .{});
    
    // Demo AI service integration
    std.debug.print("🤖 AI Service Integration Example:\n", .{});
    std.debug.print("```zig\n", .{});
    std.debug.print("var claude_client = try ghostnet.http.ClaudeClient.init(allocator, &runtime, \"your-api-key\");\n", .{});
    std.debug.print("const response = try claude_client.sendMessage(\"Explain async networking\", \"claude-3-sonnet-20240229\");\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("var copilot_client = try ghostnet.http.CopilotClient.init(allocator, &runtime, \"your-token\");\n", .{});
    std.debug.print("const completions = try copilot_client.getCompletions(\"fn main() {{\", \"zig\");\n", .{});
    std.debug.print("```\n\n", .{});
    
    std.debug.print("🎯 Perfect for zeke AI tool:\n", .{});
    std.debug.print("- HTTP/HTTPS clients for Claude and Copilot APIs\n", .{});
    std.debug.print("- WebSocket support for real-time communication\n", .{});
    std.debug.print("- Async filesystem operations (via zsync)\n", .{});
    std.debug.print("- P2P networking for distributed AI tools\n", .{});
    std.debug.print("- Secure VPN tunnels with WireGuard\n", .{});
    std.debug.print("- Service discovery with mDNS\n", .{});
    
    _ = allocator;
}