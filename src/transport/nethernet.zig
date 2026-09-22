const std = @import("std");

const session_mod = @import("../session/session.zig");

const Packet = session_mod.Packet;
const Session = session_mod.Session;

/// connects a bedwire session to nethernet (webrtc datachannel)
///
/// used for lan games, friend invites and xbox relay connections.
/// Connection needs send(bytes, reliability) and receive() !Message.
/// Handler needs onPacket(*Handler, *Session, Packet) !void.
///
/// can be driven push-style with deliver() when your loop gets data,
/// or pull-style with pump() on a polling thread.
/// minecraft bedrock drops the session if packets arrive out of order,
/// so pump() will error out if an unreliable datagram slips through.
/// send must consume or copy bytes before returning. Message.data must remain
/// valid through deliver; handlers must not retain borrowed packet bytes.
pub fn NetherNet(comptime Connection: type, comptime Handler: type) type {
    comptime validate(Handler);

    return struct {
        session: *Session,
        connection: *Connection,
        handler: *Handler,
        pumping: bool = false,

        const Self = @This();

        /// process a packet received from the datachannel
        pub fn deliver(self: *Self, payload: []const u8) !void {
            var packets = try self.session.ingest(payload);
            defer packets.deinit();
            errdefer self.session.close();
            while (packets.next()) |packet| try self.handler.onPacket(self.session, packet);
        }

        /// pull the next reliable message from NetherNet
        pub fn pump(self: *Self) !void {
            if (self.session.state == .disconnected) return error.TransportClosed;
            if (self.pumping or self.session.active_generation != null or self.session.rx_slot != null) return error.InvalidState;
            self.pumping = true;
            defer self.pumping = false;

            const message = self.connection.receive() catch |err| {
                // NetherNet poll closes on error; Canceled and UnexpectedSignal
                // come from receive after a successful poll.
                if (err != error.Canceled and err != error.UnexpectedSignal) self.session.close();
                return err;
            };
            // The message has been consumed. Admission failure cannot be retried here.
            errdefer self.session.close();
            if (message.reliability != .reliable) {
                self.session.close();
                return error.TransportClosed;
            }

            return self.deliver(message.data);
        }

        pub fn send(self: *Self, packets: []const []const u8) !void {
            const frame = try self.session.encode(packets);
            defer frame.release();
            self.connection.send(frame.bytes, .reliable) catch |err| {
                self.session.close();
                return err;
            };
        }

        pub fn sendOne(self: *Self, packet: []const u8) !void {
            return self.send(&.{packet});
        }
    };
}

fn validate(comptime Handler: type) void {
    if (!@hasDecl(Handler, "onPacket")) {
        @compileError(@typeName(Handler) ++ " must declare onPacket(*Handler, *Session, Packet) !void");
    }
}

const testing = std.testing;
const registry = @import("../protocol/registry.zig");

/// mock nethernet channel
const Channel = struct {
    const Reliability = enum { unreliable, reliable };
    const Message = struct { reliability: Reliability, data: []const u8 };

    inbound: []const u8 = &.{},
    inbound_reliability: Reliability = .reliable,
    receive_error: ?anyerror = null,
    outbound: [4096]u8 = undefined,
    outbound_len: usize = 0,

    fn receive(self: *Channel) !Message {
        if (self.receive_error) |err| return err;
        if (self.inbound.len == 0) return error.TransportClosed;
        return .{ .reliability = self.inbound_reliability, .data = self.inbound };
    }

    fn send(self: *Channel, bytes: []const u8, reliability: Reliability) !void {
        try testing.expectEqual(Reliability.reliable, reliability);
        @memcpy(self.outbound[0..bytes.len], bytes);
        self.outbound_len = bytes.len;
    }
};

const Counter = struct {
    packets: usize = 0,

    fn onPacket(self: *Counter, s: *Session, packet: Packet) !void {
        _ = s;
        _ = packet;
        self.packets += 1;
    }
};

const limits: @import("../limits.zig").Limits = .{
    .max_frame_bytes = 4096,
    .max_batch_bytes = 4096,
    .max_packet_bytes = 2048,
};

test "pump accepts reliable messages and refuses unreliable ones" {
    const allocator = testing.allocator;
    const version = comptime registry.describe(800) catch unreachable;

    var pool = try session_mod.BufferPool.init(allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var peer_session = try Session.init(allocator, .server, &version, .{ .limits = limits, .pool = &pool });
    defer peer_session.deinit();
    peer_session.state = .in_game;

    var local = try Session.init(allocator, .client, &version, .{ .limits = limits, .pool = &pool });
    defer local.deinit();
    local.state = .in_game;

    const encoded = try peer_session.encode(&.{ &.{ 9, 1 }, &.{ 10, 2 } });
    defer encoded.release();
    const frame = try allocator.dupe(u8, encoded.bytes);
    defer allocator.free(frame);

    var channel: Channel = .{ .inbound = frame };
    var counter: Counter = .{};
    var adapter = NetherNet(Channel, Counter){ .session = &local, .connection = &channel, .handler = &counter };

    try adapter.pump();
    try testing.expectEqual(@as(usize, 2), counter.packets);

    channel.inbound_reliability = .unreliable;
    try testing.expectError(error.TransportClosed, adapter.pump());
    try testing.expectEqual(session_mod.State.disconnected, local.state);
}

test "terminal connection failure in pump disconnects the session" {
    const allocator = testing.allocator;
    const version = comptime registry.describe(800) catch unreachable;

    var pool = try session_mod.BufferPool.init(allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var local = try Session.init(allocator, .client, &version, .{ .limits = limits, .pool = &pool });
    defer local.deinit();
    local.state = .in_game;

    var channel: Channel = .{ .inbound = &.{} };
    var counter: Counter = .{};
    var adapter = NetherNet(Channel, Counter){ .session = &local, .connection = &channel, .handler = &counter };

    try testing.expectError(error.TransportClosed, adapter.pump());
    try testing.expectEqual(session_mod.State.disconnected, local.state);
}

test "pump closes on upstream terminal receive failures" {
    const version = comptime registry.describe(800) catch unreachable;
    inline for (.{ error.ConnectionClosed, error.Timeout, error.ReassemblyTimeout }) |receive_error| {
        var pool = try session_mod.BufferPool.init(testing.allocator, limits, .{ .rx_slots = 1, .tx_slots = 1 });
        defer pool.deinit();
        var local = try Session.init(testing.allocator, .client, &version, .{ .pool = &pool });
        defer local.deinit();
        local.state = .in_game;
        var channel: Channel = .{ .receive_error = receive_error };
        var counter: Counter = .{};
        var adapter = NetherNet(Channel, Counter){ .session = &local, .connection = &channel, .handler = &counter };

        try testing.expectError(receive_error, adapter.pump());
        try testing.expectEqual(session_mod.State.disconnected, local.state);
        try testing.expectError(error.TransportClosed, adapter.pump());
    }
}

test "pump preserves session on canceled wait" {
    const version = comptime registry.describe(800) catch unreachable;
    var pool = try session_mod.BufferPool.init(testing.allocator, limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var local = try Session.init(testing.allocator, .client, &version, .{ .pool = &pool });
    defer local.deinit();
    local.state = .in_game;
    var channel: Channel = .{ .receive_error = error.Canceled };
    var counter: Counter = .{};
    var adapter = NetherNet(Channel, Counter){ .session = &local, .connection = &channel, .handler = &counter };

    try testing.expectError(error.Canceled, adapter.pump());
    try testing.expectEqual(session_mod.State.in_game, local.state);
    try testing.expect(!adapter.pumping);
}

test "adapter sends reliable frames and stops once closed" {
    const allocator = testing.allocator;
    const version = comptime registry.describe(800) catch unreachable;

    var pool = try session_mod.BufferPool.init(allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var local = try Session.init(allocator, .client, &version, .{ .limits = limits, .pool = &pool });
    defer local.deinit();
    local.state = .in_game;

    var channel: Channel = .{};
    var counter: Counter = .{};
    var adapter = NetherNet(Channel, Counter){ .session = &local, .connection = &channel, .handler = &counter };

    try adapter.sendOne(&.{ 9, 7 });
    try testing.expectEqual(@as(u8, 0xfe), channel.outbound[0]);

    local.close();
    try testing.expectError(error.TransportClosed, adapter.sendOne(&.{ 9, 7 }));
    try testing.expectError(error.TransportClosed, adapter.deliver(&.{ 0xfe, 2, 9, 7 }));
}
