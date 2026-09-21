const std = @import("std");

const session_mod = @import("../session/session.zig");

const Packet = session_mod.Packet;
const Session = session_mod.Session;

/// hooks a bedwire session up to a raknet peer
///
/// Peer can be anything that has send(bytes, reliability, channel), like raknet.Session or raknet.Client.
/// Handler gets called once per parsed packet. Note that packet.bytes is borrowed straight from the
/// session buffer and goes away when deliver returns, so don't hang onto it without copying first.
///
/// Bedwire doesn't touch transport level stuff like acks, packet loss, resends or MTU splits,
/// that's all left up to raknet.
pub fn RakNet(comptime Peer: type, comptime Handler: type) type {
    comptime validate(Handler);

    return struct {
        session: *Session,
        peer: *Peer,
        handler: *Handler,
        // bedrock traffic uses channel 0
        channel: u8 = 0,

        const Self = @This();

        /// feeds a payload from raknet into the session and dispatches each decoded packet to handler
        pub fn deliver(self: *Self, payload: []const u8) !void {
            var packets = try self.session.ingest(payload);
            defer packets.deinit();
            while (packets.next()) |packet| try self.handler.onPacket(self.session, packet);
        }

        /// encodes packets into a 0xfe batch and sends reliable ordered
        pub fn send(self: *Self, packets: []const []const u8) !void {
            const frame = try self.session.encode(packets);
            defer frame.release();
            self.peer.send(frame.bytes, .reliable_ordered, self.channel) catch |err| {
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

/// mock raknet peer that records sent frames
const FakePeer = struct {
    frames: std.ArrayList([]u8) = .empty,
    allocator: std.mem.Allocator,
    fail: bool = false,

    const Reliability = enum { unreliable, reliable, reliable_ordered };

    fn send(self: *FakePeer, bytes: []const u8, reliability: Reliability, channel: u8) !void {
        try testing.expectEqual(Reliability.reliable_ordered, reliability);
        try testing.expectEqual(@as(u8, 0), channel);
        if (self.fail) return error.TransportClosed;
        try self.frames.append(self.allocator, try self.allocator.dupe(u8, bytes));
    }

    fn deinit(self: *FakePeer) void {
        for (self.frames.items) |frame| self.allocator.free(frame);
        self.frames.deinit(self.allocator);
    }
};

const Collector = struct {
    allocator: std.mem.Allocator,
    kinds: std.ArrayList(session_mod.PacketKind) = .empty,
    copies: std.ArrayList([]u8) = .empty,

    fn onPacket(self: *Collector, s: *Session, packet: Packet) !void {
        try testing.expect(s.state != .disconnected);
        try self.kinds.append(self.allocator, packet.kind);
        try self.copies.append(self.allocator, try self.allocator.dupe(u8, packet.bytes));
    }

    fn deinit(self: *Collector) void {
        for (self.copies.items) |copy| self.allocator.free(copy);
        self.copies.deinit(self.allocator);
        self.kinds.deinit(self.allocator);
    }
};

const registry = @import("../protocol/registry.zig");

const limits: @import("../limits.zig").Limits = .{
    .max_frame_bytes = 4096,
    .max_batch_bytes = 4096,
    .max_packet_bytes = 2048,
};

test "adapter drives ingest and reliable ordered send" {
    const allocator = testing.allocator;
    const version = comptime registry.describe(800) catch unreachable;

    var pool = try session_mod.BufferPool.init(allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var server = try Session.init(allocator, .server, &version, .{ .limits = limits, .pool = &pool });
    defer server.deinit();
    server.state = .in_game;

    var client = try Session.init(allocator, .client, &version, .{ .limits = limits, .pool = &pool });
    defer client.deinit();
    client.state = .in_game;

    var peer: FakePeer = .{ .allocator = allocator };
    defer peer.deinit();

    var collector: Collector = .{ .allocator = allocator };
    defer collector.deinit();

    var adapter = RakNet(FakePeer, Collector){ .session = &client, .peer = &peer, .handler = &collector };
    try adapter.sendOne(&.{ 9, 1, 2 });
    try testing.expectEqual(@as(usize, 1), peer.frames.items.len);

    const encoded = try server.encode(&.{ &.{ 10, 7 }, &.{ 12, 8 } });
    defer encoded.release();
    const frame = try allocator.dupe(u8, encoded.bytes);
    defer allocator.free(frame);

    try adapter.deliver(frame);
    try testing.expectEqual(@as(usize, 2), collector.kinds.items.len);
    try testing.expectEqualSlices(u8, &.{ 10, 7 }, collector.copies.items[0]);
}

test "transport failure closes the session" {
    const allocator = testing.allocator;
    const version = comptime registry.describe(800) catch unreachable;

    var pool = try session_mod.BufferPool.init(allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var client = try Session.init(allocator, .client, &version, .{ .limits = limits, .pool = &pool });
    defer client.deinit();
    client.state = .in_game;

    var peer: FakePeer = .{ .allocator = allocator, .fail = true };
    defer peer.deinit();

    var collector: Collector = .{ .allocator = allocator };
    defer collector.deinit();

    var adapter = RakNet(FakePeer, Collector){ .session = &client, .peer = &peer, .handler = &collector };
    try testing.expectError(error.TransportClosed, adapter.sendOne(&.{9}));
    try testing.expectEqual(session_mod.State.disconnected, client.state);
    try testing.expectError(error.TransportClosed, adapter.sendOne(&.{9}));
}

test "hostile payload closes the session inside the callback" {
    const allocator = testing.allocator;
    const version = comptime registry.describe(800) catch unreachable;

    var pool = try session_mod.BufferPool.init(allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var server = try Session.init(allocator, .server, &version, .{ .limits = limits, .pool = &pool });
    defer server.deinit();

    var peer: FakePeer = .{ .allocator = allocator };
    defer peer.deinit();

    var collector: Collector = .{ .allocator = allocator };
    defer collector.deinit();

    var adapter = RakNet(FakePeer, Collector){ .session = &server, .peer = &peer, .handler = &collector };
    try testing.expectError(error.MalformedBatch, adapter.deliver(&.{ 0xfe, 4, 1 }));
    try testing.expectEqual(session_mod.State.disconnected, server.state);
    try testing.expectEqual(@as(usize, 0), collector.kinds.items.len);
}

test "reentrant deliver or ingest is rejected with InvalidState" {
    const allocator = testing.allocator;
    const version = comptime registry.describe(800) catch unreachable;

    var pool = try session_mod.BufferPool.init(allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var server = try Session.init(allocator, .server, &version, .{ .limits = limits, .pool = &pool });
    defer server.deinit();
    server.state = .in_game;

    var client = try Session.init(allocator, .client, &version, .{ .limits = limits, .pool = &pool });
    defer client.deinit();
    client.state = .in_game;

    var peer: FakePeer = .{ .allocator = allocator };
    defer peer.deinit();

    const ReentrantHandler = struct {
        reentrant_err: ?anyerror = null,

        pub fn onPacket(self: *@This(), s: *Session, packet: Packet) !void {
            _ = packet;
            if (s.ingest(&.{ 0xfe, 2, 9, 1 })) |_| {
                self.reentrant_err = null;
            } else |err| {
                self.reentrant_err = err;
            }
        }
    };

    var handler: ReentrantHandler = .{};
    var adapter = RakNet(FakePeer, ReentrantHandler){ .session = &client, .peer = &peer, .handler = &handler };

    const encoded = try server.encode(&.{&.{ 9, 1 }});
    defer encoded.release();
    const frame = try allocator.dupe(u8, encoded.bytes);
    defer allocator.free(frame);

    try adapter.deliver(frame);
    try testing.expectEqual(@as(?anyerror, error.InvalidState), handler.reentrant_err);
}
