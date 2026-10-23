const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const Session = support.Session;
const Algorithm = bedwire.compression.Algorithm;
const SessionCrypto = bedwire.crypto.SessionCrypto;

const Link = struct {
    limits: bedwire.Limits,
    pool: bedwire.BufferPool,
    sender: Session,
    receiver: Session,

    fn init(self: *Link, limits: bedwire.Limits, algorithm: ?Algorithm, encrypted: bool) !void {
        self.limits = limits;
        self.pool = try .init(testing.allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
        self.sender = try Session.init(.server, .{ .pool = &self.pool });
        self.receiver = try Session.init(.client, .{ .pool = &self.pool });
        for ([_]*Session{ &self.sender, &self.receiver }) |session| {
            if (algorithm) |a| try session.compression.negotiate(a, 0);
            session.state = .in_game;
            if (encrypted) session.crypto = SessionCrypto.init(@splat(7));
        }
    }

    fn deinit(self: *Link) void {
        self.sender.deinit();
        self.receiver.deinit();
        self.pool.deinit();
    }

    fn send(self: *Link, packets: []const []const u8) !usize {
        var batches = try self.sender.encodeBatches(packets);
        var frames: usize = 0;
        var index: usize = 0;
        while (try batches.next()) |frame| {
            defer frame.release();
            frames += 1;
            try testing.expect(frame.bytes.len <= self.limits.max_frame_bytes);
            var received = try self.receiver.ingest(frame.bytes);
            defer received.deinit();
            while (received.next()) |packet| : (index += 1) {
                try testing.expectEqualSlices(u8, packets[index], packet.bytes);
            }
        }
        try testing.expectEqual(packets.len, index);
        try testing.expectEqual(@as(usize, 0), batches.remaining());
        return frames;
    }
};

const Group = struct {
    storage: [128][320]u8 = undefined,
    packets: [128][]const u8 = undefined,

    fn fill(self: *Group, count: usize, len: usize, seed: u64) []const []const u8 {
        var prng = std.Random.DefaultPrng.init(seed);
        for (0..count) |i| {
            var body: [317]u8 = undefined;
            prng.random().bytes(body[0..len]);
            std.mem.writeInt(u16, body[0..2], @intCast(i), .little);
            self.packets[i] = support.packet(&self.storage[i], support.opaque_packet_id, body[0..len]);
        }
        return self.packets[0..count];
    }
};

const variants = [_]struct { algorithm: ?Algorithm, encrypted: bool }{
    .{ .algorithm = null, .encrypted = false },
    .{ .algorithm = .none, .encrypted = true },
    .{ .algorithm = .deflate, .encrypted = false },
    .{ .algorithm = .deflate, .encrypted = true },
    .{ .algorithm = .snappy, .encrypted = true },
};

test "groups split at the outgoing packet count and keep their order" {
    var group: Group = .{};
    const packets = group.fill(100, 8, 1);
    var limits = support.limits;
    limits.max_outgoing_packets_per_batch = 7;

    for (variants) |variant| {
        var link: Link = undefined;
        try link.init(limits, variant.algorithm, variant.encrypted);
        defer link.deinit();

        try testing.expectEqual(@as(usize, 15), try link.send(packets));
        try testing.expectError(error.LimitExceeded, link.sender.encode(packets[0..8]));
        const whole = try link.sender.encode(packets[0..7]);
        whole.release();
    }
}

test "groups split by size so every frame fits even when nothing compresses" {
    var group: Group = .{};
    const packets = group.fill(40, 300, 2);
    var limits = support.limits;
    limits.max_frame_bytes = 1024;

    for (variants) |variant| {
        var link: Link = undefined;
        try link.init(limits, variant.algorithm, variant.encrypted);
        defer link.deinit();

        const frames = try link.send(packets);
        try testing.expect(frames >= 40 * 303 / 1024 + 1);
        try testing.expect(frames <= 14);
    }
}

test "the outgoing byte cap splits groups below the frame limit" {
    var group: Group = .{};
    const packets = group.fill(30, 100, 3);
    var limits = support.limits;
    limits.max_outgoing_batch_bytes = 515;

    var link: Link = undefined;
    try link.init(limits, .snappy, true);
    defer link.deinit();
    try testing.expectEqual(@as(usize, 6), try link.send(packets));
}

test "a group with an unsendable packet fails before any frame" {
    var group: Group = .{};
    const packets = group.fill(4, 8, 4);
    var limits = support.limits;
    limits.max_frame_bytes = 256;

    var link: Link = undefined;
    try link.init(limits, .deflate, true);
    defer link.deinit();

    var big: [300]u8 = undefined;
    var login: support.Builder = .{};
    const oversized = support.packet(&big, support.opaque_packet_id, &@as([260]u8, @splat(1)));
    for ([_][]const u8{ oversized, login.make(support.modern, .login), &.{} }, [_]anyerror{ error.LimitExceeded, error.InvalidState, error.MalformedBatch }) |bad, expected| {
        const mixed = [_][]const u8{ packets[0], packets[1], bad };
        try testing.expectError(expected, link.sender.encodeBatches(&mixed));
        try testing.expect(link.pool.isIdle());
        try testing.expectEqual(@as(u64, 0), link.sender.crypto.?.send_counter);
        try testing.expectEqual(bedwire.State.in_game, link.sender.state);
    }
    try testing.expectError(error.MalformedBatch, link.sender.encodeBatches(&.{}));
    try testing.expectEqual(@as(usize, 1), try link.send(packets));
}

test "a held frame or a busy pool pauses splitting without losing packets" {
    var group: Group = .{};
    const packets = group.fill(9, 8, 5);
    var limits = support.limits;
    limits.max_outgoing_packets_per_batch = 3;

    var link: Link = undefined;
    try link.init(limits, .deflate, true);
    defer link.deinit();

    var others: [2]Session = undefined;
    for (&others) |*other| {
        other.* = try Session.init(.server, .{ .pool = &link.pool });
        other.state = .in_game;
    }
    defer for (&others) |*other| other.deinit();

    var batches = try link.sender.encodeBatches(packets);
    var index: usize = 0;
    const first = (try batches.next()).?;
    try testing.expectError(error.PoolExhausted, batches.next());
    try deliver(&link, first, packets, &index);

    const held = [_]Session.Frame{ try others[0].encodeOne(packets[0]), try others[1].encodeOne(packets[0]) };
    try testing.expectError(error.PoolExhausted, batches.next());
    try testing.expectEqual(@as(usize, 6), batches.remaining());
    for (held) |frame| frame.release();

    while (try batches.next()) |frame| try deliver(&link, frame, packets, &index);
    try testing.expectEqual(@as(usize, 9), index);
}

fn deliver(link: *Link, frame: Session.Frame, packets: []const []const u8, index: *usize) !void {
    defer frame.release();
    var received = try link.receiver.ingest(frame.bytes);
    defer received.deinit();
    while (received.next()) |packet| : (index.* += 1) try testing.expectEqualSlices(u8, packets[index.*], packet.bytes);
}

test "a session that closes mid-group stops splitting" {
    var group: Group = .{};
    const packets = group.fill(6, 8, 6);
    var limits = support.limits;
    limits.max_outgoing_packets_per_batch = 2;

    var link: Link = undefined;
    try link.init(limits, .snappy, true);
    defer link.deinit();

    var batches = try link.sender.encodeBatches(packets);
    const frame = (try batches.next()).?;
    frame.release();
    link.sender.close();
    try testing.expectError(error.TransportClosed, batches.next());
    try testing.expect(link.pool.isIdle());
}

test "handshake stages refuse multi-packet groups" {
    var pair = try support.Pair.init(testing.allocator, support.modern);
    defer pair.deinit();
    pair.client.state = .authenticating;

    var a: support.Builder = .{};
    var b: support.Builder = .{};
    const login = a.make(support.modern, .login);
    try testing.expectError(error.InvalidState, pair.client.encodeBatches(&.{ login, b.make(support.modern, .login) }));
    var batches = try pair.client.encodeBatches(&.{login});
    const frame = (try batches.next()).?;
    frame.release();
    try testing.expect(pair.client.didSend(.login));
}

test "batches that would grow go out uncompressed" {
    var noise: [2000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    prng.random().bytes(&noise);
    var storage: [2100]u8 = undefined;
    const random = support.packet(&storage, support.opaque_packet_id, &noise);
    var plain: [2100]u8 = undefined;
    const compressible = support.packet(&plain, support.opaque_packet_id, &@as([2000]u8, @splat('c')));
    var tiny: [8]u8 = undefined;
    const small = support.packet(&tiny, support.opaque_packet_id, "hi");

    for ([_]Algorithm{ .deflate, .snappy }) |algorithm| {
        var link: Link = undefined;
        try link.init(support.limits, algorithm, false);
        defer link.deinit();

        for ([_][]const u8{ random, small }) |packet| {
            const frame = try link.sender.encodeOne(packet);
            defer frame.release();
            try testing.expectEqual(@as(u8, 0xff), frame.bytes[1]);
            try testing.expectEqual(2 + bedwire.framing.batch.entryLen(packet.len), frame.bytes.len);
            var received = try link.receiver.ingest(frame.bytes);
            defer received.deinit();
            try testing.expectEqualSlices(u8, packet, received.next().?.bytes);
        }

        const frame = try link.sender.encodeOne(compressible);
        defer frame.release();
        try testing.expectEqual(@backingInt(algorithm), frame.bytes[1]);
        try testing.expect(frame.bytes.len < 200);
    }
}

test "implicit DEFLATE splits leave room for incompressible data" {
    const Legacy = bedwire.SessionWithProfile(support.legacy);
    var limits = support.limits;
    limits.max_frame_bytes = 2048;
    var pool = try bedwire.BufferPool.init(testing.allocator, limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var sender = try Legacy.init(.server, .{ .pool = &pool });
    defer sender.deinit();
    var receiver = try Legacy.init(.client, .{ .pool = &pool });
    defer receiver.deinit();
    sender.state = .in_game;
    receiver.state = .in_game;

    var group: Group = .{};
    const packets = group.fill(60, 317, 8);
    var batches = try sender.encodeBatches(packets);
    var index: usize = 0;
    while (try batches.next()) |frame| {
        defer frame.release();
        try testing.expect(frame.bytes.len <= limits.max_frame_bytes);
        var received = try receiver.ingest(frame.bytes);
        defer received.deinit();
        while (received.next()) |packet| : (index += 1) try testing.expectEqualSlices(u8, packets[index], packet.bytes);
    }
    try testing.expectEqual(packets.len, index);
}
