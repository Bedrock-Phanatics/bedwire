const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;

fn gameSession(allocator: std.mem.Allocator, pool: *bedwire.BufferPool, role: bedwire.Role) !support.Session {
    var session = try support.Session.init(allocator, role, .{ .pool = pool, .limits = support.limits });
    session.state = .in_game;
    return session;
}

test "frames must carry the session header" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    try testing.expectError(error.MalformedBatch, session.ingest(&.{}));
    try testing.expectEqual(bedwire.State.disconnected, session.state);

    var other = try gameSession(testing.allocator, &pool, .server);
    defer other.deinit();
    try testing.expectError(error.MalformedBatch, other.ingest(&.{ 0xfd, 2, 60, 0 }));
}

test "empty batches are refused in both directions" {
    var pair = try support.Pair.init(testing.allocator, support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    try testing.expectError(error.MalformedBatch, pair.client.encode(&.{}));
    try testing.expectError(error.MalformedBatch, pair.server.ingest(&.{0xfe}));
    try testing.expectEqual(bedwire.State.disconnected, pair.server.state);
}

test "malformed and truncated length prefixes are rejected" {
    const cases = [_][]const u8{
        &.{ 0xfe, 0 }, // zero-length packet
        &.{ 0xfe, 4, 60, 1 }, // length past the end of the batch
        &.{ 0xfe, 0x80 }, // dangling continuation byte
        &.{ 0xfe, 0x80, 0x00, 60 }, // overlong length prefix
        &.{ 0xfe, 2, @as(u8, @intCast(support.packetId(support.modern, .player_action))), 1, 5 }, // trailing prefix with no payload
    };

    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    for (cases) |frame| {
        var session = try gameSession(testing.allocator, &pool, .server);
        defer session.deinit();

        try testing.expectError(error.MalformedBatch, session.ingest(frame));
        try testing.expectEqual(bedwire.State.disconnected, session.state);
    }
}

test "a batch that smuggles one illegal packet delivers none of them" {
    var pair = try support.Pair.init(testing.allocator, support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var legal: [16]u8 = undefined;
    var illegal: [16]u8 = undefined;
    const login_id = support.packetId(support.modern, .login);

    pair.client.state = .spawn_ready;
    const frame = try pair.client.encode(&.{
        support.packet(&legal, 1020, "ok"),
        support.packet(&illegal, support.packetId(support.modern, .set_local_player_as_initialised), "ok"),
    });
    defer frame.release();
    @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
    const captured = pair.relay[0..frame.bytes.len];

    pair.server.state = .resource_packs;
    try testing.expectError(error.InvalidState, pair.server.ingest(captured));
    try testing.expectEqual(bedwire.State.disconnected, pair.server.state);
    try testing.expect(login_id != support.opaque_packet_id);
}

test "packet count and packet size limits bound one batch" {
    const tight: bedwire.Limits = .{
        .max_frame_bytes = 4096,
        .max_batch_bytes = 4096,
        .max_packet_bytes = 16,
        .max_packets_per_batch = 3,
    };

    var pool = try bedwire.BufferPool.init(testing.allocator, tight, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try support.Session.init(testing.allocator, .server, .{ .pool = &pool, .limits = tight });
    defer session.deinit();
    session.state = .in_game;

    var storage: [4][32]u8 = undefined;
    var packets: [4][]const u8 = undefined;
    for (&packets, 0..) |*slot, i| slot.* = support.packet(&storage[i], 1020 + @as(u16, @intCast(i)), "x");

    const ok_frame = try session.encode(packets[0..3]);
    ok_frame.release();
    try testing.expectError(error.LimitExceeded, session.encode(&packets));

    var oversized: [64]u8 = undefined;
    try testing.expectError(error.LimitExceeded, session.encodeOne(support.packet(&oversized, 1020, &([_]u8{7} ** 32))));
}

test "an oversized frame is refused before it is copied" {
    const tight: bedwire.Limits = .{ .max_frame_bytes = 32, .max_batch_bytes = 64, .max_packet_bytes = 32 };

    var pool = try bedwire.BufferPool.init(testing.allocator, tight, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try support.Session.init(testing.allocator, .server, .{ .pool = &pool, .limits = tight });
    defer session.deinit();
    session.state = .in_game;

    var frame: [64]u8 = undefined;
    frame[0] = 0xfe;
    @memset(frame[1..], 1);

    try testing.expectError(error.LimitExceeded, session.ingest(&frame));
}

test "output that cannot fit a frame fails instead of truncating" {
    const tight: bedwire.Limits = .{ .max_frame_bytes = 48, .max_batch_bytes = 4096, .max_packet_bytes = 4096 };

    var pool = try bedwire.BufferPool.init(testing.allocator, tight, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try support.Session.init(testing.allocator, .server, .{ .pool = &pool, .limits = tight });
    defer session.deinit();
    session.state = .in_game;

    var storage: [256]u8 = undefined;
    const payload = [_]u8{0xa5} ** 200;

    try testing.expectError(error.NoSpaceLeft, session.encodeOne(support.packet(&storage, 1020, &payload)));
    try testing.expectEqual(bedwire.State.in_game, session.state);
}

test "invalid packet headers are refused on both paths" {
    var pair = try support.Pair.init(testing.allocator, support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    // 0x4000 and above does not fit the 14-bit header
    try testing.expectError(error.MalformedBatch, pair.client.encodeOne(&.{ 0x80, 0x80, 0x02 }));
    try testing.expectError(error.MalformedBatch, pair.server.ingest(&.{ 0xfe, 3, 0x80, 0x80, 0x02 }));
}

test "packet iteration can be replayed and reports semantic identity" {
    var pair = try support.Pair.init(testing.allocator, support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var first: [16]u8 = undefined;
    var second: support.Builder = .{};
    const disconnect_id = support.packetId(support.modern, .disconnect);

    var packets = try pair.clientToServer(&.{
        support.packet(&first, 1020, "a"),
        second.make(support.modern, .disconnect),
    });
    defer packets.deinit();

    try testing.expectEqual(null, packets.next().?.kind);
    const disconnect = packets.next().?;
    try testing.expectEqual(bedwire.PacketKind.disconnect, disconnect.kind);
    try testing.expectEqual(disconnect_id, disconnect.id);

    packets.reset();
    try testing.expectEqual(null, packets.next().?.kind);
}

const Link = struct {
    pool: *bedwire.BufferPool,
    server: support.Session,
    client: support.Session,
    storage: [4][32]u8 = undefined,

    fn init(pool: *bedwire.BufferPool) !Link {
        return .{
            .pool = pool,
            .server = try gameSession(testing.allocator, pool, .server),
            .client = try gameSession(testing.allocator, pool, .client),
        };
    }

    fn deinit(self: *Link) void {
        self.server.deinit();
        self.client.deinit();
    }

    /// Encodes one opaque packet per payload on the client; the frame is held until released.
    fn frame(self: *Link, payloads: []const []const u8) !support.Session.Frame {
        var packets: [4][]const u8 = undefined;
        for (payloads, 0..) |payload, i| packets[i] = support.packet(&self.storage[i], 1020 + @as(u16, @intCast(i)), payload);
        return self.client.encode(packets[0..payloads.len]);
    }
};

const none: ?support.Session.Packet = null;

test "an iterator keeps its lease past EOF and copies never touch a newer lease" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var link = try Link.init(&pool);
    defer link.deinit();

    const first = try link.frame(&.{ "packet_one", "packet_two" });
    var packets = try link.server.ingest(first.bytes);
    var copy = packets;
    first.release();

    for ([_]*support.Session.Packets{ &packets, &copy }) |iterator| {
        try testing.expectEqualStrings("packet_one", iterator.next().?.bytes[2..]);
        try testing.expectEqual(@as(u10, 1021), iterator.next().?.id);
        try testing.expectEqual(none, iterator.next());
    }
    try testing.expect(link.server.rx_slot != null);

    const second = try link.frame(&.{"second_batch"});
    defer second.release();
    try testing.expectError(error.InvalidState, link.server.ingest(second.bytes));

    packets.deinit();
    packets.deinit();
    try testing.expectEqual(@as(?u64, null), link.server.active_generation);
    try testing.expect(link.server.rx_slot == null);

    var next = try link.server.ingest(second.bytes);
    defer next.deinit();
    const generation = link.server.active_generation.?;

    copy.reset();
    try testing.expectEqual(none, copy.next());
    copy.deinit();
    packets.deinit();
    try testing.expectEqual(generation, link.server.active_generation.?);
    try testing.expectEqualStrings("second_batch", next.next().?.bytes[2..]);
}

test "reset rewinds until EOF and a nested ingest leaves the outer batch intact" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var link = try Link.init(&pool);
    defer link.deinit();

    const outer_frame = try link.frame(&.{ "a", "b" });
    var outer = try link.server.ingest(outer_frame.bytes);
    defer outer.deinit();
    outer_frame.release();

    try testing.expectEqual(@as(u10, 1020), outer.next().?.id);
    outer.reset();
    try testing.expectEqual(@as(u10, 1020), outer.next().?.id);

    const nested = try link.frame(&.{"nested"});
    try testing.expectError(error.InvalidState, link.server.ingest(nested.bytes));
    nested.release();
    try testing.expectEqual(bedwire.State.in_game, link.server.state);

    try testing.expectEqual(@as(u10, 1021), outer.next().?.id);
    try testing.expectEqual(none, outer.next());
    outer.reset();
    try testing.expectEqual(none, outer.next());
}

test "close stops iteration but keeps the RX lease until deinit" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var link = try Link.init(&pool);
    defer link.deinit();

    const frame = try link.frame(&.{ "a", "b" });
    defer frame.release();
    var packets = try link.server.ingest(frame.bytes);
    const held = packets.next().?;

    link.server.close();
    try testing.expect(link.server.rx_slot != null);
    try testing.expectEqualStrings("a", held.bytes[2..]);
    try testing.expectEqual(none, packets.next());
    packets.reset();
    try testing.expectEqual(none, packets.next());

    packets.deinit();
    try testing.expect(link.server.rx_slot == null);
}

test "a held frame blocks encoding and a stale release cannot free its successor" {
    const tight: bedwire.Limits = .{ .max_frame_bytes = 48, .max_batch_bytes = 4096, .max_packet_bytes = 4096 };
    var pool = try bedwire.BufferPool.init(testing.allocator, tight, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();

    var session = try support.Session.init(testing.allocator, .server, .{ .pool = &pool, .limits = tight });
    defer session.deinit();
    session.state = .in_game;

    var small: [16]u8 = undefined;
    var large: [256]u8 = undefined;
    const oversized = support.packet(&large, 1020, &([_]u8{0xa5} ** 200));

    const first = try session.encode(&.{support.packet(&small, 1020, "ok")});
    try testing.expectError(error.PoolExhausted, session.encodeOne(oversized));
    first.release();
    try testing.expectError(error.NoSpaceLeft, session.encodeOne(oversized));
    try testing.expect(session.tx_slot == null);

    const second = try session.encode(&.{support.packet(&small, 1020, "ok")});
    defer second.release();
    first.release();
    try testing.expect(session.tx_slot != null);
}

test "fatal framing error consumes no pool slot and closes session" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    const token = try pool.acquireRx();
    defer pool.releaseRx(token);

    try testing.expectError(error.MalformedBatch, session.ingest(&.{}));
    try testing.expectEqual(bedwire.State.disconnected, session.state);

    const other_token = try pool.acquireRx();
    pool.releaseRx(other_token);
}

test "PoolExhausted is non-fatal and leaves session state intact" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    var client = try gameSession(testing.allocator, &pool, .client);
    defer client.deinit();

    const rx_token = try pool.acquireRx();
    defer pool.releaseRx(rx_token);

    var storage: [16]u8 = undefined;
    const frame = try client.encode(&.{support.packet(&storage, 1020, "x")});

    try testing.expectError(error.PoolExhausted, session.ingest(frame.bytes));
    frame.release();
    try testing.expectEqual(bedwire.State.in_game, session.state);

    const tx_token = try pool.acquireTx();
    defer pool.releaseTx(tx_token);

    try testing.expectError(error.PoolExhausted, session.encode(&.{support.packet(&storage, 1020, "x")}));
    try testing.expectEqual(bedwire.State.in_game, session.state);
}

test "encode failure on fresh TX acquisition releases slot" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    try testing.expect(pool.isIdle());
    try testing.expectError(error.MalformedBatch, session.encode(&.{}));
    try testing.expect(session.tx_slot == null);
    try testing.expect(pool.isIdle());
}

test "post-acquisition ingest failure releases RX slot and disconnects session" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();
    try session.compression.negotiate(.deflate, 0);

    const malformed = [_]u8{ 0xfe, @intFromEnum(bedwire.compression.Algorithm.deflate), 0x78, 0x9c, 0xff, 0xff };
    try testing.expectError(error.MalformedCompressedData, session.ingest(&malformed));

    try testing.expectEqual(bedwire.State.disconnected, session.state);
    try testing.expect(pool.isIdle());
}
