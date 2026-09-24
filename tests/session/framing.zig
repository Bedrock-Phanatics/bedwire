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

    // encode a mixed batch while the state machine permits both
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

    // reset while active rewinds to beginning
    packets.reset();
    try testing.expectEqual(null, packets.next().?.kind);
}

test "exhaust -> deinit -> new ingest" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    var storage1: [16]u8 = undefined;
    var storage2: [16]u8 = undefined;

    var client = try gameSession(testing.allocator, &pool, .client);
    defer client.deinit();
    const frame1 = try client.encode(&.{support.packet(&storage1, 1020, "p1")});
    defer frame1.release();

    var iter1 = try session.ingest(frame1.bytes);
    try testing.expect(session.active_generation != null);
    const p1 = iter1.next().?;
    try testing.expectEqual(null, p1.kind);
    try testing.expectEqual(@as(?support.Session.Packet, null), iter1.next());

    // EOF preserves RX storage and active ownership until deinit
    try testing.expect(session.active_generation != null);
    try testing.expectEqualStrings("p1", p1.bytes[p1.bytes.len - 2 ..]);

    // new ingest rejected while EOF iterator still active
    frame1.release();
    const frame2 = try client.encode(&.{support.packet(&storage2, 1020, "p2")});
    defer frame2.release();
    try testing.expectError(error.InvalidState, session.ingest(frame2.bytes));

    // deinit releases the RX lease
    iter1.deinit();
    try testing.expectEqual(@as(?u64, null), session.active_generation);

    var iter2 = try session.ingest(frame2.bytes);
    defer iter2.deinit();
    try testing.expect(session.active_generation != null);
    try testing.expectEqual(null, iter2.next().?.kind);
    try testing.expectEqual(@as(?support.Session.Packet, null), iter2.next());
}

test "double deinit" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    var client = try gameSession(testing.allocator, &pool, .client);
    defer client.deinit();

    var storage: [16]u8 = undefined;
    const frame1 = try client.encode(&.{support.packet(&storage, 1020, "p1")});
    defer frame1.release();

    var iter1 = try session.ingest(frame1.bytes);
    try testing.expect(session.active_generation != null);

    iter1.deinit();
    try testing.expectEqual(@as(?u64, null), session.active_generation);

    // second deinit is safe no-op
    iter1.deinit();
    try testing.expectEqual(@as(?u64, null), session.active_generation);

    frame1.release();
    const frame2 = try client.encode(&.{support.packet(&storage, 1020, "p2")});
    defer frame2.release();
    var iter2 = try session.ingest(frame2.bytes);
    defer iter2.deinit();
    const active_gen = session.active_generation.?;

    // stale deinit must not touch newer iterator lease
    iter1.deinit();
    try testing.expectEqual(active_gen, session.active_generation.?);

    try testing.expectEqual(null, iter2.next().?.kind);
}

test "old iterator vs newer ingest" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    var client = try gameSession(testing.allocator, &pool, .client);
    defer client.deinit();

    var storage1: [16]u8 = undefined;
    var storage2: [16]u8 = undefined;

    const frame1 = try client.encode(&.{support.packet(&storage1, 1020, "first_batch")});
    defer frame1.release();
    var iter1 = try session.ingest(frame1.bytes);

    var copy1 = iter1;

    iter1.deinit();
    try testing.expectEqual(@as(?u64, null), session.active_generation);

    frame1.release();
    const frame2 = try client.encode(&.{support.packet(&storage2, 1020, "second_batch")});
    defer frame2.release();
    var iter2 = try session.ingest(frame2.bytes);
    defer iter2.deinit();
    const gen2 = session.active_generation.?;

    // old copy cannot read reused buffer
    try testing.expectEqual(@as(?support.Session.Packet, null), copy1.next());

    // stale deinit cannot clear new lease
    copy1.deinit();
    try testing.expectEqual(gen2, session.active_generation.?);

    // stale reset cannot reacquire either
    copy1.reset();
    try testing.expectEqual(gen2, session.active_generation.?);
    try testing.expectEqual(@as(?support.Session.Packet, null), copy1.next());

    const p = iter2.next().?;
    try testing.expectEqual(null, p.kind);
    try testing.expectEqualSlices(u8, support.packet(&storage2, 1020, "second_batch"), p.bytes);
}

test "reset semantics" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    var client = try gameSession(testing.allocator, &pool, .client);
    defer client.deinit();

    var storage1: [16]u8 = undefined;
    var storage2: [16]u8 = undefined;

    const frame1 = try client.encode(&.{
        support.packet(&storage1, 1020, "a"),
        support.packet(&storage2, 1021, "b"),
    });
    defer frame1.release();

    var iter = try session.ingest(frame1.bytes);
    defer iter.deinit();

    // reset while active rewinds to start
    try testing.expectEqual(null, iter.next().?.kind);
    iter.reset();
    try testing.expectEqual(null, iter.next().?.kind);
    try testing.expectEqual(null, iter.next().?.kind);
    try testing.expectEqual(@as(?support.Session.Packet, null), iter.next());

    // reset after EOF is permanently disabled
    iter.reset();
    try testing.expectEqual(@as(?support.Session.Packet, null), iter.next());
}

test "nested ingest rejection without disconnect" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    var client = try gameSession(testing.allocator, &pool, .client);
    defer client.deinit();

    var storage1: [16]u8 = undefined;
    var storage2: [16]u8 = undefined;

    const frame1 = try client.encode(&.{
        support.packet(&storage1, 1020, "p1"),
        support.packet(&storage2, 1021, "p2"),
    });
    defer frame1.release();

    var outer = try session.ingest(frame1.bytes);
    defer outer.deinit();

    const p1 = outer.next().?;
    try testing.expectEqual(null, p1.kind);

    // nested ingest rejected while outer iterator still has the lease
    var storage3: [16]u8 = undefined;
    frame1.release();
    const frame2 = try client.encode(&.{support.packet(&storage3, 1020, "nested")});
    defer frame2.release();
    try testing.expectError(error.InvalidState, session.ingest(frame2.bytes));

    // rejection does not tear down the session
    try testing.expectEqual(bedwire.State.in_game, session.state);
    try testing.expect(session.active_generation != null);

    // outer iterator still works
    const p2 = outer.next().?;
    try testing.expectEqual(null, p2.kind);
    try testing.expectEqual(@as(u10, 1021), p2.id);
    try testing.expectEqual(@as(?support.Session.Packet, null), outer.next());
}

test "close with active Packets stops reads without prematurely freeing RX slot" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    var client = try gameSession(testing.allocator, &pool, .client);
    defer client.deinit();

    var storage1: [16]u8 = undefined;
    var storage2: [16]u8 = undefined;

    const frame = try client.encode(&.{
        support.packet(&storage1, 1020, "a"),
        support.packet(&storage2, support.opaque_packet_id_2, "b"),
    });
    defer frame.release();

    var packets = try session.ingest(frame.bytes);
    const p1 = packets.next().?;
    try testing.expectEqualStrings("a", p1.bytes[p1.bytes.len - 1 ..]);

    // close marks disconnected but retains RX lease
    session.close();
    try testing.expectEqual(bedwire.State.disconnected, session.state);
    try testing.expect(session.active_generation != null);
    try testing.expect(session.rx_slot != null);

    // reads stopped after close
    try testing.expectEqual(@as(?support.Session.Packet, null), packets.next());

    // reset disabled after close
    packets.reset();
    try testing.expectEqual(@as(?support.Session.Packet, null), packets.next());

    packets.deinit();
    try testing.expectEqual(@as(?u64, null), session.active_generation);
    try testing.expect(session.rx_slot == null);
}

test "fatal framing error consumes no pool slot and closes session" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    // acquire one RX slot so only 1 remains free
    const token = try pool.acquireRx();
    defer pool.releaseRx(token);

    // invalid frame rejected before pool acquisition
    try testing.expectError(error.MalformedBatch, session.ingest(&.{}));
    try testing.expectEqual(bedwire.State.disconnected, session.state);

    // remaining slot still available
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

    // exhaust RX pool
    const rx_token = try pool.acquireRx();
    defer pool.releaseRx(rx_token);

    var storage: [16]u8 = undefined;
    const frame = try client.encode(&.{support.packet(&storage, 1020, "x")});

    try testing.expectError(error.PoolExhausted, session.ingest(frame.bytes));
    frame.release();
    // session remains alive and connected
    try testing.expectEqual(bedwire.State.in_game, session.state);

    // exhaust TX pool
    const tx_token = try pool.acquireTx();
    defer pool.releaseTx(tx_token);

    try testing.expectError(error.PoolExhausted, session.encode(&.{support.packet(&storage, 1020, "x")}));
    try testing.expectEqual(bedwire.State.in_game, session.state);
}

test "stale Frame release does not release reused TX slot" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 1 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    var storage: [16]u8 = undefined;
    const p = support.packet(&storage, 1020, "data");

    const frame1 = try session.encode(&.{p});
    frame1.release();

    const frame2 = try session.encode(&.{p});
    defer frame2.release();

    frame1.release();

    try testing.expect(session.tx_slot != null);
}

test "held frame blocks a failing encode until explicitly released" {
    const tight: bedwire.Limits = .{ .max_frame_bytes = 48, .max_batch_bytes = 4096, .max_packet_bytes = 4096 };
    var pool = try bedwire.BufferPool.init(testing.allocator, tight, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();

    var session = try support.Session.init(testing.allocator, .server, .{ .pool = &pool, .limits = tight });
    defer session.deinit();
    session.state = .in_game;

    var storage1: [16]u8 = undefined;
    const frame1 = try session.encode(&.{support.packet(&storage1, 1020, "ok")});

    var storage2: [256]u8 = undefined;
    const oversized = [_]u8{0xa5} ** 200;
    try testing.expectError(error.PoolExhausted, session.encodeOne(support.packet(&storage2, 1020, &oversized)));
    try testing.expect(session.tx_slot != null);
    frame1.release();
    try testing.expectError(error.NoSpaceLeft, session.encodeOne(support.packet(&storage2, 1020, &oversized)));
    try testing.expect(session.tx_slot == null);

    // frame1 release is safe no-op
    frame1.release();
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

test "encode while Packets is active preserves uncorrupted data" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var server = try gameSession(testing.allocator, &pool, .server);
    defer server.deinit();

    var client = try gameSession(testing.allocator, &pool, .client);
    defer client.deinit();

    var client_storage: [16]u8 = undefined;
    const client_packet = support.packet(&client_storage, 1020, "client_msg");
    const client_frame = try client.encode(&.{client_packet});
    defer client_frame.release();

    var packets = try server.ingest(client_frame.bytes);
    defer packets.deinit();

    const p = packets.next().?;
    try testing.expectEqualSlices(u8, client_packet, p.bytes);

    var server_storage: [16]u8 = undefined;
    const server_packet = support.packet(&server_storage, support.opaque_packet_id_2, "server_msg");
    const server_frame = try server.encode(&.{server_packet});
    defer server_frame.release();

    // incoming packet bytes are uncorrupted
    try testing.expectEqualSlices(u8, client_packet, p.bytes);
}

test "copied Packets EOF semantics: cursor-local traversal with generation-scoped storage" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();

    var client = try gameSession(testing.allocator, &pool, .client);
    defer client.deinit();

    var storage1: [16]u8 = undefined;
    var storage2: [16]u8 = undefined;
    const p1_bytes = support.packet(&storage1, 1020, "packet_one");
    const p2_bytes = support.packet(&storage2, support.opaque_packet_id_2, "packet_two");

    const frame = try client.encode(&.{ p1_bytes, p2_bytes });
    defer frame.release();

    var packets = try session.ingest(frame.bytes);
    var copy = packets;

    const first = packets.next().?;
    try testing.expectEqualSlices(u8, p1_bytes, first.bytes);
    const second = packets.next().?;
    try testing.expectEqualSlices(u8, p2_bytes, second.bytes);
    try testing.expectEqual(@as(?support.Session.Packet, null), packets.next());

    try testing.expect(session.active_generation != null);
    try testing.expect(session.rx_slot != null);

    const copy_first = copy.next().?;
    try testing.expectEqualSlices(u8, p1_bytes, copy_first.bytes);
    const copy_second = copy.next().?;
    try testing.expectEqualSlices(u8, p2_bytes, copy_second.bytes);
    try testing.expectEqual(@as(?support.Session.Packet, null), copy.next());

    packets.deinit();
    try testing.expectEqual(@as(?u64, null), session.active_generation);
    try testing.expect(session.rx_slot == null);

    try testing.expectEqual(@as(?support.Session.Packet, null), copy.next());

    var storage3: [16]u8 = undefined;
    frame.release();
    const frame2 = try client.encode(&.{support.packet(&storage3, 1020, "gen2")});
    defer frame2.release();
    var packets2 = try session.ingest(frame2.bytes);
    defer packets2.deinit();
    const gen2 = session.active_generation.?;

    copy.deinit();
    try testing.expectEqual(gen2, session.active_generation.?);
    try testing.expectEqual(@as(?support.Session.Packet, null), copy.next());
    try testing.expect(packets2.next() != null);
}

test "post-acquisition ingest failure releases RX slot and disconnects session" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session = try gameSession(testing.allocator, &pool, .server);
    defer session.deinit();
    try session.compression.negotiate(.deflate, 0);

    // valid framing header 0xfe + deflate marker + corrupt compressed body
    // this passes batch.strip, acquires an rx slot, but fails in decompression
    const malformed = [_]u8{ 0xfe, @intFromEnum(bedwire.compression.Algorithm.deflate), 0x78, 0x9c, 0xff, 0xff };
    try testing.expectError(error.MalformedCompressedData, session.ingest(&malformed));

    try testing.expectEqual(bedwire.State.disconnected, session.state);
    // rx slot released by errdefer, no slot leak
    try testing.expect(pool.isIdle());
}
