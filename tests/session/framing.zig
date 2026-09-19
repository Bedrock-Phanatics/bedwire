const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;

fn gameSession(allocator: std.mem.Allocator, role: bedwire.Role) !bedwire.Session {
    var session = try bedwire.Session.init(allocator, role, &support.modern, .{ .limits = support.limits });
    session.state = .in_game;
    return session;
}

test "frames must carry the session header" {
    var session = try gameSession(testing.allocator, .server);
    defer session.deinit();

    try testing.expectError(error.MalformedBatch, session.ingest(&.{}));
    try testing.expectEqual(bedwire.State.disconnected, session.state);

    var other = try gameSession(testing.allocator, .server);
    defer other.deinit();
    try testing.expectError(error.MalformedBatch, other.ingest(&.{ 0xfd, 2, 60, 0 }));
}

test "empty batches are refused in both directions" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
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
        &.{ 0xfe, 2, 60, 1, 5 }, // trailing prefix with no payload
    };

    for (cases) |frame| {
        var session = try gameSession(testing.allocator, .server);
        defer session.deinit();

        try testing.expectError(error.MalformedBatch, session.ingest(frame));
        try testing.expectEqual(bedwire.State.disconnected, session.state);
    }
}

test "a batch that smuggles one illegal packet delivers none of them" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var legal: [16]u8 = undefined;
    var illegal: [16]u8 = undefined;
    const login_id = support.idOf(&support.modern, .login);

    // Encode a mixed batch while the state machine still permits both, then
    // deliver it to a session that does not.
    pair.client.state = .spawn_ready;
    const frame = try pair.client.encode(&.{
        support.packet(&legal, 60, "ok"),
        support.packet(&illegal, 61, "ok"),
    });
    @memcpy(pair.relay[0..frame.len], frame);
    const captured = pair.relay[0..frame.len];

    pair.server.state = .resource_packs;
    try testing.expectError(error.InvalidState, pair.server.ingest(captured));
    try testing.expectEqual(bedwire.State.disconnected, pair.server.state);
    try testing.expect(login_id != 60);
}

test "packet count and packet size limits bound one batch" {
    const tight: bedwire.Limits = .{
        .max_frame_bytes = 4096,
        .max_batch_bytes = 4096,
        .max_packet_bytes = 16,
        .max_packets_per_batch = 3,
    };

    var session = try bedwire.Session.init(testing.allocator, .server, &support.modern, .{ .limits = tight });
    defer session.deinit();
    session.state = .in_game;

    var storage: [4][32]u8 = undefined;
    var packets: [4][]const u8 = undefined;
    for (&packets, 0..) |*slot, i| slot.* = support.packet(&storage[i], 60 + @as(u16, @intCast(i)), "x");

    _ = try session.encode(packets[0..3]);
    try testing.expectError(error.LimitExceeded, session.encode(&packets));

    var oversized: [64]u8 = undefined;
    try testing.expectError(error.LimitExceeded, session.encodeOne(support.packet(&oversized, 60, &([_]u8{7} ** 32))));
}

test "an oversized frame is refused before it is copied" {
    const tight: bedwire.Limits = .{ .max_frame_bytes = 32, .max_batch_bytes = 64, .max_packet_bytes = 32 };

    var session = try bedwire.Session.init(testing.allocator, .server, &support.modern, .{ .limits = tight });
    defer session.deinit();
    session.state = .in_game;

    var frame: [64]u8 = undefined;
    frame[0] = 0xfe;
    @memset(frame[1..], 1);

    try testing.expectError(error.LimitExceeded, session.ingest(&frame));
}

test "output that cannot fit a frame fails instead of truncating" {
    const tight: bedwire.Limits = .{ .max_frame_bytes = 48, .max_batch_bytes = 4096, .max_packet_bytes = 4096 };

    var session = try bedwire.Session.init(testing.allocator, .server, &support.modern, .{ .limits = tight });
    defer session.deinit();
    session.state = .in_game;

    var storage: [256]u8 = undefined;
    const payload = [_]u8{0xa5} ** 200;

    try testing.expectError(error.NoSpaceLeft, session.encodeOne(support.packet(&storage, 60, &payload)));
    try testing.expectEqual(bedwire.State.in_game, session.state);
}

test "invalid packet headers are refused on both paths" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    // 0x4000 and above does not fit the 14-bit header.
    try testing.expectError(error.MalformedBatch, pair.client.encodeOne(&.{ 0x80, 0x80, 0x02 }));
    try testing.expectError(error.MalformedBatch, pair.server.ingest(&.{ 0xfe, 3, 0x80, 0x80, 0x02 }));
}

test "packet iteration can be replayed and reports semantic identity" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var first: [16]u8 = undefined;
    var second: [16]u8 = undefined;
    const disconnect_id = support.idOf(&support.modern, .disconnect);

    var packets = try pair.clientToServer(&.{
        support.packet(&first, 60, "a"),
        support.packet(&second, disconnect_id, "b"),
    });

    try testing.expectEqual(bedwire.PacketKind.other, packets.next().?.kind);
    const disconnect = packets.next().?;
    try testing.expectEqual(bedwire.PacketKind.disconnect, disconnect.kind);
    try testing.expectEqual(disconnect_id, disconnect.id);
    try testing.expectEqual(@as(?bedwire.Packet, null), packets.next());

    packets.reset();
    try testing.expectEqual(bedwire.PacketKind.other, packets.next().?.kind);
}
