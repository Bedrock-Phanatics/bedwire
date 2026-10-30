const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const Algorithm = bedwire.compression.Algorithm;

fn negotiated(allocator: std.mem.Allocator, algorithm: Algorithm, threshold: u16) !support.PairFor(support.modern) {
    var pair = try support.Pair.init(allocator, support.modern);
    errdefer pair.deinit();

    try pair.server.compression.negotiate(algorithm, threshold);
    try pair.client.compression.negotiate(algorithm, threshold);
    pair.server.state = .in_game;
    pair.client.state = .in_game;

    return pair;
}

fn roundTrip(pair: *support.PairFor(support.modern), payload: []const u8) !void {
    var storage: [8192]u8 = undefined;
    const packet = support.packet(&storage, support.opaque_packet_id, payload);

    var packets = try pair.clientToServer(&.{packet});
    defer packets.deinit();
    try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
    try testing.expectEqual(@as(?support.Session.Packet, null), packets.next());
}

test "every algorithm round-trips compressible and incompressible payloads" {
    var random = std.Random.DefaultPrng.init(0xbed016);
    var noise: [1024]u8 = undefined;
    random.random().bytes(&noise);

    for ([_]Algorithm{ .deflate, .snappy }) |algorithm| {
        var pair = try negotiated(testing.allocator, algorithm, 0);
        defer pair.deinit();

        try roundTrip(&pair, "a");
        try roundTrip(&pair, &@as([2048]u8, @splat('z')));
        try roundTrip(&pair, &noise);
    }
}

test "the threshold decides per batch and both sides agree" {
    for ([_]Algorithm{ .deflate, .snappy }) |algorithm| {
        var pair = try negotiated(testing.allocator, algorithm, 64);
        defer pair.deinit();

        var storage: [256]u8 = undefined;

        const small = support.packet(&storage, support.opaque_packet_id, &@as([16]u8, @splat('a')));
        const small_frame = try pair.client.encode(&.{small});
        defer small_frame.release();
        try testing.expectEqual(@as(u8, 0xff), small_frame.bytes[1]);
        small_frame.release();

        var big_storage: [256]u8 = undefined;
        const big = support.packet(&big_storage, support.opaque_packet_id, &@as([96]u8, @splat('a')));
        const big_frame = try pair.client.encode(&.{big});
        defer big_frame.release();
        try testing.expectEqual(@backingInt(algorithm), big_frame.bytes[1]);
        big_frame.release();

        try roundTrip(&pair, &@as([16]u8, @splat('a')));
        try roundTrip(&pair, &@as([96]u8, @splat('a')));
    }
}

test "an unexpected algorithm marker is refused" {
    var pair = try negotiated(testing.allocator, .snappy, 0);
    defer pair.deinit();

    var storage: [128]u8 = undefined;
    const frame = try pair.client.encode(&.{support.packet(&storage, support.opaque_packet_id, &@as([64]u8, @splat('a')))});
    defer frame.release();
    @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
    const captured = pair.relay[0..frame.bytes.len];

    captured[1] = @backingInt(Algorithm.deflate);
    try testing.expectError(error.UnexpectedCompression, pair.server.ingest(captured));
    try testing.expectEqual(bedwire.State.disconnected, pair.server.state);
}

test "an unknown algorithm marker is refused" {
    var pair = try negotiated(testing.allocator, .deflate, 0);
    defer pair.deinit();

    try testing.expectError(error.UnsupportedCompression, pair.server.ingest(&.{ 0xfe, 0x07, 1, 2, 3 }));
}

test "a version that does not support Snappy refuses to negotiate it" {
    const Profile = support.Profile(818, .{ .supports_snappy = false, .login_flow = .certificate_chain });

    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var session = try bedwire.SessionWithProfile(Profile).init(.server, .{ .pool = &pool, .limits = support.limits });
    defer session.deinit();

    try testing.expectError(error.UnsupportedCompression, session.compression.negotiate(.snappy, 0));
    try session.compression.negotiate(.deflate, 0);
    try testing.expectError(error.InvalidState, session.compression.negotiate(.deflate, 0));
}

test "malformed compressed streams are rejected" {
    for ([_]Algorithm{ .deflate, .snappy }) |algorithm| {
        var pair = try negotiated(testing.allocator, algorithm, 0);
        defer pair.deinit();

        var storage: [1024]u8 = undefined;
        const frame = try pair.client.encode(&.{support.packet(&storage, support.opaque_packet_id, &@as([512]u8, @splat('q')))});
        defer frame.release();
        @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
        const captured = pair.relay[0..frame.bytes.len];

        for (captured[2..]) |*byte| byte.* ^= 0xa5;

        const result = pair.server.ingest(captured);
        try testing.expectError(error.MalformedCompressedData, result);
        try testing.expectEqual(bedwire.State.disconnected, pair.server.state);
    }
}

test "truncated compressed streams are rejected" {
    for ([_]Algorithm{ .deflate, .snappy }) |algorithm| {
        var pair = try negotiated(testing.allocator, algorithm, 0);
        defer pair.deinit();

        var storage: [1024]u8 = undefined;
        const frame = try pair.client.encode(&.{support.packet(&storage, support.opaque_packet_id, &@as([512]u8, @splat('q')))});
        defer frame.release();
        @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
        const captured = pair.relay[0 .. frame.bytes.len - 4];

        try testing.expectError(error.MalformedCompressedData, pair.server.ingest(captured));
    }
}

test "a DEFLATE bomb is bounded by the batch limit, not by memory" {
    const tight: bedwire.Limits = .{ .max_frame_bytes = 4096, .max_batch_bytes = 4096, .max_packet_bytes = 4096 };

    var history: [bedwire.compression.flate.history_len]u8 = undefined;
    var compressed: [4096]u8 = undefined;
    const bomb = try bedwire.compression.flate.compress(&@as([65536]u8, @splat(0)), &compressed, &history);

    var pool = try bedwire.BufferPool.init(testing.allocator, tight, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var session = try support.Session.init(.server, .{ .pool = &pool, .limits = tight });
    defer session.deinit();
    session.state = .in_game;
    try session.compression.negotiate(.deflate, 0);

    var frame: [4096]u8 = undefined;
    frame[0] = 0xfe;
    frame[1] = @backingInt(Algorithm.deflate);
    @memcpy(frame[2..][0..bomb.len], bomb);

    try testing.expectError(error.LimitExceeded, session.ingest(frame[0 .. 2 + bomb.len]));
    try testing.expectEqual(bedwire.State.disconnected, session.state);
}

test "a Snappy bomb is refused on its advertised length alone" {
    const tight: bedwire.Limits = .{ .max_frame_bytes = 4096, .max_batch_bytes = 1024, .max_packet_bytes = 1024 };

    var pool = try bedwire.BufferPool.init(testing.allocator, tight, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var session = try support.Session.init(.server, .{ .pool = &pool, .limits = tight });
    defer session.deinit();
    session.state = .in_game;
    try session.compression.negotiate(.snappy, 0);

    const frame = [_]u8{ 0xfe, @backingInt(Algorithm.snappy), 0x80, 0x80, 0x80, 0x08, 0x00, 0x41 };
    try testing.expectError(error.LimitExceeded, session.ingest(&frame));
}

test "compression that cannot beat the frame limit fails cleanly" {
    const tight: bedwire.Limits = .{ .max_frame_bytes = 64, .max_batch_bytes = 8192, .max_packet_bytes = 8192 };

    for ([_]Algorithm{ .deflate, .snappy }) |algorithm| {
        var pool = try bedwire.BufferPool.init(testing.allocator, tight, .{ .rx_slots = 2, .tx_slots = 2 });
        defer pool.deinit();
        var session = try support.Session.init(.server, .{ .pool = &pool, .limits = tight });
        defer session.deinit();
        session.state = .in_game;
        try session.compression.negotiate(algorithm, 0);

        var random = std.Random.DefaultPrng.init(7);
        var noise: [4096]u8 = undefined;
        random.random().bytes(&noise);

        var storage: [8192]u8 = undefined;
        try testing.expectError(error.NoSpaceLeft, session.encodeOne(support.packet(&storage, support.opaque_packet_id, &noise)));
        try testing.expectEqual(bedwire.State.in_game, session.state);
    }
}

test "Snappy carries batches larger than the frame limit when they compress" {
    var pair = try support.Pair.init(testing.allocator, support.modern);
    defer pair.deinit();

    try pair.client.compression.negotiate(.snappy, 0);
    try pair.server.compression.negotiate(.snappy, 0);
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [8192]u8 = undefined;
    const packet = support.packet(&storage, support.opaque_packet_id, &@as([4096]u8, @splat('a')));

    const frame = try pair.client.encode(&.{packet});
    defer frame.release();
    try testing.expect(frame.bytes.len < 256);

    @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
    var packets = try pair.server.ingest(pair.relay[0..frame.bytes.len]);
    defer packets.deinit();
    try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
}

test "implicit compression mode carries no marker byte" {
    var pair = try support.Pair.init(testing.allocator, support.legacy);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [256]u8 = undefined;
    const packet = support.packet(&storage, support.opaque_packet_id, &@as([64]u8, @splat('a')));

    const frame = try pair.client.encode(&.{packet});
    defer frame.release();
    try testing.expect(!pair.client.compression.marks());
    try testing.expectEqual(bedwire.compression.Algorithm.deflate, pair.client.compression.selected(1));

    @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
    var packets = try pair.server.ingest(pair.relay[0..frame.bytes.len]);
    defer packets.deinit();
    try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
}

test "an absent compression mode never compresses" {
    const Profile = support.Profile(818, .{
        .compression_mode = .absent,
        .initial_algorithm = .none,
        .login_flow = .certificate_chain,
    });

    var pair = try support.Pair.init(testing.allocator, Profile);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [256]u8 = undefined;
    const packet = support.packet(&storage, support.opaque_packet_id, &@as([128]u8, @splat('a')));

    const frame = try pair.client.encode(&.{packet});
    defer frame.release();
    const expected = 1 + bedwire.framing.varint.sizeU32(@intCast(packet.len)) + packet.len;
    try testing.expectEqual(expected, frame.bytes.len);

    @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
    var packets = try pair.server.ingest(pair.relay[0..frame.bytes.len]);
    defer packets.deinit();
    try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
}

test "every DEFLATE level round-trips and out-of-range levels are refused" {
    for ([_]u4{ 0, 10 }) |level| {
        try testing.expectError(error.InvalidLimits, bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1, .deflate_level = level }));
    }

    var payload: [2048]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i / 7 + i % 5);
    var storage: [4096]u8 = undefined;
    const packet = support.packet(&storage, support.opaque_packet_id, &payload);

    for (1..10) |level| {
        var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1, .deflate_level = @intCast(level) });
        defer pool.deinit();
        var sender = try support.Session.init(.client, .{ .pool = &pool });
        defer sender.deinit();
        var receiver = try support.Session.init(.server, .{ .pool = &pool });
        defer receiver.deinit();
        for ([_]*support.Session{ &sender, &receiver }) |session| {
            try session.compression.negotiate(.deflate, 0);
            session.state = .in_game;
        }

        var copy: [4096]u8 = undefined;
        const frame = try sender.encodeOne(packet);
        const sent = copy[0..frame.bytes.len];
        @memcpy(sent, frame.bytes);
        frame.release();
        try testing.expect(sent.len < packet.len);

        var packets = try receiver.ingest(sent);
        defer packets.deinit();
        try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
    }
}

test "clients get a smaller frame limit until they are in game" {
    const limits: bedwire.Limits = .{ .max_frame_bytes = 4096, .max_batch_bytes = 4096, .max_packet_bytes = 4096, .max_handshake_frame_bytes = 64 };

    var pool = try bedwire.BufferPool.init(testing.allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var session = try support.Session.init(.server, .{ .pool = &pool, .limits = limits });
    defer session.deinit();

    var frame: [128]u8 = @splat(0);
    frame[0] = 0xfe;
    try testing.expectError(error.LimitExceeded, session.ingest(&frame));
    try testing.expectEqual(bedwire.State.disconnected, session.state);
}
