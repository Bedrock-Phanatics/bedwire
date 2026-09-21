const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const Algorithm = bedwire.compression.Algorithm;

/// A negotiated pair already in gameplay, so only compression is under test
fn negotiated(allocator: std.mem.Allocator, algorithm: Algorithm, threshold: u16) !support.Pair {
    var pair = try support.Pair.init(allocator, &support.modern);
    errdefer pair.deinit();

    try pair.server.compression.negotiate(algorithm, threshold);
    try pair.client.compression.negotiate(algorithm, threshold);
    pair.server.state = .in_game;
    pair.client.state = .in_game;

    return pair;
}

fn roundTrip(pair: *support.Pair, payload: []const u8) !void {
    var storage: [8192]u8 = undefined;
    const packet = support.packet(&storage, 60, payload);

    var packets = try pair.clientToServer(&.{packet});
    defer packets.deinit();
    try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
    try testing.expectEqual(@as(?bedwire.Packet, null), packets.next());
}

test "every algorithm round-trips compressible and incompressible payloads" {
    var random = std.Random.DefaultPrng.init(0xbed016);
    var noise: [1024]u8 = undefined;
    random.random().bytes(&noise);

    for ([_]Algorithm{ .deflate, .snappy }) |algorithm| {
        var pair = try negotiated(testing.allocator, algorithm, 0);
        defer pair.deinit();

        try roundTrip(&pair, "a");
        try roundTrip(&pair, &([_]u8{'z'} ** 2048));
        try roundTrip(&pair, &noise);
    }
}

test "the threshold decides per batch and both sides agree" {
    for ([_]Algorithm{ .deflate, .snappy }) |algorithm| {
        var pair = try negotiated(testing.allocator, algorithm, 64);
        defer pair.deinit();

        var storage: [256]u8 = undefined;

        // under threshold uses uncompressed marker 0xff
        const small = support.packet(&storage, 60, &([_]u8{'a'} ** 16));
        const small_frame = try pair.client.encode(&.{small});
        defer small_frame.release();
        try testing.expectEqual(@as(u8, 0xff), small_frame.bytes[1]);

        // at or above threshold uses negotiated algorithm marker
        var big_storage: [256]u8 = undefined;
        const big = support.packet(&big_storage, 60, &([_]u8{'a'} ** 96));
        const big_frame = try pair.client.encode(&.{big});
        defer big_frame.release();
        try testing.expectEqual(@intFromEnum(algorithm), big_frame.bytes[1]);

        try roundTrip(&pair, &([_]u8{'a'} ** 16));
        try roundTrip(&pair, &([_]u8{'a'} ** 96));
    }
}

test "an unexpected algorithm marker is refused" {
    var pair = try negotiated(testing.allocator, .snappy, 0);
    defer pair.deinit();

    var storage: [128]u8 = undefined;
    const frame = try pair.client.encode(&.{support.packet(&storage, 60, &([_]u8{'a'} ** 64))});
    defer frame.release();
    @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
    const captured = pair.relay[0..frame.bytes.len];

    captured[1] = @intFromEnum(Algorithm.deflate);
    try testing.expectError(error.UnexpectedCompression, pair.server.ingest(captured));
    try testing.expectEqual(bedwire.State.disconnected, pair.server.state);
}

test "an unknown algorithm marker is refused" {
    var pair = try negotiated(testing.allocator, .deflate, 0);
    defer pair.deinit();

    try testing.expectError(error.UnsupportedCompression, pair.server.ingest(&.{ 0xfe, 0x07, 1, 2, 3 }));
}

test "a version that does not support Snappy refuses to negotiate it" {
    const descriptor: bedwire.Descriptor = comptime bedwire.protocol.describeWith(818, .{ .supports_snappy = false }) catch unreachable;

    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var session = try bedwire.Session.init(testing.allocator, .server, &descriptor, .{ .pool = &pool, .limits = support.limits });
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
        const frame = try pair.client.encode(&.{support.packet(&storage, 60, &([_]u8{'q'} ** 512))});
        defer frame.release();
        @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
        const captured = pair.relay[0..frame.bytes.len];

        // corrupt compressed body without touching marker
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
        const frame = try pair.client.encode(&.{support.packet(&storage, 60, &([_]u8{'q'} ** 512))});
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
    const bomb = try bedwire.compression.flate.compress(&([_]u8{0} ** 65536), &compressed, &history);

    var pool = try bedwire.BufferPool.init(testing.allocator, tight, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var session = try bedwire.Session.init(testing.allocator, .server, &support.modern, .{ .pool = &pool, .limits = tight });
    defer session.deinit();
    session.state = .in_game;
    try session.compression.negotiate(.deflate, 0);

    var frame: [4096]u8 = undefined;
    frame[0] = 0xfe;
    frame[1] = @intFromEnum(Algorithm.deflate);
    @memcpy(frame[2..][0..bomb.len], bomb);

    try testing.expectError(error.LimitExceeded, session.ingest(frame[0 .. 2 + bomb.len]));
    try testing.expectEqual(bedwire.State.disconnected, session.state);
}

test "a Snappy bomb is refused on its advertised length alone" {
    const tight: bedwire.Limits = .{ .max_frame_bytes = 4096, .max_batch_bytes = 1024, .max_packet_bytes = 1024 };

    var pool = try bedwire.BufferPool.init(testing.allocator, tight, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var session = try bedwire.Session.init(testing.allocator, .server, &support.modern, .{ .pool = &pool, .limits = tight });
    defer session.deinit();
    session.state = .in_game;
    try session.compression.negotiate(.snappy, 0);

    // a varint advertising 16 MiB followed by a single literal token
    const frame = [_]u8{ 0xfe, @intFromEnum(Algorithm.snappy), 0x80, 0x80, 0x80, 0x08, 0x00, 0x41 };
    try testing.expectError(error.LimitExceeded, session.ingest(&frame));
}

test "compression that cannot beat the frame limit fails cleanly" {
    const tight: bedwire.Limits = .{ .max_frame_bytes = 64, .max_batch_bytes = 8192, .max_packet_bytes = 8192 };

    for ([_]Algorithm{ .deflate, .snappy }) |algorithm| {
        var pool = try bedwire.BufferPool.init(testing.allocator, tight, .{ .rx_slots = 2, .tx_slots = 2 });
        defer pool.deinit();
        var session = try bedwire.Session.init(testing.allocator, .server, &support.modern, .{ .pool = &pool, .limits = tight });
        defer session.deinit();
        session.state = .in_game;
        try session.compression.negotiate(algorithm, 0);

        var random = std.Random.DefaultPrng.init(7);
        var noise: [4096]u8 = undefined;
        random.random().bytes(&noise);

        var storage: [8192]u8 = undefined;
        try testing.expectError(error.NoSpaceLeft, session.encodeOne(support.packet(&storage, 60, &noise)));
        try testing.expectEqual(bedwire.State.in_game, session.state);
    }
}

test "Snappy carries batches larger than the frame limit when they compress" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    try pair.client.compression.negotiate(.snappy, 0);
    try pair.server.compression.negotiate(.snappy, 0);
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [8192]u8 = undefined;
    const packet = support.packet(&storage, 60, &([_]u8{'a'} ** 4096));

    const frame = try pair.client.encode(&.{packet});
    defer frame.release();
    try testing.expect(frame.bytes.len < 256);

    @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
    var packets = try pair.server.ingest(pair.relay[0..frame.bytes.len]);
    defer packets.deinit();
    try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
}

test "implicit compression mode carries no marker byte" {
    var pair = try support.Pair.init(testing.allocator, &support.legacy);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [256]u8 = undefined;
    const packet = support.packet(&storage, 60, &([_]u8{'a'} ** 64));

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
    const descriptor: bedwire.Descriptor = comptime bedwire.protocol.describeWith(818, .{
        .compression_mode = .absent,
        .initial_algorithm = .none,
    }) catch unreachable;

    var pair = try support.Pair.init(testing.allocator, &descriptor);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [256]u8 = undefined;
    const packet = support.packet(&storage, 60, &([_]u8{'a'} ** 128));

    const frame = try pair.client.encode(&.{packet});
    defer frame.release();
    const expected = 1 + bedwire.framing.varint.sizeU32(@intCast(packet.len)) + packet.len;
    try testing.expectEqual(expected, frame.bytes.len);

    @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
    var packets = try pair.server.ingest(pair.relay[0..frame.bytes.len]);
    defer packets.deinit();
    try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
}
