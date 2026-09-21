const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;

test "steady-state ingest and encode make no allocator calls" {
    for ([_]bedwire.compression.Algorithm{ .none, .deflate, .snappy }) |algorithm| {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{});
        const allocator = failing.allocator();

        var pair = try support.Pair.init(allocator, &support.modern);
        defer pair.deinit();

        try pair.client.compression.negotiate(if (algorithm == .none) .deflate else algorithm, 0);
        try pair.server.compression.negotiate(if (algorithm == .none) .deflate else algorithm, 0);
        if (algorithm == .none) {
            pair.client.compression.threshold = std.math.maxInt(u16);
            pair.server.compression.threshold = std.math.maxInt(u16);
        }
        pair.client.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
        pair.server.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
        pair.client.state = .in_game;
        pair.server.state = .in_game;

        // Nothing past this point may reach the allocator.
        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;

        var storage: [1024]u8 = undefined;
        const packet = support.packet(&storage, 60, &([_]u8{'g'} ** 512));

        for (0..128) |_| {
            var packets = try pair.clientToServer(&.{packet});
            defer packets.deinit();
            try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
        }

        try testing.expect(!failing.has_induced_failure);
    }
}

fn initCase(allocator: std.mem.Allocator) !void {
    var pool = try bedwire.BufferPool.init(allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 1 });
    defer pool.deinit();
    var session = try bedwire.Session.init(allocator, .server, &support.modern, .{ .pool = &pool });
    session.deinit();
}

test "initialization unwinds every allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, initCase, .{});
}

test "limits are validated before any buffer is reserved" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 1 });
    defer pool.deinit();

    const invalid: bedwire.Limits = .{ .max_frame_bytes = 0 };
    try testing.expectError(error.InvalidLimits, bedwire.Session.init(testing.allocator, .server, &support.modern, .{ .limits = invalid, .pool = &pool }));
}

test "session limits exceeding pool limits are rejected" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 1 });
    defer pool.deinit();

    var excessive = support.limits;
    excessive.max_frame_bytes += 1;

    try testing.expectError(error.IncompatibleLimits, bedwire.Session.init(testing.allocator, .server, &support.modern, .{
        .limits = excessive,
        .pool = &pool,
    }));
}

test "a contradictory descriptor is refused at session start" {
    const broken: bedwire.Descriptor = comptime blk: {
        var descriptor = bedwire.protocol.describe(818) catch unreachable;
        descriptor.features.supports_deflate = false;
        descriptor.features.supports_snappy = false;
        break :blk descriptor;
    };

    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 1 });
    defer pool.deinit();

    try testing.expectError(error.UnsupportedProtocol, bedwire.Session.init(testing.allocator, .server, &broken, .{ .limits = support.limits, .pool = &pool }));
}

test "idle sessions allocate zero eager backing buffers" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 1 });
    defer pool.deinit();

    var counting = std.testing.FailingAllocator.init(testing.allocator, .{});

    var sessions: [500]bedwire.Session = undefined;
    for (&sessions) |*s| {
        s.* = try bedwire.Session.init(counting.allocator(), .server, &support.modern, .{ .pool = &pool });
    }
    defer for (&sessions) |*s| s.deinit();

    try testing.expectEqual(@as(usize, 0), counting.allocated_bytes);
    try testing.expectEqual(@as(usize, 0), counting.allocations);
}

test "ingested packets survive an encode on the same session" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    try pair.client.compression.negotiate(.snappy, 0);
    try pair.server.compression.negotiate(.snappy, 0);
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [512]u8 = undefined;
    const packet = support.packet(&storage, 60, &([_]u8{'r'} ** 256));

    var packets = try pair.clientToServer(&.{packet});
    defer packets.deinit();
    const received = packets.next().?;

    var reply: [64]u8 = undefined;
    const reply_frame = try pair.server.encodeOne(support.packet(&reply, 61, "reply"));
    defer reply_frame.release();

    try testing.expectEqualSlices(u8, packet, received.bytes);
}

test "session max_frame_bytes is enforced when pool limits are larger" {
    var pool_limits = support.limits;
    pool_limits.max_frame_bytes = 4096;
    pool_limits.max_batch_bytes = 4096;
    pool_limits.max_packet_bytes = 4096;

    var pool = try bedwire.BufferPool.init(testing.allocator, pool_limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var session_frame_limits = pool_limits;
    session_frame_limits.max_frame_bytes = 256;

    var session = try bedwire.Session.init(testing.allocator, .server, &support.modern, .{
        .pool = &pool,
        .limits = session_frame_limits,
    });
    defer session.deinit();
    session.state = .in_game;

    var client = try bedwire.Session.init(testing.allocator, .client, &support.modern, .{
        .pool = &pool,
        .limits = pool_limits,
    });
    defer client.deinit();
    client.state = .in_game;

    // 1. TX frame limit: session frame > 256 and < 4096 fails on encode
    var small_buf: [128]u8 = undefined;
    const small_packet = support.packet(&small_buf, 60, &([_]u8{'s'} ** 50));
    const small_frame = try session.encodeOne(small_packet);
    try testing.expect(small_frame.bytes.len <= 256);
    small_frame.release();

    var large_buf: [512]u8 = undefined;
    const large_packet = support.packet(&large_buf, 60, &([_]u8{'l'} ** 300));
    try testing.expectError(error.NoSpaceLeft, session.encodeOne(large_packet));

    // 2. RX frame limit: raw frame > 256 and < 4096 ingested by session fails and closes session
    const client_frame = try client.encodeOne(large_packet);
    defer client_frame.release();
    try testing.expect(client_frame.bytes.len > 256 and client_frame.bytes.len < 4096);
    try testing.expectError(error.LimitExceeded, session.ingest(client_frame.bytes));
    try testing.expectEqual(bedwire.State.disconnected, session.state);

    // 3. Batch limits remain Session-scoped rather than using pool capacity
    var session_batch_limits = pool_limits;
    session_batch_limits.max_batch_bytes = 256;
    session_batch_limits.max_packet_bytes = 256;

    var batch_session = try bedwire.Session.init(testing.allocator, .server, &support.modern, .{
        .pool = &pool,
        .limits = session_batch_limits,
    });
    defer batch_session.deinit();
    batch_session.state = .in_game;

    // TX batch limit: multi-packet batch > 256 and < 4096 fails encode
    var p1_buf: [160]u8 = undefined;
    var p2_buf: [160]u8 = undefined;
    const p1 = support.packet(&p1_buf, 60, &([_]u8{'a'} ** 140));
    const p2 = support.packet(&p2_buf, 61, &([_]u8{'b'} ** 140));
    try testing.expectError(error.LimitExceeded, batch_session.encode(&.{ p1, p2 }));

    // RX batch limit: compressed frame fits in 256 bytes, but decompressed batch exceeds 256
    try client.compression.negotiate(.deflate, 0);
    try batch_session.compression.negotiate(.deflate, 0);

    var compressible_buf: [512]u8 = undefined;
    const compressible = support.packet(&compressible_buf, 60, &([_]u8{'z'} ** 350));
    const compressed_frame = try client.encodeOne(compressible);
    defer compressed_frame.release();
    try testing.expect(compressed_frame.bytes.len < 256);
    try testing.expectError(error.LimitExceeded, batch_session.ingest(compressed_frame.bytes));
}
