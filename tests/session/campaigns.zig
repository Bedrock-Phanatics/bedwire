const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");
const testing = std.testing;

const small: bedwire.Limits = .{
    .max_frame_bytes = 256,
    .max_batch_bytes = 512,
    .max_packet_bytes = 128,
    .max_packets_per_batch = 4,
};

test "deterministic session operation sequences preserve leases and commits" {
    var pool = try bedwire.BufferPool.init(testing.allocator, small, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(0x5e5510);
    const random = prng.random();
    const cycles = @max(32, @import("build_options").fuzz_iterations / 100);

    for (0..cycles) |_| {
        var sender = try support.Session.init(testing.allocator, .client, .{ .pool = &pool });
        defer sender.deinit();
        var receiver = try support.Session.init(testing.allocator, .server, .{ .pool = &pool });
        defer receiver.deinit();
        sender.state = .in_game;
        receiver.state = .in_game;
        sender.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
        receiver.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));

        var storage: [16]u8 = undefined;
        const packet = support.packet(&storage, support.opaque_packet_id, "x");
        var held_frame: ?support.Session.Frame = null;
        var stale_frame: ?support.Session.Frame = null;
        var held_packets: ?support.Session.Packets = null;
        var frame_consumed = false;
        var sent_count: u64 = 0;
        var received_count: u64 = 0;

        for (0..32) |_| {
            switch (random.uintLessThan(u8, 8)) {
                0 => if (held_frame == null and sender.state != .disconnected and sent_count == received_count) {
                    const frame = try sender.encodeOne(packet);
                    held_frame = frame;
                    frame_consumed = false;
                    sent_count += 1;
                },
                1 => if (held_frame) |frame| {
                    if (held_packets == null and !frame_consumed and receiver.state != .disconnected) {
                        held_packets = try receiver.ingest(frame.bytes);
                        frame_consumed = true;
                        received_count += 1;
                    } else if (held_packets != null and receiver.state != .disconnected) {
                        const before = receiver.crypto.?.recv_counter;
                        const observed = receiver.received;
                        try testing.expectError(error.InvalidState, receiver.ingest(frame.bytes));
                        try testing.expectEqual(before, receiver.crypto.?.recv_counter);
                        try testing.expectEqualDeep(observed, receiver.received);
                    }
                },
                2 => if (held_packets) |*packets| {
                    packets.reset();
                    try testing.expect(packets.next() != null or receiver.state == .disconnected);
                },
                3 => if (held_packets) |*packets| {
                    packets.deinit();
                    held_packets = null;
                },
                4 => if (held_frame) |frame| {
                    frame.release();
                    stale_frame = frame;
                    held_frame = null;
                },
                5 => if (sender.state != .disconnected) {
                    const before = sender.crypto.?.send_counter;
                    const observed = sender.sent;
                    const token = sender.tx_token;
                    const expected: anyerror = if (held_frame != null) error.PoolExhausted else error.MalformedBatch;
                    try testing.expectError(expected, sender.encode(&.{}));
                    try testing.expectEqual(before, sender.crypto.?.send_counter);
                    try testing.expectEqualDeep(observed, sender.sent);
                    try testing.expectEqual(token, sender.tx_token);
                },
                6 => if (stale_frame) |frame| frame.release(),
                7 => {
                    sender.close();
                    receiver.close();
                },
                else => unreachable,
            }
            if (sender.state == .disconnected) {
                try testing.expectError(error.TransportClosed, sender.encodeOne(packet));
                try testing.expectEqual(bedwire.State.disconnected, sender.state);
            } else {
                try testing.expectEqual(sent_count, sender.crypto.?.send_counter);
            }
            if (receiver.state == .disconnected) {
                try testing.expectError(error.TransportClosed, receiver.ingest(&.{0xfe}));
                try testing.expectEqual(bedwire.State.disconnected, receiver.state);
            } else {
                try testing.expectEqual(received_count, receiver.crypto.?.recv_counter);
            }
            try testing.expectEqual(held_frame == null, sender.tx_slot == null);
            try testing.expectEqual(held_packets == null, receiver.rx_slot == null);
            try testing.expectEqual(held_frame == null and held_packets == null, pool.isIdle());
        }
        if (held_packets) |*packets| packets.deinit();
        if (held_frame) |frame| frame.release();
        try testing.expect(pool.isIdle());
        const stale = try pool.acquireTx();
        pool.releaseTx(stale);
        try testing.expect(pool.getTx(stale) == null);
        try testing.expect(pool.isIdle());
    }
}

test "mutated compressed frames release leases and keep commits atomic" {
    var pool = try bedwire.BufferPool.init(testing.allocator, small, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(0xf6a9e);
    const random = prng.random();
    for ([_]bedwire.compression.Algorithm{ .deflate, .snappy }) |algorithm| {
        var sender = try support.Session.init(testing.allocator, .client, .{ .pool = &pool });
        defer sender.deinit();
        sender.state = .in_game;
        try sender.compression.negotiate(algorithm, 0);
        var storage: [128]u8 = undefined;
        const packet = support.packet(&storage, support.opaque_packet_id, &([_]u8{'a'} ** 96));
        const frame = try sender.encodeOne(packet);
        var valid: [256]u8 = undefined;
        @memcpy(valid[0..frame.bytes.len], frame.bytes);
        const len = frame.bytes.len;
        frame.release();

        const cases = @max(64, @import("build_options").fuzz_iterations / 40);
        for (0..cases) |i| {
            var receiver = try support.Session.init(testing.allocator, .server, .{ .pool = &pool });
            defer receiver.deinit();
            receiver.state = .in_game;
            try receiver.compression.negotiate(algorithm, 0);
            var mutated = valid;
            const cut = if (i % 3 == 0) random.uintLessThan(usize, len + 1) else len;
            if (i % 3 != 0) mutated[random.uintLessThan(usize, len)] ^= @as(u8, 1) << @intCast(random.uintLessThan(u8, 8));
            if (receiver.ingest(mutated[0..cut])) |admitted| {
                var packets = admitted;
                while (packets.next()) |p| try testing.expect(p.bytes.len <= small.max_packet_bytes);
                packets.deinit();
            } else |_| {
                try testing.expectEqual(bedwire.State.disconnected, receiver.state);
                try testing.expect(receiver.rx_slot == null);
                try testing.expectEqual(@as(usize, 0), receiver.received.count());
            }
            try testing.expect(pool.isIdle());
        }
    }
}

test "shared pool remains reusable after repeated session deinit" {
    var pool = try bedwire.BufferPool.init(testing.allocator, small, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    const cycles = @max(64, @import("build_options").fuzz_iterations / 20);
    var storage: [16]u8 = undefined;
    const packet = support.packet(&storage, support.opaque_packet_id, "reuse");

    for (0..cycles) |_| {
        var sender = try support.Session.init(testing.allocator, .client, .{ .pool = &pool });
        var receiver = try support.Session.init(testing.allocator, .server, .{ .pool = &pool });
        sender.state = .in_game;
        receiver.state = .in_game;
        const frame = try sender.encodeOne(packet);
        var packets = try receiver.ingest(frame.bytes);
        try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
        sender.close();
        receiver.close();
        try testing.expect(packets.next() == null);
        try testing.expectError(error.TransportClosed, sender.encodeOne(packet));
        packets.deinit();
        frame.release();
        sender.deinit();
        receiver.deinit();
        try testing.expect(pool.isIdle());
    }
}
