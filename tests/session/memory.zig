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
    var session = try bedwire.Session.init(allocator, .server, &support.modern, .{ .limits = support.limits });
    session.deinit();
}

test "initialization unwinds every allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, initCase, .{});
}

test "limits are validated before any buffer is reserved" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });

    const invalid: bedwire.Limits = .{ .max_frame_bytes = 0 };
    try testing.expectError(error.InvalidLimits, bedwire.Session.init(failing.allocator(), .server, &support.modern, .{ .limits = invalid }));
    try testing.expect(!failing.has_induced_failure);
}

test "a contradictory descriptor is refused at session start" {
    const broken: bedwire.Descriptor = comptime blk: {
        var descriptor = bedwire.protocol.describe(818) catch unreachable;
        descriptor.features.supports_deflate = false;
        descriptor.features.supports_snappy = false;
        break :blk descriptor;
    };

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.UnsupportedProtocol, bedwire.Session.init(failing.allocator(), .server, &broken, .{ .limits = support.limits }));
    try testing.expect(!failing.has_induced_failure);
}

test "per-session memory is fixed by the limits" {
    var counting = std.testing.FailingAllocator.init(testing.allocator, .{});

    var session = try bedwire.Session.init(counting.allocator(), .server, &support.modern, .{ .limits = support.limits });
    defer session.deinit();

    // Two frame buffers, one assembly buffer, one decompression buffer, plus
    // the workspace struct holding the DEFLATE window and Snappy table.
    const buffers = 2 * support.limits.max_frame_bytes + 2 * support.limits.max_batch_bytes;
    const workspace = @sizeOf(bedwire.compression.Workspace);

    try testing.expectEqual(buffers + workspace, counting.allocated_bytes);
    try testing.expect(counting.allocations <= 5);
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
    _ = try pair.server.encodeOne(support.packet(&reply, 61, "reply"));

    // Encoding writes to the outbound buffers only.
    try testing.expectEqualSlices(u8, packet, received.bytes);
}
