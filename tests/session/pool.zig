const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;

test "acquire release exhaustion and reuse for RX and TX" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    // acquire both RX slots
    const rx1 = try pool.acquireRx();
    const rx2 = try pool.acquireRx();
    try testing.expectError(error.PoolExhausted, pool.acquireRx());

    // acquire both TX slots
    const tx1 = try pool.acquireTx();
    const tx2 = try pool.acquireTx();
    try testing.expectError(error.PoolExhausted, pool.acquireTx());

    // release and reacquire RX
    pool.releaseRx(rx1);
    const rx3 = try pool.acquireRx();
    try testing.expectEqual(rx1.slot_index, rx3.slot_index);
    try testing.expect(rx3.epoch > rx1.epoch);

    // release and reacquire TX
    pool.releaseTx(tx1);
    const tx3 = try pool.acquireTx();
    try testing.expectEqual(tx1.slot_index, tx3.slot_index);
    try testing.expect(tx3.epoch > tx1.epoch);

    // clean up all remaining leases
    pool.releaseRx(rx2);
    pool.releaseRx(rx3);
    pool.releaseTx(tx2);
    pool.releaseTx(tx3);
}

test "stale and duplicate token release are rejected via epoch CAS" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();

    const rx = try pool.acquireRx();
    pool.releaseRx(rx);

    // duplicate release of same token is safe no-op
    pool.releaseRx(rx);

    // acquire again to advance epoch
    const rx_reacquired = try pool.acquireRx();
    try testing.expect(rx_reacquired.epoch > rx.epoch);

    // release with stale token cannot free the newly acquired slot
    pool.releaseRx(rx);
    try testing.expectError(error.PoolExhausted, pool.acquireRx());

    // valid release works
    pool.releaseRx(rx_reacquired);
    const rx_final = try pool.acquireRx();
    pool.releaseRx(rx_final);

    // repeat for TX
    const tx = try pool.acquireTx();
    pool.releaseTx(tx);
    pool.releaseTx(tx);

    const tx_reacquired = try pool.acquireTx();
    pool.releaseTx(tx);
    try testing.expectError(error.PoolExhausted, pool.acquireTx());

    pool.releaseTx(tx_reacquired);
}

test "out-of-bounds slot tokens are rejected safely" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    const invalid_rx: bedwire.BufferPool.RxToken = .{ .slot_index = 64, .epoch = 0 };
    const invalid_tx: bedwire.BufferPool.TxToken = .{ .slot_index = 64, .epoch = 0 };
    pool.releaseRx(invalid_rx);
    pool.releaseTx(invalid_tx);
}

test "64-slot boundary mask handles all 64 bits without overflow" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 64, .tx_slots = 64 });
    defer pool.deinit();

    var rx_tokens: [64]bedwire.BufferPool.RxToken = undefined;
    for (&rx_tokens) |*t| t.* = try pool.acquireRx();
    try testing.expectError(error.PoolExhausted, pool.acquireRx());

    for (rx_tokens) |t| pool.releaseRx(t);

    var tx_tokens: [64]bedwire.BufferPool.TxToken = undefined;
    for (&tx_tokens) |*t| t.* = try pool.acquireTx();
    try testing.expectError(error.PoolExhausted, pool.acquireTx());

    for (tx_tokens) |t| pool.releaseTx(t);
}

test "isIdle reflects returned lease invariant" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    try testing.expect(pool.isIdle());

    const rx = try pool.acquireRx();
    try testing.expect(!pool.isIdle());

    const tx = try pool.acquireTx();
    try testing.expect(!pool.isIdle());

    pool.releaseRx(rx);
    try testing.expect(!pool.isIdle());

    pool.releaseTx(tx);
    try testing.expect(pool.isIdle());
}

test "stale and out-of-bounds tokens return null in getRx and getTx" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();

    const rx = try pool.acquireRx();
    try testing.expect(pool.getRx(rx) != null);
    pool.releaseRx(rx);
    try testing.expect(pool.getRx(rx) == null);

    const tx = try pool.acquireTx();
    try testing.expect(pool.getTx(tx) != null);
    pool.releaseTx(tx);
    try testing.expect(pool.getTx(tx) == null);

    const invalid_rx: bedwire.BufferPool.RxToken = .{ .slot_index = 64, .epoch = 0 };
    const invalid_tx: bedwire.BufferPool.TxToken = .{ .slot_index = 64, .epoch = 0 };
    try testing.expect(pool.getRx(invalid_rx) == null);
    try testing.expect(pool.getTx(invalid_tx) == null);
}

test "invalid slot counts are rejected" {
    try testing.expectError(error.InvalidLimits, bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 0, .tx_slots = 1 }));
    try testing.expectError(error.InvalidLimits, bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 65, .tx_slots = 1 }));
    try testing.expectError(error.InvalidLimits, bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 0 }));
    try testing.expectError(error.InvalidLimits, bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 65 }));
}

test "checked arithmetic prevents storage size overflow" {
    const huge: bedwire.Limits = .{
        .max_frame_bytes = std.math.maxInt(usize),
        .max_batch_bytes = 1024,
        .max_packet_bytes = 1024,
    };
    try testing.expectError(error.LimitExceeded, bedwire.BufferPool.init(testing.allocator, huge, .{ .rx_slots = 2, .tx_slots = 2 }));
}
