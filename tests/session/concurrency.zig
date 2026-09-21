const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;

const Worker = struct {
    pool: *bedwire.BufferPool,
    iterations: usize,
    seed: u64,

    fn run(self: *Worker) void {
        var prng = std.Random.DefaultPrng.init(self.seed);
        const random = prng.random();

        var i: usize = 0;
        while (i < self.iterations) {
            const do_rx = random.boolean();
            if (do_rx) {
                const token = self.pool.acquireRx() catch |err| switch (err) {
                    error.PoolExhausted => {
                        std.Thread.yield() catch {};
                        continue;
                    },
                };

                const slot = self.pool.getRx(token) orelse @panic("invalid rx token");
                const fill_byte: u8 = @truncate(self.seed + i);
                @memset(slot.frame, fill_byte);
                std.Thread.yield() catch {};

                for (slot.frame) |b| {
                    if (b != fill_byte) @panic("concurrent RX slot data corruption");
                }

                self.pool.releaseRx(token);
            } else {
                const token = self.pool.acquireTx() catch |err| switch (err) {
                    error.PoolExhausted => {
                        std.Thread.yield() catch {};
                        continue;
                    },
                };

                const slot = self.pool.getTx(token) orelse @panic("invalid tx token");
                const fill_byte: u8 = @truncate(self.seed + i);
                @memset(slot.egress, fill_byte);
                std.Thread.yield() catch {};

                for (slot.egress) |b| {
                    if (b != fill_byte) @panic("concurrent TX slot data corruption");
                }

                self.pool.releaseTx(token);
            }
            i += 1;
        }
    }
};

test "concurrent multi-threaded pool stress test" {
    const limits: bedwire.Limits = .{
        .max_frame_bytes = 1024,
        .max_batch_bytes = 2048,
        .max_packet_bytes = 1024,
    };

    var pool = try bedwire.BufferPool.init(testing.allocator, limits, .{ .rx_slots = 4, .tx_slots = 4 });
    defer pool.deinit();

    const num_threads = 4;
    const iterations_per_thread = 2000;

    var workers: [num_threads]Worker = undefined;
    var threads: [num_threads]std.Thread = undefined;

    for (0..num_threads) |i| {
        workers[i] = .{
            .pool = &pool,
            .iterations = iterations_per_thread,
            .seed = @as(u64, @intCast(i + 1)) * 0x12345678,
        };
        threads[i] = try std.Thread.spawn(.{}, Worker.run, .{&workers[i]});
    }

    for (threads) |t| {
        t.join();
    }

    // verify all slots returned to pool
    try testing.expectEqual(pool.rx_all_mask, pool.rx_free.load(.seq_cst));
    try testing.expectEqual(pool.tx_all_mask, pool.tx_free.load(.seq_cst));
}

test "concurrent multi-threaded stale release and reacquire contention" {
    const limits: bedwire.Limits = .{
        .max_frame_bytes = 1024,
        .max_batch_bytes = 1024,
        .max_packet_bytes = 512,
    };

    var pool = try bedwire.BufferPool.init(testing.allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    const StaleWorker = struct {
        pool: *bedwire.BufferPool,
        iterations: usize,

        fn run(self: *@This()) void {
            var stale_rx: ?bedwire.BufferPool.RxToken = null;
            var stale_tx: ?bedwire.BufferPool.TxToken = null;

            for (0..self.iterations) |_| {
                if (self.pool.acquireRx()) |rx| {
                    if (stale_rx) |stale| {
                        self.pool.releaseRx(stale);
                    }
                    stale_rx = rx;
                    std.Thread.yield() catch {};
                    self.pool.releaseRx(rx);
                } else |_| {
                    std.Thread.yield() catch {};
                }

                if (self.pool.acquireTx()) |tx| {
                    if (stale_tx) |stale| {
                        self.pool.releaseTx(stale);
                    }
                    stale_tx = tx;
                    std.Thread.yield() catch {};
                    self.pool.releaseTx(tx);
                } else |_| {
                    std.Thread.yield() catch {};
                }
            }

            if (stale_rx) |stale| self.pool.releaseRx(stale);
            if (stale_tx) |stale| self.pool.releaseTx(stale);
        }
    };

    const num_threads = 4;
    var workers: [num_threads]StaleWorker = undefined;
    var threads: [num_threads]std.Thread = undefined;

    for (0..num_threads) |i| {
        workers[i] = .{
            .pool = &pool,
            .iterations = 2000,
        };
        threads[i] = try std.Thread.spawn(.{}, StaleWorker.run, .{&workers[i]});
    }

    for (threads) |t| {
        t.join();
    }

    try testing.expect(pool.isIdle());
}
