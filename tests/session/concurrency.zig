const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;

const SessionWorker = struct {
    pool: *bedwire.BufferPool,
    key_byte: u8,
    failure: ?anyerror = null,

    fn run(self: *@This()) void {
        self.exchange() catch |err| {
            self.failure = err;
        };
    }

    fn exchange(self: *@This()) !void {
        var sender = try bedwire.Session.init(testing.allocator, .client, &support.modern, .{ .pool = self.pool });
        defer sender.deinit();
        var receiver = try bedwire.Session.init(testing.allocator, .server, &support.modern, .{ .pool = self.pool });
        defer receiver.deinit();
        sender.state = .in_game;
        receiver.state = .in_game;
        sender.crypto = bedwire.crypto.SessionCrypto.init(@splat(self.key_byte));
        receiver.crypto = bedwire.crypto.SessionCrypto.init(@splat(self.key_byte));
        var storage: [32]u8 = undefined;
        const packet = support.packet(&storage, support.idOf(&support.modern, .client_cache_status), &.{self.key_byte});

        for (0..1000) |_| {
            const frame = while (true) {
                break sender.encodeOne(packet) catch |err| {
                    if (err != error.PoolExhausted) return err;
                    try std.Thread.yield();
                    continue;
                };
            };
            defer frame.release();
            try std.Thread.yield();
            var packets = while (true) {
                break receiver.ingest(frame.bytes) catch |err| {
                    if (err != error.PoolExhausted) return err;
                    try std.Thread.yield();
                    continue;
                };
            };
            defer packets.deinit();
            try std.Thread.yield();
            try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
        }
        try testing.expectEqual(@as(u64, 1000), sender.crypto.?.send_counter);
        try testing.expectEqual(@as(u64, 1000), receiver.crypto.?.recv_counter);
    }
};

test "independent encrypted sessions share bounded slots under contention" {
    const limits: bedwire.Limits = .{ .max_frame_bytes = 1024, .max_batch_bytes = 1024, .max_packet_bytes = 512 };
    var pool = try bedwire.BufferPool.init(testing.allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var workers: [4]SessionWorker = undefined;
    var threads: [4]std.Thread = undefined;
    var started: usize = 0;
    {
        defer for (threads[0..started]) |thread| thread.join();
        for (&workers, 0..) |*worker, i| {
            worker.* = .{ .pool = &pool, .key_byte = @intCast(i + 1) };
            threads[i] = try std.Thread.spawn(.{}, SessionWorker.run, .{worker});
            started += 1;
        }
    }
    for (workers) |worker| if (worker.failure) |err| return err;
    try testing.expect(pool.isIdle());
}

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
