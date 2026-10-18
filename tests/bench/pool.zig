const std = @import("std");
const bedwire = @import("bedwire");
const legacy = @import("main.zig");
const Mode = enum { rx, mixed, split };
const iterations = 50_000;
const limits: bedwire.Limits = .{ .max_frame_bytes = 4096, .max_batch_bytes = 4096, .max_packet_bytes = 4096 };

const Gate = struct {
    ready: std.atomic.Value(usize) = .init(0),
    start: std.atomic.Value(bool) = .init(false),
};

const Worker = struct {
    io: std.Io,
    pool: *bedwire.BufferPool,
    gate: *Gate,
    mode: Mode,
    index: usize,
    failures: usize = 0,
    pairs: usize = 0,
    failure: ?anyerror = null,

    fn run(self: *Worker) void {
        _ = self.gate.ready.fetchAdd(1, .release);
        while (!self.gate.start.load(.acquire)) std.Thread.yield() catch {};
        self.work() catch |err| {
            self.failure = err;
        };
    }

    fn work(self: *Worker) !void {
        const timer = legacy.Timer.start(self.io);
        var attempts: usize = 0;
        var failures: usize = 0;
        var pairs: usize = 0;
        var completed: usize = 0;
        while (completed < iterations) {
            attempts += 1;
            if (attempts % 4096 == 0 and timer.read() > 5 * std.time.ns_per_s) return error.BenchmarkTimeout;
            const rx = self.mode != .split or self.index % 2 == 0;
            if (rx) {
                const token = self.pool.acquireRx() catch {
                    failures += 1;
                    std.Thread.yield() catch {};
                    continue;
                };
                if (self.pool.getRx(token) == null) {
                    self.pool.releaseRx(token);
                    return error.InvalidToken;
                }
                self.pool.releaseRx(token);
                pairs += 1;
            } else {
                const token = self.pool.acquireTx() catch {
                    failures += 1;
                    std.Thread.yield() catch {};
                    continue;
                };
                if (self.pool.getTx(token) == null) {
                    self.pool.releaseTx(token);
                    return error.InvalidToken;
                }
                self.pool.releaseTx(token);
                pairs += 1;
            }
            if (self.mode == .mixed) {
                const token = self.pool.acquireTx() catch {
                    failures += 1;
                    std.Thread.yield() catch {};
                    continue;
                };
                if (self.pool.getTx(token) == null) {
                    self.pool.releaseTx(token);
                    return error.InvalidToken;
                }
                self.pool.releaseTx(token);
                pairs += 1;
            }
            completed += 1;
        }
        self.failures = failures;
        self.pairs = pairs;
    }
};

fn measure(io: std.Io, slots: u8, count: usize, shared: bool, mode: Mode, out: *std.Io.Writer) !void {
    var counting: legacy.Counting = .{ .backing = std.heap.page_allocator };
    var pools: [8]bedwire.BufferPool = undefined;
    const pool_count = if (shared) 1 else count;
    var initialized: usize = 0;
    defer for (pools[0..initialized]) |*pool| pool.deinit();
    for (pools[0..pool_count]) |*pool| {
        pool.* = try bedwire.BufferPool.init(counting.allocator(), limits, .{ .rx_slots = slots, .tx_slots = slots });
        initialized += 1;
    }
    const allocations = counting.allocations;
    var gate: Gate = .{};
    var workers: [8]Worker = undefined;
    var threads: [8]std.Thread = undefined;
    var started: usize = 0;
    var timer: legacy.Timer = undefined;
    {
        defer {
            gate.start.store(true, .release);
            for (threads[0..started]) |thread| thread.join();
        }
        for (0..count) |i| {
            workers[i] = .{ .io = io, .pool = &pools[if (shared) 0 else i], .gate = &gate, .mode = mode, .index = i };
            threads[i] = try std.Thread.spawn(.{}, Worker.run, .{&workers[i]});
            started += 1;
        }
        while (gate.ready.load(.acquire) < count) std.Thread.yield() catch {};
        timer = legacy.Timer.start(io);
    }
    const elapsed = timer.read();
    var failures: usize = 0;
    var pairs: usize = 0;
    for (workers[0..count]) |worker| {
        if (worker.failure) |err| return err;
        failures += worker.failures;
        pairs += worker.pairs;
    }
    for (pools[0..pool_count]) |*pool| if (!pool.isIdle()) return error.LeaseLeak;
    if (counting.allocations != allocations) return error.SteadyStateAllocation;
    try out.print("{d},{d},{s},{s},{d},{d},{d},{d:.2},{d},{d}\n", .{
        slots,
        count,
        if (shared) "shared" else "private",
        @tagName(mode),
        pairs,
        failures,
        elapsed,
        @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(pairs)),
        counting.bytes,
        @offsetOf(bedwire.BufferPool, "tx_free") - @offsetOf(bedwire.BufferPool, "rx_free"),
    });
    try out.flush();
}

pub fn main(init: std.process.Init) !void {
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    const out = &stdout.interface;
    try out.print("slots,threads,pools,mode,acquire_release_pairs,exhausted_attempts,wall_ns,ns_per_pair,allocated_bytes,mask_spacing_bytes\n", .{});
    for ([_]u8{ 1, 2, 4, 16, 64 }) |slots| {
        for ([_]usize{ 1, 2, 4, 8 }) |count| {
            for (std.enums.values(Mode)) |mode| try measure(init.io, slots, count, true, mode, out);
        }
    }
    for ([_]usize{ 2, 4, 8 }) |count| {
        for (std.enums.values(Mode)) |mode| try measure(init.io, 1, count, false, mode, out);
    }
}
