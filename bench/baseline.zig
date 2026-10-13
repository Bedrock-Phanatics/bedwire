const std = @import("std");
const builtin = @import("builtin");
const bedwire = @import("bedwire");
const legacy = @import("main.zig");
const protocol = bedwire.protocol;
const Timer = legacy.Timer;
const limits = legacy.limits;
const Phase = enum { encode, decode, roundtrip };
const Content = enum { compressible, realistic, noise };
const latency_samples = 1024;
const throughput_samples = 7;
const frame_budget = 16 * 1024 * 1024;

const Workload = struct {
    storage: []u8,
    packets: [1024][]const u8 = undefined,
    count: usize = 0,
    payload_bytes: usize = 0,
    batch_bytes: usize = 0,

    fn init(allocator: std.mem.Allocator, content: Content, size: usize) !Workload {
        var self: Workload = .{ .storage = try allocator.alloc(u8, size + 4096) };
        errdefer allocator.free(self.storage);
        const payload = try allocator.alloc(u8, size);
        defer allocator.free(payload);
        var prng = std.Random.DefaultPrng.init(0xbed);
        var offset: usize = 0;
        while (offset < size) {
            var writer = protocol.Writer.init(self.storage[offset..]);
            if (content == .realistic and size < 256 * 1024) {
                const i: f32 = @floatFromInt(self.count);
                try protocol.Current.encode(&writer, .{
                    .header = .{ .packet_id = protocol.Current.packetId(.move_player).? },
                    .kind = .move_player,
                    .payload = &.{},
                    .value = .{ .typed = .{ .move_player = .{
                        .player_runtime_id = 4000 + self.count % 64,
                        .position = .{ .x = 128 + i * 0.125, .y = 64, .z = -32 + i * 0.25 },
                        .rotation = .{ .x = i * 0.5, .y = 0 },
                        .y_head_rotation = i * 0.5,
                        .position_mode = .normal,
                        .on_ground = true,
                        .riding_runtime_id = 0,
                        .teleport_data = null,
                        .tick = 123456 + self.count,
                    } } },
                });
            } else {
                const len = @min(size - offset, if (size == 16 * 1024) @as(usize, 1024) else size);
                const body = payload[0 .. len - 2];
                switch (content) {
                    .compressible => @memset(body, 0),
                    .noise => prng.random().bytes(body),
                    .realistic => {
                        for (body, 0..) |*byte, i| {
                            byte.* = if (i % 4096 < 3072) @intCast((i / 256) % 16) else prng.random().int(u8);
                        }
                    },
                }
                if (content == .realistic) {
                    try protocol.Current.encode(&writer, .{
                        .header = .{ .packet_id = protocol.Current.packetId(.level_chunk).? },
                        .kind = .level_chunk,
                        .payload = &.{},
                        .value = .{ .typed = .{ .level_chunk = .{
                            .chunk_position = .{ .x = 8, .z = -2 },
                            .dimension_id = 0,
                            .sub_chunks_count = 16,
                            .client_request_sub_chunk_limit = null,
                            .cache_enabled = false,
                            .cache_metadata = .empty,
                            .serialized_chunk_data = body,
                        } } },
                    });
                } else {
                    try writer.writeVarU32(1020);
                    try writer.writeRaw(body);
                }
            }
            const packet = writer.written();
            if (self.count == self.packets.len) return error.TooManyPackets;
            self.packets[self.count] = packet;
            self.count += 1;
            self.payload_bytes += packet.len;
            self.batch_bytes += bedwire.framing.varint.sizeU32(@intCast(packet.len)) + packet.len;
            offset += packet.len;
        }
        return self;
    }

    fn slice(self: *const Workload) []const []const u8 {
        return self.packets[0..self.count];
    }
};

fn consume(receiver: *bedwire.Session, frame: []const u8) !void {
    var packets = try receiver.ingest(frame);
    defer packets.deinit();
    while (packets.next()) |packet| std.mem.doNotOptimizeAway(packet.bytes);
}

fn verify(sender: *bedwire.Session, receiver: *bedwire.Session, workload: *const Workload) !usize {
    const frame = try sender.encode(workload.slice());
    defer frame.release();
    var packets = try receiver.ingest(frame.bytes);
    defer packets.deinit();
    for (workload.slice()) |expected| {
        const actual = packets.next() orelse return error.MissingPacket;
        if (!std.mem.eql(u8, expected, actual.bytes)) return error.PacketMismatch;
        std.mem.doNotOptimizeAway(actual.bytes);
    }
    if (packets.next() != null) return error.ExtraPacket;
    return frame.bytes.len;
}

fn operation(comptime phase: Phase, sender: *bedwire.Session, receiver: *bedwire.Session, workload: *const Workload, prepared: []const u8) !void {
    if (phase == .decode) return consume(receiver, prepared);
    const frame = try sender.encode(workload.slice());
    defer frame.release();
    std.mem.doNotOptimizeAway(frame.bytes);
    if (phase == .roundtrip) try consume(receiver, frame.bytes);
}

fn cpuNow(io: std.Io) u64 {
    return @intCast(std.Io.Timestamp.now(io, .cpu_thread).nanoseconds);
}

fn measure(comptime phase: Phase, io: std.Io, allocator: std.mem.Allocator, pool: *bedwire.BufferPool, counting: *legacy.Counting, workload: *const Workload, size_name: []const u8, content: Content, mode: []const u8, setup: legacy.Setup, out: *std.Io.Writer) !void {
    const allocations = counting.allocations;
    var sender = try legacy.open(protocol.Current, pool, .server, setup);
    defer sender.deinit();
    var receiver = try legacy.open(protocol.Current, pool, .client, setup);
    defer receiver.deinit();
    const frame_bytes = try verify(&sender, &receiver, workload);
    const sender_crypto = sender.crypto;
    const receiver_crypto = receiver.crypto;
    const one = try sender.encode(workload.slice());
    const prepared = try allocator.dupe(u8, one.bytes);
    one.release();
    defer allocator.free(prepared);
    if (phase == .roundtrip) sender.crypto = sender_crypto;

    var latencies: [latency_samples]u64 = undefined;
    for (&latencies) |*sample| {
        if (phase == .decode) receiver.crypto = receiver_crypto;
        const timer = Timer.start(io);
        try operation(phase, &sender, &receiver, workload, prepared);
        sample.* = timer.read();
    }
    std.mem.sort(u64, &latencies, {}, std.sort.asc(u64));
    const estimate = @max(latencies[(latency_samples + 1) / 2 - 1], 1);
    const cap = if (phase == .decode) @min(frame_budget / frame_bytes, 1_000_000) else 1_000_000;
    const iterations = @max(1, @min(cap, 20 * std.time.ns_per_ms / estimate));
    const repeats = @max(1, 20 * std.time.ns_per_ms / (iterations * estimate));
    var frames: []u8 = &.{};
    if (phase == .decode) {
        frames = try allocator.alloc(u8, iterations * frame_bytes);
        sender.crypto = sender_crypto;
        for (0..iterations) |i| {
            const frame = try sender.encode(workload.slice());
            defer frame.release();
            if (frame.bytes.len != frame_bytes) return error.FrameSizeChanged;
            @memcpy(frames[i * frame_bytes ..][0..frame_bytes], frame.bytes);
        }
    }
    defer if (frames.len != 0) allocator.free(frames);

    var elapsed: u64 = 0;
    var cpu: u64 = 0;
    for (0..throughput_samples) |_| {
        const cpu_start = cpuNow(io);
        const timer = Timer.start(io);
        for (0..repeats) |_| {
            if (phase == .decode) receiver.crypto = receiver_crypto;
            for (0..iterations) |i| {
                const input = if (phase == .decode) frames[i * frame_bytes ..][0..frame_bytes] else prepared;
                try operation(phase, &sender, &receiver, workload, input);
            }
        }
        elapsed += timer.read();
        cpu += cpuNow(io) - cpu_start;
    }
    if (counting.allocations != allocations or !pool.isIdle()) return error.SteadyStateRegression;
    const operations: f64 = @floatFromInt(iterations * repeats * throughput_samples);
    const ns: f64 = @floatFromInt(elapsed);
    const trailer: usize = if (setup.encrypt) 8 else 0;
    const ratio = @as(f64, @floatFromInt(frame_bytes - 2 - trailer)) / @as(f64, @floatFromInt(workload.batch_bytes));
    try out.print("{s},{s},{s},{s},{d},{d},{d},{d},{d:.2},{d:.2},{d:.6},0,{d},{d:.2},{d},{d},{d}\n", .{
        size_name,
        @tagName(content),
        mode,
        @tagName(phase),
        workload.count,
        workload.payload_bytes,
        frame_bytes,
        iterations * repeats * throughput_samples,
        ns / operations,
        @as(f64, @floatFromInt(workload.payload_bytes)) * operations * 1000 / ns,
        ratio,
        cpu,
        @as(f64, @floatFromInt(cpu)) / operations,
        latencies[(latency_samples + 1) / 2 - 1],
        latencies[(latency_samples * 95 + 99) / 100 - 1],
        latencies[(latency_samples * 99 + 99) / 100 - 1],
    });
    try out.flush();
}

fn poolBaseline(io: std.Io, out: *std.Io.Writer) !void {
    for ([_]u8{ 1, 2, 4, 16, 64 }) |slots| {
        var counting = std.testing.FailingAllocator.init(std.heap.page_allocator, .{});
        var pool = try bedwire.BufferPool.init(counting.allocator(), limits, .{ .rx_slots = slots, .tx_slots = slots });
        defer pool.deinit();
        const allocated = counting.allocated_bytes;
        var rx: [64]bedwire.BufferPool.RxToken = undefined;
        var tx: [64]bedwire.BufferPool.TxToken = undefined;
        const iterations: usize = 100_000;
        const timer = Timer.start(io);
        for (0..iterations) |_| {
            for (0..slots) |i| {
                rx[i] = try pool.acquireRx();
                tx[i] = try pool.acquireTx();
            }
            for (0..slots) |i| {
                pool.releaseRx(rx[i]);
                pool.releaseTx(tx[i]);
            }
        }
        const elapsed = timer.read();
        if (!pool.isIdle() or counting.allocated_bytes != allocated) return error.PoolRegression;
        try out.print("# pool,{d},{d},{d},{d},{d:.2}\n", .{
            slots,                                                                          pool.storageBytes(), allocated, @sizeOf(bedwire.compression.Scratch),
            @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations * slots)),
        });
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.page_allocator;
    var counting: legacy.Counting = .{ .backing = allocator };
    var pool = try bedwire.BufferPool.init(counting.allocator(), limits, .{ .rx_slots = 2, .tx_slots = 1 });
    defer pool.deinit();
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    const out = &stdout.interface;
    try out.print("# Zig {s}, {s}-{s}, ReleaseFast, seed=0xbed\n", .{ builtin.zig_version_string, @tagName(builtin.cpu.arch), @tagName(builtin.os.tag) });
    try out.print("# latency_samples={d}, throughput_samples={d}, target_sample_ms=20, prepared_frame_budget={d}\n", .{ latency_samples, throughput_samples, frame_budget });
    try out.print("size,content,mode,phase,packets,payload_bytes,frame_bytes,operations,ns_per_op,MB_per_s,compressed_over_raw,allocations_per_op,cpu_ns,cpu_ns_per_op,p50_ns,p95_ns,p99_ns\n", .{});
    const modes = [_]struct { name: []const u8, setup: legacy.Setup }{
        .{ .name = "none", .setup = .{ .algorithm = .none, .encrypt = false } },
        .{ .name = "snappy", .setup = .{ .algorithm = .snappy, .encrypt = false } },
        .{ .name = "deflate", .setup = .{ .algorithm = .deflate, .encrypt = false } },
        .{ .name = "snappy+aes", .setup = .{ .algorithm = .snappy, .encrypt = true } },
        .{ .name = "deflate+aes", .setup = .{ .algorithm = .deflate, .encrypt = true } },
    };
    for ([_]struct { name: []const u8, bytes: usize }{
        .{ .name = "small", .bytes = 256 },
        .{ .name = "medium", .bytes = 16 * 1024 },
        .{ .name = "large", .bytes = 256 * 1024 },
    }) |size| {
        for (std.enums.values(Content)) |content| {
            const workload = try Workload.init(allocator, content, size.bytes);
            defer allocator.free(workload.storage);
            for (modes) |mode| {
                inline for (std.enums.values(Phase)) |phase| {
                    try measure(phase, init.io, allocator, &pool, &counting, &workload, size.name, content, mode.name, mode.setup, out);
                }
            }
        }
    }
    try out.print("# pool: slots_per_direction,backing_bytes,allocated_bytes,scratch_bytes,ns_per_rx_tx_acquire_release\n", .{});
    try poolBaseline(init.io, out);
    try out.flush();
}
