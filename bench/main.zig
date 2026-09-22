//! benchmarks for bedwire hot path (zig build bench)

const std = @import("std");
const bedwire = @import("bedwire");

const Counting = struct {
    backing: std.mem.Allocator,
    allocations: usize = 0,
    bytes: usize = 0,

    fn allocator(self: *Counting) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.allocations += 1;
        self.bytes += len;
        return self.backing.rawAlloc(len, alignment, ra);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.allocations += 1;
        return self.backing.rawResize(memory, alignment, new_len, ra);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.allocations += 1;
        return self.backing.rawRemap(memory, alignment, new_len, ra);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(memory, alignment, ra);
    }
};

const Result = struct {
    name: []const u8,
    operations: usize,
    nanoseconds: u64,
    payload_bytes: usize,
    allocations: usize,
    allocated_bytes: usize,

    fn report(self: Result, out: *std.Io.Writer) !void {
        const seconds = @as(f64, @floatFromInt(self.nanoseconds)) / std.time.ns_per_s;
        const per_op = @as(f64, @floatFromInt(self.nanoseconds)) / @as(f64, @floatFromInt(self.operations));
        const ops = @as(f64, @floatFromInt(self.operations)) / seconds;
        const throughput = @as(f64, @floatFromInt(self.payload_bytes)) / seconds / (1024 * 1024);

        try out.print("{s: <34} {d: >10.1} ns/op  {d: >12.0} ops/s  {d: >8.1} MB/s  {d: >4} allocs/op  {d: >6} B/op\n", .{
            self.name,
            per_op,
            ops,
            throughput,
            self.allocations / self.operations,
            self.allocated_bytes / self.operations,
        });
    }
};

const limits: bedwire.Limits = .{
    .max_frame_bytes = 1 << 20,
    .max_batch_bytes = 4 << 20,
    .max_packet_bytes = 1 << 20,
};

const descriptor: bedwire.Descriptor = bedwire.protocol.describe(818) catch unreachable;

/// One packet of `len` bytes, header included
fn makePacket(storage: []u8, id: u16, len: usize) []const u8 {
    const header = bedwire.framing.varint.writeU32(storage, id) catch unreachable;
    for (storage[header..len], 0..) |*byte, i| byte.* = @truncate(i *% 31 +% 7);
    return storage[0..len];
}

const Session = bedwire.Session;

const Setup = struct {
    algorithm: ?bedwire.compression.Algorithm,
    encrypt: bool,
};

fn open(allocator: std.mem.Allocator, pool: *bedwire.BufferPool, role: bedwire.Role, setup: Setup) !Session {
    var session = try Session.init(allocator, role, &descriptor, .{ .pool = pool, .limits = limits });
    errdefer session.deinit();

    try session.compression.negotiate(setup.algorithm orelse .deflate, 0);
    if (setup.algorithm == null) session.compression.threshold = std.math.maxInt(u16);
    if (setup.encrypt) session.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    session.state = .in_game;

    return session;
}

const Timer = struct {
    io: std.Io,
    start_ts: std.Io.Timestamp,

    fn start(io: std.Io) Timer {
        return .{
            .io = io,
            .start_ts = std.Io.Timestamp.now(io, .awake),
        };
    }

    fn read(self: Timer) u64 {
        const now = std.Io.Timestamp.now(self.io, .awake);
        const duration = self.start_ts.durationTo(now);
        return @intCast(duration.nanoseconds);
    }
};

fn benchSend(io: std.Io, allocator: std.mem.Allocator, pool: *bedwire.BufferPool, name: []const u8, setup: Setup, packets: []const []const u8, iterations: usize) !Result {
    var counting: Counting = .{ .backing = allocator };
    var session = try open(counting.allocator(), pool, .server, setup);
    defer session.deinit();

    var payload: usize = 0;
    for (packets) |packet| payload += packet.len;

    const before = counting.allocations;
    const before_bytes = counting.bytes;

    var timer = Timer.start(io);
    for (0..iterations) |_| {
        const frame = try session.encode(packets);
        std.mem.doNotOptimizeAway(frame.bytes.ptr);
        frame.release();
    }
    const elapsed = timer.read();

    return .{
        .name = name,
        .operations = iterations,
        .nanoseconds = elapsed,
        .payload_bytes = payload * iterations,
        .allocations = counting.allocations - before,
        .allocated_bytes = counting.bytes - before_bytes,
    };
}

fn benchIngest(io: std.Io, allocator: std.mem.Allocator, pool: *bedwire.BufferPool, name: []const u8, setup: Setup, packets: []const []const u8, iterations: usize) !Result {
    var counting: Counting = .{ .backing = allocator };

    var sender = try open(counting.allocator(), pool, .client, setup);
    defer sender.deinit();
    var receiver = try open(counting.allocator(), pool, .server, setup);
    defer receiver.deinit();

    const frames = try allocator.alloc([]u8, iterations);
    defer {
        for (frames) |frame| allocator.free(frame);
        allocator.free(frames);
    }

    var payload: usize = 0;
    for (packets) |packet| payload += packet.len;

    for (frames) |*frame| {
        const f = try sender.encode(packets);
        defer f.release();
        frame.* = try allocator.dupe(u8, f.bytes);
    }

    const before = counting.allocations;
    const before_bytes = counting.bytes;

    var timer = Timer.start(io);
    for (frames) |frame| {
        var iterator = try receiver.ingest(frame);
        while (iterator.next()) |packet| std.mem.doNotOptimizeAway(packet.bytes.ptr);
        iterator.deinit();
    }
    const elapsed = timer.read();

    return .{
        .name = name,
        .operations = iterations,
        .nanoseconds = elapsed,
        .payload_bytes = payload * iterations,
        .allocations = counting.allocations - before,
        .allocated_bytes = counting.bytes - before_bytes,
    };
}

fn benchBatchSplit(io: std.Io, allocator: std.mem.Allocator, packets: []const []const u8, iterations: usize) !Result {
    var assembled: std.ArrayList(u8) = .empty;
    defer assembled.deinit(allocator);

    const storage = try allocator.alloc(u8, limits.max_batch_bytes);
    defer allocator.free(storage);

    var writer = bedwire.framing.batch.Writer.init(storage, limits);
    for (packets) |packet| try writer.append(packet);

    var payload: usize = 0;
    for (packets) |packet| payload += packet.len;

    var timer = Timer.start(io);
    for (0..iterations) |_| {
        var reader = try bedwire.framing.batch.Reader.init(writer.written(), limits);
        while (try reader.next()) |packet| std.mem.doNotOptimizeAway(packet.ptr);
    }
    const elapsed = timer.read();

    return .{
        .name = "batch split",
        .operations = iterations,
        .nanoseconds = elapsed,
        .payload_bytes = payload * iterations,
        .allocations = 0,
        .allocated_bytes = 0,
    };
}

fn benchSeal(io: std.Io, iterations: usize) !Result {
    var crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    defer crypto.deinit();

    var storage: [1400]u8 = undefined;
    @memset(&storage, 0x5a);

    var timer = Timer.start(io);
    for (0..iterations) |_| {
        const sealed = try crypto.seal(&storage, storage.len - 8);
        std.mem.doNotOptimizeAway(sealed.ptr);
    }
    const elapsed = timer.read();

    return .{
        .name = "seal 1392 B",
        .operations = iterations,
        .nanoseconds = elapsed,
        .payload_bytes = (storage.len - 8) * iterations,
        .allocations = 0,
        .allocated_bytes = 0,
    };
}

fn benchOpen(io: std.Io, allocator: std.mem.Allocator, iterations: usize) !Result {
    var sender = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    defer sender.deinit();
    var receiver = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    defer receiver.deinit();

    const frames = try allocator.alloc([]u8, iterations);
    defer {
        for (frames) |frame| allocator.free(frame);
        allocator.free(frames);
    }

    var storage: [1400]u8 = undefined;
    for (frames) |*frame| {
        @memset(&storage, 0x5a);
        frame.* = try allocator.dupe(u8, try sender.seal(&storage, storage.len - 8));
    }

    var timer = Timer.start(io);
    for (frames) |frame| {
        const opened = try receiver.open(frame);
        std.mem.doNotOptimizeAway(opened.ptr);
    }
    const elapsed = timer.read();

    return .{
        .name = "open 1392 B",
        .operations = iterations,
        .nanoseconds = elapsed,
        .payload_bytes = (storage.len - 8) * iterations,
        .allocations = 0,
        .allocated_bytes = 0,
    };
}

fn reportFootprint(allocator: std.mem.Allocator, pool: *bedwire.BufferPool, pool_counting: Counting, out: *std.Io.Writer) !void {
    var counting: Counting = .{ .backing = allocator };

    var session = try Session.init(counting.allocator(), .server, &descriptor, .{ .pool = pool, .limits = limits });
    defer session.deinit();

    try out.print("\nper-session fixed memory\n", .{});
    try out.print("  limits: frame {d} KiB, batch {d} KiB\n", .{ limits.max_frame_bytes / 1024, limits.max_batch_bytes / 1024 });
    try out.print("  heap:   {d} KiB across {d} allocations (0 B eager backing buffers)\n", .{ counting.bytes / 1024, counting.allocations });
    try out.print("  pool logical:   {d} KiB ({d} B) backing storage\n", .{ pool.storageBytes() / 1024, pool.storageBytes() });
    try out.print("  pool allocator: {d} KiB ({d} B) across {d} allocations ({d} RX, {d} TX slots)\n", .{ pool_counting.bytes / 1024, pool_counting.bytes, pool_counting.allocations, pool.config.rx_slots, pool.config.tx_slots });
    try out.print("  struct: {d} B (Session), {d} B (BufferPool), {d} B (Packets), {d} B (Frame)\n", .{ @sizeOf(Session), @sizeOf(bedwire.BufferPool), @sizeOf(bedwire.Packets), @sizeOf(bedwire.Frame) });
}

pub fn main(init: std.process.Init) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var pool_counting: Counting = .{ .backing = allocator };
    var pool = try bedwire.BufferPool.init(pool_counting.allocator(), limits, .{ .rx_slots = 4, .tx_slots = 4 });
    defer pool.deinit();

    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    const out = &stdout.interface;

    // a single small packet, a typical gameplay batch, and a chunk-sized batch
    var single_storage: [64]u8 = undefined;
    const single: []const []const u8 = &.{makePacket(&single_storage, 60, 32)};

    var gameplay_storage: [16][256]u8 = undefined;
    var gameplay_packets: [16][]const u8 = undefined;
    for (&gameplay_packets, 0..) |*slot, i| {
        slot.* = makePacket(&gameplay_storage[i], 150 + @as(u16, @intCast(i)), 96 + i * 8);
    }
    const gameplay: []const []const u8 = &gameplay_packets;

    const chunk_storage = try allocator.alloc(u8, 256 * 1024);
    const chunk: []const []const u8 = &.{makePacket(chunk_storage, 58, chunk_storage.len)};

    const cases = [_]struct { name: []const u8, setup: Setup }{
        .{ .name = "plain", .setup = .{ .algorithm = null, .encrypt = false } },
        .{ .name = "deflate", .setup = .{ .algorithm = .deflate, .encrypt = false } },
        .{ .name = "snappy", .setup = .{ .algorithm = .snappy, .encrypt = false } },
        .{ .name = "snappy+aes", .setup = .{ .algorithm = .snappy, .encrypt = true } },
        .{ .name = "deflate+aes", .setup = .{ .algorithm = .deflate, .encrypt = true } },
    };

    const workloads = [_]struct { name: []const u8, packets: []const []const u8, iterations: usize }{
        .{ .name = "1-packet", .packets = single, .iterations = 200_000 },
        .{ .name = "gameplay", .packets = gameplay, .iterations = 50_000 },
        .{ .name = "chunk", .packets = chunk, .iterations = 2_000 },
    };

    try out.print("bedwire benchmarks (ReleaseFast)\n\n", .{});

    try out.print("send path\n", .{});
    for (cases) |case| {
        for (workloads) |workload| {
            var name_storage: [64]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_storage, "  encode {s} / {s}", .{ workload.name, case.name });
            (try benchSend(init.io, allocator, &pool, name, case.setup, workload.packets, workload.iterations)).report(out) catch {};
        }
    }

    try out.print("\nreceive path\n", .{});
    for (cases) |case| {
        for (workloads) |workload| {
            var name_storage: [64]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_storage, "  ingest {s} / {s}", .{ workload.name, case.name });
            (try benchIngest(init.io, allocator, &pool, name, case.setup, workload.packets, workload.iterations)).report(out) catch {};
        }
    }

    try out.print("\nprimitives\n", .{});
    try (try benchBatchSplit(init.io, allocator, gameplay, 200_000)).report(out);
    try (try benchSeal(init.io, 200_000)).report(out);
    try (try benchOpen(init.io, allocator, 200_000)).report(out);

    try reportFootprint(allocator, &pool, pool_counting, out);
    try out.flush();
}
