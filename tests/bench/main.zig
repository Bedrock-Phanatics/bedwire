const std = @import("std");
const bedwire = @import("bedwire");

pub const Counting = struct {
    backing: std.mem.Allocator,
    allocations: usize = 0,
    bytes: usize = 0,

    pub fn allocator(self: *Counting) std.mem.Allocator {
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

    fn report(self: Result, out: *std.Io.Writer) !void {
        const seconds = @as(f64, @floatFromInt(self.nanoseconds)) / std.time.ns_per_s;
        const per_op = @as(f64, @floatFromInt(self.nanoseconds)) / @as(f64, @floatFromInt(self.operations));
        const ops = @as(f64, @floatFromInt(self.operations)) / seconds;
        const throughput = @as(f64, @floatFromInt(self.payload_bytes)) / seconds / (1024 * 1024);

        try out.print("{s: <34} {d: >10.1} ns/op  {d: >12.0} ops/s  {d: >8.1} MB/s\n", .{ self.name, per_op, ops, throughput });
    }
};

pub const limits: bedwire.Limits = .{
    .max_frame_bytes = 1 << 20,
    .max_batch_bytes = 4 << 20,
    .max_packet_bytes = 1 << 20,
};

fn makePacket(storage: []u8, id: u16, len: usize) []const u8 {
    const header = bedwire.framing.varint.writeU32(storage, id) catch unreachable;
    for (storage[header..len], 0..) |*byte, i| byte.* = @truncate(i *% 31 +% 7);
    return storage[0..len];
}

const Session = bedwire.Session;
const control = bedwire.control;

pub const Setup = struct {
    algorithm: ?bedwire.compression.Algorithm,
    encrypt: bool,
};

pub fn open(pool: *bedwire.BufferPool, role: bedwire.Role, setup: Setup) !Session {
    var session = try Session.init(role, .{ .pool = pool, .limits = limits });
    errdefer session.deinit();

    try session.compression.negotiate(setup.algorithm orelse .none, 0);
    if (setup.encrypt) session.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    session.state = .in_game;

    return session;
}

pub const Timer = struct {
    io: std.Io,
    start_ts: std.Io.Timestamp,

    pub fn start(io: std.Io) Timer {
        return .{
            .io = io,
            .start_ts = std.Io.Timestamp.now(io, .awake),
        };
    }

    pub fn read(self: Timer) u64 {
        const now = std.Io.Timestamp.now(self.io, .awake);
        const duration = self.start_ts.durationTo(now);
        return @intCast(duration.nanoseconds);
    }
};

fn makeNetworkSettings(storage: []u8) ![]const u8 {
    return control.encode(storage, control.NetworkSettings{ .compression_algorithm = .snappy, .compression_threshold = 128 });
}

const ControlResults = struct { send: Result, ingest: Result };

fn benchNetworkSettings(io: std.Io, allocator: std.mem.Allocator, pool: *bedwire.BufferPool, label: []const u8, packet: []const u8, iterations: usize) !ControlResults {
    var sender = try Session.init(.server, .{ .pool = pool, .limits = limits });
    defer sender.deinit();
    var receiver = try Session.init(.client, .{ .pool = pool, .limits = limits });
    defer receiver.deinit();
    sender.state = .network_settings;
    receiver.state = .network_settings;

    const frames = try allocator.alloc([]u8, iterations);
    defer {
        for (frames) |frame| allocator.free(frame);
        allocator.free(frames);
    }
    for (frames) |*bytes| {
        const frame = try sender.encodeOne(packet);
        defer frame.release();
        bytes.* = try allocator.dupe(u8, frame.bytes);
    }

    var timer = Timer.start(io);
    for (0..iterations) |_| {
        const frame = try sender.encodeOne(packet);
        std.mem.doNotOptimizeAway(frame.bytes.ptr);
        frame.release();
    }
    const send_elapsed = timer.read();

    timer = Timer.start(io);
    for (frames) |frame| {
        var packets = try receiver.ingest(frame);
        while (packets.next()) |decoded| std.mem.doNotOptimizeAway(decoded.bytes.ptr);
        packets.deinit();
    }
    const ingest_elapsed = timer.read();

    return .{
        .send = .{
            .name = try std.fmt.allocPrint(allocator, "encode NetworkSettings / {s}", .{label}),
            .operations = iterations,
            .nanoseconds = send_elapsed,
            .payload_bytes = packet.len * iterations,
        },
        .ingest = .{
            .name = try std.fmt.allocPrint(allocator, "ingest NetworkSettings / {s}", .{label}),
            .operations = iterations,
            .nanoseconds = ingest_elapsed,
            .payload_bytes = packet.len * iterations,
        },
    };
}

fn benchSend(io: std.Io, pool: *bedwire.BufferPool, name: []const u8, setup: Setup, packets: []const []const u8, iterations: usize) !Result {
    var session = try open(pool, .server, setup);
    defer session.deinit();

    var payload: usize = 0;
    for (packets) |packet| payload += packet.len;

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
    };
}

fn benchIngest(io: std.Io, allocator: std.mem.Allocator, pool: *bedwire.BufferPool, name: []const u8, setup: Setup, packets: []const []const u8, iterations: usize) !Result {
    var sender = try open(pool, .client, setup);
    defer sender.deinit();
    var receiver = try open(pool, .server, setup);
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
    };
}

fn benchRelay(io: std.Io, allocator: std.mem.Allocator, pool: *bedwire.BufferPool, name: []const u8, algorithm: bedwire.compression.Algorithm, packet: []const u8, iterations: usize, fast: bool) !Result {
    const setup: Setup = .{ .algorithm = algorithm, .encrypt = true };
    var peer = try open(pool, .client, setup);
    defer peer.deinit();
    var inbound = try open(pool, .server, setup);
    defer inbound.deinit();
    var outbound = try open(pool, .client, setup);
    defer outbound.deinit();
    outbound.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x24));

    const frames = try allocator.alloc([]u8, iterations);
    defer {
        for (frames) |frame| allocator.free(frame);
        allocator.free(frames);
    }
    for (frames) |*frame| {
        const f = try peer.encodeOne(packet);
        defer f.release();
        frame.* = try allocator.dupe(u8, f.bytes);
    }

    var timer = Timer.start(io);
    for (frames) |frame| {
        const out = if (fast) try inbound.relayTo(&outbound, frame) else blk: {
            var packets = try inbound.ingest(frame);
            defer packets.deinit();
            break :blk try outbound.encodeOne(packets.next().?.bytes);
        };
        std.mem.doNotOptimizeAway(out.bytes.ptr);
        out.release();
    }
    const elapsed = timer.read();

    return .{ .name = name, .operations = iterations, .nanoseconds = elapsed, .payload_bytes = packet.len * iterations };
}

fn benchSessionLifecycle(io: std.Io, pool: *bedwire.BufferPool, iterations: usize) !Result {
    var storage: [64]u8 = undefined;
    const packet = makePacket(&storage, 1020, 32);
    var timer = Timer.start(io);
    for (0..iterations) |_| {
        var sender = try open(pool, .client, .{ .algorithm = .snappy, .encrypt = true });
        defer sender.deinit();
        var receiver = try open(pool, .server, .{ .algorithm = .snappy, .encrypt = true });
        defer receiver.deinit();
        const frame = try sender.encodeOne(packet);
        defer frame.release();
        var packets = try receiver.ingest(frame.bytes);
        defer packets.deinit();
        std.mem.doNotOptimizeAway(packets.next().?.bytes.ptr);
        sender.close();
        receiver.close();
    }
    std.debug.assert(pool.isIdle());
    return .{ .name = "Session pair / shared pool", .operations = iterations, .nanoseconds = timer.read(), .payload_bytes = packet.len * iterations };
}

fn benchClassification(io: std.Io, name: []const u8, iterations: usize) Result {
    var timer = Timer.start(io);
    for (0..iterations) |i| {
        const id: u10 = @truncate(i);
        std.mem.doNotOptimizeAway(bedwire.PacketKind.fromId(id));
    }
    return .{ .name = name, .operations = iterations, .nanoseconds = timer.read(), .payload_bytes = 0 };
}

fn benchState(io: std.Io, name: []const u8, iterations: usize) Result {
    var timer = Timer.start(io);
    for (0..iterations) |i| {
        const kind = bedwire.PacketKind.fromId(@truncate(i));
        std.mem.doNotOptimizeAway(bedwire.State.in_game.permits(.{}, .client, kind));
    }
    return .{ .name = name, .operations = iterations, .nanoseconds = timer.read(), .payload_bytes = 0 };
}

fn benchBatchSplit(io: std.Io, allocator: std.mem.Allocator, packets: []const []const u8, iterations: usize) !Result {
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
    };
}

fn reportFootprint(pool: *bedwire.BufferPool, pool_counting: Counting, out: *std.Io.Writer) !void {
    try out.print("\nmemory\n", .{});
    try out.print("  limits: frame {d} KiB, batch {d} KiB\n", .{ limits.max_frame_bytes / 1024, limits.max_batch_bytes / 1024 });
    try out.print("  pool logical:   {d} KiB ({d} B) backing storage\n", .{ pool.storageBytes() / 1024, pool.storageBytes() });
    try out.print("  pool allocator: {d} KiB ({d} B) across {d} allocations ({d} RX, {d} TX slots)\n", .{ pool_counting.bytes / 1024, pool_counting.bytes, pool_counting.allocations, pool.config.rx_slots, pool.config.tx_slots });
    try out.print("  struct: {d} B (Session), {d} B (BufferPool), {d} B (Packets), {d} B (Frame)\n", .{ @sizeOf(Session), @sizeOf(bedwire.BufferPool), @sizeOf(bedwire.Packets), @sizeOf(bedwire.Frame) });
}

fn tapFrame(dest: []u8, packet: []const u8, compressed: bool) ![]const u8 {
    var raw: [4096]u8 = undefined;
    var writer = bedwire.framing.batch.Writer.init(&raw, limits);
    try writer.append(packet);
    dest[0] = bedwire.framing.batch.header;
    if (!compressed) {
        @memcpy(dest[1 .. 1 + writer.written().len], writer.written());
        return dest[0 .. 1 + writer.written().len];
    }
    var codec = bedwire.compression.Compression.init(.{});
    try codec.negotiate(.snappy, 0);
    var scratch: bedwire.compression.Scratch = undefined;
    const framed = try codec.encode(writer.written(), dest[2..], &scratch);
    dest[1] = @backingInt(framed.algorithm);
    return dest[0 .. 2 + framed.bytes.len];
}

const tap_version = 800;

fn benchTap(io: std.Io, pool: *bedwire.BufferPool, iterations: usize) !Result {
    var packet_storage: [4][4096]u8 = undefined;
    var frame_storage: [4][4096]u8 = undefined;
    var frames: [4][]const u8 = undefined;

    for (0..4) |i| {
        const packet = try switch (i) {
            0 => control.encode(&packet_storage[i], control.RequestNetworkSettings{ .protocol_version = tap_version }),
            1 => control.encode(&packet_storage[i], control.NetworkSettings{ .compression_threshold = 0, .compression_algorithm = .snappy }),
            2 => control.encode(&packet_storage[i], control.Login{ .protocol_version = tap_version, .connection_request = "fixture" }),
            else => control.encode(&packet_storage[i], control.ServerToClientHandshake{ .token = "fixture" }),
        };
        frames[i] = try tapFrame(&frame_storage[i], packet, i >= 2);
    }

    const directions: [4]bedwire.TapDirection = .{ .client_to_server, .server_to_client, .client_to_server, .server_to_client };
    var timer = Timer.start(io);
    for (0..iterations) |_| {
        var tap = try bedwire.Tap.init(.{ .pool = pool, .limits = limits, .protocol_version = tap_version });
        for (frames, directions) |frame, direction| {
            var packets = try tap.observe(direction, frame);
            std.mem.doNotOptimizeAway(packets.next().?.bytes.ptr);
            packets.deinit();
        }
        std.debug.assert(tap.phase() == .encrypted);
        tap.deinit();
    }
    const elapsed = timer.read();
    var payload: usize = 0;
    for (frames) |frame| payload += frame.len;
    return .{ .name = "Tap handshake / shared pool", .operations = iterations, .nanoseconds = elapsed, .payload_bytes = payload * iterations };
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

    var single_storage: [64]u8 = undefined;
    const single: []const []const u8 = &.{makePacket(&single_storage, 1020, 32)};

    var gameplay_storage: [16][256]u8 = undefined;
    var gameplay_packets: [16][]const u8 = undefined;
    for (&gameplay_packets, 0..) |*slot, i| {
        slot.* = makePacket(&gameplay_storage[i], 1020 + @as(u16, @intCast(i % 4)), 96 + i * 8);
    }
    const gameplay: []const []const u8 = &gameplay_packets;

    const chunk_storage = try allocator.alloc(u8, 256 * 1024);
    const chunk: []const []const u8 = &.{makePacket(chunk_storage, 1020, chunk_storage.len)};

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
            try (try benchSend(init.io, &pool, name, case.setup, workload.packets, workload.iterations)).report(out);
        }
    }

    try out.print("\nreceive path\n", .{});
    for (cases) |case| {
        for (workloads) |workload| {
            var name_storage: [64]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_storage, "  ingest {s} / {s}", .{ workload.name, case.name });
            try (try benchIngest(init.io, allocator, &pool, name, case.setup, workload.packets, workload.iterations)).report(out);
        }
    }

    try out.print("\nmanaged relay, encrypted both legs (ingest+encode vs relayTo)\n", .{});
    const relay_storage = try allocator.alloc(u8, 64 * 1024);
    var prng = std.Random.DefaultPrng.init(0xbed);
    for ([_]bedwire.compression.Algorithm{ .deflate, .snappy }) |algorithm| {
        for ([_]bool{ true, false }) |compressible| {
            for ([_]struct { len: usize, iterations: usize }{
                .{ .len = 256, .iterations = 50_000 },
                .{ .len = 1024, .iterations = 50_000 },
                .{ .len = 8 * 1024, .iterations = 10_000 },
                .{ .len = 64 * 1024, .iterations = 1_000 },
            }) |size| {
                const packet = makePacket(relay_storage, 1020, size.len);
                if (!compressible) prng.random().bytes(relay_storage[2..size.len]);
                for ([_]bool{ false, true }) |fast| {
                    var name_storage: [64]u8 = undefined;
                    const name = try std.fmt.bufPrint(&name_storage, "  {s} {s} {s} {d} B", .{
                        if (fast) "relay " else "decode",
                        @tagName(algorithm),
                        if (compressible) "game " else "noise",
                        size.len,
                    });
                    try (try benchRelay(init.io, allocator, &pool, name, algorithm, packet, size.iterations, fast)).report(out);
                }
            }
        }
    }

    try out.print("\nsession create, encrypted exchange, close, destroy\n", .{});
    const before_sessions = pool_counting.allocations;
    try (try benchSessionLifecycle(init.io, &pool, 200_000)).report(out);
    try out.print("  steady allocations: {d}\n", .{pool_counting.allocations - before_sessions});

    try out.print("\nprimitives\n", .{});
    try (try benchBatchSplit(init.io, allocator, gameplay, 200_000)).report(out);
    try (try benchSeal(init.io, 200_000)).report(out);
    try (try benchOpen(init.io, allocator, 200_000)).report(out);

    try out.print("\ncontrol\n", .{});
    try benchClassification(init.io, "classify", 2_000_000).report(out);
    try benchState(init.io, "state validation", 2_000_000).report(out);
    var settings_storage: [64]u8 = undefined;
    const settings = try makeNetworkSettings(&settings_storage);
    const settings_control = try benchNetworkSettings(init.io, allocator, &pool, "network settings", settings, 200_000);
    try settings_control.send.report(out);
    try settings_control.ingest.report(out);

    try out.print("\npassive observer (request, settings, compressed Login, clear handshake)\n", .{});
    const before_tap = pool_counting.allocations;
    try (try benchTap(init.io, &pool, 200_000)).report(out);
    try out.print("  steady allocations: {d}; Tap struct: {d} B\n", .{ pool_counting.allocations - before_tap, @sizeOf(bedwire.Tap) });
    var observer_counting: Counting = .{ .backing = allocator };
    var observer_pool = try bedwire.BufferPool.init(observer_counting.allocator(), limits, bedwire.PoolConfig.observer());
    try out.print("  observer pool: {d} B backing; {d} B allocated in {d} calls\n", .{
        observer_pool.storageBytes(), observer_counting.bytes, observer_counting.allocations,
    });
    observer_pool.deinit();

    try reportFootprint(&pool, pool_counting, out);
    try out.flush();
}
