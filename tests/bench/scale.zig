const std = @import("std");
const bedwire = @import("bedwire");
const bench = @import("main.zig");

const Session = bedwire.Session;
const Setup = bench.Setup;
const packs = bedwire.resource_packs;

const modes = [_]struct { name: []const u8, setup: Setup }{
    .{ .name = "plain", .setup = .{ .algorithm = null, .encrypt = false } },
    .{ .name = "deflate", .setup = .{ .algorithm = .deflate, .encrypt = false } },
    .{ .name = "snappy+aes", .setup = .{ .algorithm = .snappy, .encrypt = true } },
    .{ .name = "deflate+aes", .setup = .{ .algorithm = .deflate, .encrypt = true } },
};

fn makePacket(storage: []u8, id: u16, len: usize, random: std.Random) []const u8 {
    const header = bedwire.framing.varint.writeU32(storage, id) catch unreachable;
    for (storage[header..len], 0..) |*byte, i| byte.* = if (i % 2 == 0) @truncate(i / 16) else random.int(u8);
    return storage[0..len];
}

const Group = struct {
    storage: []u8,
    packets: [][]const u8,

    fn init(allocator: std.mem.Allocator, count: usize, min: usize, max: usize, seed: u64) !Group {
        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();
        const storage = try allocator.alloc(u8, count * max);
        const packets = try allocator.alloc([]const u8, count);
        for (packets, 0..) |*packet, i| {
            const len = if (min == max) min else random.intRangeAtMost(usize, min, max);
            packet.* = makePacket(storage[i * max ..][0..max], 1020 + @as(u16, @intCast(i % 4)), len, random);
        }
        return .{ .storage = storage, .packets = packets };
    }

    fn bytes(self: Group) usize {
        var total: usize = 0;
        for (self.packets) |packet| total += packet.len;
        return total;
    }
};

const Exchange = struct { frames: usize, wire: usize };

fn splitExchange(server: *Session, client: *Session, group: Group) !Exchange {
    var result: Exchange = .{ .frames = 0, .wire = 0 };
    var batches = try server.encodeBatches(group.packets);
    while (try batches.next()) |frame| {
        defer frame.release();
        result.frames += 1;
        result.wire += frame.bytes.len;
        var packets = try client.ingest(frame.bytes);
        defer packets.deinit();
        while (packets.next()) |_| {}
    }
    return result;
}

fn singleExchange(server: *Session, client: *Session, group: Group) !Exchange {
    var result: Exchange = .{ .frames = 0, .wire = 0 };
    for (group.packets) |packet| {
        const frame = try server.encodeOne(packet);
        defer frame.release();
        result.frames += 1;
        result.wire += frame.bytes.len;
        var packets = try client.ingest(frame.bytes);
        defer packets.deinit();
        while (packets.next()) |_| {}
    }
    return result;
}

fn open(pool: *bedwire.BufferPool, role: bedwire.Role, setup: Setup, limits: bedwire.Limits) !Session {
    var session = try Session.init(role, .{ .pool = pool, .limits = limits });
    try session.compression.negotiate(setup.algorithm orelse .none, 0);
    if (setup.encrypt) session.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    session.state = .in_game;
    return session;
}

fn benchGroups(io: std.Io, allocator: std.mem.Allocator, out: *std.Io.Writer) !void {
    var counting: bench.Counting = .{ .backing = allocator };
    var pool = try bedwire.BufferPool.init(counting.allocator(), bench.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    const workloads = [_]struct { name: []const u8, group: Group, rounds: usize }{
        .{ .name = "1024 x 48 B", .group = try .init(allocator, 1024, 48, 48, 1), .rounds = 200 },
        .{ .name = "256 x 32 B-6 KiB", .group = try .init(allocator, 256, 32, 6 * 1024, 2), .rounds = 40 },
        .{ .name = "64 x 16 KiB", .group = try .init(allocator, 64, 16 * 1024, 16 * 1024, 3), .rounds = 20 },
    };

    try out.print("\n# packet groups, server encode + client ingest, ReleaseFast\n", .{});
    try out.print("{s: <18} {s: <12} {s: <9} {s: >7} {s: >11} {s: >10} {s: >12}\n", .{ "group", "mode", "path", "frames", "wire bytes", "ns/packet", "packets/s" });
    for (workloads) |workload| for (modes) |mode| {
        inline for (.{ .{ "split", splitExchange, null }, .{ "split64K", splitExchange, 64 * 1024 }, .{ "single", singleExchange, null } }) |path| {
            var limits = bench.limits;
            limits.max_outgoing_batch_bytes = path[2];
            var server = try open(&pool, .server, mode.setup, limits);
            defer server.deinit();
            var client = try open(&pool, .client, mode.setup, limits);
            defer client.deinit();

            const warm = try path[1](&server, &client, workload.group);
            const before = counting.allocations;
            const timer = bench.Timer.start(io);
            for (0..workload.rounds) |_| _ = try path[1](&server, &client, workload.group);
            const elapsed = timer.read();
            if (counting.allocations != before) return error.SteadyStateAllocation;

            const packets_sent = workload.rounds * workload.group.packets.len;
            const per_packet = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(packets_sent));
            try out.print("{s: <18} {s: <12} {s: <9} {d: >7} {d: >11} {d: >10.1} {d: >12.0}\n", .{
                workload.name, mode.name, path[0], warm.frames, warm.wire, per_packet, std.time.ns_per_s / per_packet,
            });
        }
    };
}

fn benchSessions(io: std.Io, allocator: std.mem.Allocator, out: *std.Io.Writer) !void {
    const small: bedwire.Limits = .{
        .max_frame_bytes = 64 * 1024,
        .max_batch_bytes = 256 * 1024,
        .max_packet_bytes = 64 * 1024,
    };
    var prng = std.Random.DefaultPrng.init(4);
    var storage: [128]u8 = undefined;
    const packet = makePacket(&storage, 1020, 96, prng.random());

    try out.print("\n# sessions sharing one pool (2 RX, 2 TX slots), snappy+aes, one 96 B packet each way per session per round\n", .{});
    try out.print("Session is {d} bytes; SessionCrypto is {d} bytes of it\n", .{ @sizeOf(Session), @sizeOf(bedwire.crypto.SessionCrypto) });
    try out.print("{s: >8} {s: >14} {s: >16} {s: >12} {s: >14}\n", .{ "pairs", "pool bytes", "bytes/session", "ns/packet", "packets/s" });

    for ([_]usize{ 100, 1_000, 10_000 }) |count| {
        var counting: bench.Counting = .{ .backing = allocator };
        const tracked = counting.allocator();
        var pool = try bedwire.BufferPool.init(tracked, small, .{ .rx_slots = 2, .tx_slots = 2 });
        defer pool.deinit();
        const pool_bytes = counting.bytes;

        const servers = try tracked.alloc(Session, count);
        defer tracked.free(servers);
        const clients = try tracked.alloc(Session, count);
        defer tracked.free(clients);
        for (servers, clients) |*server, *client| {
            server.* = try Session.init(.server, .{ .pool = &pool });
            client.* = try Session.init(.client, .{ .pool = &pool });
            for ([_]*Session{ server, client }) |session| {
                try session.compression.negotiate(.snappy, 0);
                session.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
                session.state = .in_game;
            }
        }
        defer for (servers, clients) |*server, *client| {
            server.deinit();
            client.deinit();
        };
        const session_bytes = (counting.bytes - pool_bytes) / (2 * count);

        const rounds = @max(1, 200_000 / count);
        const before = counting.allocations;
        const timer = bench.Timer.start(io);
        for (0..rounds) |_| for (servers, clients) |*server, *client| {
            inline for (.{ .{ server, client }, .{ client, server } }) |pair| {
                const frame = try pair[0].encodeOne(packet);
                defer frame.release();
                var received = try pair[1].ingest(frame.bytes);
                defer received.deinit();
                while (received.next()) |_| {}
            }
        };
        const elapsed = timer.read();
        if (counting.allocations != before) return error.SteadyStateAllocation;

        const per_packet = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(rounds * count * 2));
        try out.print("{d: >8} {d: >14} {d: >16} {d: >12.1} {d: >14.0}\n", .{ count, pool_bytes, session_bytes, per_packet, std.time.ns_per_s / per_packet });
    }
}

fn benchPacks(io: std.Io, allocator: std.mem.Allocator, out: *std.Io.Writer) !void {
    const size = 32 * 1024 * 1024;
    const archive = try allocator.alloc(u8, size);
    defer allocator.free(archive);
    var prng = std.Random.DefaultPrng.init(5);
    prng.random().bytes(archive);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(archive, &hash, .{});
    const stored = try allocator.alloc(u8, size);
    defer allocator.free(stored);
    const scratch = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(scratch);

    const limits: bedwire.Limits = .{ .max_resource_pack_bytes = size, .max_resource_pack_chunk_bytes = 1024 * 1024 };
    try out.print("\n# resource pack transfer, Delivery from memory into Transfer with SHA-256, {d} MiB archive\n", .{size >> 20});
    try out.print("{s: >10} {s: >7} {s: <9} {s: >10}\n", .{ "chunk", "window", "order", "MB/s" });

    for ([_]u32{ 64 * 1024, 1024 * 1024 }) |chunk_size| for ([_]u8{ 1, 8, 32 }) |window| for ([_]bool{ false, true }) |reversed| {
        if (window == 1 and reversed) continue;
        const metadata = try packs.Metadata.init("bench_1.0.0", size, chunk_size, hash);
        var delivery = try packs.Delivery.init(allocator, metadata, limits);
        defer delivery.deinit();
        var transfer = try packs.Transfer.init(allocator, metadata, limits, .{ .window = window });
        defer transfer.deinit();

        var queue: [packs.max_window]packs.Request = undefined;
        const timer = bench.Timer.start(io);
        while (!transfer.complete) {
            var count: usize = 0;
            while (transfer.nextRequest()) |request| : (count += 1) queue[count] = request;
            for (0..count) |i| {
                const request = queue[if (reversed) count - 1 - i else i];
                const chunk = try delivery.serve(request, packs.Archive{ .bytes = archive }, scratch);
                _ = try transfer.accept(chunk, packs.Memory{ .bytes = stored });
            }
        }
        const elapsed = timer.read();
        if (!std.mem.eql(u8, archive, stored)) return error.CorruptTransfer;

        const mb_per_s = @as(f64, size) / 1e6 / (@as(f64, @floatFromInt(elapsed)) / std.time.ns_per_s);
        try out.print("{d: >10} {d: >7} {s: <9} {d: >10.0}\n", .{ chunk_size, window, if (reversed) "reversed" else "in order", mb_per_s });
    };
}

pub fn main(init: std.process.Init) !void {
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    const out = &stdout.interface;
    defer out.flush() catch {};

    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();

    try benchGroups(init.io, arena_state.allocator(), out);
    try out.flush();
    try benchSessions(init.io, std.heap.page_allocator, out);
    try out.flush();
    try benchPacks(init.io, std.heap.page_allocator, out);
}
