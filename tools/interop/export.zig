const std = @import("std");
const bedwire = @import("bedwire");

pub fn main(init: std.process.Init) !void {
    var table: bedwire.compression.snappy.Table = undefined;
    var output: [8192]u8 = undefined;
    const input: [100][33]u8 = @splat("Bedrock Snappy interoperability. ".*);
    const encoded = try bedwire.compression.snappy.compress(std.mem.asBytes(&input), &output, &table);
    std.debug.print("{x}", .{encoded});

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) return;
    try writeFrames(init.io, init.gpa, args[1]);
}

/// Per stream a u8 algorithm, u32 frame count and u32-prefixed frames, then a u32 count and the u32-prefixed packets.
fn writeFrames(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !void {
    const limits: bedwire.Limits = .{ .max_frame_bytes = 4096, .max_batch_bytes = 64 * 1024, .max_packet_bytes = 4096, .max_outgoing_packets_per_batch = 16 };
    var pool = try bedwire.BufferPool.init(allocator, limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();

    var prng = std.Random.DefaultPrng.init(0x1e7);
    const random = prng.random();
    var storage: [96][1200]u8 = undefined;
    var packets: [96][]const u8 = undefined;
    for (&packets, 0..) |*packet, i| {
        const len = 3 + random.uintLessThan(usize, 1100);
        const header = try bedwire.framing.varint.writeU32(&storage[i], 1020);
        // Runs of noise packets make whole batches that can't shrink and go out marked uncompressed.
        for (storage[i][header..len], 0..) |*byte, j| byte.* = if (i / 16 % 2 == 1) random.int(u8) else @truncate(j / 8);
        packet.* = storage[i][0..len];
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    for ([_]bedwire.compression.Algorithm{ .deflate, .snappy }) |algorithm| {
        var session = try bedwire.Session.init(.server, .{ .pool = &pool });
        defer session.deinit();
        try session.compression.negotiate(algorithm, 0);
        session.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
        session.state = .in_game;

        try out.append(allocator, @backingInt(algorithm));
        const count_at = out.items.len;
        try out.appendNTimes(allocator, 0, 4);
        var frames: u32 = 0;
        var batches = try session.encodeBatches(&packets);
        while (try batches.next()) |frame| : (frames += 1) {
            defer frame.release();
            try appendBlock(&out, allocator, frame.bytes);
        }
        std.mem.writeInt(u32, out.items[count_at..][0..4], frames, .little);
    }
    var count: [4]u8 = undefined;
    std.mem.writeInt(u32, &count, packets.len, .little);
    try out.appendSlice(allocator, &count);
    for (packets) |packet| try appendBlock(&out, allocator, packet);

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = out.items });
}

fn appendBlock(out: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) !void {
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(bytes.len), .little);
    try out.appendSlice(allocator, &len);
    try out.appendSlice(allocator, bytes);
}
