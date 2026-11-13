const std = @import("std");
const bedwire = @import("bedwire");
const baseline = @import("baseline.zig");
const Timer = @import("main.zig").Timer;
const flate = bedwire.compression.flate;

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.page_allocator;
    const cases = [_]struct { content: baseline.Content, size: usize }{
        .{ .content = .realistic, .size = 1024 },
        .{ .content = .realistic, .size = 2400 },
        .{ .content = .realistic, .size = 16 * 1024 },
        .{ .content = .realistic, .size = 256 * 1024 },
        .{ .content = .noise, .size = 1024 },
        .{ .content = .noise, .size = 16 * 1024 },
        .{ .content = .compressible, .size = 16 * 1024 },
    };
    const raw = try gpa.alloc(u8, 300 * 1024);
    const out = try gpa.alloc(u8, 320 * 1024);
    const back = try gpa.alloc(u8, 300 * 1024);
    const histories = try gpa.alloc([flate.history_len]u8, 2);
    const encoder: flate.Encoder = .{ .level = 1 };
    for (cases) |case| {
        const workload = try baseline.Workload.init(gpa, case.content, case.size);
        var writer = bedwire.framing.batch.Writer.init(raw, .{});
        for (workload.slice()) |packet| try writer.append(packet);
        const input = writer.written();
        const packed_bytes = try encoder.compress(input, out, &histories[0]);
        const size = packed_bytes.len;
        if (!std.mem.eql(u8, input, try flate.decompress(packed_bytes, back, &histories[1], .{}))) return error.Mismatch;

        var best: u64 = std.math.maxInt(u64);
        const rounds: usize = @max(20, 4_000_000 / input.len);
        for (0..15) |_| {
            const timer = Timer.start(init.io);
            for (0..rounds) |_| std.mem.doNotOptimizeAway(try encoder.compress(input, out, &histories[0]));
            best = @min(best, timer.read() / rounds);
        }
        std.debug.print("{t:12} {d:7} B  {d:8} ns  {d:6.2} ns/B  ratio {d:.4}  ({d} B)\n", .{ case.content, input.len, best, @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(input.len)), @as(f64, @floatFromInt(size)) / @as(f64, @floatFromInt(input.len)), size });
    }
}
