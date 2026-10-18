const std = @import("std");
const builtin = @import("builtin");
const bedwire = @import("bedwire");
const baseline = @import("baseline.zig");
const legacy = @import("main.zig");
const lib = @import("libdeflate.zig");
const interop = @import("interop");
const Timer = legacy.Timer;
const limits = legacy.limits;
const Backend = enum { zig1, zig3, zig6, lib1, lib3, lib6, snappy };
const Phase = enum { encode, decode };
const corpus_dir = "zig-out/bench-corpus";

const Codec = struct {
    backend: Backend,
    scratch: *bedwire.compression.Scratch,
    context: ?lib.Context = null,

    fn init(backend: Backend, scratch: *bedwire.compression.Scratch) !Codec {
        return .{ .backend = backend, .scratch = scratch, .context = switch (backend) {
            .lib1 => try .init(1),
            .lib3 => try .init(3),
            .lib6 => try .init(6),
            else => null,
        } };
    }

    fn deinit(self: Codec) void {
        if (self.context) |context| context.deinit();
    }

    fn encode(self: *Codec, input: []const u8, output: []u8) ![]u8 {
        return switch (self.backend) {
            .zig1 => zigEncode(input, output, &self.scratch.history, .level_1),
            .zig3 => zigEncode(input, output, &self.scratch.history, .level_3),
            .zig6 => bedwire.compression.flate.compress(input, output, &self.scratch.history),
            .lib1, .lib3, .lib6 => self.context.?.compress(input, output),
            .snappy => bedwire.compression.snappy.compress(input, output, &self.scratch.table),
        };
    }

    fn decode(self: *Codec, input: []const u8, output: []u8) ![]u8 {
        return switch (self.backend) {
            .zig1, .zig3, .zig6 => bedwire.compression.flate.decompress(input, output, &self.scratch.history, limits),
            .lib1, .lib3, .lib6 => self.context.?.decompress(input, output, limits),
            .snappy => bedwire.compression.snappy.decompress(input, output, limits),
        };
    }
};

noinline fn zigEncode(input: []const u8, output: []u8, history: *[bedwire.compression.flate.history_len]u8, options: std.compress.flate.Compress.Options) ![]u8 {
    if (output.len < bedwire.compression.flate.minimum_output_bytes) return error.NoSpaceLeft;
    var writer: std.Io.Writer = .fixed(output);
    var compressor: std.compress.flate.Compress = try .init(&writer, history, .raw, options);
    compressor.writer.writeAll(input) catch return error.NoSpaceLeft;
    compressor.finish() catch return error.NoSpaceLeft;
    return output[0..writer.end];
}

noinline fn zigInit(scratch: *bedwire.compression.Scratch) !void {
    var output: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output);
    var compressor: std.compress.flate.Compress = try .init(&writer, &scratch.history, .raw, .default);
    std.mem.doNotOptimizeAway(&compressor);
}

fn operation(comptime phase: Phase, codec: *Codec, input: []const u8, output: []u8) !void {
    const bytes = if (phase == .encode) try codec.encode(input, output) else try codec.decode(input, output);
    std.mem.doNotOptimizeAway(bytes);
}

fn measure(comptime phase: Phase, io: std.Io, codec: *Codec, name: []const u8, source: []const u8, input: []const u8, output: []u8, raw_len: usize, compressed_len: usize, out: *std.Io.Writer) !void {
    const allocations = lib.bw_allocations();
    for (0..32) |_| try operation(phase, codec, input, output);
    var latencies: [1024]u64 = undefined;
    for (&latencies) |*latency| {
        const timer = Timer.start(io);
        try operation(phase, codec, input, output);
        latency.* = timer.read();
    }
    std.mem.sort(u64, &latencies, {}, std.sort.asc(u64));
    const iterations = @max(1, @min(1_000_000, 10 * std.time.ns_per_ms / @max(latencies[511], 1)));
    var elapsed: u64 = 0;
    var cpu: i96 = 0;
    for (0..7) |_| {
        const cpu_start = std.Io.Timestamp.now(io, .cpu_thread);
        const timer = Timer.start(io);
        for (0..iterations) |_| try operation(phase, codec, input, output);
        elapsed += timer.read();
        cpu += cpu_start.durationTo(std.Io.Timestamp.now(io, .cpu_thread)).nanoseconds;
    }
    if (lib.bw_allocations() != allocations) return error.SteadyStateAllocation;
    const ns: f64 = @floatFromInt(elapsed);
    const operations: f64 = @floatFromInt(iterations * 7);
    try out.print("{s},{s},{s},{s},{d},{d},{d},{d:.2},{d:.2},{d:.6},0,{d},{d},{d},{d}\n", .{
        name,
        @tagName(codec.backend),
        @tagName(phase),
        source,
        raw_len,
        compressed_len,
        iterations * 7,
        ns / operations,
        @as(f64, @floatFromInt(raw_len)) * operations * 1000 / ns,
        @as(f64, @floatFromInt(compressed_len)) / @as(f64, @floatFromInt(raw_len)),
        cpu,
        latencies[511],
        latencies[972],
        latencies[1013],
    });
    try out.flush();
}

fn checkBytes(expected: []const u8, actual: []const u8) !void {
    if (!std.mem.eql(u8, expected, actual)) return error.RoundtripMismatch;
}

fn fixtures(allocator: std.mem.Allocator, scratch: *bedwire.compression.Scratch) !void {
    const parsed = try std.json.parseFromSlice(interop.Fixture, allocator, interop.fixture_json, .{});
    defer parsed.deinit();
    const plain = try allocator.alloc(u8, parsed.value.plain.len / 2);
    defer allocator.free(plain);
    _ = try std.fmt.hexToBytes(plain, parsed.value.plain);
    const encoded = try allocator.alloc(u8, parsed.value.flate.len / 2);
    defer allocator.free(encoded);
    _ = try std.fmt.hexToBytes(encoded, parsed.value.flate);
    const output = try allocator.alloc(u8, plain.len);
    defer allocator.free(output);
    var codec = try Codec.init(.lib6, scratch);
    defer codec.deinit();
    const live = lib.bw_live_bytes();
    for (0..2) |offset| {
        lib.bw_fail_after(lib.bw_allocations() + offset);
        defer lib.bw_fail_after(std.math.maxInt(usize));
        if (lib.Context.init(6)) |unexpected| {
            unexpected.deinit();
            return error.MissingAllocationFailure;
        } else |err| {
            if (err != error.OutOfMemory) return err;
        }
        if (lib.bw_live_bytes() != live) return error.PartialInitializationLeak;
    }
    try checkBytes(plain, try codec.decode(encoded, output));
    if (codec.decode(encoded, output[0 .. output.len - 1])) |_| return error.MissingOutputBound else |err| {
        if (err != error.LimitExceeded) return err;
    }
    const trailing = try allocator.alloc(u8, encoded.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..encoded.len], encoded);
    trailing[encoded.len] = 0;
    if (codec.decode(trailing, output)) |_| return error.AcceptedTrailingData else |err| {
        if (err != error.MalformedCompressedData) return err;
    }
    if (codec.decode(encoded[0 .. encoded.len - 1], output)) |_| return error.AcceptedTruncation else |_| {}
    const bomb_input = try allocator.alloc(u8, 131072);
    defer allocator.free(bomb_input);
    @memset(bomb_input, 0);
    var compressed: [4096]u8 = undefined;
    const bomb = try codec.encode(bomb_input, &compressed);
    var reduced = limits;
    reduced.max_batch_bytes = 128;
    if (codec.context.?.decompress(bomb, output, reduced)) |_| return error.MissingBombBound else |err| {
        if (err != error.LimitExceeded) return err;
    }
    var prng = std.Random.DefaultPrng.init(0xdef);
    var malformed: [128]u8 = undefined;
    for (0..1000) |i| {
        prng.random().bytes(&malformed);
        _ = codec.decode(malformed[0 .. i % malformed.len], output[0..128]) catch {};
    }
}

fn exportFile(io: std.Io, name: []const u8, extension: []const u8, bytes: []const u8) !void {
    var path: [128]u8 = undefined;
    const filename = try std.fmt.bufPrint(&path, corpus_dir ++ "/{s}.{s}", .{ name, extension });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = filename, .data = bytes });
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.page_allocator;
    var scratch: bedwire.compression.Scratch = undefined;
    const raw_storage = try allocator.alloc(u8, limits.max_batch_bytes);
    defer allocator.free(raw_storage);
    const compressed = try allocator.alloc(u8, limits.max_frame_bytes - 10);
    defer allocator.free(compressed);
    const decoded = try allocator.alloc(u8, limits.max_batch_bytes);
    defer allocator.free(decoded);
    try fixtures(allocator, &scratch);
    if (lib.bw_live_bytes() != 0) return error.ContextLeak;
    try std.Io.Dir.cwd().createDirPath(init.io, corpus_dir);
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    const out = &stdout.interface;
    const zig_setup = Timer.start(init.io);
    for (0..1000) |_| try zigInit(&scratch);
    try out.print("# setup,zig6,init_ns={d:.2},allocations_per_context=0\n", .{@as(f64, @floatFromInt(zig_setup.read())) / 1000});
    try out.print("# libdeflate=1.26, C=-O2, Zig={s} ReleaseFast, {s}-{s}, decode_output_limit={d}, encode_output_limit={d}\n", .{ builtin.zig_version_string, @tagName(builtin.cpu.arch), @tagName(builtin.os.tag), decoded.len, compressed.len });
    try out.print("# std_compressor_struct_bytes={d}, scratch_bytes={d}\n", .{ @sizeOf(std.compress.flate.Compress), @sizeOf(bedwire.compression.Scratch) });
    try out.print("workload,backend,phase,source,raw_bytes,compressed_bytes,operations,ns_per_op,MB_per_s,compressed_over_raw,allocations_per_op,cpu_ns,p50_ns,p95_ns,p99_ns\n", .{});
    for ([_]struct { name: []const u8, bytes: usize }{
        .{ .name = "small", .bytes = 256 },
        .{ .name = "medium", .bytes = 16 * 1024 },
        .{ .name = "large", .bytes = 256 * 1024 },
    }) |size| {
        for (std.enums.values(baseline.Content)) |content| {
            const workload = try baseline.Workload.init(allocator, content, size.bytes);
            defer allocator.free(workload.storage);
            var name_storage: [64]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_storage, "{s}-{s}", .{ size.name, @tagName(content) });
            var writer = bedwire.framing.batch.Writer.init(raw_storage, limits);
            for (workload.slice()) |packet| try writer.append(packet);
            const raw = writer.written();
            try exportFile(init.io, name, "raw", raw);
            for (std.enums.values(Backend)) |backend| {
                var codec = try Codec.init(backend, &scratch);
                defer codec.deinit();
                const encoded = try codec.encode(raw, compressed);
                try checkBytes(raw, try codec.decode(encoded, decoded));
                try measure(.encode, init.io, &codec, name, "raw", raw, compressed, raw.len, encoded.len, out);
                if (backend == .snappy) {
                    try exportFile(init.io, name, "snappy", encoded);
                    try measure(.decode, init.io, &codec, name, "snappy", encoded, decoded, raw.len, encoded.len, out);
                } else {
                    if (backend == .zig6) try exportFile(init.io, name, "flate", encoded);
                    if (backend == .lib6) try exportFile(init.io, name, "libflate", encoded);
                    var zig_decoder = try Codec.init(.zig6, &scratch);
                    try checkBytes(raw, try zig_decoder.decode(encoded, decoded));
                    try measure(.decode, init.io, &zig_decoder, name, @tagName(backend), encoded, decoded, raw.len, encoded.len, out);
                    var lib_decoder = try Codec.init(.lib6, &scratch);
                    defer lib_decoder.deinit();
                    try checkBytes(raw, try lib_decoder.decode(encoded, decoded));
                    try measure(.decode, init.io, &lib_decoder, name, @tagName(backend), encoded, decoded, raw.len, encoded.len, out);
                }
            }
            var path_storage: [128]u8 = undefined;
            const path = try std.fmt.bufPrint(&path_storage, corpus_dir ++ "/{s}.s2snappy", .{name});
            if (std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(limits.max_frame_bytes))) |reference| {
                defer allocator.free(reference);
                var codec = try Codec.init(.snappy, &scratch);
                try checkBytes(raw, try codec.decode(reference, decoded));
                try measure(.decode, init.io, &codec, name, "s2snappy", reference, decoded, raw.len, reference.len, out);
            } else |err| {
                if (err != error.FileNotFound) return err;
            }
        }
    }
    try std.Io.Dir.cwd().createDirPath(init.io, corpus_dir ++ "/micro");
    for ([_]usize{ 1, 3, 4, 16, 32, 64, 128 }) |len| {
        var name_storage: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_storage, "micro/noise-{d}", .{len});
        const raw = raw_storage[0..len];
        var codec = try Codec.init(.snappy, &scratch);
        const encoded = try codec.encode(raw, compressed);
        try checkBytes(raw, try codec.decode(encoded, decoded));
        try exportFile(init.io, name, "raw", raw);
        try exportFile(init.io, name, "snappy", encoded);
        try measure(.encode, init.io, &codec, name, "raw", raw, compressed, raw.len, encoded.len, out);
        try measure(.decode, init.io, &codec, name, "snappy", encoded, decoded, raw.len, encoded.len, out);
        var path_storage: [128]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_storage, corpus_dir ++ "/{s}.s2snappy", .{name});
        if (std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(limits.max_frame_bytes))) |reference| {
            defer allocator.free(reference);
            try checkBytes(raw, try codec.decode(reference, decoded));
            try measure(.decode, init.io, &codec, name, "s2snappy", reference, decoded, raw.len, reference.len, out);
        } else |err| {
            if (err != error.FileNotFound) return err;
        }
    }
    if (lib.bw_live_bytes() != 0) return error.ContextLeak;
    for ([_]c_int{ 1, 3, 6 }) |level| {
        lib.bw_reset_peak();
        const before = lib.bw_allocations();
        const timer = Timer.start(init.io);
        for (0..1000) |_| {
            const context = try lib.Context.init(level);
            context.deinit();
        }
        try out.print("# setup,lib{d},init_free_ns={d:.2},allocations_per_context={d},peak_state_bytes={d},compressor_bytes={d},decompressor_bytes={d}\n", .{
            level,
            @as(f64, @floatFromInt(timer.read())) / 1000,
            (lib.bw_allocations() - before) / 1000,
            lib.bw_peak_bytes(),
            lib.bw_compressor_bytes(),
            lib.bw_decompressor_bytes(),
        });
        if (lib.bw_live_bytes() != 0) return error.ContextLeak;
    }
    try out.flush();
}
