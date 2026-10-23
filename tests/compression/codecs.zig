const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const flate = bedwire.compression.flate;
const snappy = bedwire.compression.snappy;

const limits: bedwire.Limits = .{
    .max_frame_bytes = 1 << 20,
    .max_batch_bytes = 1 << 20,
    .max_packet_bytes = 1 << 20,
};

fn snappyRoundTrip(input: []const u8) !void {
    const allocator = testing.allocator;

    const encoded = try allocator.alloc(u8, try snappy.maxEncodedLen(input.len));
    defer allocator.free(encoded);

    const table = try allocator.create(snappy.Table);
    defer allocator.destroy(table);

    const compressed = try snappy.compress(input, encoded, table);

    const decoded = try allocator.alloc(u8, input.len + 1);
    defer allocator.free(decoded);

    try testing.expectEqualSlices(u8, input, try snappy.decompress(compressed, decoded, limits));
}

test "Snappy round-trips every literal and copy form" {
    var random = std.Random.DefaultPrng.init(0x5eed);
    var noise: [8192]u8 = undefined;
    random.random().bytes(&noise);

    try snappyRoundTrip("");
    try snappyRoundTrip("a");
    try snappyRoundTrip("abc");
    try snappyRoundTrip(&@as([60]u8, @splat('a')));
    try snappyRoundTrip(&@as([61]u8, @splat('a')));
    try snappyRoundTrip(&@as([300]u8, @splat('b')));
    try snappyRoundTrip(&@as([70000]u8, @splat('c')));
    try snappyRoundTrip(repeat("abcd", 4096));
    try snappyRoundTrip(&noise);
}

test "Snappy rejects malformed streams without writing output" {
    var output: [64]u8 = undefined;

    const cases = [_][]const u8{
        &.{},
        &.{0x04},
        &.{ 0x04, 0x00 },
        &.{ 0x04, 0x0c, 'a', 'b', 'c' },
        &.{ 0x04, 0x01, 0x00 },
        &.{ 0x04, 0x05, 0x01 },
        &.{ 0x04, 0xfc },
        &.{ 0x04, 0x00, 'a', 0x00, 'b' },
    };

    for (cases) |input| {
        try testing.expect(std.meta.isError(snappy.decompress(input, &output, limits)));
    }
}

test "Snappy refuses to decompress past the caller's buffer" {
    var output: [4]u8 = undefined;
    try testing.expectError(error.LimitExceeded, snappy.decompress(&.{0x20}, &output, limits));
}

test "Snappy self-references decode correctly when the copy overlaps" {
    var output: [64]u8 = undefined;

    const input = [_]u8{ 0x08, 0x00, 'a', (3 << 2) | 1, 0x01 };
    try testing.expectEqualSlices(u8, "aaaaaaaa", try snappy.decompress(&input, &output, limits));
}

test "Snappy copy forms preserve every short overlap and output boundary" {
    var encoded: [80]u8 = undefined;
    var expected: [128]u8 = undefined;
    var storage: [130]u8 = undefined;
    for (1..65) |offset| {
        for (1..65) |len| {
            for ([_]u8{ 1, 2, 3 }) |kind| {
                if (kind == 1 and (len < 4 or len > 11)) continue;
                const total = offset + len;
                var cursor = try bedwire.framing.varint.writeU32(&encoded, @intCast(total));
                if (offset <= 60) {
                    encoded[cursor] = @as(u8, @intCast(offset - 1)) << 2;
                    cursor += 1;
                } else {
                    encoded[cursor] = 60 << 2;
                    encoded[cursor + 1] = @intCast(offset - 1);
                    cursor += 2;
                }
                for (expected[0..offset], 0..) |*byte, i| byte.* = @truncate(i * 17 + 3);
                @memcpy(encoded[cursor..][0..offset], expected[0..offset]);
                cursor += offset;
                encoded[cursor] = if (kind == 1) (@as(u8, @intCast(len - 4)) << 2) | kind else (@as(u8, @intCast(len - 1)) << 2) | kind;
                cursor += 1;
                const count: usize = if (kind == 1) 1 else if (kind == 2) 2 else 4;
                var encoded_offset: [4]u8 = undefined;
                std.mem.writeInt(u32, &encoded_offset, @intCast(offset), .little);
                @memcpy(encoded[cursor..][0..count], encoded_offset[0..count]);
                cursor += count;
                for (offset..total) |i| expected[i] = expected[i - offset];
                @memset(&storage, 0xa5);
                try testing.expectEqualSlices(u8, expected[0..total], try snappy.decompress(encoded[0..cursor], storage[1..][0..total], limits));
                try testing.expectEqual(@as(u8, 0xa5), storage[0]);
                try testing.expectEqual(@as(u8, 0xa5), storage[total + 1]);
            }
        }
    }
}

test "Snappy wide matches handle unaligned inputs, mismatches and tails without allocating" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    const table = try failing.allocator().create(snappy.Table);
    defer failing.allocator().destroy(table);
    const large_input = try failing.allocator().alloc(u8, 65536 + 16 + 7);
    defer failing.allocator().free(large_input);
    const large_encoded = try failing.allocator().alloc(u8, try snappy.maxEncodedLen(65536 + 16));
    defer failing.allocator().free(large_encoded);
    const large_output = try failing.allocator().alloc(u8, 65536 + 16);
    defer failing.allocator().free(large_output);
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    var input: [136]u8 = undefined;
    var encoded: [256]u8 = undefined;
    var output: [128]u8 = undefined;
    for (0..8) |alignment| {
        for (1..17) |period| {
            for (0..129) |len| {
                const plain = input[alignment..][0..len];
                for (plain, 0..) |*byte, i| byte.* = @intCast((i % period) * 13);
                if (len != 0) plain[len - 1] ^= 0x80;
                const compressed = try snappy.compress(plain, &encoded, table);
                try testing.expectEqualSlices(u8, plain, try snappy.decompress(compressed, output[0..len], limits));
            }
        }
        const sparse_plain = large_input[alignment..][0 .. 65536 + 16];
        var random = std.Random.DefaultPrng.init(0x5a9);
        random.random().bytes(sparse_plain);
        @memset(sparse_plain[50000..51024], 'k');
        @memset(sparse_plain[60000..61024], 'k');
        for (0..256) |size| {
            try testing.expectError(error.NoSpaceLeft, snappy.compress(sparse_plain, large_encoded[0..size], table));
        }
        const sparse_compressed = try snappy.compress(sparse_plain, large_encoded, table);
        try testing.expectEqualSlices(u8, sparse_plain, try snappy.decompress(sparse_compressed, large_output, limits));
        try testing.expectError(error.LimitExceeded, snappy.decompress(sparse_compressed, large_output[0 .. sparse_plain.len - 1], limits));
        for (1..17) |period| {
            for (0..17) |tail| {
                const plain = large_input[alignment..][0 .. 65536 + tail];
                for (plain, 0..) |*byte, i| byte.* = @intCast((i % period) * 13);
                plain[plain.len - 1] ^= 0x80;
                const compressed = try snappy.compress(plain, large_encoded, table);
                try testing.expectEqualSlices(u8, plain, try snappy.decompress(compressed, large_output[0..plain.len], limits));
            }
        }
    }
    try testing.expect(!failing.has_induced_failure);
}

test "raw DEFLATE round-trips and rejects corruption" {
    const allocator = testing.allocator;

    var history: [flate.history_len]u8 = undefined;
    const input = repeat("bedrock ", 512);

    const encoded = try allocator.alloc(u8, input.len + 64);
    defer allocator.free(encoded);

    const compressed = try flate.compress(input, encoded, &history);
    try testing.expect(compressed.len < input.len);

    const decoded = try allocator.alloc(u8, input.len);
    defer allocator.free(decoded);

    try testing.expectEqualSlices(u8, input, try flate.decompress(compressed, decoded, &history, limits));

    const mutated = try allocator.dupe(u8, compressed);
    defer allocator.free(mutated);
    for (mutated) |*byte| byte.* ^= 0x5a;

    try testing.expect(std.meta.isError(flate.decompress(mutated, decoded, &history, limits)));
}

test "raw DEFLATE rejects trailing bytes after the stream" {
    const allocator = testing.allocator;

    var history: [flate.history_len]u8 = undefined;
    var encoded: [256]u8 = undefined;
    const compressed = try flate.compress("bedrock", &encoded, &history);

    const padded = try allocator.alloc(u8, compressed.len + 4);
    defer allocator.free(padded);
    @memcpy(padded[0..compressed.len], compressed);
    @memset(padded[compressed.len..], 0xaa);

    var decoded: [64]u8 = undefined;
    try testing.expectError(error.MalformedCompressedData, flate.decompress(padded, &decoded, &history, limits));
}

test "raw DEFLATE bounds its output by the batch limit" {
    var history: [flate.history_len]u8 = undefined;
    var encoded: [4096]u8 = undefined;
    const bomb = try flate.compress(&@as([131072]u8, @splat(0)), &encoded, &history);

    var decoded: [131072]u8 = undefined;
    var tight = limits;
    tight.max_batch_bytes = 1024;

    try testing.expectError(error.LimitExceeded, flate.decompress(bomb, &decoded, &history, tight));
}

test "raw DEFLATE bounds its input by the frame limit" {
    var history: [flate.history_len]u8 = undefined;
    var decoded: [64]u8 = undefined;

    var tight = limits;
    tight.max_frame_bytes = 4;

    try testing.expectError(error.LimitExceeded, flate.decompress(&@as([16]u8, @splat(0)), &decoded, &history, tight));
}

test "raw DEFLATE fixture decompresses correctly and enforces output buffer bound" {
    const compressed = [_]u8{ 0x73, 0x74, 0x1c, 0x05, 0xa3, 0x60, 0x14, 0x0c, 0x77, 0x00, 0x00 };
    var output: [1024]u8 = undefined;
    var history: [flate.history_len]u8 = undefined;
    const plain = try flate.decompress(&compressed, &output, &history, limits);
    try testing.expectEqual(@as(usize, 1000), plain.len);
    for (plain) |v| try testing.expectEqual(@as(u8, 'A'), v);

    var tiny: [16]u8 = undefined;
    try testing.expectError(error.LimitExceeded, flate.decompress(&compressed, &tiny, &history, limits));
}

test "the encoded length bound rejects inputs it cannot describe" {
    try testing.expectError(error.LimitExceeded, snappy.maxEncodedLen(@as(usize, std.math.maxInt(u32)) + 1));
    try testing.expect(try snappy.maxEncodedLen(0) >= 32);
}

test "compressing into any destination size either succeeds or reports no space" {
    var scratch: bedwire.compression.Scratch = undefined;
    var destination: [512]u8 = undefined;
    var decoded: [2048]u8 = undefined;

    var random = std.Random.DefaultPrng.init(3);
    var noise: [1024]u8 = undefined;
    random.random().bytes(&noise);

    for ([_][]const u8{ "", "a", repeat("bedrock ", 64), &noise }) |input| {
        for (0..destination.len) |size| {
            const dest = destination[0..size];
            if (snappy.compress(input, dest, &scratch.table)) |compressed| {
                try testing.expectEqualSlices(u8, input, try snappy.decompress(compressed, &decoded, limits));
            } else |err| try testing.expectEqual(error.NoSpaceLeft, err);

            if (flate.compress(input, dest, &scratch.history)) |compressed| {
                var history: [flate.history_len]u8 = undefined;
                try testing.expectEqualSlices(u8, input, try flate.decompress(compressed, &decoded, &history, limits));
            } else |err| try testing.expectEqual(error.NoSpaceLeft, err);
        }
    }
}

fn repeat(comptime text: []const u8, comptime count: usize) *const [text.len * count]u8 {
    const parts: [count][text.len]u8 = @splat(text[0..text.len].*);
    const bytes = comptime @as([text.len * count]u8, @bitCast(parts));
    return &bytes;
}

test "reusable DEFLATE contexts interoperate and preserve input and output limits" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    const encoder = try flate.Encoder.init(failing.allocator());
    defer encoder.deinit();
    const decoder = try flate.Decoder.init(failing.allocator());
    defer decoder.deinit();
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;

    var history: [flate.history_len]u8 = undefined;
    var encoded: [4096]u8 = undefined;
    var output: [8256]u8 = undefined;
    var random = std.Random.DefaultPrng.init(0xbed);
    var noise: [1024]u8 = undefined;
    random.random().bytes(&noise);

    for ([_][]const u8{ "", "a", repeat("bedrock ", 1024), &noise }) |input| {
        const pure = try flate.compress(input, &encoded, &history);
        try testing.expectEqualSlices(u8, input, try decoder.decompress(pure, &output, &history, limits));
        const compressed = try encoder.compress(input, &encoded, &history);
        try testing.expectEqualSlices(u8, input, try flate.decompress(compressed, &output, &history, limits));
        try testing.expectEqualSlices(u8, input, try decoder.decompress(compressed, &output, &history, limits));
        if (decoder.decompress(compressed[0 .. compressed.len - 1], &output, &history, limits)) |_| {
            return error.TestExpectedError;
        } else |err| try testing.expect(err == error.MalformedCompressedData or err == error.LimitExceeded);
        encoded[compressed.len] = 0xaa;
        try testing.expectError(error.MalformedCompressedData, decoder.decompress(encoded[0 .. compressed.len + 1], &output, &history, limits));
        if (input.len > 0) {
            try testing.expectError(error.LimitExceeded, decoder.decompress(compressed, output[0 .. input.len - 1], &history, limits));
        }
    }
    for ([_][]const u8{ repeat("bedrock ", 64), &noise }) |input| {
        for (0..512) |size| {
            if (encoder.compress(input, encoded[0..size], &history)) |compressed| {
                try testing.expectEqualSlices(u8, input, try decoder.decompress(compressed, &output, &history, limits));
            } else |err| try testing.expectEqual(error.NoSpaceLeft, err);
        }
    }
    var tight = limits;
    tight.max_frame_bytes = 4;
    try testing.expectError(error.LimitExceeded, decoder.decompress(&@as([16]u8, @splat(0)), &output, &history, tight));
    const bomb = try encoder.compress(&@as([131072]u8, @splat(0)), &encoded, &history);
    tight = limits;
    tight.max_batch_bytes = 128;
    try testing.expectError(error.LimitExceeded, decoder.decompress(bomb, &output, &history, tight));
    for (0..1000) |_| {
        try testing.expectError(error.MalformedCompressedData, decoder.decompress(&.{0xff}, &output, &history, limits));
    }
    try testing.expectEqualSlices(u8, "reused", try decoder.decompress(try encoder.compress("reused", &encoded, &history), &output, &history, limits));
    try testing.expect(!failing.has_induced_failure);
}

test "Snappy short copies decode the same into exact and roomy outputs" {
    const allocator = testing.allocator;
    var input: [6000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xc0b1);
    prng.random().bytes(&input);
    var at: usize = 2100;
    for ([_]usize{ 2047, 2048, 9, 1, 3, 8, 100, 2047 }, [_]usize{ 4, 11, 12, 64, 65, 68, 69, 260 }) |offset, len| {
        for (0..len) |i| input[at + i] = input[at + i - offset];
        at += len + 50;
    }

    const encoded = try allocator.alloc(u8, try snappy.maxEncodedLen(input.len));
    defer allocator.free(encoded);
    const table = try allocator.create(snappy.Table);
    defer allocator.destroy(table);
    const compressed = try snappy.compress(&input, encoded, table);

    for ([_]usize{ input.len, input.len + 128 }) |room| {
        const decoded = try allocator.alloc(u8, room);
        defer allocator.free(decoded);
        try testing.expectEqualSlices(u8, &input, try snappy.decompress(compressed, decoded, limits));
    }
}
