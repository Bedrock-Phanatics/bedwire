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
    try snappyRoundTrip(&([_]u8{'a'} ** 60)); // short literal boundary
    try snappyRoundTrip(&([_]u8{'a'} ** 61)); // one-byte extended literal
    try snappyRoundTrip(&([_]u8{'b'} ** 300)); // two-byte extended literal
    try snappyRoundTrip(&([_]u8{'c'} ** 70000)); // three-byte extended literal
    try snappyRoundTrip("abcd" ** 4096); // long copy runs
    try snappyRoundTrip(&noise); // incompressible
}

test "Snappy rejects malformed streams without writing output" {
    var output: [64]u8 = undefined;

    const cases = [_][]const u8{
        &.{}, // no length prefix
        &.{0x04}, // length with no tokens
        &.{ 0x04, 0x00 }, // literal shorter than advertised
        &.{ 0x04, 0x0c, 'a', 'b', 'c' }, // literal longer than advertised
        &.{ 0x04, 0x01, 0x00 }, // copy with zero offset
        &.{ 0x04, 0x05, 0x01 }, // copy reaching before the output start
        &.{ 0x04, 0xfc }, // literal length header with no bytes
        &.{ 0x04, 0x00, 'a', 0x00, 'b' }, // trailing token past the advertised size
    };

    for (cases) |input| {
        try testing.expect(std.meta.isError(snappy.decompress(input, &output, limits)));
    }
}

test "Snappy refuses to decompress past the caller's buffer" {
    var output: [4]u8 = undefined;
    // The stream advertises 32 bytes; the caller offered 4.
    try testing.expectError(error.LimitExceeded, snappy.decompress(&.{0x20}, &output, limits));
}

test "Snappy refuses output it cannot fit" {
    var table: snappy.Table = undefined;
    var tiny: [4]u8 = undefined;

    try testing.expectError(error.NoSpaceLeft, snappy.compress(&([_]u8{'z'} ** 1024), &tiny, &table));
}

test "Snappy compressing into any destination size either succeeds or reports no space" {
    var table: snappy.Table = undefined;
    var destination: [512]u8 = undefined;

    var random = std.Random.DefaultPrng.init(11);
    var noise: [1024]u8 = undefined;
    random.random().bytes(&noise);

    const inputs = [_][]const u8{ "", "a", "bedrock " ** 64, &noise };

    for (inputs) |input| {
        for (0..destination.len) |size| {
            if (snappy.compress(input, destination[0..size], &table)) |compressed| {
                var decoded: [2048]u8 = undefined;
                try testing.expectEqualSlices(u8, input, try snappy.decompress(compressed, &decoded, limits));
            } else |err| {
                try testing.expectEqual(error.NoSpaceLeft, err);
            }
        }
    }
}

test "Snappy self-references decode correctly when the copy overlaps" {
    var output: [64]u8 = undefined;

    // Length 8, one literal byte, then a copy of length 7 at offset 1.
    const input = [_]u8{ 0x08, 0x00, 'a', (3 << 2) | 1, 0x01 };
    try testing.expectEqualSlices(u8, "aaaaaaaa", try snappy.decompress(&input, &output, limits));
}

test "raw DEFLATE round-trips and rejects corruption" {
    const allocator = testing.allocator;

    var history: [flate.history_len]u8 = undefined;
    const input = "bedrock " ** 512;

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
    const bomb = try flate.compress(&([_]u8{0} ** 131072), &encoded, &history);

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

    try testing.expectError(error.LimitExceeded, flate.decompress(&([_]u8{0} ** 16), &decoded, &history, tight));
}

test "compressing into any destination size either succeeds or reports no space" {
    var history: [flate.history_len]u8 = undefined;
    var destination: [512]u8 = undefined;

    var random = std.Random.DefaultPrng.init(3);
    var noise: [1024]u8 = undefined;
    random.random().bytes(&noise);

    const inputs = [_][]const u8{ "", "a", "bedrock " ** 64, &noise };

    for (inputs) |input| {
        for (0..destination.len) |size| {
            if (flate.compress(input, destination[0..size], &history)) |compressed| {
                var decoded: [2048]u8 = undefined;
                try testing.expectEqualSlices(u8, input, try flate.decompress(compressed, &decoded, &history, limits));
            } else |err| {
                try testing.expectEqual(error.NoSpaceLeft, err);
            }
        }
    }
}

test "the encoded length bound rejects inputs it cannot describe" {
    try testing.expectError(error.LimitExceeded, snappy.maxEncodedLen(@as(usize, std.math.maxInt(u32)) + 1));
    try testing.expect(try snappy.maxEncodedLen(0) >= 32);
}

test "a workspace sizes itself to the batch limit" {
    const workspace = try bedwire.compression.Workspace.create(testing.allocator, 4096);
    defer workspace.destroy();

    try testing.expectEqual(@as(usize, 4096), workspace.output.len);

    const minimum = try bedwire.compression.Workspace.create(testing.allocator, 1);
    defer minimum.destroy();
    try testing.expect(minimum.output.len >= 64);
}
