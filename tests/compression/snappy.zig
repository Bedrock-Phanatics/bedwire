const std = @import("std");
const zigrock = @import("zigrock");

test "tiny Snappy blocks round trip before and after table reuse" {
    const workspace = try zigrock.FlateWorkspace.create(std.testing.allocator, 128);
    defer workspace.destroy();
    var output: [16]u8 = undefined;
    for ([_][]const u8{ "", "a", "ab", "abc", "abcdabcd", "abc", "", "abcdabcd" }) |input| {
        const encoded = try zigrock.snappy.compress(input, workspace.output, &workspace.snappy_table);
        try std.testing.expectEqualSlices(u8, input, try zigrock.snappy.decompress(encoded, &output, .{}));
    }
}

test "Snappy copy forms accept adjacent and separated source ranges" {
    var output: [16]u8 = undefined;
    for ([_][]const u8{
        &.{ 8, 12, 'a', 'b', 'c', 'd', 1, 4 },
        &.{ 8, 12, 'a', 'b', 'c', 'd', 14, 4, 0 },
        &.{ 8, 12, 'a', 'b', 'c', 'd', 15, 4, 0, 0, 0 },
    }) |encoded| {
        try std.testing.expectEqualStrings("abcdabcd", try zigrock.snappy.decompress(encoded, &output, .{}));
    }
    try std.testing.expectEqualStrings("abcdab", try zigrock.snappy.decompress(&.{ 6, 12, 'a', 'b', 'c', 'd', 6, 4, 0 }, &output, .{}));
}

test "raw Snappy compresses repetitive bytes and round trips arbitrary data" {
    const workspace = try zigrock.FlateWorkspace.create(std.testing.allocator, 8192);
    defer workspace.destroy();
    var input: [2048]u8 = undefined;
    var output: [2048]u8 = undefined;
    var random = std.Random.DefaultPrng.init(42);
    for (0..128) |i| {
        random.random().bytes(&input);
        if (i % 2 == 0) @memset(&input, 'a');
        const len = i * 16;
        const encoded = try zigrock.snappy.compress(input[0..len], workspace.output, &workspace.snappy_table);
        if (i > 1 and i % 2 == 0) try std.testing.expect(encoded.len < len);
        try std.testing.expectEqualSlices(u8, input[0..len], try zigrock.snappy.decompress(encoded, &output, .{}));
        for (0..encoded.len) |end| {
            if (zigrock.snappy.decompress(encoded[0..end], &output, .{})) |_| return error.AcceptedTruncation else |_| {}
        }
    }
}

test "all Snappy copy tags, overlap, malformed offsets, and output atomicity" {
    var output = [_]u8{0xaa} ** 32;
    for ([_][]const u8{ &.{ 7, 8, 'x', 'a', 'b', 1, 2 }, &.{ 7, 8, 'x', 'a', 'b', 14, 2, 0 }, &.{ 7, 8, 'x', 'a', 'b', 15, 2, 0, 0, 0 } }) |encoded| {
        try std.testing.expectEqualStrings("xababab", try zigrock.snappy.decompress(encoded, &output, .{}));
    }
    for ([_][]const u8{ &.{ 5, 0, 'a', 1, 0 }, &.{ 5, 0, 'a', 1, 2 }, &.{ 4, 0, 'a', 1, 1 } }) |encoded| {
        @memset(&output, 0xaa);
        try std.testing.expectError(error.InvalidCompressedData, zigrock.snappy.decompress(encoded, &output, .{}));
        try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 32), &output);
    }
    try std.testing.expectError(error.LimitExceeded, zigrock.snappy.decompress(&.{ 0xff, 0xff, 0xff, 0xff, 0x0f }, &output, .{}));
    try std.testing.expectError(error.NonCanonicalVarInt, zigrock.snappy.decompress(&.{ 0x80, 0 }, &output, .{}));
    try std.testing.expectError(error.VarIntOverflow, zigrock.snappy.decompress(&.{ 0xff, 0xff, 0xff, 0xff, 0x10 }, &output, .{}));
    try std.testing.expectError(error.LimitExceeded, zigrock.snappy.decompress(&.{ 7, 8, 'x', 'a', 'b', 1, 2 }, &output, .{ .max_decompressed_batch_bytes = 6 }));
}

test "bounded random parser inputs cannot modify output on failure" {
    var random = std.Random.DefaultPrng.init(8192);
    var input: [64]u8 = undefined;
    var output: [128]u8 = undefined;
    for (0..10000) |i| {
        random.random().bytes(&input);
        @memset(&output, 0xaa);
        const bytes = input[0 .. i % input.len];
        if (zigrock.snappy.decompress(bytes, &output, .{ .max_decompressed_batch_bytes = 128 })) |decoded| {
            try std.testing.expect(decoded.len <= output.len);
        } else |_| {
            for (output) |byte| try std.testing.expectEqual(@as(u8, 0xaa), byte);
        }
        zigrock.batch.validate(bytes, .{ .max_decompressed_batch_bytes = 128, .max_packets_per_batch = 16 }) catch {};
    }
}

test "extended Snappy literals and copy offsets beyond 64 KiB" {
    const a = std.testing.allocator;
    const input = try a.alloc(u8, 65560);
    defer a.free(input);
    const output = try a.alloc(u8, 65560);
    defer a.free(output);
    for ([_]usize{ 60, 61, 256, 257, 65536, 65537 }) |len| {
        var writer = zigrock.protocol.Writer.init(input);
        try writer.writeVarU32(@intCast(len));
        if (len <= 60) {
            try writer.writeU8(@as(u8, @intCast(len - 1)) << 2);
        } else {
            const count: usize = if (len <= 256) 1 else if (len <= 65536) 2 else 3;
            try writer.writeU8(@as(u8, @intCast(59 + count)) << 2);
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, @intCast(len - 1), .little);
            try writer.writeRaw(encoded[0..count]);
        }
        @memset(input[writer.cursor..][0..len], 'a');
        writer.cursor += len;
        const decoded = try zigrock.snappy.decompress(writer.written(), output, .{});
        try std.testing.expectEqual(len, decoded.len);
        for (decoded) |byte| try std.testing.expectEqual(@as(u8, 'a'), byte);
    }
    var writer = zigrock.protocol.Writer.init(input);
    try writer.writeVarU32(65540);
    try writer.writeU8(61 << 2);
    try writer.writeU16(65535);
    @memset(input[writer.cursor..][0..65536], 'b');
    writer.cursor += 65536;
    try writer.writeU8(15);
    try writer.writeU32(65536);
    const decoded = try zigrock.snappy.decompress(writer.written(), output, .{});
    try std.testing.expectEqualStrings("bbbb", decoded[65536..]);
}
