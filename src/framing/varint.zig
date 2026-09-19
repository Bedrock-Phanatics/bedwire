const std = @import("std");

pub const max_u32_bytes = 5;

pub const Decoded = struct { value: u32, len: usize };

/// reads a u32 varint (leb128), rejects overlong sequences
pub fn readU32(input: []const u8) !Decoded {
    var value: u32 = 0;
    var shift: u5 = 0;

    for (input[0..@min(input.len, max_u32_bytes)], 0..) |byte, i| {
        const payload: u32 = byte & 0x7f;
        if (i == max_u32_bytes - 1 and payload > 0xf) return error.MalformedBatch;

        value |= payload << shift;
        if (byte & 0x80 == 0) {
            if (i != 0 and payload == 0) return error.MalformedBatch;
            return .{ .value = value, .len = i + 1 };
        }
        shift +|= 7;
    }

    return error.MalformedBatch;
}

pub fn sizeU32(value: u32) usize {
    var remaining = value;
    var len: usize = 1;
    while (remaining >= 0x80) : (len += 1) remaining >>= 7;
    return len;
}

/// writes u32 as varint into dest, returns bytes written
pub fn writeU32(dest: []u8, value: u32) !usize {
    const len = sizeU32(value);
    if (len > dest.len) return error.NoSpaceLeft;

    var remaining = value;
    for (dest[0..len], 0..) |*byte, i| {
        byte.* = @as(u8, @truncate(remaining & 0x7f)) | @as(u8, if (i + 1 == len) 0 else 0x80);
        remaining >>= 7;
    }

    return len;
}

const testing = std.testing;

test "varint round-trips the full u32 range boundaries" {
    const values = [_]u32{ 0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456, std.math.maxInt(u32) };
    var storage: [max_u32_bytes]u8 = undefined;

    for (values) |value| {
        const len = try writeU32(&storage, value);
        try testing.expectEqual(sizeU32(value), len);

        const decoded = try readU32(storage[0..len]);
        try testing.expectEqual(value, decoded.value);
        try testing.expectEqual(len, decoded.len);
    }
}

test "varint rejects overlong, truncated and overflowing encodings" {
    try testing.expectError(error.MalformedBatch, readU32(&.{ 0x80, 0x00 }));
    try testing.expectError(error.MalformedBatch, readU32(&.{ 0x81, 0x80, 0x00 }));
    try testing.expectError(error.MalformedBatch, readU32(&.{0x80}));
    try testing.expectError(error.MalformedBatch, readU32(&.{}));
    try testing.expectError(error.MalformedBatch, readU32(&.{ 0x80, 0x80, 0x80, 0x80, 0x10 }));
    try testing.expectError(error.MalformedBatch, readU32(&.{ 0xff, 0xff, 0xff, 0xff, 0xff }));
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), (try readU32(&.{ 0xff, 0xff, 0xff, 0xff, 0x0f })).value);
}

test "varint writer leaves destination untouched when it cannot fit" {
    var storage = [_]u8{0xaa} ** 2;
    try testing.expectError(error.NoSpaceLeft, writeU32(&storage, 16384));
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xaa }, &storage);
}
