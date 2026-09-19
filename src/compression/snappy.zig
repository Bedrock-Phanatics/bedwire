const std = @import("std");

const Limits = @import("../limits.zig").Limits;
const varint = @import("../framing/varint.zig");

// 16k entry lookup table for snappy matches
pub const Table = [16384]u32;

pub fn maxEncodedLen(len: usize) !usize {
    if (len > std.math.maxInt(u32)) return error.LimitExceeded;
    return std.math.add(usize, try std.math.add(usize, len, len / 6), 32);
}

/// snappy raw block compressor
pub fn compress(input: []const u8, output: []u8, table: *Table) ![]u8 {
    if (input.len > std.math.maxInt(u32)) return error.LimitExceeded;

    if (input.len >= 4) @memset(table, std.math.maxInt(u32));
    var writer: Cursor = .{ .bytes = output };
    try writer.varInt(@intCast(input.len));

    var cursor: usize = 0;
    var literal_start: usize = 0;

    while (input.len - cursor >= 4) {
        const word = std.mem.readInt(u32, input[cursor..][0..4], .little);
        const slot = (word *% 0x1e35a7bd) >> 18;
        const previous: usize = table[slot];
        table[slot] = @intCast(cursor);

        const candidate = previous < cursor and cursor - previous <= 65535;
        if (!candidate or !std.mem.eql(u8, input[previous..][0..4], input[cursor..][0..4])) {
            cursor += 1;
            continue;
        }

        try writer.literal(input[literal_start..cursor]);
        var len: usize = 4;
        while (len < input.len - cursor and input[previous + len] == input[cursor + len]) len += 1;

        const offset: u16 = @intCast(cursor - previous);

        cursor += len;
        literal_start = cursor;

        var encoded_offset: [2]u8 = undefined;
        std.mem.writeInt(u16, &encoded_offset, offset, .little);

        while (len != 0) {
            const count = @min(len, 64);
            try writer.byte((@as(u8, @intCast(count - 1)) << 2) | 2);
            try writer.raw(&encoded_offset);
            len -= count;
        }
    }

    try writer.literal(input[literal_start..]);

    return output[0..writer.cursor];
}

/// two-pass snappy decompressor (first checks bounds and tokens, then writes output)
pub fn decompress(input: []const u8, output: []u8, limits: Limits) ![]u8 {
    const len = try decode(false, input, output, limits);
    _ = decode(true, input, output, limits) catch unreachable;

    return output[0..len];
}

const Cursor = struct {
    bytes: []u8,
    cursor: usize = 0,

    fn byte(self: *Cursor, value: u8) !void {
        if (self.cursor == self.bytes.len) return error.NoSpaceLeft;
        self.bytes[self.cursor] = value;
        self.cursor += 1;
    }

    fn raw(self: *Cursor, values: []const u8) !void {
        if (self.bytes.len - self.cursor < values.len) return error.NoSpaceLeft;
        @memcpy(self.bytes[self.cursor..][0..values.len], values);
        self.cursor += values.len;
    }

    fn varInt(self: *Cursor, value: u32) !void {
        self.cursor += try varint.writeU32(self.bytes[self.cursor..], value);
    }

    fn literal(self: *Cursor, bytes: []const u8) !void {
        if (bytes.len == 0) return;

        const len: u32 = @intCast(bytes.len - 1);
        if (bytes.len <= 60) {
            try self.byte(@as(u8, @intCast(len)) << 2);
        } else {
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, len, .little);
            const count: usize = if (len <= 0xff) 1 else if (len <= 0xffff) 2 else if (len <= 0xffffff) 3 else 4;
            try self.byte(@as(u8, @intCast(59 + count)) << 2);
            try self.raw(encoded[0..count]);
        }

        try self.raw(bytes);
    }
};

const Scanner = struct {
    bytes: []const u8,
    cursor: usize = 0,

    fn end(self: *const Scanner) bool {
        return self.cursor == self.bytes.len;
    }

    fn take(self: *Scanner, count: usize) ![]const u8 {
        const stop = std.math.add(usize, self.cursor, count) catch return error.MalformedCompressedData;
        if (stop > self.bytes.len) return error.MalformedCompressedData;

        defer self.cursor = stop;
        return self.bytes[self.cursor..stop];
    }

    fn byte(self: *Scanner) !u8 {
        return (try self.take(1))[0];
    }

    fn int(self: *Scanner, comptime T: type) !T {
        const size = @divExact(@typeInfo(T).int.bits, 8);
        const bytes = try self.take(size);
        return std.mem.readInt(T, bytes[0..size], .little);
    }

    fn varInt(self: *Scanner) !u32 {
        const decoded = varint.readU32(self.bytes[self.cursor..]) catch return error.MalformedCompressedData;
        self.cursor += decoded.len;
        return decoded.value;
    }
};

fn decode(comptime emit: bool, input: []const u8, output: []u8, limits: Limits) !usize {
    if (input.len > limits.max_frame_bytes) return error.LimitExceeded;

    var scanner: Scanner = .{ .bytes = input };
    const expected: usize = try scanner.varInt();
    if (expected > limits.max_batch_bytes or expected > output.len) return error.LimitExceeded;

    var cursor: usize = 0;

    while (!scanner.end()) {
        const tag = try scanner.byte();
        const kind = tag & 3;
        var len: usize = 0;
        var offset: usize = 0;

        switch (kind) {
            0 => {
                const upper: usize = tag >> 2;
                if (upper < 60) {
                    len = upper + 1;
                } else {
                    const encoded = try scanner.take(upper - 59);
                    var value: u64 = 0;
                    for (encoded, 0..) |byte, i| value |= @as(u64, byte) << @intCast(i * 8);
                    if (value >= std.math.maxInt(u32)) return error.LimitExceeded;
                    len = @intCast(value + 1);
                }
                if (len > expected - cursor) return error.MalformedCompressedData;
                const bytes = try scanner.take(len);
                if (emit) @memcpy(output[cursor..][0..len], bytes);
            },
            1 => {
                len = 4 + ((tag >> 2) & 7);
                offset = (@as(usize, tag & 0xe0) << 3) | try scanner.byte();
            },
            2 => {
                len = 1 + @as(usize, tag >> 2);
                offset = try scanner.int(u16);
            },
            3 => {
                len = 1 + @as(usize, tag >> 2);
                offset = try scanner.int(u32);
            },
            else => unreachable,
        }

        if (kind != 0) {
            const valid = offset > 0 and offset <= cursor and len <= expected - cursor;
            if (!valid) return error.MalformedCompressedData;
            if (emit) {
                if (offset >= len) {
                    @memcpy(output[cursor..][0..len], output[cursor - offset ..][0..len]);
                } else {
                    for (0..len) |i| output[cursor + i] = output[cursor + i - offset];
                }
            }
        }

        cursor += len;
    }

    if (cursor != expected) return error.MalformedCompressedData;

    return cursor;
}
