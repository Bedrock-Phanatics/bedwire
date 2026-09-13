const std = @import("std");
const protocol = @import("bedrock_protocol");

/// Raw Snappy blocks, as specified by google/snappy/format_description.txt.
/// Reusable encoder lookup storage must be connection-owned, not per-packet stack storage.
pub const Table = [16384]u32;

pub fn maxEncodedLen(len: usize) !usize {
    if (len > std.math.maxInt(u32)) return error.LimitExceeded;
    return std.math.add(usize, try std.math.add(usize, len, len / 6), 32);
}

/// Input/output must not overlap. Destination is unchanged on failure.
pub fn compress(input: []const u8, output: []u8, table: *Table) ![]u8 {
    if (try maxEncodedLen(input.len) > output.len) return error.NoSpaceLeft;

    if (input.len >= 4) @memset(table, std.math.maxInt(u32));
    var writer = protocol.Writer.init(output);
    writer.writeVarU32(@intCast(input.len)) catch unreachable;

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

        literal(&writer, input[literal_start..cursor]);
        var len: usize = 4;
        while (len < input.len - cursor and input[previous + len] == input[cursor + len]) len += 1;

        const offset: u16 = @intCast(cursor - previous);

        cursor += len;
        literal_start = cursor;

        while (len != 0) {
            const count = @min(len, 64);
            writer.writeU8((@as(u8, @intCast(count - 1)) << 2) | 2) catch unreachable;
            writer.writeU16(offset) catch unreachable;
            len -= count;
        }
    }

    literal(&writer, input[literal_start..]);

    return output[0..writer.cursor];
}

/// Validates every token before publishing output, including all three copy forms.
/// Input/output must not overlap. No allocation; advertised sizes never allocate storage.
pub fn decompress(input: []const u8, output: []u8, limits: protocol.DecodeLimits) ![]u8 {
    const len = try decode(false, input, output, limits);
    _ = decode(true, input, output, limits) catch unreachable;

    return output[0..len];
}

fn literal(writer: *protocol.Writer, bytes: []const u8) void {
    if (bytes.len == 0) return;

    const len: u32 = @intCast(bytes.len - 1);
    if (bytes.len <= 60) {
        writer.writeU8(@as(u8, @intCast(len)) << 2) catch unreachable;
    } else {
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, len, .little);
        const count: usize = if (len <= 0xff) 1 else if (len <= 0xffff) 2 else if (len <= 0xffffff) 3 else 4;
        writer.writeU8(@as(u8, @intCast(59 + count)) << 2) catch unreachable;
        writer.writeRaw(encoded[0..count]) catch unreachable;
    }

    writer.writeRaw(bytes) catch unreachable;
}

fn decode(comptime emit: bool, input: []const u8, output: []u8, limits: protocol.DecodeLimits) !usize {
    var reader = try protocol.Reader.initWithInputLimit(input, limits, limits.max_batch_bytes);
    const expected: usize = try reader.readVarU32();
    if (expected > limits.max_decompressed_batch_bytes or expected > output.len) return error.LimitExceeded;

    var cursor: usize = 0;

    while (!reader.end()) {
        const tag = try reader.readU8();
        const kind = tag & 3;
        var len: usize = 0;
        var offset: usize = 0;

        switch (kind) {
            0 => {
                const upper: usize = tag >> 2;
                if (upper < 60) {
                    len = upper + 1;
                } else {
                    const encoded = try reader.take(upper - 59);
                    var value: u64 = 0;
                    for (encoded, 0..) |byte, i| value |= @as(u64, byte) << @intCast(i * 8);
                    if (value >= std.math.maxInt(u32)) return error.LimitExceeded;
                    len = @intCast(value + 1);
                }
                if (len > expected - cursor) return error.InvalidCompressedData;
                const bytes = try reader.take(len);
                if (emit) @memcpy(output[cursor..][0..len], bytes);
            },
            1 => {
                len = 4 + ((tag >> 2) & 7);
                offset = (@as(usize, tag & 0xe0) << 3) | try reader.readU8();
            },
            2 => {
                len = 1 + @as(usize, tag >> 2);
                offset = try reader.readU16();
            },
            3 => {
                len = 1 + @as(usize, tag >> 2);
                offset = try reader.readU32();
            },
            else => unreachable,
        }

        if (kind != 0) {
            const valid = offset > 0 and offset <= cursor and len <= expected - cursor;
            if (!valid) return error.InvalidCompressedData;
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

    if (cursor != expected) return error.EndOfStream;

    return cursor;
}
