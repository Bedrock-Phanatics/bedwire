const std = @import("std");

const Limits = @import("../limits.zig").Limits;
const varint = @import("varint.zig");

// bedrock batch frames always start with 0xfe
pub const header: u8 = 0xfe;

/// strip 0xfe header byte and verify frame size is within limits
pub fn strip(frame: []const u8, limits: Limits) ![]const u8 {
    if (frame.len == 0 or frame[0] != header) return error.MalformedBatch;
    if (frame.len > limits.max_frame_bytes) return error.LimitExceeded;
    return frame[1..];
}

/// splits a batch payload into packets using varint length prefixes
/// returned slices borrow directly from the input buffer
pub const Reader = struct {
    bytes: []const u8,
    cursor: usize = 0,
    count: usize = 0,
    limits: Limits,

    pub fn init(bytes: []const u8, limits: Limits) !Reader {
        if (bytes.len > limits.max_batch_bytes) return error.LimitExceeded;
        return .{ .bytes = bytes, .limits = limits };
    }

    pub fn next(self: *Reader) !?[]const u8 {
        if (self.cursor == self.bytes.len) return null;
        if (self.count == self.limits.max_packets_per_batch) return error.LimitExceeded;

        const prefix = try varint.readU32(self.bytes[self.cursor..]);
        if (prefix.value == 0) return error.MalformedBatch;
        if (prefix.value > self.limits.max_packet_bytes) return error.LimitExceeded;

        const start = self.cursor + prefix.len;
        const end = std.math.add(usize, start, prefix.value) catch return error.MalformedBatch;
        if (end > self.bytes.len) return error.MalformedBatch;

        self.cursor = end;
        self.count += 1;
        return self.bytes[start..end];
    }

    pub fn reset(self: *Reader) void {
        self.cursor = 0;
        self.count = 0;
    }
};

/// packs packets into a buffer, prefixing each with a varint length
pub const Writer = struct {
    dest: []u8,
    cursor: usize = 0,
    count: usize = 0,
    limits: Limits,

    pub fn init(dest: []u8, limits: Limits) Writer {
        return .{ .dest = dest, .limits = limits };
    }

    pub fn append(self: *Writer, packet: []const u8) !void {
        if (self.count == self.limits.max_packets_per_batch) return error.LimitExceeded;
        if (packet.len == 0) return error.MalformedBatch;
        if (packet.len > self.limits.max_packet_bytes or packet.len > std.math.maxInt(u32)) return error.LimitExceeded;

        const prefix_len = varint.sizeU32(@intCast(packet.len));
        const total = std.math.add(usize, prefix_len, packet.len) catch return error.LimitExceeded;
        const end = std.math.add(usize, self.cursor, total) catch return error.LimitExceeded;
        if (end > self.limits.max_batch_bytes) return error.LimitExceeded;
        if (end > self.dest.len) return error.NoSpaceLeft;

        _ = varint.writeU32(self.dest[self.cursor..], @intCast(packet.len)) catch unreachable;
        @memcpy(self.dest[self.cursor + prefix_len ..][0..packet.len], packet);

        self.cursor = end;
        self.count += 1;
    }

    pub fn written(self: *const Writer) []u8 {
        return self.dest[0..self.cursor];
    }
};

const testing = std.testing;

test "frames must carry the session header and stay within bounds" {
    const limits: Limits = .{ .max_frame_bytes = 8 };
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, try strip(&.{ header, 1, 2 }, limits));
    try testing.expectEqualSlices(u8, &.{}, try strip(&.{header}, limits));
    try testing.expectError(error.MalformedBatch, strip(&.{}, limits));
    try testing.expectError(error.MalformedBatch, strip(&.{ 0xfd, 1 }, limits));
    try testing.expectError(error.LimitExceeded, strip(&([_]u8{header} ++ [_]u8{0} ** 8), limits));
}

test "reader splits empty, single and many-packet batches" {
    const limits: Limits = .{};

    var empty = try Reader.init(&.{}, limits);
    try testing.expectEqual(@as(?[]const u8, null), try empty.next());

    var single = try Reader.init(&.{ 3, 9, 8, 7 }, limits);
    try testing.expectEqualSlices(u8, &.{ 9, 8, 7 }, (try single.next()).?);
    try testing.expectEqual(@as(?[]const u8, null), try single.next());

    var many = try Reader.init(&.{ 1, 10, 2, 20, 21, 1, 30 }, limits);
    try testing.expectEqualSlices(u8, &.{10}, (try many.next()).?);
    try testing.expectEqualSlices(u8, &.{ 20, 21 }, (try many.next()).?);
    try testing.expectEqualSlices(u8, &.{30}, (try many.next()).?);
    try testing.expectEqual(@as(?[]const u8, null), try many.next());

    many.reset();
    try testing.expectEqualSlices(u8, &.{10}, (try many.next()).?);
}

test "reader rejects truncation, zero lengths and malformed prefixes" {
    const limits: Limits = .{};

    var truncated = try Reader.init(&.{ 4, 1, 2 }, limits);
    try testing.expectError(error.MalformedBatch, truncated.next());

    var zero = try Reader.init(&.{ 0, 1 }, limits);
    try testing.expectError(error.MalformedBatch, zero.next());

    var overlong = try Reader.init(&.{ 0x80, 0x00, 1 }, limits);
    try testing.expectError(error.MalformedBatch, overlong.next());

    var dangling = try Reader.init(&.{0x80}, limits);
    try testing.expectError(error.MalformedBatch, dangling.next());
}

test "reader enforces packet count and packet size limits" {
    var counted = try Reader.init(&.{ 1, 1, 1, 2, 1, 3 }, .{ .max_packets_per_batch = 2 });
    _ = try counted.next();
    _ = try counted.next();
    try testing.expectError(error.LimitExceeded, counted.next());

    var sized = try Reader.init(&.{ 3, 1, 2, 3 }, .{ .max_packet_bytes = 2, .max_batch_bytes = 64 });
    try testing.expectError(error.LimitExceeded, sized.next());

    try testing.expectError(error.LimitExceeded, Reader.init(&.{ 1, 1, 1, 1 }, .{ .max_batch_bytes = 2, .max_packet_bytes = 2 }));
}

test "writer assembles batches the reader accepts" {
    var storage: [64]u8 = undefined;
    var writer = Writer.init(&storage, .{});
    try writer.append(&.{ 9, 9 });
    try writer.append(&.{7});

    var reader = try Reader.init(writer.written(), .{});
    try testing.expectEqualSlices(u8, &.{ 9, 9 }, (try reader.next()).?);
    try testing.expectEqualSlices(u8, &.{7}, (try reader.next()).?);
    try testing.expectEqual(@as(?[]const u8, null), try reader.next());
}

test "writer refuses overflow and keeps earlier packets intact" {
    var storage: [8]u8 = undefined;
    var writer = Writer.init(&storage, .{});
    try writer.append(&.{ 1, 2, 3 });
    const committed = writer.written().len;

    try testing.expectError(error.NoSpaceLeft, writer.append(&([_]u8{5} ** 16)));
    try testing.expectError(error.MalformedBatch, writer.append(&.{}));
    try testing.expectEqual(committed, writer.written().len);

    var counted = Writer.init(&storage, .{ .max_packets_per_batch = 1 });
    try counted.append(&.{1});
    try testing.expectError(error.LimitExceeded, counted.append(&.{2}));

    var bounded = Writer.init(&storage, .{ .max_batch_bytes = 2, .max_packet_bytes = 2 });
    try testing.expectError(error.LimitExceeded, bounded.append(&.{ 1, 2 }));
}
