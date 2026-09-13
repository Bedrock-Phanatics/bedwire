const std = @import("std");
const n = @import("network");

test "iterator borrows slices and enforces hostile lengths" {
    const bytes = [_]u8{ 1, 1, 2, 2, 3 };
    var iterator = try n.BatchIterator.init(&bytes, .{});
    const first = (try iterator.next()).?;
    try std.testing.expect(first.ptr == bytes[1..].ptr);
    try std.testing.expectEqualSlices(u8, &.{ 2, 3 }, (try iterator.next()).?);
    try std.testing.expectEqual(null, try iterator.next());
    try std.testing.expectError(error.NonCanonicalVarInt, n.batch.validate(&.{ 0x80, 0 }, .{}));
    try std.testing.expectError(error.VarIntOverflow, n.batch.validate(&.{ 0xff, 0xff, 0xff, 0xff, 0x10 }, .{}));
    try std.testing.expectError(error.InvalidPacketId, n.batch.validate(&.{0}, .{}));
    try std.testing.expectError(error.LimitExceeded, n.batch.validate(&bytes, .{ .max_packets_per_batch = 1 }));
    const single = [_]u8{ 4, 1, 2, 3, 4 };
    for (1..single.len) |end| try std.testing.expectError(error.EndOfStream, n.batch.validate(single[0..end], .{}));
}
