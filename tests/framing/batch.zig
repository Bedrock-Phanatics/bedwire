const std = @import("std");
const zigrock = @import("zigrock");

test "batch encoding preflights destination and validates envelopes" {
    var dest = [_]u8{0xaa} ** 16;
    const packets = [_][]const u8{ &.{1}, &.{ 2, 3 } };
    try std.testing.expectError(error.NoSpaceLeft, zigrock.batch.encode(&packets, dest[0..2], .{}));
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 16), &dest);
    const encoded = try zigrock.batch.encode(&packets, &dest, .{});
    try zigrock.batch.validate(encoded, .{});
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 2, 2, 3 }, encoded);
    try std.testing.expectError(error.InvalidPacketId, zigrock.batch.validate(&.{ 3, 0x80, 0x80, 1 }, .{}));
    try std.testing.expectError(error.InvalidPacketId, zigrock.batch.unframed(&.{0}, .{}));
    try std.testing.expectError(error.LimitExceeded, zigrock.batch.unframed(&.{ 0xfe, 1 }, .{ .max_batch_bytes = 1 }));
}
