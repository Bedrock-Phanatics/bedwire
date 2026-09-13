const std = @import("std");
const bedwire = @import("bedwire");

test "batch encoding preflights destination and validates envelopes" {
    var dest = [_]u8{0xaa} ** 16;
    const packets = [_][]const u8{ &.{1}, &.{ 2, 3 } };
    try std.testing.expectError(error.NoSpaceLeft, bedwire.batch.encode(&packets, dest[0..2], .{}));
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 16), &dest);
    const encoded = try bedwire.batch.encode(&packets, &dest, .{});
    try bedwire.batch.validate(encoded, .{});
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 2, 2, 3 }, encoded);
    try std.testing.expectError(error.InvalidPacketId, bedwire.batch.validate(&.{ 3, 0x80, 0x80, 1 }, .{}));
    try std.testing.expectError(error.InvalidPacketId, bedwire.batch.unframed(&.{0}, .{}));
    try std.testing.expectError(error.LimitExceeded, bedwire.batch.unframed(&.{ 0xfe, 1 }, .{ .max_batch_bytes = 1 }));
}
