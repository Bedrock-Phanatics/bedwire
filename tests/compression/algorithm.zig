const std = @import("std");
const n = @import("network");

test "compression headers and threshold boundaries" {
    const settings: n.compression.Settings = .{ .enabled = true, .threshold = 4 };
    try std.testing.expectEqual(.none, settings.selected(3));
    try std.testing.expectEqual(.deflate, settings.selected(4));
    try std.testing.expectEqual(.deflate, settings.selected(5));
    try std.testing.expectEqual(.deflate, (n.compression.Settings{ .enabled = true, .threshold = 0 }).selected(0));
    const workspace = try n.FlateWorkspace.create(std.testing.allocator, 64);
    defer workspace.destroy();
    try std.testing.expectEqualSlices(u8, &.{ 1, 1 }, try settings.decode(&.{ 0xff, 1, 1 }, workspace, .{}));
    try std.testing.expectError(error.UnsupportedCompression, settings.decode(&.{2}, workspace, .{}));
    try std.testing.expectError(error.EndOfStream, settings.decode(&.{}, workspace, .{}));
    try std.testing.expectError(error.LimitExceeded, settings.decode(&.{ 0xff, 1, 1 }, workspace, .{ .max_decompressed_batch_bytes = 1 }));
}
