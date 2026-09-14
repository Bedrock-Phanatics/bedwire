const std = @import("std");
const bedwire = @import("bedwire");

test "direct DEFLATE decoding enforces compressed input limit before work" {
    const workspace = try bedwire.FlateWorkspace.create(std.testing.allocator, 16);
    defer workspace.destroy();
    const empty = [_]u8{ 1, 0, 0, 0xff, 0xff };
    try std.testing.expectEqual(@as(usize, 0), (try workspace.decompress(&empty, .{ .max_batch_bytes = empty.len })).len);
    @memset(workspace.output, 0xaa);
    try std.testing.expectError(error.LimitExceeded, workspace.decompress(&empty, .{ .max_batch_bytes = empty.len - 1 }));
    for (workspace.output) |byte| try std.testing.expectEqual(@as(u8, 0xaa), byte);
}

test "raw DEFLATE round trip, truncation, bomb, and allocator cleanup" {
    const encoder = try bedwire.FlateWorkspace.create(std.testing.allocator, 4096);
    defer encoder.destroy();
    const decoder = try bedwire.FlateWorkspace.create(std.testing.allocator, 4096);
    defer decoder.destroy();
    const input = "bedrock network " ** 64;
    const compressed = try encoder.compress(input);
    try std.testing.expect(compressed.len < input.len);
    try std.testing.expectEqualStrings(input, try decoder.decompress(compressed, .{}));
    for (0..compressed.len) |end| {
        if (decoder.decompress(compressed[0..end], .{})) |_| return error.AcceptedTruncation else |_| {}
    }
    const bomb = [_]u8{ 0x73, 0x74, 0x1c, 0x05, 0xa3, 0x60, 0x14, 0x0c, 0x77, 0, 0 };
    try std.testing.expectError(error.LimitExceeded, decoder.decompress(&bomb, .{ .max_decompressed_batch_bytes = 16 }));
    try std.testing.expectEqual(@as(usize, 1000), (try decoder.decompress(&bomb, .{ .max_decompressed_batch_bytes = 1000 })).len);
    try std.testing.expectError(error.TrailingData, decoder.decompress(&(bomb ++ [_]u8{0xaa}), .{}));
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const workspace = try bedwire.FlateWorkspace.create(allocator, 100);
    defer workspace.destroy();
}

test "flate initialization unwinds every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}
