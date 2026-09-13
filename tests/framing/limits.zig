const std = @import("std");
const zigrock = @import("zigrock");

test "limits preserve protocol defaults and reject invalid bounds" {
    const limits: zigrock.DecodeLimits = .{};
    try limits.validate();
    try std.testing.expectEqual(16 * 1024 * 1024, limits.protocol.max_decompressed_batch_bytes);
    try std.testing.expectError(error.InvalidLimits, (zigrock.DecodeLimits{ .max_chain_length = 0 }).validate());
    try std.testing.expectError(error.InvalidLimits, (zigrock.DecodeLimits{ .protocol = .{ .max_packets_per_batch = 0 } }).validate());
}
