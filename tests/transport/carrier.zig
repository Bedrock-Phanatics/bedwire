const std = @import("std");
const zigrock = @import("zigrock");
const Transport = struct {
    pub fn receive(_: *@This()) !struct { data: []const u8, reliability: enum { reliable, unreliable } } {
        return .{ .data = &.{0xfe}, .reliability = .reliable };
    }
    pub fn send(_: *@This(), _: []const u8, _: enum { reliable, unreliable }) !void {}
    pub fn close(_: *@This()) void {}
};
test "NetherNet carrier forwards reliable data" {
    var transport: Transport = .{};
    var carrier: zigrock.carrier.NetherNet(Transport) = .{ .connection = &transport };
    try std.testing.expectEqualSlices(u8, &.{0xfe}, try carrier.receive());
    try carrier.send(&.{0xfe});
    carrier.close();
}
