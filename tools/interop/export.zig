const std = @import("std");
const bedwire = @import("bedwire");

pub fn main() !void {
    var table: bedwire.compression.snappy.Table = undefined;
    var output: [8192]u8 = undefined;
    const input: [100][33]u8 = @splat("Bedrock Snappy interoperability. ".*);
    const encoded = try bedwire.compression.snappy.compress(std.mem.asBytes(&input), &output, &table);
    std.debug.print("{x}", .{encoded});
}
