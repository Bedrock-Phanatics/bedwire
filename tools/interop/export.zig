const std = @import("std");
const bedwire = @import("bedwire");

pub fn main() !void {
    var table: bedwire.compression.snappy.Table = undefined;
    var output: [8192]u8 = undefined;
    const encoded = try bedwire.compression.snappy.compress("Bedrock Snappy interoperability. " ** 100, &output, &table);
    std.debug.print("{x}", .{encoded});
}
