const std = @import("std");
const bedwire = @import("bedwire");

pub fn main() !void {
    const workspace = try bedwire.compression.Workspace.create(std.heap.page_allocator, 8192);
    defer workspace.destroy();
    const encoded = try bedwire.compression.snappy.compress("Bedrock Snappy interoperability. " ** 100, workspace.output, &workspace.table);
    std.debug.print("{x}", .{encoded});
}
