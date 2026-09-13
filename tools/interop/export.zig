const std = @import("std");
const bedwire = @import("bedwire");

pub fn main() !void {
    const workspace = try bedwire.FlateWorkspace.create(std.heap.page_allocator, 8192);
    defer workspace.destroy();
    const encoded = try bedwire.snappy.compress("Bedrock Snappy interoperability. " ** 100, workspace.output, &workspace.snappy_table);
    std.debug.print("{x}", .{encoded});
}
