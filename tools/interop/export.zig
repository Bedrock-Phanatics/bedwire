const std = @import("std");
const n = @import("network");

pub fn main() !void {
    const workspace = try n.FlateWorkspace.create(std.heap.page_allocator, 8192);
    defer workspace.destroy();
    const encoded = try n.snappy.compress("Bedrock Snappy interoperability. " ** 100, workspace.output, &workspace.snappy_table);
    std.debug.print("{x}", .{encoded});
}
