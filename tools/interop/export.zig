const std = @import("std");
const zigrock = @import("zigrock");

pub fn main() !void {
    const workspace = try zigrock.FlateWorkspace.create(std.heap.page_allocator, 8192);
    defer workspace.destroy();
    const encoded = try zigrock.snappy.compress("Bedrock Snappy interoperability. " ** 100, workspace.output, &workspace.snappy_table);
    std.debug.print("{x}", .{encoded});
}
