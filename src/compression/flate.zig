const std = @import("std");
const protocol = @import("bedrock_protocol");

const snappy = @import("snappy.zig");

/// Connection-owned scratch. Results borrow storage until the next operation,
/// including failed operations. Not thread-safe. Allocate once with create().
pub const Workspace = struct {
    allocator: std.mem.Allocator,
    output: []u8,
    history: [std.compress.flate.max_window_len]u8 = undefined,
    compressor: std.compress.flate.Compress = undefined,
    snappy_table: snappy.Table = undefined,

    pub fn create(allocator: std.mem.Allocator, capacity: usize) !*Workspace {
        const self = try allocator.create(Workspace);
        errdefer allocator.destroy(self);

        self.* = .{ .allocator = allocator, .output = try allocator.alloc(u8, @max(capacity, 16)) };

        return self;
    }

    pub fn destroy(self: *Workspace) void {
        const allocator = self.allocator;
        allocator.free(self.output);
        allocator.destroy(self);
    }

    pub fn compress(self: *Workspace, input: []const u8) ![]const u8 {
        var writer: std.Io.Writer = .fixed(self.output);
        self.compressor = try .init(&writer, &self.history, .raw, .default);
        self.compressor.writer.writeAll(input) catch return error.LimitExceeded;
        self.compressor.finish() catch return error.LimitExceeded;

        return self.output[0..writer.end];
    }

    pub fn decompress(self: *Workspace, input: []const u8, limits: protocol.DecodeLimits) ![]const u8 {
        const output = self.output[0..@min(self.output.len, limits.max_decompressed_batch_bytes)];
        return protocol.batch.decompressDeflate(input, output, &self.history, limits);
    }
};
