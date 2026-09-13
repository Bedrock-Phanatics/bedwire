const protocol = @import("bedrock_protocol");
const Workspace = @import("flate.zig").Workspace;
pub const Algorithm = protocol.batch.Compression;

pub const Settings = struct {
    enabled: bool = false,
    algorithm: Algorithm = .deflate,
    threshold: u16 = 512,

    pub fn selected(self: Settings, size: usize) Algorithm {
        if (!self.enabled or size < self.threshold) return .none;
        return self.algorithm;
    }

    /// Returns borrowed input or workspace storage. Failed calls invalidate scratch.
    pub fn decode(self: Settings, input: []const u8, workspace: *Workspace, limits: protocol.DecodeLimits) ![]const u8 {
        if (input.len > limits.max_batch_bytes) return error.LimitExceeded;
        if (!self.enabled) {
            if (input.len > limits.max_decompressed_batch_bytes) return error.LimitExceeded;
            return input;
        }
        if (input.len == 0) return error.EndOfStream;
        const algorithm: Algorithm = switch (input[0]) {
            0 => .deflate,
            1 => .snappy,
            0xff => .none,
            else => return error.UnsupportedCompression,
        };
        if (algorithm == .none) {
            if (input.len - 1 > limits.max_decompressed_batch_bytes) return error.LimitExceeded;
            return input[1..];
        }
        if (algorithm != self.algorithm) return error.UnexpectedCompression;
        return switch (algorithm) {
            .deflate => workspace.decompress(input[1..], limits),
            .snappy => @import("snappy.zig").decompress(input[1..], workspace.output, limits),
            .none => unreachable,
        };
    }
};
