const std = @import("std");

const Limits = @import("../limits.zig").Limits;
const features = @import("../protocol/features.zig");
const flate = @import("flate.zig");
const snappy = @import("snappy.zig");

pub const Algorithm = features.Algorithm;
pub const CompressionMode = features.CompressionMode;
pub const SessionFeatures = features.SessionFeatures;

/// reusable buffers for deflate window and snappy tables so we don't alloc per packet
pub const Workspace = struct {
    allocator: std.mem.Allocator,
    output: []u8,
    history: [flate.history_len]u8 = undefined,
    table: snappy.Table = undefined,

    pub fn create(allocator: std.mem.Allocator, capacity: usize) !*Workspace {
        const self = try allocator.create(Workspace);
        errdefer allocator.destroy(self);

        self.* = .{ .allocator = allocator, .output = try allocator.alloc(u8, @max(capacity, 64)) };

        return self;
    }

    pub fn destroy(self: *Workspace) void {
        const allocator = self.allocator;
        allocator.free(self.output);
        allocator.destroy(self);
    }
};

pub const Framed = struct { algorithm: Algorithm, bytes: []const u8 };

/// negotiated compression algorithm and threshold
/// modern versions start uncompressed until NetworkSettings is received
pub const Compression = struct {
    mode: CompressionMode,
    supports_deflate: bool,
    supports_snappy: bool,
    algorithm: Algorithm = .none,
    threshold: u16 = 0,
    negotiated: bool = false,

    pub fn init(session_features: SessionFeatures) Compression {
        return .{
            .mode = session_features.compression_mode,
            .supports_deflate = session_features.supports_deflate,
            .supports_snappy = session_features.supports_snappy,
            .algorithm = session_features.initial_algorithm,
            .negotiated = session_features.compression_mode != .marked,
        };
    }

    /// apply algorithm and threshold chosen in NetworkSettings
    pub fn negotiate(self: *Compression, algorithm: Algorithm, threshold: u16) !void {
        if (self.mode != .marked or self.negotiated) return error.InvalidState;
        if (!self.supports(algorithm)) return error.UnsupportedCompression;

        self.algorithm = algorithm;
        self.threshold = threshold;
        self.negotiated = true;
    }

    pub fn supports(self: Compression, algorithm: Algorithm) bool {
        return switch (algorithm) {
            .none => true,
            .deflate => self.supports_deflate,
            .snappy => self.supports_snappy,
        };
    }

    /// whether frames need the 1-byte compression algorithm prefix
    pub fn marks(self: Compression) bool {
        return self.mode == .marked and self.negotiated;
    }

    pub fn selected(self: Compression, len: usize) Algorithm {
        return switch (self.mode) {
            .absent => .none,
            .implicit => self.algorithm,
            .marked => if (!self.negotiated or len < self.threshold) .none else self.algorithm,
        };
    }

    /// compresses input into dest if above threshold, otherwise copies verbatim
    pub fn encode(self: Compression, input: []const u8, dest: []u8, workspace: *Workspace) !Framed {
        const algorithm = self.selected(input.len);
        return .{ .algorithm = algorithm, .bytes = switch (algorithm) {
            .none => try copy(input, dest),
            .deflate => try flate.compress(input, dest, &workspace.history),
            .snappy => try snappy.compress(input, dest, &workspace.table),
        } };
    }

    /// decompress decrypted payload into workspace buffer, or pass through as-is if uncompressed
    pub fn decode(self: Compression, input: []const u8, workspace: *Workspace, limits: Limits) ![]const u8 {
        if (input.len > limits.max_frame_bytes) return error.LimitExceeded;

        const framed = try self.split(input);
        return switch (framed.algorithm) {
            .none => if (framed.bytes.len > limits.max_batch_bytes) error.LimitExceeded else framed.bytes,
            .deflate => flate.decompress(framed.bytes, workspace.output, &workspace.history, limits),
            .snappy => snappy.decompress(framed.bytes, workspace.output, limits),
        };
    }

    fn copy(input: []const u8, dest: []u8) error{NoSpaceLeft}![]const u8 {
        if (input.len > dest.len) return error.NoSpaceLeft;
        @memcpy(dest[0..input.len], input);
        return dest[0..input.len];
    }

    // peel off the 1-byte algorithm marker if present
    fn split(self: Compression, input: []const u8) !Framed {
        if (!self.marks()) return .{ .algorithm = self.algorithm, .bytes = input };
        if (input.len == 0) return error.MalformedCompressedData;

        const marked = try Algorithm.fromWire(input[0]);
        if (marked != .none and marked != self.algorithm) return error.UnexpectedCompression;
        if (!self.supports(marked)) return error.UnsupportedCompression;

        return .{ .algorithm = marked, .bytes = input[1..] };
    }
};
