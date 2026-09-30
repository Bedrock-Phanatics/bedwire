const std = @import("std");

const Limits = @import("../limits.zig").Limits;
const flate = @import("flate.zig");
const snappy = @import("snappy.zig");

pub const Algorithm = enum(u8) {
    deflate = 0,
    snappy = 1,
    none = 0xff,

    pub fn fromWire(byte: u8) !Algorithm {
        return switch (byte) {
            0 => .deflate,
            1 => .snappy,
            0xff => .none,
            else => error.UnsupportedCompression,
        };
    }
};
pub const CompressionMode = @FieldType(SessionFeatures, "compression_mode");
pub const SessionFeatures = @import("bedrock_protocol").SessionFeatures;

/// An encode needs either the DEFLATE window or the Snappy table.
pub const Scratch = extern union {
    history: [flate.history_len]u8,
    table: snappy.Table,
};

pub const Framed = struct { algorithm: Algorithm, bytes: []const u8 };

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
            .algorithm = switch (session_features.initial_algorithm) {
                .none => .none,
                .deflate => .deflate,
                .snappy => .snappy,
            },
            .negotiated = session_features.compression_mode != .marked,
        };
    }

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

    pub fn encode(self: Compression, input: []const u8, dest: []u8, scratch: *Scratch) !Framed {
        const algorithm = self.selected(input.len);
        return .{ .algorithm = algorithm, .bytes = switch (algorithm) {
            .none => try copy(input, dest),
            .deflate => try flate.compress(input, dest, &scratch.history),
            .snappy => try snappy.compress(input, dest, &scratch.table),
        } };
    }

    /// Uncompressed input is returned without copying.
    pub fn decode(
        self: Compression,
        input: []const u8,
        dest: []u8,
        history: *[flate.history_len]u8,
        limits: Limits,
    ) ![]const u8 {
        if (input.len > limits.max_frame_bytes) return error.LimitExceeded;

        const framed = try self.split(input);
        return switch (framed.algorithm) {
            .none => if (framed.bytes.len > limits.max_batch_bytes) error.LimitExceeded else framed.bytes,
            .deflate => flate.decompress(framed.bytes, dest, history, limits),
            .snappy => snappy.decompress(framed.bytes, dest, limits),
        };
    }

    fn copy(input: []const u8, dest: []u8) error{NoSpaceLeft}![]const u8 {
        if (input.len > dest.len) return error.NoSpaceLeft;
        @memcpy(dest[0..input.len], input);
        return dest[0..input.len];
    }

    fn split(self: Compression, input: []const u8) !Framed {
        if (!self.marks()) return .{ .algorithm = self.algorithm, .bytes = input };
        if (input.len == 0) return error.MalformedCompressedData;

        const marked = try Algorithm.fromWire(input[0]);
        if (marked != .none and marked != self.algorithm) return error.UnexpectedCompression;
        if (!self.supports(marked)) return error.UnsupportedCompression;

        return .{ .algorithm = marked, .bytes = input[1..] };
    }
};
