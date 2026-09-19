const std = @import("std");

// compression algorithms negotiated on wire
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

// how compression is framed on the wire
pub const CompressionMode = enum {
    absent,
    implicit,
    marked,
};

pub const LoginFlow = enum {
    certificate_chain,
    oidc,
};

pub const ResourcePackFlow = enum {
    classic,
    with_validation,
};

pub const EncryptionPolicy = enum { required, optional };

/// session quirks and feature flags for a protocol version
pub const SessionFeatures = struct {
    uses_request_network_settings: bool = true,
    compression_mode: CompressionMode = .marked,
    supports_snappy: bool = true,
    supports_deflate: bool = true,
    // default algorithm before negotiation
    initial_algorithm: Algorithm = .none,
    login_flow: LoginFlow = .certificate_chain,
    resource_pack_flow: ResourcePackFlow = .with_validation,
    encryption: EncryptionPolicy = .required,

    pub fn supports(self: SessionFeatures, algorithm: Algorithm) bool {
        return switch (algorithm) {
            .none => true,
            .deflate => self.supports_deflate,
            .snappy => self.supports_snappy,
        };
    }

    pub fn validate(self: SessionFeatures) !void {
        const negotiable = self.compression_mode == .marked;
        if (negotiable and !self.supports_deflate and !self.supports_snappy) return error.UnsupportedProtocol;
        if (self.compression_mode == .implicit and self.initial_algorithm == .none) return error.UnsupportedProtocol;
        if (self.compression_mode == .absent and self.initial_algorithm != .none) return error.UnsupportedProtocol;
        if (!self.supports(self.initial_algorithm)) return error.UnsupportedProtocol;
    }
};

/// returns session flags for a given bedrock protocol version
pub fn forVersion(version: u32) SessionFeatures {
    // 1.19.30 (554)+ added RequestNetworkSettings, snappy and compression markers
    if (version >= 554) {
        return .{
            .uses_request_network_settings = true,
            .compression_mode = .marked,
            .supports_snappy = true,
            .initial_algorithm = .none,
            // 1.21.90 (818)+ added ResourcePacksReadyForValidation
            .resource_pack_flow = if (version >= 818) .with_validation else .classic,
        };
    }

    // 1.16.220 (431) - 1.19.20 used raw deflate without algo marker
    if (version >= 431) {
        return .{
            .uses_request_network_settings = false,
            .compression_mode = .implicit,
            .supports_snappy = false,
            .initial_algorithm = .deflate,
            .resource_pack_flow = .classic,
        };
    }

    return .{
        .uses_request_network_settings = false,
        .compression_mode = .implicit,
        .supports_snappy = false,
        .initial_algorithm = .deflate,
        .resource_pack_flow = .classic,
    };
}

test "version profiles stay internally consistent" {
    for ([_]u32{ 200, 431, 553, 554, 800, 818, 900 }) |version| {
        try forVersion(version).validate();
    }
    try std.testing.expect(forVersion(766).uses_request_network_settings);
    try std.testing.expect(!forVersion(500).uses_request_network_settings);
    try std.testing.expectEqual(CompressionMode.implicit, forVersion(500).compression_mode);
    try std.testing.expectEqual(ResourcePackFlow.classic, forVersion(600).resource_pack_flow);
    try std.testing.expectEqual(ResourcePackFlow.with_validation, forVersion(818).resource_pack_flow);
}

test "feature validation rejects contradictory profiles" {
    const marked_without_algorithms: SessionFeatures = .{ .supports_deflate = false, .supports_snappy = false };
    try std.testing.expectError(error.UnsupportedProtocol, marked_without_algorithms.validate());

    const implicit_without_algorithm: SessionFeatures = .{ .compression_mode = .implicit };
    try std.testing.expectError(error.UnsupportedProtocol, implicit_without_algorithm.validate());

    const absent_with_algorithm: SessionFeatures = .{ .compression_mode = .absent, .initial_algorithm = .deflate };
    try std.testing.expectError(error.UnsupportedProtocol, absent_with_algorithm.validate());

    const snappy_without_support: SessionFeatures = .{ .compression_mode = .implicit, .initial_algorithm = .snappy, .supports_snappy = false };
    try std.testing.expectError(error.UnsupportedProtocol, snappy_without_support.validate());
}
