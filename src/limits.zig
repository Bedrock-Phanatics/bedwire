const std = @import("std");

/// session layer limits and buffer bounds
pub const Limits = struct {
    // max wire frame size including 0xfe
    max_frame_bytes: usize = 4 * 1024 * 1024,
    // max decompressed batch size
    max_batch_bytes: usize = 16 * 1024 * 1024,
    // max individual packet size inside a batch
    max_packet_bytes: usize = 4 * 1024 * 1024,
    max_packets_per_batch: usize = 1024,

    max_jwt_header_bytes: usize = 8 * 1024,
    max_jwt_payload_bytes: usize = 1024 * 1024,
    max_json_nesting: usize = 64,
    max_chain_length: usize = 8,
    max_identity_bytes: usize = 1024,

    max_resource_pack_bytes: u64 = 512 * 1024 * 1024,
    max_resource_packs: usize = 128,
    max_resource_pack_chunk_bytes: usize = 1024 * 1024,
    max_pack_id_bytes: usize = 256,

    max_jwks_bytes: usize = 64 * 1024,
    max_jwks_keys: usize = 16,
    max_connection_request_bytes: usize = 2 * 1024 * 1024,
    max_kid_bytes: usize = 64,

    pub const max_supported_json_nesting: usize = 128;

    pub fn validate(self: Limits) !void {
        const positive =
            self.max_frame_bytes > 0 and
            self.max_batch_bytes > 0 and
            self.max_packet_bytes > 0 and
            self.max_packets_per_batch > 0 and
            self.max_jwt_header_bytes > 0 and
            self.max_jwt_payload_bytes > 0 and
            self.max_json_nesting > 0 and
            self.max_chain_length > 0 and
            self.max_identity_bytes > 0 and
            self.max_resource_pack_bytes > 0 and
            self.max_resource_packs > 0 and
            self.max_resource_pack_chunk_bytes > 0 and
            self.max_pack_id_bytes > 0 and
            self.max_jwks_bytes > 0 and
            self.max_jwks_keys > 0 and
            self.max_connection_request_bytes > 0 and
            self.max_kid_bytes > 0;
        if (!positive) return error.InvalidLimits;

        if (self.max_json_nesting > max_supported_json_nesting) return error.InvalidLimits;
        if (self.max_packet_bytes > self.max_batch_bytes) return error.InvalidLimits;

        // Buffer sizing multiplies these during init, reject inputs that would overflow.
        _ = std.math.add(usize, self.max_jwt_header_bytes, self.max_jwt_payload_bytes) catch return error.InvalidLimits;
        _ = std.math.mul(usize, self.max_batch_bytes, 2) catch return error.InvalidLimits;
    }
};

test "limits reject impossible configurations" {
    try (Limits{}).validate();
    try std.testing.expectError(error.InvalidLimits, (Limits{ .max_frame_bytes = 0 }).validate());
    try std.testing.expectError(error.InvalidLimits, (Limits{ .max_json_nesting = 1000 }).validate());
    try std.testing.expectError(error.InvalidLimits, (Limits{ .max_packet_bytes = 32, .max_batch_bytes = 16 }).validate());
    try std.testing.expectError(error.InvalidLimits, (Limits{ .max_batch_bytes = std.math.maxInt(usize) }).validate());
    try std.testing.expectError(error.InvalidLimits, (Limits{ .max_jwks_bytes = 0 }).validate());
    try std.testing.expectError(error.InvalidLimits, (Limits{ .max_jwks_keys = 0 }).validate());
    try std.testing.expectError(error.InvalidLimits, (Limits{ .max_connection_request_bytes = 0 }).validate());
    try std.testing.expectError(error.InvalidLimits, (Limits{ .max_kid_bytes = 0 }).validate());
}
