const std = @import("std");

pub const Limits = struct {
    max_frame_bytes: usize = 4 * 1024 * 1024,
    /// Frames a client may send before it is in game. Login is the largest of them, and a smaller cap bounds how much
    /// decompression work an unauthenticated peer can force, since empty DEFLATE blocks cost CPU without output.
    /// A full size login of incompressible skin data still deflates to under three quarters of its size.
    max_handshake_frame_bytes: usize = 3 * 1024 * 1024,
    max_batch_bytes: usize = 16 * 1024 * 1024,
    max_packet_bytes: usize = 4 * 1024 * 1024,
    max_packets_per_batch: usize = 1024,
    max_outgoing_batch_bytes: ?usize = null,
    max_outgoing_packets_per_batch: ?usize = null,

    max_jwt_header_bytes: usize = 8 * 1024,
    /// Client data carries the skin, geometry and animations, which large persona and marketplace skins push past 1 MiB.
    max_jwt_payload_bytes: usize = 3 * 1024 * 1024,
    max_json_nesting: usize = 64,
    /// Values one JSON document may hold, since parsing builds a tree many times the size of its input.
    max_json_values: usize = 16 * 1024,
    max_chain_length: usize = 8,
    max_identity_bytes: usize = 1024,

    max_resource_pack_bytes: u64 = 512 * 1024 * 1024,
    max_resource_packs: usize = 128,
    max_resource_pack_chunk_bytes: usize = 1024 * 1024,
    max_pack_id_bytes: usize = 256,

    max_jwks_bytes: usize = 64 * 1024,
    max_jwks_keys: usize = 16,
    max_connection_request_bytes: usize = 3 * 1024 * 1024,
    max_kid_bytes: usize = 64,

    pub const max_supported_json_nesting: usize = 128;

    pub fn validate(self: Limits) !void {
        const positive =
            self.max_frame_bytes > 0 and
            self.max_handshake_frame_bytes > 0 and
            self.max_batch_bytes > 0 and
            self.max_packet_bytes > 0 and
            self.max_packets_per_batch > 0 and
            self.max_jwt_header_bytes > 0 and
            self.max_jwt_payload_bytes > 0 and
            self.max_json_nesting > 0 and
            self.max_json_values > 0 and
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
        if (self.max_outgoing_batch_bytes) |bytes| if (bytes == 0 or bytes > self.max_batch_bytes) return error.InvalidLimits;
        if (self.max_outgoing_packets_per_batch == 0) return error.InvalidLimits;

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
    try std.testing.expectError(error.InvalidLimits, (Limits{ .max_outgoing_batch_bytes = 0 }).validate());
    try std.testing.expectError(error.InvalidLimits, (Limits{ .max_outgoing_batch_bytes = 32 * 1024 * 1024 }).validate());
    try std.testing.expectError(error.InvalidLimits, (Limits{ .max_outgoing_packets_per_batch = 0 }).validate());
    try (Limits{ .max_outgoing_batch_bytes = 1024, .max_outgoing_packets_per_batch = 4096 }).validate();
}
