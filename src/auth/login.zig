const std = @import("std");
const protocol = @import("bedrock_protocol");
const Limits = @import("../framing/limits.zig").DecodeLimits;
const jwt = @import("jwt.zig");
const spki = @import("../crypto/spki.zig");

/// Slices borrow the Login packet payload, including the connection request JSON.
pub const Login = struct {
    protocol_version: i32,
    identity_json: []const u8,
    client_data: []const u8,

    pub fn decode(payload: []const u8, limits: Limits) !Login {
        var reader = try protocol.Reader.init(payload, limits.protocol);
        const version = try reader.readI32Be();
        const bytes = try reader.readByteArray();
        try reader.finish();
        var request = try protocol.Reader.init(bytes, limits.protocol);
        const identity_len = try request.readI32();
        if (identity_len <= 0) return error.InvalidLogin;
        if (@as(u32, @intCast(identity_len)) > limits.max_jwt_payload_bytes) return error.LimitExceeded;
        const identity_json = try request.take(@intCast(identity_len));
        const client_len = try request.readI32();
        if (client_len <= 0) return error.InvalidLogin;
        const client_data = try request.take(@intCast(client_len));
        try request.finish();
        return .{ .protocol_version = version, .identity_json = identity_json, .client_data = client_data };
    }
};

/// Owns returned compact ES384 JWT. JSON must already be validated by its producer.
pub fn sign(allocator: std.mem.Allocator, key: spki.Ecdsa.KeyPair, header: []const u8, payload: []const u8, limits: Limits) ![]u8 {
    if (header.len > limits.max_jwt_header_bytes or payload.len > limits.max_jwt_payload_bytes) return error.LimitExceeded;
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const h = encoder.calcSize(header.len);
    const p = encoder.calcSize(payload.len);
    const size = try std.math.add(usize, try std.math.add(usize, h, p), 130);
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    _ = encoder.encode(bytes[0..h], header);
    bytes[h] = '.';
    _ = encoder.encode(bytes[h + 1 ..][0..p], payload);
    const end = h + 1 + p;
    const signature = try key.sign(bytes[0..end], null);
    bytes[end] = '.';
    _ = encoder.encode(bytes[end + 1 ..], &signature.toBytes());
    return bytes;
}

/// Caller supplies a fresh ephemeral key and cryptographically random 16-byte salt.
pub fn serverHandshake(allocator: std.mem.Allocator, key: spki.Ecdsa.KeyPair, salt: [16]u8, limits: Limits) ![]u8 {
    var public_key: [160]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&public_key, &spki.encode(key.public_key));
    var salt_text: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&salt_text, &salt);
    var header_storage: [200]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_storage, "{{\"alg\":\"ES384\",\"x5u\":\"{s}\"}}", .{public_key});
    var payload_storage: [40]u8 = undefined;
    const payload = try std.fmt.bufPrint(&payload_storage, "{{\"salt\":\"{s}\"}}", .{salt_text});
    return sign(allocator, key, header, payload, limits);
}
