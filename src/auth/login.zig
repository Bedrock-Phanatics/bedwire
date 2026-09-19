const std = @import("std");

const Limits = @import("../limits.zig").Limits;
const jwt = @import("jwt.zig");
const spki = @import("../crypto/spki.zig");

/// signs header.payload with p384 ecdsa and returns compact jwt
pub fn sign(allocator: std.mem.Allocator, key: spki.Ecdsa.KeyPair, header: []const u8, payload: []const u8, limits: Limits) ![]u8 {
    if (header.len > limits.max_jwt_header_bytes or payload.len > limits.max_jwt_payload_bytes) return error.LimitExceeded;

    const encoder = std.base64.url_safe_no_pad.Encoder;
    const header_len = encoder.calcSize(header.len);
    const payload_len = encoder.calcSize(payload.len);
    const size = try std.math.add(usize, try std.math.add(usize, header_len, payload_len), 130);

    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);

    _ = encoder.encode(bytes[0..header_len], header);
    bytes[header_len] = '.';
    _ = encoder.encode(bytes[header_len + 1 ..][0..payload_len], payload);

    const end = header_len + 1 + payload_len;
    const signature = try key.sign(bytes[0..end], null);
    bytes[end] = '.';
    _ = encoder.encode(bytes[end + 1 ..], &signature.toBytes());

    return bytes;
}

// base64 spki encoding for jwt x5u header
pub fn encodedPublicKey(key: spki.Ecdsa.PublicKey) [160]u8 {
    var encoded: [160]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &spki.encode(key));
    return encoded;
}

/// builds and signs the ServerToClientHandshake jwt with server pubkey and salt
pub fn serverHandshake(allocator: std.mem.Allocator, key: spki.Ecdsa.KeyPair, salt: [16]u8, limits: Limits) ![]u8 {
    var salt_text: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&salt_text, &salt);

    var header_storage: [200]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_storage, "{{\"alg\":\"{s}\",\"x5u\":\"{s}\"}}", .{ jwt.algorithm, encodedPublicKey(key.public_key) });

    var payload_storage: [40]u8 = undefined;
    const payload = try std.fmt.bufPrint(&payload_storage, "{{\"salt\":\"{s}\"}}", .{salt_text});

    return sign(allocator, key, header, payload, limits);
}

/// verified ServerToClientHandshake token
pub const Handshake = struct {
    peer_key: spki.Ecdsa.PublicKey,
    salt: [16]u8,

    pub fn verify(allocator: std.mem.Allocator, encoded: []const u8, limits: Limits) !Handshake {
        var token = try jwt.Token.parse(allocator, encoded, limits);
        defer token.deinit();

        const peer_key = try spki.fromBase64(try jwt.string(token.header.value, "x5u"));
        try token.verify(peer_key);

        return .{ .peer_key = peer_key, .salt = try decodeSalt(try jwt.string(token.payload.value, "salt")) };
    }
};

/// Vanilla emits padded standard base64; some implementations drop the padding.
fn decodeSalt(encoded: []const u8) ![16]u8 {
    const decoder = switch (encoded.len) {
        22 => std.base64.standard_no_pad.Decoder,
        24 => std.base64.standard.Decoder,
        else => return error.InvalidSalt,
    };
    if ((decoder.calcSizeForSlice(encoded) catch return error.InvalidSalt) != 16) return error.InvalidSalt;

    var salt: [16]u8 = undefined;
    decoder.decode(&salt, encoded) catch return error.InvalidSalt;

    return salt;
}
