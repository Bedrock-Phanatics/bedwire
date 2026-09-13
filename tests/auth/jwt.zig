const std = @import("std");
const bedwire = @import("bedwire");

pub fn sign(allocator: std.mem.Allocator, key: bedwire.spki.Ecdsa.KeyPair, header: []const u8, payload: []const u8) ![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const h = encoder.calcSize(header.len);
    const p = encoder.calcSize(payload.len);
    const bytes = try allocator.alloc(u8, h + p + 130);
    errdefer allocator.free(bytes);
    _ = encoder.encode(bytes[0..h], header);
    bytes[h] = '.';
    _ = encoder.encode(bytes[h + 1 ..][0..p], payload);
    const signed_len = h + 1 + p;
    const signature = try key.sign(bytes[0..signed_len], null);
    bytes[signed_len] = '.';
    _ = encoder.encode(bytes[signed_len + 1 ..], &signature.toBytes());
    return bytes;
}

pub fn public(key: bedwire.spki.Ecdsa.PublicKey) [160]u8 {
    var bytes: [160]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&bytes, &bedwire.spki.encode(key));
    return bytes;
}

test "JWT signature, time, malformed syntax, duplicate fields, and limits" {
    const a = std.testing.allocator;
    const key = try bedwire.spki.Ecdsa.KeyPair.generateDeterministic(@splat(1));
    const other = try bedwire.spki.Ecdsa.KeyPair.generateDeterministic(@splat(2));
    const encoded = try sign(a, key, "{\"alg\":\"ES384\"}", "{\"exp\":200,\"nbf\":100}");
    defer a.free(encoded);
    var token = try bedwire.jwt.Token.parse(a, encoded, .{});
    defer token.deinit();
    try token.verify(key.public_key);
    try std.testing.expectError(error.InvalidSignature, token.verify(other.public_key));
    try token.validateTime(100, true);
    try std.testing.expectError(error.ExpiredToken, token.validateTime(200, true));
    try std.testing.expectError(error.TokenNotYetValid, token.validateTime(99, true));
    try std.testing.expectError(error.LimitExceeded, bedwire.jwt.Token.parse(a, encoded, .{ .max_jwt_header_bytes = 1 }));
    try std.testing.expectError(error.InvalidJwt, bedwire.jwt.Token.parse(a, "a.b.c.d", .{}));
    try std.testing.expectError(error.DuplicateField, bedwire.jwt.parseJson(a, "{\"a\":1,\"a\":2}", .{}));
    try std.testing.expectError(error.LimitExceeded, bedwire.jwt.parseJson(a, "{\"a\":[[[]]]}", .{ .protocol = .{ .max_nesting_depth = 2 } }));
    for (0..encoded.len) |end| {
        if (bedwire.jwt.Token.parse(a, encoded[0..end], .{})) |result| {
            var owned = result;
            owned.deinit();
            return error.AcceptedTruncation;
        } else |_| {}
    }
}
