const std = @import("std");
const protocol = @import("bedrock_protocol");

const Limits = @import("../limits.zig").Limits;
const jwt = @import("jwt.zig");
const wire = @import("wire.zig");
const identity_mod = @import("identity.zig");
const spki = @import("../crypto/spki.zig");

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

pub fn encodedPublicKey(key: spki.Ecdsa.PublicKey) [160]u8 {
    var encoded: [160]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &spki.encode(key));
    return encoded;
}

/// The backend must trust this key explicitly; these are not Microsoft credentials.
pub fn buildProxyConnectionRequest(
    comptime Profile: type,
    allocator: std.mem.Allocator,
    key: spki.Ecdsa.KeyPair,
    identity: *const identity_mod.Identity,
    client_data_payload: []const u8,
    expires_at: i64,
    format: wire.ConnectionRequestFormat,
    limits: Limits,
) ![]u8 {
    comptime protocol.validateProfile(Profile);
    if (Profile.features.login_flow != .certificate_chain) return error.UnsupportedProtocol;
    try limits.validate();
    if (expires_at <= 0 or identity.display_name.len == 0 or
        identity.display_name.len > limits.max_identity_bytes or
        !std.unicode.utf8ValidateSlice(identity.display_name) or
        !identity_mod.validateUuid(identity.uuid)) return error.InvalidClaims;

    const client_json = try jwt.parseJson(allocator, client_data_payload, limits);
    defer client_json.deinit();

    var header_storage: [200]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_storage, "{{\"alg\":\"{s}\",\"x5u\":\"{s}\"}}", .{ jwt.algorithm, encodedPublicKey(key.public_key) });
    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"exp\":{d},\"identityPublicKey\":\"{s}\",\"extraData\":{{\"displayName\":{f},\"identity\":{f}}}}}",
        .{ expires_at, encodedPublicKey(key.public_key), std.json.fmt(identity.display_name, .{}), std.json.fmt(identity.uuid, .{}) },
    );
    defer allocator.free(payload);
    const link = try sign(allocator, key, header, payload, limits);
    defer allocator.free(link);
    const client_data = try sign(allocator, key, header, client_data_payload, limits);
    defer allocator.free(client_data);

    const chain_json = try std.fmt.allocPrint(allocator, "{{\"chain\":[\"{s}\"]}}", .{link});
    defer allocator.free(chain_json);
    if (chain_json.len > limits.max_jwt_payload_bytes) return error.LimitExceeded;

    const envelope = if (format == .envelope)
        try std.fmt.allocPrint(allocator, "{{\"AuthenticationType\":2,\"Certificate\":{f}}}", .{std.json.fmt(chain_json, .{})})
    else
        null;
    defer if (envelope) |bytes| allocator.free(bytes);
    const chain_data = envelope orelse chain_json;
    if (chain_data.len > limits.max_jwt_payload_bytes) return error.LimitExceeded;
    return wire.encodeConnectionRequest(allocator, .{ .chain_data = chain_data, .client_data = client_data }, limits);
}

pub fn encodeLoginPacket(comptime Profile: type, dest: []u8, connection_request: []const u8, limits: Limits) ![]const u8 {
    comptime protocol.validateProfile(Profile);
    try limits.validate();
    if (connection_request.len > limits.max_connection_request_bytes) return error.LimitExceeded;
    const packet_id = Profile.packetId(.login) orelse return error.UnsupportedProtocol;
    const version = std.math.cast(i32, Profile.protocol_number) orelse return error.UnsupportedProtocol;
    var writer = protocol.Writer.init(dest[0..@min(dest.len, limits.max_packet_bytes)]);
    try Profile.encode(&writer, .{
        .header = .{ .packet_id = packet_id },
        .kind = .login,
        .payload = &.{},
        .value = .{ .typed = .{ .login = .{
            .client_network_version = version,
            .connection_request = connection_request,
        } } },
    });
    return writer.written();
}

pub fn serverHandshake(allocator: std.mem.Allocator, key: spki.Ecdsa.KeyPair, salt: [16]u8, limits: Limits) ![]u8 {
    var salt_text: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&salt_text, &salt);

    var header_storage: [200]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_storage, "{{\"alg\":\"{s}\",\"x5u\":\"{s}\"}}", .{ jwt.algorithm, encodedPublicKey(key.public_key) });

    var payload_storage: [40]u8 = undefined;
    const payload = try std.fmt.bufPrint(&payload_storage, "{{\"salt\":\"{s}\"}}", .{salt_text});

    return sign(allocator, key, header, payload, limits);
}

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
