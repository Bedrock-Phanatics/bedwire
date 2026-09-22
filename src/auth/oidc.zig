const std = @import("std");
const Limits = @import("../limits.zig").Limits;
const jwt = @import("jwt.zig");
const jwks = @import("jwks.zig");
const identity = @import("identity.zig");
const spki = @import("../crypto/spki.zig");

pub const Identity = identity.Identity;

pub const OidcPolicy = struct {
    now: i64,
    clock_skew: i64 = 60,
    keys: *const jwks.KeySet,
    issuer: []const u8 = "https://authorization.franchise.minecraft-services.net/",
    audience: []const u8 = "api://auth-minecraft-services/multiplayer",
};

/// verifies a modern Bedrock OpenID Connect RS256 token and binds the client_data ES384 token
/// using the ephemeral client public key (cpk)
pub fn verifyOidc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    client_data: []const u8,
    policy: OidcPolicy,
    limits: Limits,
) !Identity {
    var token = try jwt.Token.parseWithAlgorithm(allocator, encoded, limits, .RS256);
    defer token.deinit();

    const kid = token.kid() orelse return error.UnknownKey;
    const rsa_key = try policy.keys.find(kid);

    token.verifyRsa(rsa_key) catch return error.InvalidSignature;

    // time validation on RS256 ID token
    const exp_val = token.payload.value.object.get("exp") orelse return error.InvalidClaims;
    if (exp_val != .integer) return error.InvalidClaims;
    const exp = exp_val.integer;

    const min_now = std.math.sub(i64, policy.now, policy.clock_skew) catch return error.ExpiredToken;
    if (min_now >= exp) return error.ExpiredToken;

    if (token.payload.value.object.get("nbf")) |nbf_val| {
        if (nbf_val != .integer) return error.InvalidClaims;
        const nbf = nbf_val.integer;
        const max_now = std.math.add(i64, policy.now, policy.clock_skew) catch return error.TokenNotYetValid;
        if (max_now < nbf) return error.TokenNotYetValid;
    }

    if (token.payload.value.object.get("iat")) |iat_val| {
        if (iat_val != .integer) return error.InvalidClaims;
        const iat = iat_val.integer;
        const max_now = std.math.add(i64, policy.now, policy.clock_skew) catch return error.InvalidClaims;
        if (max_now < iat) return error.InvalidClaims;
        if (iat > exp) return error.InvalidClaims;
    }

    const iss = try jwt.string(token.payload.value, "iss");
    if (!std.mem.eql(u8, iss, policy.issuer)) return error.InvalidClaims;

    const aud = try jwt.string(token.payload.value, "aud");
    if (!std.mem.eql(u8, aud, policy.audience)) return error.InvalidClaims;

    const cpk_str = try jwt.string(token.payload.value, "cpk");
    const client_key = spki.fromBase64(cpk_str) catch return error.InvalidPublicKey;

    var client = try jwt.Token.parseWithAlgorithm(allocator, client_data, limits, .ES384);
    defer client.deinit();

    client.verifyEcdsa(client_key) catch return error.InvalidSignature;
    try client.validateTime(policy.now, false);

    const display_name = (jwt.string(token.payload.value, "xname") catch null) orelse
        (try jwt.string(token.payload.value, "displayName"));

    const xuid = (jwt.string(token.payload.value, "xid") catch null) orelse
        (try jwt.string(token.payload.value, "XUID"));

    _ = std.fmt.parseInt(u64, xuid, 10) catch return error.InvalidClaims;

    var uuid_buf: [36]u8 = undefined;
    const uuid_slice: []const u8 = blk: {
        if (token.payload.value.object.get("leguuid")) |leg_val| {
            if (leg_val != .string) return error.InvalidClaims;
            if (!identity.validateUuid(leg_val.string)) return error.InvalidClaims;
            break :blk leg_val.string;
        }
        identity.deriveUuidV3(&uuid_buf, xuid);
        break :blk &uuid_buf;
    };

    return identity.validateAndCreate(allocator, .{
        .display_name = display_name,
        .uuid = uuid_slice,
        .xuid = xuid,
        .key = client_key,
        .online = true,
    }, limits);
}
