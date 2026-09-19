const std = @import("std");

const Limits = @import("../limits.zig").Limits;
const jwt = @import("jwt.zig");
const spki = @import("../crypto/spki.zig");

pub const moj_root = @import("moj_root.zig");

/// verified player identity from auth tokens
pub const Identity = struct {
    allocator: std.mem.Allocator,
    display_name: []u8,
    uuid: []u8,
    xuid: []u8,
    public_key: spki.Ecdsa.PublicKey,
    online: bool,

    pub fn deinit(self: *Identity) void {
        self.allocator.free(self.display_name);
        self.allocator.free(self.uuid);
        self.allocator.free(self.xuid);
        self.* = undefined;
    }
};

/// trust policy for mojang cert chain
pub const ChainPolicy = struct {
    now: i64,
    // allow self-signed chains for offline/lan mode
    allow_offline: bool = false,
    // custom root key, or pinned mojang root if null
    root: ?spki.Ecdsa.PublicKey = null,
};

pub const OidcKey = struct {
    kid: []const u8,
    key: spki.Ecdsa.PublicKey,
};

pub const OidcPolicy = struct {
    now: i64,
    issuer: []const u8,
    audience: []const u8,
    keys: []const OidcKey,
};

/// verifies the mojang cert chain and unpacks the player's identity
pub fn verifyChain(
    allocator: std.mem.Allocator,
    chain_json: []const u8,
    client_data: []const u8,
    policy: ChainPolicy,
    limits: Limits,
) !Identity {
    if (chain_json.len > limits.max_jwt_payload_bytes) return error.LimitExceeded;

    const parsed = try jwt.parseJson(allocator, chain_json, limits);
    defer parsed.deinit();

    const chain = parsed.value.object.get("chain") orelse return error.InvalidClaims;
    if (chain != .array) return error.InvalidClaims;

    const links = chain.array.items;
    if (links.len > limits.max_chain_length) return error.LimitExceeded;

    const online = links.len == 3;
    if (!online and (links.len != 1 or !policy.allow_offline)) return error.UntrustedChain;

    var first: ?spki.Ecdsa.PublicKey = null;
    var next_key: ?spki.Ecdsa.PublicKey = null;

    for (links, 0..) |link, i| {
        if (link != .string) return error.InvalidClaims;

        var token = try jwt.Token.parse(allocator, link.string, limits);
        defer token.deinit();

        const header_key = try spki.fromBase64(try jwt.string(token.header.value, "x5u"));
        if (i == 0) {
            first = header_key;
        } else if (!sameKey(header_key, next_key.?)) {
            return error.UntrustedChain;
        }

        try token.verify(if (i == 0) header_key else next_key.?);
        try token.validateTime(policy.now, true);

        const invalid_issuer = online and i > 0 and
            !std.mem.eql(u8, try jwt.string(token.payload.value, "iss"), "Mojang");
        if (invalid_issuer) return error.InvalidClaims;

        next_key = try spki.fromBase64(try jwt.string(token.payload.value, "identityPublicKey"));
        const untrusted_root = online and i == 0 and
            !sameKey(next_key.?, policy.root orelse moj_root.key());
        if (untrusted_root) return error.UntrustedChain;

        if (online and i < 2) {
            const ca = token.payload.value.object.get("certificateAuthority") orelse return error.InvalidClaims;
            if (ca != .bool or !ca.bool) return error.InvalidClaims;
        }

        if (i + 1 != links.len) continue;
        if (!sameKey(next_key.?, first.?)) return error.UntrustedChain;

        var client = try jwt.Token.parse(allocator, client_data, limits);
        defer client.deinit();
        try client.verify(next_key.?);
        try client.validateTime(policy.now, false);

        const extra = token.payload.value.object.get("extraData") orelse return error.InvalidClaims;
        return identity(allocator, .{
            .display_name = try jwt.string(extra, "displayName"),
            .uuid = try jwt.string(extra, "identity"),
            .xuid = if (online) try jwt.string(extra, "XUID") else "",
            .key = next_key.?,
            .online = online,
        }, limits);
    }

    return error.UntrustedChain;
}

/// verify xbox oidc token against trusted keys
pub fn verifyOidc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    client_data: []const u8,
    policy: OidcPolicy,
    limits: Limits,
) !Identity {
    var token = try jwt.Token.parse(allocator, encoded, limits);
    defer token.deinit();

    const kid = try jwt.string(token.header.value, "kid");
    var key: ?spki.Ecdsa.PublicKey = null;

    for (policy.keys) |candidate| {
        if (!std.mem.eql(u8, candidate.kid, kid)) continue;
        if (key != null) return error.AmbiguousKey;

        key = candidate.key;
    }

    try token.verify(key orelse return error.UnknownKey);
    try token.validateTime(policy.now, true);

    const valid_claims =
        std.mem.eql(u8, try jwt.string(token.payload.value, "iss"), policy.issuer) and
        std.mem.eql(u8, try jwt.string(token.payload.value, "aud"), policy.audience);
    if (!valid_claims) return error.InvalidClaims;

    const client_key = try spki.fromBase64(try jwt.string(token.payload.value, "cpk"));
    var client = try jwt.Token.parse(allocator, client_data, limits);
    defer client.deinit();
    try client.verify(client_key);
    try client.validateTime(policy.now, false);

    return identity(allocator, .{
        .display_name = try jwt.string(token.payload.value, "xname"),
        .uuid = try jwt.string(token.payload.value, "mid"),
        .xuid = try jwt.string(token.payload.value, "xid"),
        .key = client_key,
        .online = true,
    }, limits);
}

const Claims = struct {
    display_name: []const u8,
    uuid: []const u8,
    xuid: []const u8,
    key: spki.Ecdsa.PublicKey,
    online: bool,
};

fn identity(allocator: std.mem.Allocator, claims: Claims, limits: Limits) !Identity {
    if (claims.display_name.len == 0 or claims.display_name.len > limits.max_identity_bytes) return error.InvalidClaims;
    if (claims.uuid.len != 36) return error.InvalidClaims;

    for (claims.uuid, 0..) |byte, i| {
        const separator = i == 8 or i == 13 or i == 18 or i == 23;
        if (separator) {
            if (byte != '-') return error.InvalidClaims;
        } else if (!std.ascii.isHex(byte)) return error.InvalidClaims;
    }

    if (claims.online) _ = std.fmt.parseInt(u64, claims.xuid, 10) catch return error.InvalidClaims;
    if (claims.xuid.len > limits.max_identity_bytes) return error.InvalidClaims;

    const display_name = try allocator.dupe(u8, claims.display_name);
    errdefer allocator.free(display_name);

    const uuid = try allocator.dupe(u8, claims.uuid);
    errdefer allocator.free(uuid);

    return .{
        .allocator = allocator,
        .display_name = display_name,
        .uuid = uuid,
        .xuid = try allocator.dupe(u8, claims.xuid),
        .public_key = claims.key,
        .online = claims.online,
    };
}

fn sameKey(a: spki.Ecdsa.PublicKey, b: spki.Ecdsa.PublicKey) bool {
    return std.crypto.timing_safe.eql([97]u8, a.toUncompressedSec1(), b.toUncompressedSec1());
}
