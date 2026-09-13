const std = @import("std");
const jwt = @import("jwt.zig");
const spki = @import("../crypto/spki.zig");
const Limits = @import("../framing/limits.zig").DecodeLimits;
pub const moj_root = @import("moj_root.zig");

pub const AuthData = struct {
    allocator: std.mem.Allocator,
    display_name: []u8,
    identity: []u8,
    xuid: []u8,
    public_key: spki.Ecdsa.PublicKey,
    online: bool,

    pub fn deinit(self: *AuthData) void {
        self.allocator.free(self.display_name);
        self.allocator.free(self.identity);
        self.allocator.free(self.xuid);
        self.* = undefined;
    }
};

pub const Policy = struct {
    now: i64,
    allow_offline: bool = false,
    /// Explicit trust-anchor injection supports private realms and deterministic tests.
    root: ?spki.Ecdsa.PublicKey = null,
};

fn sameKey(a: spki.Ecdsa.PublicKey, b: spki.Ecdsa.PublicKey) bool {
    return std.mem.eql(u8, &a.toUncompressedSec1(), &b.toUncompressedSec1());
}

pub fn verifyLegacy(allocator: std.mem.Allocator, chain_json: []const u8, client_data: []const u8, policy: Policy, limits: Limits) !AuthData {
    if (chain_json.len > limits.max_jwt_payload_bytes) return error.LimitExceeded;
    const parsed = try jwt.parseJson(allocator, chain_json, limits);
    defer parsed.deinit();
    const chain = parsed.value.object.get("chain") orelse return error.InvalidChain;
    if (chain != .array) return error.InvalidChain;
    const links = chain.array.items;
    if (links.len > limits.max_chain_length) return error.LimitExceeded;
    const online = links.len == 3;
    if (!online and (links.len != 1 or !policy.allow_offline)) return error.UntrustedChain;
    var first: ?spki.Ecdsa.PublicKey = null;
    var next_key: ?spki.Ecdsa.PublicKey = null;
    for (links, 0..) |link, i| {
        if (link != .string) return error.InvalidChain;
        var token = try jwt.Token.parse(allocator, link.string, limits);
        defer token.deinit();
        const header_key = try spki.fromBase64(try jwt.string(token.header.value, "x5u"));
        if (i == 0) first = header_key else if (!sameKey(header_key, next_key.?)) return error.UntrustedChain;
        const signer = if (i == 0) header_key else next_key.?;
        try token.verify(signer);
        try token.validateTime(policy.now, true);
        if (online and i > 0 and !std.mem.eql(u8, try jwt.string(token.payload.value, "iss"), "Mojang")) return error.InvalidClaims;
        next_key = try spki.fromBase64(try jwt.string(token.payload.value, "identityPublicKey"));
        if (online and i == 0 and !sameKey(next_key.?, policy.root orelse moj_root.key())) return error.UntrustedChain;
        if (online and i < 2) {
            const ca = token.payload.value.object.get("certificateAuthority") orelse return error.InvalidChain;
            if (ca != .bool or !ca.bool) return error.InvalidChain;
        }
        if (i + 1 == links.len) {
            if (!sameKey(next_key.?, first.?)) return error.UntrustedChain;
            var client = try jwt.Token.parse(allocator, client_data, limits);
            defer client.deinit();
            try client.verify(next_key.?);
            try client.validateTime(policy.now, false);
            const extra = token.payload.value.object.get("extraData") orelse return error.InvalidClaims;
            const xuid = if (online) try jwt.string(extra, "XUID") else "";
            return identity(allocator, try jwt.string(extra, "displayName"), try jwt.string(extra, "identity"), xuid, next_key.?, online, limits);
        }
    }
    return error.InvalidChain;
}

pub const OidcKey = struct { kid: []const u8, key: spki.Ecdsa.PublicKey };
pub const OidcPolicy = struct { now: i64, issuer: []const u8, audience: []const u8, keys: []const OidcKey };

pub fn verifyOidc(allocator: std.mem.Allocator, encoded: []const u8, client_data: []const u8, policy: OidcPolicy, limits: Limits) !AuthData {
    var token = try jwt.Token.parse(allocator, encoded, limits);
    defer token.deinit();
    const kid = try jwt.string(token.header.value, "kid");
    var key: ?spki.Ecdsa.PublicKey = null;
    for (policy.keys) |candidate| {
        if (std.mem.eql(u8, candidate.kid, kid)) {
            if (key != null) return error.AmbiguousKey;
            key = candidate.key;
        }
    }
    try token.verify(key orelse return error.UnknownKey);
    try token.validateTime(policy.now, true);
    const valid_claims = std.mem.eql(u8, try jwt.string(token.payload.value, "iss"), policy.issuer) and
        std.mem.eql(u8, try jwt.string(token.payload.value, "aud"), policy.audience);
    if (!valid_claims) return error.InvalidClaims;
    const client_key = try spki.fromBase64(try jwt.string(token.payload.value, "cpk"));
    var client = try jwt.Token.parse(allocator, client_data, limits);
    defer client.deinit();
    try client.verify(client_key);
    try client.validateTime(policy.now, false);
    return identity(allocator, try jwt.string(token.payload.value, "xname"), try jwt.string(token.payload.value, "mid"), try jwt.string(token.payload.value, "xid"), client_key, true, limits);
}

fn identity(allocator: std.mem.Allocator, name: []const u8, uuid: []const u8, xuid: []const u8, key: spki.Ecdsa.PublicKey, online: bool, limits: Limits) !AuthData {
    if (name.len == 0 or name.len > limits.protocol.max_string_bytes) return error.InvalidClaims;
    if (uuid.len != 36) return error.InvalidClaims;
    for (uuid, 0..) |byte, i| {
        const separator = i == 8 or i == 13 or i == 18 or i == 23;
        if (separator) {
            if (byte != '-') return error.InvalidClaims;
        } else if (!std.ascii.isHex(byte)) return error.InvalidClaims;
    }
    if (online) _ = std.fmt.parseInt(u64, xuid, 10) catch return error.InvalidClaims;
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    const owned_uuid = try allocator.dupe(u8, uuid);
    errdefer allocator.free(owned_uuid);
    return .{ .allocator = allocator, .display_name = owned_name, .identity = owned_uuid, .xuid = try allocator.dupe(u8, xuid), .public_key = key, .online = online };
}
