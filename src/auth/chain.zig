const std = @import("std");

const Limits = @import("../limits.zig").Limits;
const jwt = @import("jwt.zig");
const spki = @import("../crypto/spki.zig");

pub const moj_root = @import("moj_root.zig");
pub const identity_mod = @import("identity.zig");
pub const Identity = identity_mod.Identity;

/// trust policy for mojang cert chain
pub const ChainPolicy = struct {
    now: i64,
    // allow self-signed chains for offline/lan mode
    allow_offline: bool = false,
    // custom root key, or pinned mojang root if null
    root: ?spki.Ecdsa.PublicKey = null,
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
        return identity_mod.validateAndCreate(allocator, .{
            .display_name = try jwt.string(extra, "displayName"),
            .uuid = try jwt.string(extra, "identity"),
            .xuid = if (online) try jwt.string(extra, "XUID") else "",
            .key = next_key.?,
            .online = online,
        }, limits);
    }

    return error.UntrustedChain;
}

fn sameKey(a: spki.Ecdsa.PublicKey, b: spki.Ecdsa.PublicKey) bool {
    return std.crypto.timing_safe.eql([97]u8, a.toUncompressedSec1(), b.toUncompressedSec1());
}
