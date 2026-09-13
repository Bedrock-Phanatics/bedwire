const std = @import("std");
const n = @import("network");
const fixtures = @import("jwt.zig");

pub fn makeChain(allocator: std.mem.Allocator, keys: [3]n.spki.Ecdsa.KeyPair) ![]u8 {
    var tokens: [3][]u8 = undefined;
    var initialized: usize = 0;
    defer for (tokens[0..initialized]) |token| allocator.free(token);
    for (keys, 0..) |key, i| {
        const header = try std.fmt.allocPrint(allocator, "{{\"alg\":\"ES384\",\"x5u\":\"{s}\"}}", .{fixtures.public(key.public_key)});
        defer allocator.free(header);
        const payload = try std.fmt.allocPrint(allocator, "{{\"iss\":\"Mojang\",\"exp\":200,\"certificateAuthority\":true,\"identityPublicKey\":\"{s}\",\"extraData\":{{\"displayName\":\"Steve\",\"identity\":\"b1b01c3d-6df3-3635-b286-9a2cfbcf76be\",\"XUID\":\"1234\"}}}}", .{fixtures.public(keys[(i + 1) % 3].public_key)});
        defer allocator.free(payload);
        tokens[i] = try fixtures.sign(allocator, key, header, payload);
        initialized += 1;
    }
    return std.fmt.allocPrint(allocator, "{{\"chain\":[\"{s}\",\"{s}\",\"{s}\"]}}", .{ tokens[0], tokens[1], tokens[2] });
}

fn verifyCase(allocator: std.mem.Allocator, chain: []const u8, client: []const u8, root: n.spki.Ecdsa.PublicKey) !void {
    var identity = try n.auth.verifyLegacy(allocator, chain, client, .{ .now = 100, .root = root }, .{});
    defer identity.deinit();
    try std.testing.expectEqualStrings("Steve", identity.display_name);
    try std.testing.expect(identity.online);
}

test "online chain anchors root and binds client-data; allocation cleanup" {
    const a = std.testing.allocator;
    const keys = [3]n.spki.Ecdsa.KeyPair{
        try .generateDeterministic(@splat(1)),
        try .generateDeterministic(@splat(2)),
        try .generateDeterministic(@splat(3)),
    };
    const chain = try makeChain(a, keys);
    defer a.free(chain);
    const client = try fixtures.sign(a, keys[0], "{\"alg\":\"ES384\"}", "{}");
    defer a.free(client);
    try verifyCase(a, chain, client, keys[1].public_key);
    try std.testing.checkAllAllocationFailures(a, verifyCase, .{ chain, client, keys[1].public_key });
    try std.testing.expectError(error.UntrustedChain, n.auth.verifyLegacy(a, chain, client, .{ .now = 100 }, .{}));
    const forged = try fixtures.sign(a, keys[2], "{\"alg\":\"ES384\"}", "{}");
    defer a.free(forged);
    try std.testing.expectError(error.InvalidSignature, n.auth.verifyLegacy(a, chain, forged, .{ .now = 100, .root = keys[1].public_key }, .{}));
    try std.testing.expectError(error.ExpiredToken, n.auth.verifyLegacy(a, chain, client, .{ .now = 201, .root = keys[1].public_key }, .{}));
}

test "OIDC supplied key, issuer, audience, and cpk binding" {
    const a = std.testing.allocator;
    const key = try n.spki.Ecdsa.KeyPair.generateDeterministic(@splat(4));
    const client_key = try n.spki.Ecdsa.KeyPair.generateDeterministic(@splat(5));
    const payload = try std.fmt.allocPrint(a, "{{\"exp\":200,\"iss\":\"issuer\",\"aud\":\"audience\",\"cpk\":\"{s}\",\"xname\":\"Steve\",\"mid\":\"b1b01c3d-6df3-3635-b286-9a2cfbcf76be\",\"xid\":\"1234\"}}", .{fixtures.public(client_key.public_key)});
    defer a.free(payload);
    const token = try fixtures.sign(a, key, "{\"alg\":\"ES384\",\"kid\":\"one\"}", payload);
    defer a.free(token);
    const client = try fixtures.sign(a, client_key, "{\"alg\":\"ES384\"}", "{}");
    defer a.free(client);
    var policy: n.auth.OidcPolicy = .{ .now = 100, .issuer = "issuer", .audience = "audience", .keys = &.{.{ .kid = "one", .key = key.public_key }} };
    var identity = try n.auth.verifyOidc(a, token, client, policy, .{});
    defer identity.deinit();
    policy.audience = "wrong";
    try std.testing.expectError(error.InvalidClaims, n.auth.verifyOidc(a, token, client, policy, .{}));
}

test "offline chain requires explicit policy and strips untrusted XUID" {
    const a = std.testing.allocator;
    const key = try n.spki.Ecdsa.KeyPair.generateDeterministic(@splat(8));
    const header = try std.fmt.allocPrint(a, "{{\"alg\":\"ES384\",\"x5u\":\"{s}\"}}", .{fixtures.public(key.public_key)});
    defer a.free(header);
    const payload = try std.fmt.allocPrint(a, "{{\"exp\":200,\"identityPublicKey\":\"{s}\",\"extraData\":{{\"displayName\":\"Offline\",\"identity\":\"b1b01c3d-6df3-3635-b286-9a2cfbcf76be\",\"XUID\":\"spoofed\"}}}}", .{fixtures.public(key.public_key)});
    defer a.free(payload);
    const token = try fixtures.sign(a, key, header, payload);
    defer a.free(token);
    const chain = try std.fmt.allocPrint(a, "{{\"chain\":[\"{s}\"]}}", .{token});
    defer a.free(chain);
    const client = try fixtures.sign(a, key, header, "{}");
    defer a.free(client);
    try std.testing.expectError(error.UntrustedChain, n.auth.verifyLegacy(a, chain, client, .{ .now = 100 }, .{}));
    var identity = try n.auth.verifyLegacy(a, chain, client, .{ .now = 100, .allow_offline = true }, .{});
    defer identity.deinit();
    try std.testing.expect(!identity.online);
    try std.testing.expectEqualStrings("", identity.xuid);
}
