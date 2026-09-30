const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const oidc = bedwire.auth.oidc;
const identity = bedwire.auth.identity;

const iss = "\"iss\":\"https://authorization.franchise.minecraft-services.net/\"";
const aud = "\"aud\":\"api://auth-minecraft-services/multiplayer\"";
const claims = iss ++ "," ++ aud ++ ",\"cpk\":\"$cpk\",\"xname\":\"Alex\"";
const valid = "{" ++ claims ++ ",\"exp\":2000,\"xid\":\"987654321\"}";

const Options = struct {
    kid: []const u8 = "test-rsa-key-1",
    now: i64 = 1100,
    clock_skew: i64 = 60,
    client_data_seed: u8 = 10,
    tamper: bool = false,
};

fn verify(allocator: std.mem.Allocator, payload: []const u8, options: Options) !oidc.Identity {
    var key_set = try bedwire.auth.KeySet.parse(allocator, support.test_jwks_json, support.limits);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const bound = try std.mem.replaceOwned(u8, allocator, payload, "$cpk", &support.encodedKey(client.public_key));
    defer allocator.free(bound);

    const header = try std.fmt.allocPrint(allocator, "{{\"alg\":\"RS256\",\"kid\":\"{s}\"}}", .{options.kid});
    defer allocator.free(header);

    const token = try support.signRsaToken(allocator, header, bound);
    defer allocator.free(token);
    if (options.tamper) token[token.len - 5] ^= 0x01;

    const client_data = try support.buildClientData(allocator, try support.deterministicKey(options.client_data_seed));
    defer allocator.free(client_data);

    return oidc.verifyOidc(allocator, token, client_data, .{
        .now = options.now,
        .clock_skew = options.clock_skew,
        .keys = &key_set,
    }, support.limits);
}

fn expectUuid(payload: []const u8, expected: []const u8) !void {
    var id = try verify(testing.allocator, payload, .{});
    defer id.deinit();
    try testing.expectEqualStrings(expected, id.uuid);
    try testing.expect(id.online);
}

test "a bound RS256 token yields an online identity with a derived UUID" {
    var id = try verify(testing.allocator, "{" ++ claims ++ ",\"exp\":2000,\"nbf\":1000,\"iat\":1050,\"xid\":\"987654321\"}", .{});
    defer id.deinit();

    try testing.expectEqualStrings("Alex", id.display_name);
    try testing.expectEqualStrings("987654321", id.xuid);
    try testing.expect(id.online);

    var expected: [36]u8 = undefined;
    identity.deriveUuidV3(&expected, "987654321");
    try testing.expectEqualStrings(&expected, id.uuid);
}

test "leguuid wins over derivation and mid is ignored" {
    const xid = ",\"exp\":2000,\"xid\":\"2535451234567890\",\"mid\":\"2535451234567890\"";
    var derived: [36]u8 = undefined;
    identity.deriveUuidV3(&derived, "2535451234567890");

    try expectUuid("{" ++ claims ++ xid ++ "}", &derived);
    try expectUuid("{" ++ claims ++ xid ++ ",\"leguuid\":\"c0a80101-1234-5678-9abc-def012345678\"}", "c0a80101-1234-5678-9abc-def012345678");
}

test "exp and nbf honour the clock skew exactly at the boundary" {
    const expiring = "{" ++ claims ++ ",\"exp\":1000,\"xid\":\"987654321\"}";
    var id = try verify(testing.allocator, expiring, .{ .now = 1059 });
    id.deinit();
    try testing.expectError(error.ExpiredToken, verify(testing.allocator, expiring, .{ .now = 1060 }));

    const pending = "{" ++ claims ++ ",\"exp\":2000,\"nbf\":1000,\"xid\":\"987654321\"}";
    id = try verify(testing.allocator, pending, .{ .now = 940 });
    id.deinit();
    try testing.expectError(error.TokenNotYetValid, verify(testing.allocator, pending, .{ .now = 939 }));
}

test "tokens that fail a claim, key or signature check are refused" {
    const Case = struct { payload: []const u8 = valid, options: Options = .{}, expected: anyerror };
    const cases = [_]Case{
        .{ .payload = "{" ++ claims ++ ",\"exp\":2000,\"iat\":1200,\"xid\":\"987654321\"}", .options = .{ .now = 1000 }, .expected = error.InvalidClaims },
        .{ .payload = "{" ++ claims ++ ",\"exp\":2000,\"iat\":2100,\"xid\":\"987654321\"}", .options = .{ .now = 2050 }, .expected = error.InvalidClaims },
        .{ .payload = "{\"iss\":\"https://evil-issuer.com/\"," ++ aud ++ ",\"cpk\":\"$cpk\",\"xname\":\"Alex\",\"exp\":2000,\"xid\":\"1\"}", .expected = error.InvalidClaims },
        .{ .payload = "{\"iss\":\"https://authorization.franchise.minecraft-services.net\"," ++ aud ++ ",\"cpk\":\"$cpk\",\"xname\":\"Alex\",\"exp\":2000,\"xid\":\"1\"}", .expected = error.InvalidClaims },
        .{ .payload = "{" ++ iss ++ ",\"aud\":\"https://other-service.net\",\"cpk\":\"$cpk\",\"xname\":\"Alex\",\"exp\":2000,\"xid\":\"1\"}", .expected = error.InvalidClaims },
        .{ .payload = "{" ++ claims ++ ",\"exp\":2000,\"xid\":\"not-numeric-xuid\"}", .expected = error.InvalidClaims },
        .{ .payload = "{" ++ claims ++ ",\"exp\":2000,\"xid\":\"987654321\",\"leguuid\":\"not-a-valid-uuid\"}", .expected = error.InvalidClaims },
        .{ .options = .{ .client_data_seed = 11 }, .expected = error.InvalidSignature },
        .{ .options = .{ .kid = "unknown-kid" }, .expected = error.UnknownKey },
        .{ .options = .{ .tamper = true }, .expected = error.InvalidSignature },
    };
    for (cases) |case| try testing.expectError(case.expected, verify(testing.allocator, case.payload, case.options));
}

test "an ES384 token is never accepted as an ID token" {
    var key_set = try bedwire.auth.KeySet.parse(testing.allocator, support.test_jwks_json, support.limits);
    defer key_set.deinit();

    const client_data = try support.buildClientData(testing.allocator, try support.deterministicKey(10));
    defer testing.allocator.free(client_data);

    const token = try support.signToken(testing.allocator, try support.deterministicKey(20), "{\"alg\":\"ES384\",\"kid\":\"test-rsa-key-1\"}", "{}");
    defer testing.allocator.free(token);

    try testing.expectError(error.UnsupportedAlgorithm, oidc.verifyOidc(testing.allocator, token, client_data, .{ .now = 1100, .keys = &key_set }, support.limits));
}

fn verifyValid(allocator: std.mem.Allocator) !void {
    var id = try verify(allocator, valid, .{});
    id.deinit();
}

test "oidc verifier handles allocation failures cleanly" {
    try testing.checkAllAllocationFailures(testing.allocator, verifyValid, .{});
}
