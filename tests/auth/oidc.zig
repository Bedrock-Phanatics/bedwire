const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const oidc = bedwire.auth.oidc;
const jwks = bedwire.auth.jwks;
const identity_mod = bedwire.auth.identity;

const default_iss = "https://authorization.franchise.minecraft-services.net/";
const default_aud = "api://auth-minecraft-services/multiplayer";

fn createTestKeySet(allocator: std.mem.Allocator) !jwks.KeySet {
    return jwks.KeySet.parse(allocator, support.test_jwks_json, support.limits);
}

test "valid RS256 token and ES384 ClientData bound to cpk creates online Identity" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"nbf\":1000,\"iat\":1050,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const policy: oidc.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };

    var id = try oidc.verifyOidc(allocator, token, client_data, policy, support.limits);
    defer id.deinit();

    try testing.expectEqualStrings("Alex", id.display_name);
    try testing.expectEqualStrings("987654321", id.xuid);
    try testing.expect(id.online);
    try testing.expect(identity_mod.validateUuid(id.uuid));

    var expected_uuid: [36]u8 = undefined;
    identity_mod.deriveUuidV3(&expected_uuid, "987654321");
    try testing.expectEqualStrings(&expected_uuid, id.uuid);
}

test "UUIDv3 derivation from XUID matches test vector" {
    var dest: [36]u8 = undefined;
    identity_mod.deriveUuidV3(&dest, "123456789");
    try testing.expectEqualStrings("fa207011-346c-3a82-8499-98ef4bf3e075", &dest);
    try testing.expect(identity_mod.validateUuid(&dest));
}

test "valid leguuid is preserved when present" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\",\"leguuid\":\"b1b01c3d-6df3-3635-b286-9a2cfbcf76be\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const policy: oidc.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };

    var id = try oidc.verifyOidc(allocator, token, client_data, policy, support.limits);
    defer id.deinit();

    try testing.expectEqualStrings("b1b01c3d-6df3-3635-b286-9a2cfbcf76be", id.uuid);
    try testing.expect(id.online);
}

test "production-like token with mid (PlayFab ID) ignores mid and derives UUIDv3 from xid" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"StevePlayFab\",\"xid\":\"2535451234567890\",\"mid\":\"2535451234567890\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const policy: oidc.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };

    var id = try oidc.verifyOidc(allocator, token, client_data, policy, support.limits);
    defer id.deinit();

    try testing.expectEqualStrings("StevePlayFab", id.display_name);
    try testing.expectEqualStrings("2535451234567890", id.xuid);
    try testing.expect(id.online);

    var expected_uuid: [36]u8 = undefined;
    identity_mod.deriveUuidV3(&expected_uuid, "2535451234567890");
    try testing.expectEqualStrings(&expected_uuid, id.uuid);
    try testing.expect(identity_mod.validateUuid(id.uuid));
}

test "production-like token with both mid and leguuid preserves leguuid and ignores mid" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"StevePlayFab\",\"xid\":\"2535451234567890\",\"mid\":\"2535451234567890\",\"leguuid\":\"c0a80101-1234-5678-9abc-def012345678\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const policy: oidc.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };

    var id = try oidc.verifyOidc(allocator, token, client_data, policy, support.limits);
    defer id.deinit();

    try testing.expectEqualStrings("c0a80101-1234-5678-9abc-def012345678", id.uuid);
    try testing.expect(id.online);
}

test "cpk mismatch returns error.InvalidSignature" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const real_client = try support.deterministicKey(10);
    const impostor_client = try support.deterministicKey(11);
    const cpk_b64 = support.encodedKey(real_client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, impostor_client);
    defer allocator.free(client_data);

    const policy: oidc.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };

    try testing.expectError(error.InvalidSignature, oidc.verifyOidc(allocator, token, client_data, policy, support.limits));
}

test "expired token returns error.ExpiredToken with clock skew" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":1000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    // exp = 1000, skew = 60
    // now = 1059: now - skew = 999 < 1000 -> valid
    // now = 1060: now - skew = 1000 >= 1000 -> expired
    const policy_valid: oidc.OidcPolicy = .{
        .now = 1059,
        .clock_skew = 60,
        .keys = &key_set,
    };
    var id = try oidc.verifyOidc(allocator, token, client_data, policy_valid, support.limits);
    id.deinit();

    const policy_expired: oidc.OidcPolicy = .{
        .now = 1060,
        .clock_skew = 60,
        .keys = &key_set,
    };
    try testing.expectError(error.ExpiredToken, oidc.verifyOidc(allocator, token, client_data, policy_expired, support.limits));
}

test "token not yet valid returns error.TokenNotYetValid with clock skew" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"nbf\":1000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    // nbf = 1000, skew = 60
    // now = 940: now + skew = 1000 >= 1000 -> valid
    // now = 939: now + skew = 999 < 1000 -> not yet valid
    const policy_valid: oidc.OidcPolicy = .{
        .now = 940,
        .clock_skew = 60,
        .keys = &key_set,
    };
    var id = try oidc.verifyOidc(allocator, token, client_data, policy_valid, support.limits);
    id.deinit();

    const policy_not_yet: oidc.OidcPolicy = .{
        .now = 939,
        .clock_skew = 60,
        .keys = &key_set,
    };
    try testing.expectError(error.TokenNotYetValid, oidc.verifyOidc(allocator, token, client_data, policy_not_yet, support.limits));
}

test "future token iat returns error.InvalidClaims" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"iat\":1200,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    // now = 1000, skew = 60 -> now + skew = 1060 < iat(1200) -> future token
    const policy: oidc.OidcPolicy = .{
        .now = 1000,
        .clock_skew = 60,
        .keys = &key_set,
    };
    try testing.expectError(error.InvalidClaims, oidc.verifyOidc(allocator, token, client_data, policy, support.limits));
}

test "iat greater than exp returns error.InvalidClaims" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    // iat = 2100 > exp = 2000
    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"iat\":2100,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const policy: oidc.OidcPolicy = .{
        .now = 2050,
        .clock_skew = 60,
        .keys = &key_set,
    };
    try testing.expectError(error.InvalidClaims, oidc.verifyOidc(allocator, token, client_data, policy, support.limits));
}

test "issuer mismatch returns error.InvalidClaims" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    {
        const payload = try std.fmt.allocPrint(
            allocator,
            "{{\"iss\":\"https://evil-issuer.com/\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
            .{ default_aud, cpk_b64 },
        );
        defer allocator.free(payload);

        const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
        defer allocator.free(token);

        const client_data = try support.buildClientData(allocator, client);
        defer allocator.free(client_data);

        const policy: oidc.OidcPolicy = .{
            .now = 1100,
            .keys = &key_set,
        };
        try testing.expectError(error.InvalidClaims, oidc.verifyOidc(allocator, token, client_data, policy, support.limits));
    }

    {
        const payload = try std.fmt.allocPrint(
            allocator,
            "{{\"iss\":\"https://authorization.franchise.minecraft-services.net\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
            .{ default_aud, cpk_b64 },
        );
        defer allocator.free(payload);

        const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
        defer allocator.free(token);

        const client_data = try support.buildClientData(allocator, client);
        defer allocator.free(client_data);

        const policy: oidc.OidcPolicy = .{
            .now = 1100,
            .keys = &key_set,
        };
        try testing.expectError(error.InvalidClaims, oidc.verifyOidc(allocator, token, client_data, policy, support.limits));
    }
}

test "audience mismatch returns error.InvalidClaims" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    {
        const payload = try std.fmt.allocPrint(
            allocator,
            "{{\"iss\":\"{s}\",\"aud\":\"https://other-service.net\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
            .{ default_iss, cpk_b64 },
        );
        defer allocator.free(payload);

        const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
        defer allocator.free(token);

        const client_data = try support.buildClientData(allocator, client);
        defer allocator.free(client_data);

        const policy: oidc.OidcPolicy = .{
            .now = 1100,
            .keys = &key_set,
        };
        try testing.expectError(error.InvalidClaims, oidc.verifyOidc(allocator, token, client_data, policy, support.limits));
    }

    {
        const payload = try std.fmt.allocPrint(
            allocator,
            "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
            .{ default_iss, default_iss, cpk_b64 },
        );
        defer allocator.free(payload);

        const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
        defer allocator.free(token);

        const client_data = try support.buildClientData(allocator, client);
        defer allocator.free(client_data);

        const policy: oidc.OidcPolicy = .{
            .now = 1100,
            .keys = &key_set,
        };
        try testing.expectError(error.InvalidClaims, oidc.verifyOidc(allocator, token, client_data, policy, support.limits));
    }
}

test "non-numeric XUID returns error.InvalidClaims" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"not-numeric-xuid\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const policy: oidc.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };
    try testing.expectError(error.InvalidClaims, oidc.verifyOidc(allocator, token, client_data, policy, support.limits));
}

test "invalid leguuid structure returns error.InvalidClaims" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\",\"leguuid\":\"not-a-valid-uuid\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const policy: oidc.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };
    try testing.expectError(error.InvalidClaims, oidc.verifyOidc(allocator, token, client_data, policy, support.limits));
}

test "unknown key ID returns error.UnknownKey" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"unknown-kid\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const policy: oidc.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };
    try testing.expectError(error.UnknownKey, oidc.verifyOidc(allocator, token, client_data, policy, support.limits));
}

test "unsupported algorithm returns error.UnsupportedAlgorithm" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const ec_signer = try support.deterministicKey(20);
    const ec_token = try support.signToken(allocator, ec_signer, "{\"alg\":\"ES384\",\"kid\":\"test-rsa-key-1\"}", "{}");
    defer allocator.free(ec_token);

    const policy: oidc.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };
    try testing.expectError(error.UnsupportedAlgorithm, oidc.verifyOidc(allocator, ec_token, client_data, policy, support.limits));
}

test "tampered RSA token signature returns error.InvalidSignature" {
    const allocator = testing.allocator;
    var key_set = try createTestKeySet(allocator);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    var tampered = try allocator.dupe(u8, token);
    defer allocator.free(tampered);
    tampered[tampered.len - 5] ^= 0x01;

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const policy: oidc.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };
    try testing.expectError(error.InvalidSignature, oidc.verifyOidc(allocator, tampered, client_data, policy, support.limits));
}

fn testOidcAllocations(allocator: std.mem.Allocator) !void {
    var key_set = try jwks.KeySet.parse(allocator, support.test_jwks_json, support.limits);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{ default_iss, default_aud, cpk_b64 },
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const policy: oidc.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };

    var id = try oidc.verifyOidc(allocator, token, client_data, policy, support.limits);
    id.deinit();
}

test "oidc verifier handles allocation failures cleanly" {
    try std.testing.checkAllAllocationFailures(testing.allocator, testOidcAllocations, .{});
}
