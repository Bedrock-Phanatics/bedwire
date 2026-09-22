const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const jwks = bedwire.auth.jwks;

test "parses valid Microsoft-style JWKS catalog and finds keys by kid" {
    const allocator = testing.allocator;

    var set = try jwks.KeySet.parse(allocator, support.test_jwks_json, support.limits);
    defer set.deinit();

    try testing.expectEqual(@as(usize, 2), set.entries().len);

    const k1 = try set.find(support.rsa_key1_kid);
    const k2 = try set.find(support.rsa_key2_kid);

    // Verify key 1 can verify valid token
    var token = try bedwire.auth.jwt.Token.parseWithAlgorithm(allocator, support.rsa_valid_jwt, support.limits, .RS256);
    defer token.deinit();
    try token.verifyRsa(k1);
    try testing.expectError(error.InvalidSignature, token.verifyRsa(k2));

    try testing.expectError(error.UnknownKey, set.find("non-existent-kid"));
}

test "duplicate kid in JWKS returns error.AmbiguousKey" {
    const allocator = testing.allocator;

    const dup_jwks = "{\"keys\": [" ++
        "{\"kty\": \"RSA\", \"use\": \"sig\", \"kid\": \"dup-kid\", \"n\": \"" ++ support.rsa_key1_n_b64 ++ "\", \"e\": \"AQAB\"}," ++
        "{\"kty\": \"RSA\", \"use\": \"sig\", \"kid\": \"dup-kid\", \"n\": \"" ++ support.rsa_key2_n_b64 ++ "\", \"e\": \"AQAB\"}" ++
        "]}";

    var set = try jwks.KeySet.parse(allocator, dup_jwks, support.limits);
    defer set.deinit();

    try testing.expectError(error.AmbiguousKey, set.find("dup-kid"));
}

test "exceeding max_jwks_bytes returns LimitExceeded" {
    const allocator = testing.allocator;
    var tight_limits = support.limits;
    tight_limits.max_jwks_bytes = 64;

    try testing.expectError(error.LimitExceeded, jwks.KeySet.parse(allocator, support.test_jwks_json, tight_limits));
}

test "exceeding max_jwks_keys returns LimitExceeded" {
    const allocator = testing.allocator;
    var tight_limits = support.limits;
    tight_limits.max_jwks_keys = 1;

    try testing.expectError(error.LimitExceeded, jwks.KeySet.parse(allocator, support.test_jwks_json, tight_limits));
}

test "empty keys array returns EmptyKeySet" {
    const allocator = testing.allocator;
    try testing.expectError(error.EmptyKeySet, jwks.KeySet.parse(allocator, "{\"keys\": []}", support.limits));
}

test "non-RSA or invalid key elements return InvalidJwks" {
    const allocator = testing.allocator;

    // kty is not RSA
    const non_rsa = "{\"keys\": [{\"kty\": \"EC\", \"kid\": \"ec-1\", \"crv\": \"P-384\"}]}";
    try testing.expectError(error.EmptyKeySet, jwks.KeySet.parse(allocator, non_rsa, support.limits));

    // modulus too short (not 256 bytes)
    const bad_n = "{\"keys\": [{\"kty\": \"RSA\", \"kid\": \"short-n\", \"n\": \"AQAB\", \"e\": \"AQAB\"}]}";
    try testing.expectError(error.InvalidJwks, jwks.KeySet.parse(allocator, bad_n, support.limits));

    // exponent even (invalid RSA exponent)
    const bad_e = "{\"keys\": [{\"kty\": \"RSA\", \"kid\": \"even-e\", \"n\": \"" ++ support.rsa_key1_n_b64 ++ "\", \"e\": \"AQAC\"}]}";
    try testing.expectError(error.InvalidJwks, jwks.KeySet.parse(allocator, bad_e, support.limits));
}

fn testKeySetParseAllocations(allocator: std.mem.Allocator) !void {
    var set = try jwks.KeySet.parse(allocator, support.test_jwks_json, support.limits);
    defer set.deinit();
    try testing.expectEqual(@as(usize, 2), set.entries().len);
}

test "KeySet.parse cleans up cleanly under all allocation failure points" {
    try std.testing.checkAllAllocationFailures(testing.allocator, testKeySetParseAllocations, .{});
}
