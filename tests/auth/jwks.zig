const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const KeySet = bedwire.auth.KeySet;

test "keys are found by kid and verify only their own tokens" {
    var set = try KeySet.parse(testing.allocator, support.test_jwks_json, support.limits);
    defer set.deinit();
    try testing.expectEqual(@as(usize, 2), set.entries().len);

    var token = try bedwire.auth.jwt.Token.parseWithAlgorithm(testing.allocator, support.rsa_valid_jwt, support.limits, .RS256);
    defer token.deinit();
    try token.verifyRsa(try set.find(support.rsa_key1_kid));
    try testing.expectError(error.InvalidSignature, token.verifyRsa(try set.find(support.rsa_key2_kid)));
    try testing.expectError(error.UnknownKey, set.find("non-existent-kid"));
}

test "a kid shared by two keys is ambiguous" {
    const duplicated = "{\"keys\": [" ++
        "{\"kty\": \"RSA\", \"use\": \"sig\", \"kid\": \"dup-kid\", \"n\": \"" ++ support.rsa_key1_n_b64 ++ "\", \"e\": \"AQAB\"}," ++
        "{\"kty\": \"RSA\", \"use\": \"sig\", \"kid\": \"dup-kid\", \"n\": \"" ++ support.rsa_key2_n_b64 ++ "\", \"e\": \"AQAB\"}" ++
        "]}";
    var set = try KeySet.parse(testing.allocator, duplicated, support.limits);
    defer set.deinit();
    try testing.expectError(error.AmbiguousKey, set.find("dup-kid"));
}

test "oversized, empty and malformed catalogs are refused" {
    var tight_bytes = support.limits;
    tight_bytes.max_jwks_bytes = 64;
    var tight_keys = support.limits;
    tight_keys.max_jwks_keys = 1;

    const Case = struct { json: []const u8, limits: bedwire.Limits = support.limits, expected: anyerror };
    const cases = [_]Case{
        .{ .json = support.test_jwks_json, .limits = tight_bytes, .expected = error.LimitExceeded },
        .{ .json = support.test_jwks_json, .limits = tight_keys, .expected = error.LimitExceeded },
        .{ .json = "{\"keys\": []}", .expected = error.EmptyKeySet },
        .{ .json = "{\"keys\": [{\"kty\": \"EC\", \"kid\": \"ec-1\", \"crv\": \"P-384\"}]}", .expected = error.EmptyKeySet },
        .{ .json = "{\"keys\": [{\"kty\": \"RSA\", \"kid\": \"short-n\", \"n\": \"AQAB\", \"e\": \"AQAB\"}]}", .expected = error.EmptyKeySet },
        .{ .json = "{\"keys\": [{\"kty\": \"RSA\", \"kid\": \"even-e\", \"n\": \"" ++ support.rsa_key1_n_b64 ++ "\", \"e\": \"AQAC\"}]}", .expected = error.InvalidJwks },
    };
    for (cases) |case| try testing.expectError(case.expected, KeySet.parse(testing.allocator, case.json, case.limits));
}

fn parseCatalog(allocator: std.mem.Allocator) !void {
    var set = try KeySet.parse(allocator, support.test_jwks_json, support.limits);
    set.deinit();
}

test "KeySet.parse cleans up under every allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, parseCatalog, .{});
}

test "keys of a shape that can't be held are skipped, not fatal" {
    const wide: [512]u8 = @splat('A');
    const long_kid: [65]u8 = @splat('k');
    const catalog = "{\"keys\": [" ++
        "{\"kty\": \"RSA\", \"use\": \"sig\", \"kid\": \"wide\", \"n\": \"" ++ wide ++ "\", \"e\": \"AQAB\"}," ++
        "{\"kty\": \"RSA\", \"use\": \"sig\", \"kid\": \"" ++ long_kid ++ "\", \"n\": \"" ++ support.rsa_key2_n_b64 ++ "\", \"e\": \"AQAB\"}," ++
        "{\"kty\": \"RSA\", \"use\": \"sig\", \"kid\": \"big-e\", \"n\": \"" ++ support.rsa_key2_n_b64 ++ "\", \"e\": \"AQABAQAB\"}," ++
        "{\"kty\": \"RSA\", \"use\": \"sig\", \"kid\": \"" ++ support.rsa_key1_kid ++ "\", \"n\": \"" ++ support.rsa_key1_n_b64 ++ "\", \"e\": \"AQAB\"}" ++
        "]}";
    var set = try KeySet.parse(testing.allocator, catalog, support.limits);
    defer set.deinit();
    try testing.expectEqual(@as(usize, 1), set.entries().len);
    _ = try set.find(support.rsa_key1_kid);

    const only_wide = "{\"keys\": [{\"kty\": \"RSA\", \"kid\": \"wide\", \"n\": \"" ++ wide ++ "\", \"e\": \"AQAB\"}]}";
    try testing.expectError(error.EmptyKeySet, KeySet.parse(testing.allocator, only_wide, support.limits));
}
