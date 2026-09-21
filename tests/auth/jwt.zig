const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const jwt = bedwire.auth.jwt;

test "a valid token verifies and enforces its time claims" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(1);
    const other = try support.deterministicKey(2);

    const encoded = try support.signToken(allocator, key, "{\"alg\":\"ES384\"}", "{\"exp\":200,\"nbf\":100}");
    defer allocator.free(encoded);

    var token = try jwt.Token.parse(allocator, encoded, support.limits);
    defer token.deinit();

    try token.verify(key.public_key);
    try testing.expectError(error.InvalidSignature, token.verify(other.public_key));

    try token.validateTime(100, true);
    try testing.expectError(error.ExpiredToken, token.validateTime(200, true));
    try testing.expectError(error.ExpiredToken, token.validateTime(500, true));
    try testing.expectError(error.TokenNotYetValid, token.validateTime(99, true));
}

test "a missing expiry is refused when the policy requires one" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(1);

    const encoded = try support.signToken(allocator, key, "{\"alg\":\"ES384\"}", "{}");
    defer allocator.free(encoded);

    var token = try jwt.Token.parse(allocator, encoded, support.limits);
    defer token.deinit();

    try testing.expectError(error.InvalidClaims, token.validateTime(100, true));
    try token.validateTime(100, false);
}

test "non-integer time claims are refused, not coerced" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(1);

    for ([_][]const u8{ "{\"exp\":\"200\"}", "{\"exp\":200.5}", "{\"exp\":200,\"nbf\":\"1\"}" }) |payload| {
        const encoded = try support.signToken(allocator, key, "{\"alg\":\"ES384\"}", payload);
        defer allocator.free(encoded);

        var token = try jwt.Token.parse(allocator, encoded, support.limits);
        defer token.deinit();

        try testing.expect(std.meta.isError(token.validateTime(100, true)));
    }
}

test "only ES384 is accepted and alg is never taken from the token" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(1);

    const headers = [_][]const u8{
        "{\"alg\":\"none\"}",
        "{\"alg\":\"HS256\"}",
        "{\"alg\":\"ES256\"}",
        "{\"alg\":\"RS256\"}",
        "{\"alg\":\"es384\"}",
        "{}",
        "{\"alg\":384}",
    };

    for (headers) |header| {
        const encoded = try support.signToken(allocator, key, header, "{\"exp\":200}");
        defer allocator.free(encoded);

        const result = jwt.Token.parse(allocator, encoded, support.limits);
        try testing.expect(std.meta.isError(result));
    }
}

test "unexpected critical extensions are refused" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(1);

    for ([_][]const u8{
        "{\"alg\":\"ES384\",\"crit\":[\"exp\"]}",
        "{\"alg\":\"ES384\",\"b64\":false}",
    }) |header| {
        const encoded = try support.signToken(allocator, key, header, "{\"exp\":200}");
        defer allocator.free(encoded);

        try testing.expectError(error.UnsupportedAlgorithm, jwt.Token.parse(allocator, encoded, support.limits));
    }
}

test "malformed compact serializations are refused" {
    const allocator = testing.allocator;

    const cases = [_][]const u8{
        "",
        "a",
        "a.b",
        "a.b.c",
        "a.b.c.d",
        ".",
        "..",
        "e30.e30.short",
    };

    for (cases) |input| {
        try testing.expect(std.meta.isError(jwt.Token.parse(allocator, input, support.limits)));
    }
}

test "no truncation of a valid token is ever accepted" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(1);

    const encoded = try support.signToken(allocator, key, "{\"alg\":\"ES384\"}", "{\"exp\":200}");
    defer allocator.free(encoded);

    for (0..encoded.len) |end| {
        if (jwt.Token.parse(allocator, encoded[0..end], support.limits)) |parsed| {
            var owned = parsed;
            owned.deinit();
            return error.AcceptedTruncation;
        } else |_| {}
    }
}

test "malformed base64 segments are refused" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(1);

    const encoded = try support.signToken(allocator, key, "{\"alg\":\"ES384\"}", "{\"exp\":200}");
    defer allocator.free(encoded);

    const mutated = try allocator.dupe(u8, encoded);
    defer allocator.free(mutated);

    // Characters outside the url-safe alphabet, in each of the three segments.
    for ([_]usize{ 1, 12, encoded.len - 2 }) |index| {
        @memcpy(mutated, encoded);
        mutated[index] = '!';
        try testing.expect(std.meta.isError(jwt.Token.parse(allocator, mutated, support.limits)));
    }
}

test "segment sizes are bounded before anything is decoded" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(1);

    const encoded = try support.signToken(allocator, key, "{\"alg\":\"ES384\"}", "{\"exp\":200}");
    defer allocator.free(encoded);

    var tight = support.limits;
    tight.max_jwt_header_bytes = 4;
    try testing.expectError(error.LimitExceeded, jwt.Token.parse(allocator, encoded, tight));

    tight = support.limits;
    tight.max_jwt_payload_bytes = 4;
    try testing.expectError(error.LimitExceeded, jwt.Token.parse(allocator, encoded, tight));
}

test "JSON parsing bounds bytes and nesting before it allocates" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const tight: bedwire.Limits = .{ .max_jwt_header_bytes = 2, .max_jwt_payload_bytes = 2, .max_json_nesting = 2 };

    try testing.expectError(error.LimitExceeded, jwt.parseJson(failing.allocator(), "{}  ", tight));
    try testing.expectError(error.LimitExceeded, jwt.parseJson(failing.allocator(), "{\"a\":[[[]]]}", .{ .max_json_nesting = 2 }));
    try testing.expect(!failing.has_induced_failure);

    var parsed = try jwt.parseJson(testing.allocator, "{}", tight);
    parsed.deinit();
}

test "a deeply nested payload is refused before the parser recurses" {
    const allocator = testing.allocator;
    const depth = 4096;

    var json: std.ArrayList(u8) = .empty;
    defer json.deinit(allocator);

    try json.appendSlice(allocator, "{\"a\":");
    try json.appendNTimes(allocator, '[', depth);
    try json.appendNTimes(allocator, ']', depth);
    try json.append(allocator, '}');

    try testing.expectError(error.LimitExceeded, jwt.parseJson(allocator, json.items, support.limits));
}

test "invalid, non-object and duplicate-key JSON is refused" {
    const allocator = testing.allocator;

    for ([_][]const u8{
        "[]",
        "1",
        "\"text\"",
        "null",
        "{",
        "}",
        "{\"a\":}",
        "{\"a\":1,\"a\":2}",
        "{\"a\":1}trailing",
    }) |input| {
        try testing.expect(std.meta.isError(jwt.parseJson(allocator, input, support.limits)));
    }
}

test "invalid UTF-8 is refused before parsing" {
    try testing.expectError(error.InvalidUtf8, jwt.parseJson(testing.allocator, "{\"a\":\"\xff\"}", support.limits));
}

test "escaped quotes do not confuse the nesting scan" {
    var parsed = try jwt.parseJson(testing.allocator, "{\"a\":\"{[\\\"\"}", .{ .max_json_nesting = 1 });
    defer parsed.deinit();

    try testing.expectEqualStrings("{[\"", parsed.value.object.get("a").?.string);
}

test "string lookups reject the wrong shape" {
    var parsed = try jwt.parseJson(testing.allocator, "{\"text\":\"value\",\"number\":1}", support.limits);
    defer parsed.deinit();

    try testing.expectEqualStrings("value", try jwt.string(parsed.value, "text"));
    try testing.expectError(error.InvalidClaims, jwt.string(parsed.value, "number"));
    try testing.expectError(error.InvalidClaims, jwt.string(parsed.value, "missing"));
    try testing.expectError(error.InvalidClaims, jwt.string(.{ .integer = 1 }, "text"));
}

test "the pinned Mojang root is canonical P-384 SPKI" {
    const key = bedwire.auth.moj_root.key();
    const der = bedwire.crypto.spki.encode(key);

    try testing.expectEqual(@as(usize, 120), der.len);
    try testing.expectEqual(@as(u8, 4), der[23]);

    const round_trip = try bedwire.crypto.spki.decode(&der);
    try testing.expectEqualSlices(u8, &key.toUncompressedSec1(), &round_trip.toUncompressedSec1());
}

test "SPKI decoding refuses anything but a canonical uncompressed key" {
    const der = bedwire.crypto.spki.encode(bedwire.auth.moj_root.key());

    try testing.expectError(error.InvalidPublicKey, bedwire.crypto.spki.decode(der[0..119]));
    try testing.expectError(error.InvalidPublicKey, bedwire.crypto.spki.decode(&.{}));
    try testing.expectError(error.InvalidPublicKey, bedwire.crypto.spki.fromBase64("short"));

    var mutated = der;
    mutated[0] ^= 0xff;
    try testing.expectError(error.InvalidPublicKey, bedwire.crypto.spki.decode(&mutated));

    mutated = der;
    mutated[23] = 3;
    try testing.expectError(error.InvalidPublicKey, bedwire.crypto.spki.decode(&mutated));
}

test "RS256 token parses and verifies with valid RSA key" {
    const allocator = testing.allocator;

    var token = try jwt.Token.parseWithAlgorithm(allocator, support.rsa_valid_jwt, support.limits, .RS256);
    defer token.deinit();

    try testing.expectEqualStrings("test-rsa-key-1", token.kid().?);
    try token.verifyRsa(support.rsaKey1());
    try testing.expectError(error.InvalidSignature, token.verifyRsa(support.rsaKey2()));

    const ec_key = try support.deterministicKey(1);
    try testing.expectError(error.UnsupportedAlgorithm, token.verifyEcdsa(ec_key.public_key));

    try token.validateTime(1500000000, true);
    try testing.expectError(error.TokenNotYetValid, token.validateTime(500000000, true));
    try testing.expectError(error.ExpiredToken, token.validateTime(2500000000, true));
}

test "RS256 token rejects parse when parsed as ES384" {
    const allocator = testing.allocator;
    try testing.expectError(error.UnsupportedAlgorithm, jwt.Token.parse(allocator, support.rsa_valid_jwt, support.limits));
}

test "ES384 token rejects parse when parsed as RS256 and rejects verifyRsa" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(1);

    const encoded = try support.signToken(allocator, key, "{\"alg\":\"ES384\"}", "{\"exp\":200}");
    defer allocator.free(encoded);

    try testing.expectError(error.UnsupportedAlgorithm, jwt.Token.parseWithAlgorithm(allocator, encoded, support.limits, .RS256));

    var token = try jwt.Token.parse(allocator, encoded, support.limits);
    defer token.deinit();
    try testing.expectError(error.UnsupportedAlgorithm, token.verifyRsa(support.rsaKey1()));
}

