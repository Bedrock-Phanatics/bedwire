const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const auth = bedwire.auth;

const Keys = [3]support.Ecdsa.KeyPair;

fn keys() !Keys {
    return .{
        try support.deterministicKey(1),
        try support.deterministicKey(2),
        try support.deterministicKey(3),
    };
}

fn verifyCase(allocator: std.mem.Allocator, chain: []const u8, client_data: []const u8, root: support.Ecdsa.PublicKey) !void {
    var identity = try auth.verifyChain(allocator, chain, client_data, .{ .now = 100, .root = root }, support.limits);
    defer identity.deinit();

    try testing.expectEqualStrings("Steve", identity.display_name);
    try testing.expectEqualStrings(support.chain_uuid, identity.uuid);
    try testing.expectEqualStrings("1234", identity.xuid);
    try testing.expect(identity.online);
}

test "a valid Mojang chain anchors its root and binds the client data" {
    const allocator = testing.allocator;
    const k = try keys();

    const chain = try support.buildChain(allocator, k);
    defer allocator.free(chain);

    const client_data = try support.buildClientData(allocator, k[0]);
    defer allocator.free(client_data);

    try verifyCase(allocator, chain, client_data, k[1].public_key);
    try testing.checkAllAllocationFailures(allocator, verifyCase, .{ chain, client_data, k[1].public_key });
}

test "an untrusted root is refused" {
    const allocator = testing.allocator;
    const k = try keys();

    const chain = try support.buildChain(allocator, k);
    defer allocator.free(chain);

    const client_data = try support.buildClientData(allocator, k[0]);
    defer allocator.free(client_data);

    // The pinned Mojang root does not sign this chain.
    try testing.expectError(error.UntrustedChain, auth.verifyChain(allocator, chain, client_data, .{ .now = 100 }, support.limits));

    const wrong = try support.deterministicKey(9);
    try testing.expectError(error.UntrustedChain, auth.verifyChain(allocator, chain, client_data, .{ .now = 100, .root = wrong.public_key }, support.limits));
}

test "expired and not-yet-valid chains are refused" {
    const allocator = testing.allocator;
    const k = try keys();

    const chain = try support.buildChain(allocator, k);
    defer allocator.free(chain);

    const client_data = try support.buildClientData(allocator, k[0]);
    defer allocator.free(client_data);

    const policy: auth.ChainPolicy = .{ .now = 201, .root = k[1].public_key };
    try testing.expectError(error.ExpiredToken, auth.verifyChain(allocator, chain, client_data, policy, support.limits));
}

test "client data signed by another key is refused" {
    const allocator = testing.allocator;
    const k = try keys();

    const chain = try support.buildChain(allocator, k);
    defer allocator.free(chain);

    const forged = try support.buildClientData(allocator, k[2]);
    defer allocator.free(forged);

    try testing.expectError(
        error.InvalidSignature,
        auth.verifyChain(allocator, chain, forged, .{ .now = 100, .root = k[1].public_key }, support.limits),
    );
}

test "a tampered chain link is refused" {
    const allocator = testing.allocator;
    const k = try keys();

    const chain = try support.buildChain(allocator, k);
    defer allocator.free(chain);

    const client_data = try support.buildClientData(allocator, k[0]);
    defer allocator.free(client_data);

    const mutated = try allocator.dupe(u8, chain);
    defer allocator.free(mutated);

    // Flip a byte inside the first link's payload segment.
    const start = (std.mem.indexOf(u8, mutated, ".").? + 1);
    mutated[start + 4] = if (mutated[start + 4] == 'A') 'B' else 'A';

    try testing.expect(std.meta.isError(auth.verifyChain(allocator, mutated, client_data, .{ .now = 100, .root = k[1].public_key }, support.limits)));
}

test "chain shape is enforced: length, types and CA flags" {
    const allocator = testing.allocator;
    const k = try keys();

    const client_data = try support.buildClientData(allocator, k[0]);
    defer allocator.free(client_data);

    const cases = [_][]const u8{
        "{}",
        "{\"chain\":{}}",
        "{\"chain\":[]}",
        "{\"chain\":[1,2,3]}",
        "{\"chain\":[\"a\",\"b\"]}",
        "{\"chain\":[\"a\",\"b\",\"c\",\"d\"]}",
    };

    for (cases) |chain| {
        const result = auth.verifyChain(allocator, chain, client_data, .{ .now = 100, .root = k[1].public_key }, support.limits);
        try testing.expect(std.meta.isError(result));
    }
}

test "the chain length limit is enforced before any signature work" {
    const allocator = testing.allocator;

    var json: std.ArrayList(u8) = .empty;
    defer json.deinit(allocator);

    try json.appendSlice(allocator, "{\"chain\":[");
    for (0..64) |i| {
        if (i != 0) try json.append(allocator, ',');
        try json.appendSlice(allocator, "\"x\"");
    }
    try json.appendSlice(allocator, "]}");

    var tight = support.limits;
    tight.max_chain_length = 8;

    try testing.expectError(error.LimitExceeded, auth.verifyChain(allocator, json.items, "", .{ .now = 100 }, tight));
}

test "an oversized chain blob is refused before parsing" {
    const allocator = testing.allocator;

    var tight = support.limits;
    tight.max_jwt_payload_bytes = 16;

    try testing.expectError(error.LimitExceeded, auth.verifyChain(allocator, "{\"chain\":[\"aaaaaaaaaaaaaaaa\"]}", "", .{ .now = 100 }, tight));
}

test "offline chains need explicit policy and carry no XUID" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(8);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"exp\":200,\"identityPublicKey\":\"{s}\",\"extraData\":{{\"displayName\":\"Offline\",\"identity\":\"" ++
            support.chain_uuid ++ "\",\"XUID\":\"spoofed\"}}}}",
        .{support.encodedKey(key.public_key)},
    );
    defer allocator.free(payload);

    const link = try support.signWithKeyHeader(allocator, key, payload);
    defer allocator.free(link);

    const chain = try std.fmt.allocPrint(allocator, "{{\"chain\":[\"{s}\"]}}", .{link});
    defer allocator.free(chain);

    const client_data = try support.buildClientData(allocator, key);
    defer allocator.free(client_data);

    try testing.expectError(error.UntrustedChain, auth.verifyChain(allocator, chain, client_data, .{ .now = 100 }, support.limits));

    var identity = try auth.verifyChain(allocator, chain, client_data, .{ .now = 100, .allow_offline = true }, support.limits);
    defer identity.deinit();

    try testing.expect(!identity.online);
    try testing.expectEqualStrings("", identity.xuid);
    try testing.expectEqualStrings("Offline", identity.display_name);
}

test "identity claims are validated, not trusted" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(8);

    const bad_claims = [_][]const u8{
        "\"displayName\":\"\",\"identity\":\"" ++ support.chain_uuid ++ "\"",
        "\"displayName\":\"Steve\",\"identity\":\"not-a-uuid\"",
        "\"displayName\":\"Steve\",\"identity\":\"b1b01c3d6df33635b2869a2cfbcf76be\"",
        "\"displayName\":\"Steve\",\"identity\":\"b1b01c3dX6df3-3635-b286-9a2cfbcf76be\"",
        "\"displayName\":\"Steve\",\"identity\":\"g1b01c3d-6df3-3635-b286-9a2cfbcf76be\"",
        "\"identity\":\"" ++ support.chain_uuid ++ "\"",
        "\"displayName\":\"Steve\"",
    };

    for (bad_claims) |claims| {
        const payload = try std.fmt.allocPrint(
            allocator,
            "{{\"exp\":200,\"identityPublicKey\":\"{s}\",\"extraData\":{{{s}}}}}",
            .{ support.encodedKey(key.public_key), claims },
        );
        defer allocator.free(payload);

        const link = try support.signWithKeyHeader(allocator, key, payload);
        defer allocator.free(link);

        const chain = try std.fmt.allocPrint(allocator, "{{\"chain\":[\"{s}\"]}}", .{link});
        defer allocator.free(chain);

        const client_data = try support.buildClientData(allocator, key);
        defer allocator.free(client_data);

        try testing.expectError(error.InvalidClaims, auth.verifyChain(allocator, chain, client_data, .{ .now = 100, .allow_offline = true }, support.limits));
    }
}

test "a long display name is refused by the identity limit" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(8);

    const name = [_]u8{'n'} ** 64;
    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"exp\":200,\"identityPublicKey\":\"{s}\",\"extraData\":{{\"displayName\":\"{s}\",\"identity\":\"" ++
            support.chain_uuid ++ "\"}}}}",
        .{ support.encodedKey(key.public_key), name },
    );
    defer allocator.free(payload);

    const link = try support.signWithKeyHeader(allocator, key, payload);
    defer allocator.free(link);

    const chain = try std.fmt.allocPrint(allocator, "{{\"chain\":[\"{s}\"]}}", .{link});
    defer allocator.free(chain);

    const client_data = try support.buildClientData(allocator, key);
    defer allocator.free(client_data);

    var tight = support.limits;
    tight.max_identity_bytes = 16;

    try testing.expectError(error.InvalidClaims, auth.verifyChain(allocator, chain, client_data, .{ .now = 100, .allow_offline = true }, tight));
}
