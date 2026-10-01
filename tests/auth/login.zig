const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;

fn buildRequest(comptime Profile: type, allocator: std.mem.Allocator, format: bedwire.auth.ConnectionRequestFormat, limits: bedwire.Limits) ![]u8 {
    const proxy_key = try support.deterministicKey(9);
    const original_key = try support.deterministicKey(1);
    var identity = try bedwire.auth.identity.validateAndCreate(allocator, .{
        .display_name = "Steve",
        .uuid = support.chain_uuid,
        .xuid = "1234",
        .key = original_key.public_key,
        .online = true,
    }, limits);
    defer identity.deinit();
    return bedwire.auth.login.buildProxyConnectionRequest(Profile, allocator, proxy_key, &identity, "{\"SkinId\":\"demo\"}", 200, format, limits);
}

test "proxy-issued Login round trips through the selected profile and trusted backend" {
    const allocator = testing.allocator;
    const proxy_key = try support.deterministicKey(9);
    const wrong_key = try support.deterministicKey(8);
    const request = try buildRequest(support.modern, allocator, .envelope, support.limits);
    defer allocator.free(request);

    var storage: [support.limits.max_packet_bytes]u8 = undefined;
    const packet = try bedwire.auth.login.encodeLoginPacket(support.modern, &storage, request, support.limits);
    const decoded = try support.modern.decodeBorrowed(packet, .{});
    try testing.expectEqual(bedwire.PacketKind.login, decoded.kind.?);
    try testing.expectEqual(@as(i32, @intCast(support.modern.protocol_number)), decoded.value.typed.login.client_network_version);
    const parsed_request = try bedwire.auth.decodeConnectionRequest(decoded.value.typed.login.connection_request, support.limits);
    var envelope = try bedwire.auth.parseChainEnvelope(allocator, parsed_request.chain_data, support.limits);
    defer envelope.deinit();
    try testing.expectEqual(@as(u8, 2), envelope.authentication_type);

    var pair = try support.Pair.init(allocator, support.modern);
    defer pair.deinit();
    pair.server.state = .authenticating;
    pair.server.received.insert(.login);
    var verified = try pair.server.authenticateLogin(allocator, decoded.value.typed.login.connection_request, .{ .certificate_chain = .{
        .now = 100,
        .trusted_issuer_key = proxy_key.public_key,
    } });
    defer verified.deinit();
    try testing.expectEqualStrings("Steve", verified.display_name);
    try testing.expectEqualStrings(support.chain_uuid, verified.uuid);
    try testing.expectEqualStrings("", verified.xuid);
    try testing.expect(!verified.online);
    try testing.expectEqualSlices(u8, &proxy_key.public_key.toUncompressedSec1(), &verified.public_key.toUncompressedSec1());

    try testing.expectError(error.UntrustedChain, bedwire.auth.verifyChain(allocator, envelope.certificate.?, parsed_request.client_data, .{ .now = 100 }, support.limits));
    try testing.expectError(error.UntrustedChain, bedwire.auth.verifyChain(allocator, envelope.certificate.?, parsed_request.client_data, .{
        .now = 100,
        .trusted_issuer_key = wrong_key.public_key,
    }, support.limits));

    const tampered = try allocator.dupe(u8, parsed_request.client_data);
    defer allocator.free(tampered);
    const signature = std.mem.lastIndexOfScalar(u8, tampered, '.').? + 1;
    tampered[signature] = if (tampered[signature] == 'A') 'B' else 'A';
    try testing.expectError(error.InvalidSignature, bedwire.auth.verifyChain(allocator, envelope.certificate.?, tampered, .{
        .now = 100,
        .trusted_issuer_key = proxy_key.public_key,
    }, support.limits));

    const mislabeled = try allocator.dupe(u8, request);
    defer allocator.free(mislabeled);
    const auth_type = std.mem.indexOf(u8, mislabeled, "AuthenticationType\":2").? + "AuthenticationType\":".len;
    mislabeled[auth_type] = '0';
    var other = try support.Pair.init(allocator, support.modern);
    defer other.deinit();
    other.server.state = .authenticating;
    other.server.received.insert(.login);
    try testing.expectError(error.InvalidClaims, other.server.authenticateLogin(allocator, mislabeled, .{ .certificate_chain = .{
        .now = 100,
        .trusted_issuer_key = proxy_key.public_key,
    } }));
}

test "legacy profile uses a direct chain and OIDC cannot issue proxy credentials" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(9);
    const request = try buildRequest(support.legacy, allocator, .legacy_chain, support.limits);
    defer allocator.free(request);
    var storage: [support.limits.max_packet_bytes]u8 = undefined;
    const packet = try bedwire.auth.login.encodeLoginPacket(support.legacy, &storage, request, support.limits);
    const decoded = try support.legacy.decodeBorrowed(packet, .{});
    try testing.expectEqual(@as(i32, @intCast(support.legacy.protocol_number)), decoded.value.typed.login.client_network_version);
    const parsed = try bedwire.auth.decodeConnectionRequest(decoded.value.typed.login.connection_request, support.limits);
    var identity = try bedwire.auth.verifyChain(allocator, parsed.chain_data, parsed.client_data, .{
        .now = 100,
        .trusted_issuer_key = key.public_key,
    }, support.limits);
    defer identity.deinit();
    try testing.expectEqualStrings("Steve", identity.display_name);
    try testing.expectError(error.UnsupportedProtocol, buildRequest(support.modern_oidc, allocator, .envelope, support.limits));
}

fn buildAndFree(allocator: std.mem.Allocator) !void {
    const request = try buildRequest(support.modern, allocator, .envelope, support.limits);
    allocator.free(request);
}

test "proxy Login construction enforces limits and cleans up allocation failures" {
    const allocator = testing.allocator;
    var tight = support.limits;
    tight.max_identity_bytes = 3;
    try testing.expectError(error.InvalidClaims, buildRequest(support.modern, allocator, .envelope, tight));
    tight = support.limits;
    tight.max_connection_request_bytes = 32;
    try testing.expectError(error.LimitExceeded, buildRequest(support.modern, allocator, .envelope, tight));
    tight = support.limits;
    tight.max_jwt_payload_bytes = 32;
    try testing.expectError(error.LimitExceeded, buildRequest(support.modern, allocator, .envelope, tight));

    const key = try support.deterministicKey(9);
    var identity = try bedwire.auth.identity.validateAndCreate(allocator, .{
        .display_name = "Steve",
        .uuid = support.chain_uuid,
        .xuid = "",
        .key = key.public_key,
        .online = false,
    }, support.limits);
    defer identity.deinit();
    try testing.expectError(error.InvalidJson, bedwire.auth.login.buildProxyConnectionRequest(support.modern, allocator, key, &identity, "{", 200, .envelope, support.limits));

    const request = try buildRequest(support.modern, allocator, .envelope, support.limits);
    defer allocator.free(request);
    tight = support.limits;
    tight.max_packet_bytes = 8;
    var storage: [128]u8 = undefined;
    try testing.expect(std.meta.isError(bedwire.auth.login.encodeLoginPacket(support.modern, &storage, request, tight)));
    try testing.checkAllAllocationFailures(allocator, buildAndFree, .{});
}
