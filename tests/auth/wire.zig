const std = @import("std");
const bedwire = @import("bedwire");
const testing = std.testing;

test "wire decoder unpacks valid binary connection_request with exact consumption" {
    const chain_data = "{\"chain\":[\"jwt0\",\"jwt1\"]}";
    const client_data = "header.payload.sig";

    var buf: [256]u8 = undefined;
    std.mem.writeInt(i32, buf[0..4], @intCast(chain_data.len), .little);
    @memcpy(buf[4 .. 4 + chain_data.len], chain_data);
    const raw_offset = 4 + chain_data.len;
    std.mem.writeInt(i32, buf[raw_offset .. raw_offset + 4], @intCast(client_data.len), .little);
    @memcpy(buf[raw_offset + 4 .. raw_offset + 4 + client_data.len], client_data);

    const wire_len = raw_offset + 4 + client_data.len;
    const req = try bedwire.auth.wire.decodeConnectionRequest(buf[0..wire_len], .{});
    try testing.expectEqualStrings(chain_data, req.chain_data);
    try testing.expectEqualStrings(client_data, req.client_data);
}

test "wire decoder rejects trailing unread bytes (exact consumption invariant)" {
    const chain_data = "{\"chain\":[\"a\"]}";
    const client_data = "raw";

    var buf: [128]u8 = undefined;
    std.mem.writeInt(i32, buf[0..4], @intCast(chain_data.len), .little);
    @memcpy(buf[4 .. 4 + chain_data.len], chain_data);
    const raw_offset = 4 + chain_data.len;
    std.mem.writeInt(i32, buf[raw_offset .. raw_offset + 4], @intCast(client_data.len), .little);
    @memcpy(buf[raw_offset + 4 .. raw_offset + 4 + client_data.len], client_data);

    const wire_len = raw_offset + 4 + client_data.len;
    buf[wire_len] = 0xff;

    try testing.expectError(
        error.MalformedConnectionRequest,
        bedwire.auth.wire.decodeConnectionRequest(buf[0 .. wire_len + 1], .{}),
    );
}

test "wire decoder rejects negative, zero, and truncated lengths" {
    var bad_neg: [8]u8 = undefined;
    std.mem.writeInt(i32, bad_neg[0..4], -1, .little);
    std.mem.writeInt(i32, bad_neg[4..8], 10, .little);
    try testing.expectError(error.MalformedConnectionRequest, bedwire.auth.wire.decodeConnectionRequest(&bad_neg, .{}));

    var bad_zero: [8]u8 = undefined;
    std.mem.writeInt(i32, bad_zero[0..4], 0, .little);
    std.mem.writeInt(i32, bad_zero[4..8], 10, .little);
    try testing.expectError(error.MalformedConnectionRequest, bedwire.auth.wire.decodeConnectionRequest(&bad_zero, .{}));

    var bad_trunc: [10]u8 = undefined;
    std.mem.writeInt(i32, bad_trunc[0..4], 100, .little); // Claims 100 bytes, buffer only has 10
    try testing.expectError(error.MalformedConnectionRequest, bedwire.auth.wire.decodeConnectionRequest(&bad_trunc, .{}));
}

test "wire decoder rejects oversized request exceeding limits" {
    var buf: [16]u8 = undefined;
    std.mem.writeInt(i32, buf[0..4], 4, .little);
    @memcpy(buf[4..8], "1234");
    std.mem.writeInt(i32, buf[8..12], 4, .little);
    @memcpy(buf[12..16], "5678");

    const limits = bedwire.Limits{ .max_connection_request_bytes = 10 };
    try testing.expectError(error.LimitExceeded, bedwire.auth.wire.decodeConnectionRequest(&buf, limits));
}

test "envelope parser distinguishes legacy and modern envelope without dangling memory" {
    const legacy_json = "{\"chain\":[\"token1\",\"token2\"]}";
    const envelope_json = "{\"AuthenticationType\":0,\"Certificate\":\"{\\\"chain\\\":[\\\"cert\\\"]}\",\"Token\":\"oidc_jwt\"}";

    var legacy_env = try bedwire.auth.wire.parseChainEnvelope(testing.allocator, legacy_json, .{});
    defer legacy_env.deinit(testing.allocator);
    try testing.expect(legacy_env.is_legacy_chain);
    try testing.expectEqual(@as(u8, 0), legacy_env.authentication_type);
    try testing.expect(legacy_env.token == null);
    try testing.expect(legacy_env.certificate == null);

    var modern_env = try bedwire.auth.wire.parseChainEnvelope(testing.allocator, envelope_json, .{});
    defer modern_env.deinit(testing.allocator);
    try testing.expect(!modern_env.is_legacy_chain);
    try testing.expectEqual(@as(u8, 0), modern_env.authentication_type);
    try testing.expectEqualStrings("oidc_jwt", modern_env.token.?);
    try testing.expectEqualStrings("{\"chain\":[\"cert\"]}", modern_env.certificate.?);
}

test "envelope parser handles offline AuthenticationType 2 and guest AuthenticationType 1" {
    const offline_json = "{\"AuthenticationType\":2,\"Certificate\":\"{\\\"chain\\\":[\\\"\\\"]}\",\"Token\":\"self_token\"}";
    var offline_env = try bedwire.auth.wire.parseChainEnvelope(testing.allocator, offline_json, .{});
    defer offline_env.deinit(testing.allocator);
    try testing.expectEqual(@as(u8, 2), offline_env.authentication_type);
    try testing.expectEqualStrings("self_token", offline_env.token.?);

    const guest_json = "{\"AuthenticationType\":1}";
    var guest_env = try bedwire.auth.wire.parseChainEnvelope(testing.allocator, guest_json, .{});
    defer guest_env.deinit(testing.allocator);
    try testing.expectEqual(@as(u8, 1), guest_env.authentication_type);
}

fn testParseChainEnvelopeAllocations(allocator: std.mem.Allocator) !void {
    const envelope_json = "{\"AuthenticationType\":0,\"Certificate\":\"{\\\"chain\\\":[\\\"cert\\\"]}\",\"Token\":\"oidc_jwt\"}";
    var env = try bedwire.auth.wire.parseChainEnvelope(allocator, envelope_json, .{});
    defer env.deinit(allocator);
    try testing.expectEqualStrings("oidc_jwt", env.token.?);
}

test "parseChainEnvelope cleans up cleanly under all allocation failure points" {
    try std.testing.checkAllAllocationFailures(testing.allocator, testParseChainEnvelopeAllocations, .{});
}
