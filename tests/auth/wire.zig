const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const wire = bedwire.auth.wire;

test "a connection request must be consumed exactly" {
    const request = try support.buildConnectionRequest(testing.allocator, "{\"chain\":[\"jwt0\",\"jwt1\"]}", "header.payload.sig");
    defer testing.allocator.free(request);

    const decoded = try wire.decodeConnectionRequest(request, .{});
    try testing.expectEqualStrings("{\"chain\":[\"jwt0\",\"jwt1\"]}", decoded.chain_data);
    try testing.expectEqualStrings("header.payload.sig", decoded.client_data);

    const trailing = try std.mem.concat(testing.allocator, u8, &.{ request, &.{0xff} });
    defer testing.allocator.free(trailing);
    try testing.expectError(error.MalformedConnectionRequest, wire.decodeConnectionRequest(trailing, .{}));
    try testing.expectError(error.LimitExceeded, wire.decodeConnectionRequest(request, .{ .max_connection_request_bytes = 10 }));
}

test "negative, zero and truncated lengths are refused" {
    const lengths = [_][2]i32{ .{ -1, 10 }, .{ 0, 10 }, .{ 100, 0 } };
    for (lengths) |pair| {
        var bytes: [10]u8 = @splat(0);
        std.mem.writeInt(i32, bytes[0..4], pair[0], .little);
        std.mem.writeInt(i32, bytes[4..8], pair[1], .little);
        try testing.expectError(error.MalformedConnectionRequest, wire.decodeConnectionRequest(&bytes, .{}));
    }
}

test "the envelope parser tells legacy chains from modern envelopes" {
    var legacy = try wire.parseChainEnvelope(testing.allocator, "{\"chain\":[\"token1\",\"token2\"]}", .{});
    defer legacy.deinit();
    try testing.expect(legacy.is_legacy_chain);
    try testing.expect(legacy.token == null and legacy.certificate == null);

    var modern = try wire.parseChainEnvelope(testing.allocator, "{\"AuthenticationType\":0,\"Certificate\":\"{\\\"chain\\\":[\\\"cert\\\"]}\",\"Token\":\"oidc_jwt\"}", .{});
    defer modern.deinit();
    try testing.expect(!modern.is_legacy_chain);
    try testing.expectEqual(@as(u8, 0), modern.authentication_type);
    try testing.expectEqualStrings("oidc_jwt", modern.token.?);
    try testing.expectEqualStrings("{\"chain\":[\"cert\"]}", modern.certificate.?);

    var offline = try wire.parseChainEnvelope(testing.allocator, "{\"AuthenticationType\":2,\"Token\":\"self_token\"}", .{});
    defer offline.deinit();
    try testing.expectEqual(@as(u8, 2), offline.authentication_type);
    try testing.expectEqualStrings("self_token", offline.token.?);
}

fn parseEnvelope(allocator: std.mem.Allocator) !void {
    var envelope = try wire.parseChainEnvelope(allocator, "{\"AuthenticationType\":0,\"Token\":\"oidc_jwt\"}", .{});
    envelope.deinit();
}

test "parseChainEnvelope cleans up under every allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, parseEnvelope, .{});
}
