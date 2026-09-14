const std = @import("std");
const bedwire = @import("bedwire");

const Mock = struct {
    input: []const u8 = &.{ 0xfe, 6, 0xc1, 1, 0, 0, 0, 1 },
    output: [4096]u8 = undefined,
    len: usize = 0,
    closed: bool = false,
    pub fn receive(self: *@This()) ![]const u8 {
        return self.input;
    }
    pub fn send(self: *@This(), bytes: []const u8) !void {
        @memcpy(self.output[0..bytes.len], bytes);
        self.len = bytes.len;
    }
    pub fn close(self: *@This()) void {
        self.closed = true;
    }
};
const limits: bedwire.DecodeLimits = .{ .protocol = .{ .max_batch_bytes = 4096, .max_decompressed_batch_bytes = 4096 } };

test "resource negotiation accepts client cache status and rejects malformed payloads" {
    for ([_][]const u8{ &.{ 0xfe, 3, 0x81, 1, 0 }, &.{ 0xfe, 3, 0x81, 1, 1 }, &.{ 0xfe, 3, 0x81, 1, 2 }, &.{ 0xfe, 2, 0x81, 1 }, &.{ 0xfe, 4, 0x81, 1, 1, 0 } }, 0..) |frame, i| {
        var mock: Mock = .{ .input = frame };
        var conn = try bedwire.Connection(Mock).init(std.testing.allocator, &mock, .server, limits);
        defer conn.deinit();
        conn.state = .resource_packs;
        if (i < 2) {
            var packets = try conn.receive();
            try std.testing.expectEqualSlices(u8, frame[2..], (try packets.next()).?);
        } else {
            const expected = switch (i) {
                2 => error.InvalidBoolean,
                3 => error.EndOfStream,
                else => error.TrailingData,
            };
            try std.testing.expectError(expected, conn.receive());
            try std.testing.expectEqual(.disconnected, conn.state);
        }
    }
    try std.testing.expect(!bedwire.session.State.resource_packs.permits(.server, 129));
    try std.testing.expect(!bedwire.session.State.authenticating.permits(.client, 129));
}

test "client accepts signed padded and unpadded handshake salts and rejects malformed salts" {
    const a = std.testing.allocator;
    const server_key = try bedwire.spki.Ecdsa.KeyPair.generateDeterministic(@splat(4));
    const client_key = try bedwire.spki.Ecdsa.KeyPair.generateDeterministic(@splat(5));
    const header = try std.fmt.allocPrint(a, "{{\"alg\":\"ES384\",\"x5u\":\"{s}\"}}", .{@import("../auth/jwt.zig").public(server_key.public_key)});
    defer a.free(header);
    for ([_][]const u8{ "CQkJCQkJCQkJCQkJCQkJCQ", "CQkJCQkJCQkJCQkJCQkJCQ==", "CQkJCQkJCQkJCQkJCQkJCQ=", "CQkJCQkJCQkJCQkJCQkJC!", "CQkJ" }, 0..) |salt, i| {
        const payload = try std.fmt.allocPrint(a, "{{\"salt\":\"{s}\"}}", .{salt});
        defer a.free(payload);
        const token = try bedwire.login.sign(a, server_key, header, payload, .{});
        defer a.free(token);
        var mock: Mock = .{};
        var conn = try bedwire.Connection(Mock).init(a, &mock, .client, limits);
        defer conn.deinit();
        conn.state = .authenticating;
        conn.pending_id = 3;
        if (i < 2) {
            try conn.acceptServerHandshake(a, token, client_key.secret_key);
            try std.testing.expectEqual(.encrypted_handshake, conn.state);
            try std.testing.expectEqualSlices(u8, &(try bedwire.ecdh.derive(client_key.secret_key, server_key.public_key, @splat(9))), &conn.crypto.?.key);
        } else {
            try std.testing.expectError(error.InvalidSalt, conn.acceptServerHandshake(a, token, client_key.secret_key));
            try std.testing.expectEqual(.disconnected, conn.state);
            try std.testing.expectEqual(null, conn.crypto);
        }
    }
}

test "send records only the last successfully sent packet and preserves it for empty batches" {
    var mock: Mock = .{};
    var conn = try bedwire.Connection(Mock).init(std.testing.allocator, &mock, .server, limits);
    defer conn.deinit();
    conn.state = .in_game;
    try conn.send(&.{ &.{9}, &.{10} });
    try std.testing.expectEqual(@as(?u10, 10), conn.last_sent_id);
    try conn.send(&.{});
    try std.testing.expectEqual(@as(?u10, 10), conn.last_sent_id);
    try std.testing.expectError(error.InvalidState, conn.send(&.{ &.{11}, &.{1} }));
    try std.testing.expectEqual(@as(?u10, 10), conn.last_sent_id);
}

test "both compression algorithms carry authenticated encrypted sessions end to end" {
    const a = std.testing.allocator;
    const keys = [3]bedwire.spki.Ecdsa.KeyPair{ try .generateDeterministic(@splat(1)), try .generateDeterministic(@splat(2)), try .generateDeterministic(@splat(3)) };
    const server_key = try bedwire.spki.Ecdsa.KeyPair.generateDeterministic(@splat(4));
    const chain = try @import("../auth/chain.zig").makeChain(a, keys);
    defer a.free(chain);
    const client_data = try bedwire.login.sign(a, keys[0], "{\"alg\":\"ES384\"}", "{}", .{});
    defer a.free(client_data);
    const handshake = try bedwire.login.serverHandshake(a, server_key, @splat(9), .{});
    defer a.free(handshake);
    for ([_]bedwire.compression.Algorithm{ .deflate, .snappy }) |algorithm| {
        var client_carrier: Mock = .{};
        var server_carrier: Mock = .{};
        var client = try bedwire.Connection(Mock).init(a, &client_carrier, .client, limits);
        defer client.deinit();
        var server = try bedwire.Connection(Mock).init(a, &server_carrier, .server, limits);
        defer server.deinit();
        try client.send(&.{&.{ 0xc1, 1, 0, 0, 3, 0xb0 }});
        server_carrier.input = client_carrier.output[0..client_carrier.len];
        _ = try server.receive();
        var settings: [12]u8 = undefined;
        var settings_writer = bedwire.protocol.Writer.init(&settings);
        try settings_writer.writeVarU32(143);
        try bedwire.protocol.codecs.network_settings.encode(&settings_writer, .{ .compression_threshold = 0, .compression_algorithm = @intFromEnum(algorithm), .client_throttle = false, .client_throttle_threshold = 0, .client_throttle_scalar = 0 });
        try server.send(&.{settings_writer.written()});
        try server.enableCompression(algorithm, 0);
        client_carrier.input = server_carrier.output[0..server_carrier.len];
        _ = try client.receive();
        try client.enableCompression(algorithm, 0);
        try client.send(&.{&.{1}});
        server_carrier.input = client_carrier.output[0..client_carrier.len];
        _ = try server.receive();
        try std.testing.expectError(error.InvalidState, server.installServerCrypto(server_key.secret_key, @splat(9)));
        var identity = try server.authenticateLegacy(a, chain, client_data, .{ .now = 100, .root = keys[1].public_key });
        defer identity.deinit();
        var packet_storage: [1024]u8 = undefined;
        var writer = bedwire.protocol.Writer.init(&packet_storage);
        try writer.writeU8(3);
        try writer.writeString(handshake);
        try server.send(&.{writer.written()});
        try server.installServerCrypto(server_key.secret_key, @splat(9));
        client_carrier.input = server_carrier.output[0..server_carrier.len];
        var packets = try client.receive();
        const envelope = try bedwire.protocol.packet.decode((try packets.next()).?, .{});
        var reader = try bedwire.protocol.Reader.init(envelope.payload, .{});
        try client.acceptServerHandshake(a, try reader.readString(), keys[0].secret_key);
        try client.send(&.{&.{4}});
        try client.advance(.resource_packs);
        server_carrier.input = client_carrier.output[0..client_carrier.len];
        _ = try server.receive();
        try server.advance(.resource_packs);
        for (0..3) |_| {
            try server.send(&.{&.{ 2, 0, 0, 0, 0 }});
            try std.testing.expectEqual(@as(u8, 0xfe), server_carrier.output[0]);
            client_carrier.input = server_carrier.output[0..server_carrier.len];
            var received = try client.receive();
            try std.testing.expectEqualSlices(u8, &.{ 2, 0, 0, 0, 0 }, (try received.next()).?);
        }
        try server.send(&.{&.{ 2, 0, 0, 0, 0 }});
        server_carrier.output[2] ^= 1;
        client_carrier.input = server_carrier.output[0..server_carrier.len];
        try std.testing.expectError(error.ChecksumMismatch, client.receive());
        try std.testing.expect(client_carrier.closed);
    }
}

test "forged client-data closes authenticating connection" {
    const a = std.testing.allocator;
    const keys = [3]bedwire.spki.Ecdsa.KeyPair{ try .generateDeterministic(@splat(1)), try .generateDeterministic(@splat(2)), try .generateDeterministic(@splat(3)) };
    const chain = try @import("../auth/chain.zig").makeChain(a, keys);
    defer a.free(chain);
    const forged = try bedwire.login.sign(a, keys[2], "{\"alg\":\"ES384\"}", "{}", .{});
    defer a.free(forged);
    var mock: Mock = .{ .input = &.{ 0xfe, 0xff, 1, 1 } };
    var conn = try bedwire.Connection(Mock).init(a, &mock, .server, limits);
    defer conn.deinit();
    conn.state = .authenticating;
    conn.compression.enabled = true;
    _ = try conn.receive();
    try std.testing.expectError(error.InvalidSignature, conn.authenticateLegacy(a, chain, forged, .{ .now = 100, .root = keys[1].public_key }));
    try std.testing.expect(mock.closed);
}

test "steady-state encrypted Flate and Snappy make no allocator calls" {
    for ([_]bedwire.compression.Algorithm{ .deflate, .snappy }) |algorithm| {
        var allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var mock: Mock = .{};
        var conn = try bedwire.Connection(Mock).init(allocator.allocator(), &mock, .server, limits);
        defer conn.deinit();
        allocator.fail_index = allocator.alloc_index;
        allocator.resize_fail_index = allocator.resize_index;
        conn.state = .in_game;
        conn.compression = .{ .enabled = true, .algorithm = algorithm, .threshold = 0 };
        conn.crypto = bedwire.SessionCrypto.init(@splat(0x42));
        const packet = [_]u8{9} ++ ([_]u8{'a'} ** 256);
        for (0..100) |_| {
            try conn.send(&.{&packet});
            mock.input = mock.output[0..mock.len];
            var iterator = try conn.receive();
            try std.testing.expectEqualSlices(u8, &packet, (try iterator.next()).?);
        }
        try std.testing.expect(!allocator.has_induced_failure);
    }
}

test "control payload validation, duplicate negotiation and OIDC state gate" {
    var mock: Mock = .{ .input = &.{ 0xfe, 2, 0xc1, 1 } };
    var conn = try bedwire.Connection(Mock).init(std.testing.allocator, &mock, .server, limits);
    defer conn.deinit();
    try std.testing.expectError(error.InvalidState, conn.authenticateOidc(std.testing.allocator, "", "", .{ .now = 0, .issuer = "", .audience = "", .keys = &.{} }));
    try std.testing.expectError(error.EndOfStream, conn.receive());
    try std.testing.expect(mock.closed);
}

test "Snappy accepts compressible batches larger than the wire limit" {
    var mock: Mock = .{};
    var conn = try bedwire.Connection(Mock).init(std.testing.allocator, &mock, .server, .{ .protocol = .{ .max_batch_bytes = 128, .max_decompressed_batch_bytes = 1024 } });
    defer conn.deinit();
    conn.state = .in_game;
    conn.compression = .{ .enabled = true, .algorithm = .snappy, .threshold = 0 };
    const packet = [_]u8{9} ++ ([_]u8{'a'} ** 512);
    try conn.send(&.{&packet});
    try std.testing.expect(mock.len < 128);
    mock.input = mock.output[0..mock.len];
    var iterator = try conn.receive();
    try std.testing.expectEqualSlices(u8, &packet, (try iterator.next()).?);
}

test "connection negotiates plaintext settings then uses compression framing" {
    var mock: Mock = .{};
    var conn = try bedwire.Connection(Mock).init(std.testing.allocator, &mock, .server, limits);
    defer conn.deinit();
    var packets = try conn.receive();
    try std.testing.expectEqualSlices(u8, &.{ 0xc1, 1, 0, 0, 0, 1 }, (try packets.next()).?);
    try conn.send(&.{&.{ 0x8f, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0 }});
    try std.testing.expectEqual(@as(u8, 12), mock.output[1]);
    try conn.enableCompression(.deflate, 512);
    try std.testing.expectEqual(.authenticating, conn.state);
    try conn.send(&.{&.{3}});
    try std.testing.expectEqual(@as(u8, 0xff), mock.output[1]);
    mock.input = &.{ 0xfe, 0xff, 1, 19 };
    try std.testing.expectError(error.InvalidState, conn.receive());
    try std.testing.expect(mock.closed);
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    var mock: Mock = .{};
    var conn = try bedwire.Connection(Mock).init(allocator, &mock, .server, limits);
    defer conn.deinit();
}

test "connection initialization unwinds every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}
