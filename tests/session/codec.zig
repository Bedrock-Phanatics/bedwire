//! tests integration between bedwire sessions and protocol-zig packet codecs

const std = @import("std");
const bedwire = @import("bedwire");
const protocol = @import("bedrock_protocol");
const support = @import("../support.zig");

const testing = std.testing;

/// Encodes one semantic packet with protocol-zig, for Bedwire to carry.
fn encodePacket(storage: []u8, packet: protocol.typed.Packet, id: u10) ![]const u8 {
    var writer = protocol.Writer.init(storage);
    try protocol.typed.encode(&writer, .{ .header = .{ .packet_id = id }, .packet = packet });
    return writer.written();
}

test "a full handshake runs on packets encoded and decoded by protocol-zig" {
    const allocator = testing.allocator;
    const descriptor = &support.modern;

    var pair = try support.Pair.init(allocator, descriptor);
    defer pair.deinit();

    var storage: [1024]u8 = undefined;

    // client sends RequestNetworkSettings
    {
        const id = descriptor.idOf(.request_network_settings).?;
        const bytes = try encodePacket(&storage, .{ .request_network_settings = .{ .client_protocol = 818 } }, id);

        var packets = try pair.clientToServer(&.{bytes});
        defer packets.deinit();
        const received = packets.next().?;
        try testing.expectEqual(bedwire.PacketKind.request_network_settings, received.kind);

        const envelope = try protocol.typed.decode(received.bytes, .{});
        try testing.expectEqual(@as(i32, 818), envelope.packet.request_network_settings.client_protocol);
    }

    // server responds with NetworkSettings
    {
        const id = descriptor.idOf(.network_settings).?;
        const settings: protocol.packets.network_settings.NetworkSettingsPacket = .{
            .compression_threshold = 256,
            .compression_algorithm = @intFromEnum(bedwire.compression.Algorithm.snappy),
            .client_throttle = false,
            .client_throttle_threshold = 0,
            .client_throttle_scalar = 0,
        };
        const bytes = try encodePacket(&storage, .{ .network_settings = settings }, id);

        var packets = try pair.serverToClient(&.{bytes});
        defer packets.deinit();
        const received = packets.next().?;
        try testing.expectEqual(bedwire.PacketKind.network_settings, received.kind);

        const envelope = try protocol.typed.decode(received.bytes, .{});
        const decoded = envelope.packet.network_settings;

        // The application translates the decoded body into a session decision.
        const algorithm = try bedwire.compression.Algorithm.fromWire(@intCast(decoded.compression_algorithm));
        try pair.server.negotiateCompression(algorithm, settings.compression_threshold);
        try pair.client.negotiateCompression(algorithm, decoded.compression_threshold);
    }

    try testing.expectEqual(bedwire.compression.Algorithm.snappy, pair.client.compression.algorithm);
    try testing.expectEqual(@as(u16, 256), pair.client.compression.threshold);

    // client sends Login
    {
        const id = descriptor.idOf(.login).?;
        const bytes = try encodePacket(&storage, .{ .login = .{ .client_protocol = 818, .connection_request = "blob" } }, id);

        var packets = try pair.clientToServer(&.{bytes});
        defer packets.deinit();
        const received = packets.next().?;
        try testing.expectEqual(bedwire.PacketKind.login, received.kind);

        const envelope = try protocol.typed.decode(received.bytes, .{});
        try testing.expectEqualStrings("blob", envelope.packet.login.connection_request);
    }

    // server sends ServerToClientHandshake
    {
        const key = try support.deterministicKey(4);
        const token = try bedwire.auth.login.serverHandshake(allocator, key, @splat(9), support.limits);
        defer allocator.free(token);

        var big: [4096]u8 = undefined;
        const id = descriptor.idOf(.server_to_client_handshake).?;
        const bytes = try encodePacket(&big, .{ .server_to_client_handshake = .{ .jwt = token } }, id);

        var packets = try pair.serverToClient(&.{bytes});
        defer packets.deinit();
        const received = packets.next().?;
        try testing.expectEqual(bedwire.PacketKind.server_to_client_handshake, received.kind);

        const envelope = try protocol.typed.decode(received.bytes, .{});
        const client_key = try support.deterministicKey(1);
        try pair.client.acceptServerHandshake(allocator, envelope.packet.server_to_client_handshake.jwt, client_key.secret_key);
        try pair.server.installVerifiedClientKey(client_key.public_key);
        try pair.server.installServerCrypto(key.secret_key, @splat(9));
    }

    // client sends ClientToServerHandshake (now encrypted)
    {
        const id = descriptor.idOf(.client_to_server_handshake).?;
        const bytes = try encodePacket(&storage, .{ .client_to_server_handshake = .{} }, id);

        var packets = try pair.clientToServer(&.{bytes});
        defer packets.deinit();
        try testing.expectEqual(bedwire.PacketKind.client_to_server_handshake, packets.next().?.kind);
    }

    try pair.client.advance(.resource_packs);
    try pair.server.advance(.resource_packs);
    try testing.expect(pair.server.encrypted());
}

test "a disconnect decoded by protocol-zig still closes the session" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [256]u8 = undefined;
    const id = support.modern.idOf(.disconnect).?;
    const bytes = try encodePacket(&storage, .{ .disconnect = .{
        .reason = 0,
        .message_skipped = false,
        .message = "bye",
        .filtered_message = "",
    } }, id);

    var packets = try pair.serverToClient(&.{bytes});
    defer packets.deinit();
    const received = packets.next().?;

    const envelope = try protocol.typed.decode(received.bytes, .{});
    try testing.expectEqualStrings("bye", envelope.packet.disconnect.message);
    try testing.expectEqual(bedwire.State.closing, pair.client.state);
}

test "Bedwire carries packets it has no semantic name for" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [256]u8 = undefined;
    const id = @intFromEnum(protocol.PacketId.set_time);
    const bytes = try encodePacket(&storage, .{ .set_time = .{ .time = 1234 } }, id);

    var packets = try pair.serverToClient(&.{bytes});
    defer packets.deinit();
    const received = packets.next().?;

    try testing.expectEqual(bedwire.PacketKind.other, received.kind);
    try testing.expectEqual(@as(u10, id), received.id);

    const envelope = try protocol.typed.decode(received.bytes, .{});
    try testing.expectEqual(@as(i32, 1234), envelope.packet.set_time.time);
}
