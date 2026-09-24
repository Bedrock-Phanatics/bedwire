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
    const descriptor = protocol.Current;

    var pair = try support.Pair.init(allocator, descriptor);
    defer pair.deinit();

    var storage: [1024]u8 = undefined;

    // client sends RequestNetworkSettings
    {
        const id = descriptor.packetId(.request_network_settings).?;
        const bytes = try encodePacket(&storage, .{ .request_network_settings = .{ .client_protocol = @intCast(protocol.Current.protocol_number) } }, id);

        var packets = try pair.clientToServer(&.{bytes});
        defer packets.deinit();
        const received = packets.next().?;
        try testing.expectEqual(bedwire.PacketKind.request_network_settings, received.kind);

        const envelope = try pair.server.decodePacket(received);
        try testing.expectEqual(@as(i32, @intCast(protocol.Current.protocol_number)), envelope.value.typed.request_network_settings.client_protocol);
    }

    // server responds with NetworkSettings
    {
        const id = descriptor.packetId(.network_settings).?;
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

        const envelope = try pair.client.decodePacket(received);
        try testing.expectEqual(settings.compression_threshold, envelope.value.typed.network_settings.compression_threshold);
        try pair.server.negotiateCompression(.snappy, settings.compression_threshold);
        try pair.client.negotiateFromSettings(received);
    }

    try testing.expectEqual(bedwire.compression.Algorithm.snappy, pair.client.compression.algorithm);
    try testing.expectEqual(@as(u16, 256), pair.client.compression.threshold);

    // client sends Login
    {
        const id = descriptor.packetId(.login).?;
        const bytes = try encodePacket(&storage, .{ .login = .{ .client_protocol = @intCast(protocol.Current.protocol_number), .connection_request = "blob" } }, id);

        var packets = try pair.clientToServer(&.{bytes});
        defer packets.deinit();
        const received = packets.next().?;
        try testing.expectEqual(bedwire.PacketKind.login, received.kind);

        const envelope = try pair.server.decodePacket(received);
        try testing.expectEqualStrings("blob", envelope.value.typed.login.connection_request);
    }

    // server sends ServerToClientHandshake
    {
        const key = try support.deterministicKey(4);
        const token = try bedwire.auth.login.serverHandshake(allocator, key, @splat(9), support.limits);
        defer allocator.free(token);

        var big: [4096]u8 = undefined;
        const id = descriptor.packetId(.server_to_client_handshake).?;
        const bytes = try encodePacket(&big, .{ .server_to_client_handshake = .{ .jwt = token } }, id);

        var packets = try pair.serverToClient(&.{bytes});
        defer packets.deinit();
        const received = packets.next().?;
        try testing.expectEqual(bedwire.PacketKind.server_to_client_handshake, received.kind);

        const client_key = try support.deterministicKey(1);
        try pair.client.acceptServerHandshakePacket(allocator, received, client_key.secret_key);
        try pair.server.installVerifiedClientKey(client_key.public_key);
        try pair.server.installServerCrypto(key.secret_key, @splat(9));
    }

    // client sends ClientToServerHandshake (now encrypted)
    {
        const id = descriptor.packetId(.client_to_server_handshake).?;
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
    var pair = try support.Pair.init(testing.allocator, support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [256]u8 = undefined;
    const id = support.modern.packetId(.disconnect).?;
    const bytes = try encodePacket(&storage, .{ .disconnect = .{
        .reason = 0,
        .message_skipped = false,
        .message = "bye",
        .filtered_message = "",
    } }, id);

    var packets = try pair.serverToClient(&.{bytes});
    defer packets.deinit();
    const received = packets.next().?;

    const envelope = try pair.client.decodePacket(received);
    try testing.expectEqualStrings("bye", envelope.value.typed.disconnect.message);
    try testing.expectEqual(bedwire.State.closing, pair.client.state);
}

test "Bedwire carries shared semantic identity for gameplay packets" {
    var pair = try support.Pair.init(testing.allocator, support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [256]u8 = undefined;
    const id = @intFromEnum(protocol.PacketId.set_time);
    const bytes = try encodePacket(&storage, .{ .set_time = .{ .time = 1234 } }, id);

    var packets = try pair.serverToClient(&.{bytes});
    defer packets.deinit();
    const received = packets.next().?;

    try testing.expectEqual(bedwire.PacketKind.set_time, received.kind);
    try testing.expectEqual(@as(u10, id), received.id);

    const envelope = try pair.client.decodePacket(received);
    try testing.expectEqual(@as(i32, 1234), envelope.value.typed.set_time.time);
}
