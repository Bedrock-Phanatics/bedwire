const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");
const control = bedwire.control;

const testing = std.testing;

test "a full handshake runs on packets built by the control codec" {
    const allocator = testing.allocator;

    var pair = try support.Pair.init(allocator, support.modern);
    defer pair.deinit();

    var storage: [1024]u8 = undefined;

    {
        const bytes = support.encode(&storage, control.RequestNetworkSettings{ .protocol_version = @intCast(support.modern.protocol_version) });

        var packets = try pair.clientToServer(&.{bytes});
        defer packets.deinit();
        const received = packets.next().?;
        try testing.expectEqual(bedwire.PacketKind.request_network_settings, received.kind);

        const request = try pair.server.decodeControl(control.RequestNetworkSettings, received);
        try testing.expectEqual(@as(i32, @intCast(support.modern.protocol_version)), request.protocol_version);
    }

    {
        const settings: control.NetworkSettings = .{ .compression_threshold = 256, .compression_algorithm = .snappy };
        const bytes = support.encode(&storage, settings);

        var packets = try pair.serverToClient(&.{bytes});
        defer packets.deinit();
        const received = packets.next().?;
        try testing.expectEqual(bedwire.PacketKind.network_settings, received.kind);

        const decoded = try pair.client.decodeControl(control.NetworkSettings, received);
        try testing.expectEqual(settings.compression_threshold, decoded.compression_threshold);
        try pair.server.negotiateCompression(.snappy, settings.compression_threshold);
        try pair.client.negotiateFromSettings(received);
    }

    try testing.expectEqual(bedwire.compression.Algorithm.snappy, pair.client.compression.algorithm);
    try testing.expectEqual(@as(u16, 256), pair.client.compression.threshold);

    {
        const bytes = support.encode(&storage, control.Login{ .protocol_version = @intCast(support.modern.protocol_version), .connection_request = "blob" });

        var packets = try pair.clientToServer(&.{bytes});
        defer packets.deinit();
        const received = packets.next().?;
        try testing.expectEqual(bedwire.PacketKind.login, received.kind);

        const login = try pair.server.decodeControl(control.Login, received);
        try testing.expectEqualStrings("blob", login.connection_request);
    }

    {
        const key = try support.deterministicKey(4);
        const token = try bedwire.auth.login.serverHandshake(allocator, key, @splat(9), support.limits);
        defer allocator.free(token);

        var big: [4096]u8 = undefined;
        const bytes = support.encode(&big, control.ServerToClientHandshake{ .token = token });

        var packets = try pair.serverToClient(&.{bytes});
        defer packets.deinit();
        const received = packets.next().?;
        try testing.expectEqual(bedwire.PacketKind.server_to_client_handshake, received.kind);

        const client_key = try support.deterministicKey(1);
        try pair.client.acceptServerHandshakePacket(allocator, received, client_key.secret_key);
        try pair.server.installVerifiedClientKey(client_key.public_key);
        try pair.server.installServerCrypto(key.secret_key, @splat(9));
    }

    {
        const bytes = support.encode(&storage, control.ClientToServerHandshake{});

        var packets = try pair.clientToServer(&.{bytes});
        defer packets.deinit();
        try testing.expectEqual(bedwire.PacketKind.client_to_server_handshake, packets.next().?.kind);
    }

    try pair.client.advance(.resource_packs);
    try pair.server.advance(.resource_packs);
    try testing.expect(pair.server.encrypted());
}

test "a disconnect closes the session without being decoded" {
    var pair = try support.Pair.init(testing.allocator, support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [256]u8 = undefined;
    const bytes = support.packet(&storage, support.modern.packetId(.disconnect).?, "\x00\x00\x03bye\x00");

    var packets = try pair.serverToClient(&.{bytes});
    defer packets.deinit();
    const received = packets.next().?;
    try testing.expectEqual(bedwire.PacketKind.disconnect, received.kind);
    try testing.expectEqualSlices(u8, bytes, received.bytes);
    try testing.expectEqual(bedwire.State.closing, pair.client.state);
}

test "gameplay packets keep their ID and stay opaque" {
    var pair = try support.Pair.init(testing.allocator, support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [256]u8 = undefined;
    const set_time_id: u10 = 10;
    const bytes = support.packet(&storage, set_time_id, "\xa4\x13");

    var packets = try pair.serverToClient(&.{bytes});
    defer packets.deinit();
    const received = packets.next().?;

    try testing.expectEqual(@as(?bedwire.PacketKind, null), received.kind);
    try testing.expectEqual(set_time_id, received.id);
    try testing.expectEqualSlices(u8, bytes, received.bytes);
}
