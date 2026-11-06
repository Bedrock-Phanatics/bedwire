const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");
const control = bedwire.control;

const external = support.custom(7, .{ .login_flow = .certificate_chain });

test "sessions carry their configured protocol version and features" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var current = try bedwire.Session.init(.server, .{ .pool = &pool });
    defer current.deinit();
    var historical = try bedwire.Session.init(.server, support.legacy.options(.{ .pool = &pool }));
    defer historical.deinit();
    try std.testing.expectEqual(@as(u32, 0), current.version());
    try std.testing.expectEqual(@as(u32, 440), historical.version());
    try std.testing.expectEqual(bedwire.State.transport_ready, current.state);
    try std.testing.expectEqual(bedwire.State.authenticating, historical.state);
    try std.testing.expect(!historical.features().uses_request_network_settings);

    const broken: bedwire.SessionFeatures = .{ .compression_mode = .implicit, .initial_algorithm = .none };
    try std.testing.expectError(error.UnsupportedProtocol, bedwire.Session.init(.server, .{ .pool = &pool, .features = broken }));
}

fn frame(storage: []u8, packet: []const u8) []const u8 {
    storage[0] = 0xfe;
    const length_bytes = bedwire.framing.varint.writeU32(storage[1..], @intCast(packet.len)) catch unreachable;
    @memcpy(storage[1 + length_bytes ..][0..packet.len], packet);
    return storage[0 .. 1 + length_bytes + packet.len];
}

test "session consumes network settings" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var session = try bedwire.Session.init(.client, .{ .pool = &pool });
    defer session.deinit();
    session.state = .network_settings;
    session.received.insert(.network_settings);

    var storage: [128]u8 = undefined;
    const bytes = support.encode(&storage, control.NetworkSettings{ .compression_threshold = 64, .compression_algorithm = .snappy });
    const packet: bedwire.Packet = .{ .kind = .network_settings, .id = control.PacketKind.network_settings.id(), .bytes = bytes };
    try std.testing.expectEqual(@as(u16, 64), (try session.decodeControl(control.NetworkSettings, packet)).compression_threshold);
    try std.testing.expectError(error.InvalidState, session.decodeControl(control.Login, packet));
    try session.negotiateFromSettings(packet);
    try std.testing.expectEqual(bedwire.State.authenticating, session.state);
    try std.testing.expectEqual(bedwire.compression.Algorithm.snappy, session.compression.algorithm);
    try std.testing.expectEqual(@as(u16, 64), session.compression.threshold);
}

test "network settings accept none and reject unknown compression algorithms without changing state" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var session = try bedwire.Session.init(.client, .{ .pool = &pool });
    defer session.deinit();
    session.state = .network_settings;
    session.received.insert(.network_settings);

    var storage: [128]u8 = undefined;
    for ([_]u16{ 2, 0xffff }) |algorithm| {
        const bytes = support.encode(&storage, control.NetworkSettings{ .compression_threshold = 0, .compression_algorithm = @fromBackingInt(algorithm) });
        const packet: bedwire.Packet = .{ .kind = .network_settings, .id = control.PacketKind.network_settings.id(), .bytes = bytes };
        if (algorithm == 2) {
            try std.testing.expectError(error.UnsupportedCompression, session.negotiateFromSettings(packet));
            try std.testing.expectEqual(bedwire.State.network_settings, session.state);
            try std.testing.expect(!session.compression.negotiated);
        } else {
            try session.negotiateFromSettings(packet);
            try std.testing.expectEqual(bedwire.compression.Algorithm.none, session.compression.algorithm);
            try std.testing.expectEqual(bedwire.State.authenticating, session.state);
        }
    }
}

test "malformed authentication packets close the session" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();

    var server = try support.open(.server, .{ .pool = &pool });
    defer server.deinit();
    server.state = .authenticating;
    server.received.insert(.login);
    var login_storage: [8]u8 = undefined;
    const login_id = support.modern.packetId(.login).?;
    const login_bytes = support.packet(&login_storage, login_id, "");
    const login_packet: support.Session.Packet = .{ .kind = .login, .id = login_id, .bytes = login_bytes };
    try std.testing.expectError(error.EndOfStream, server.authenticateLoginPacket(std.testing.allocator, login_packet, .{ .certificate_chain = .{ .now = 0 } }));
    try std.testing.expectEqual(bedwire.State.disconnected, server.state);

    var client = try bedwire.Session.init(.client, .{ .pool = &pool });
    defer client.deinit();
    client.state = .authenticating;
    client.received.insert(.server_to_client_handshake);
    const key = try support.deterministicKey(1);
    var handshake_storage: [8]u8 = undefined;
    const handshake_id = control.PacketKind.server_to_client_handshake.id();
    const handshake_bytes = support.packet(&handshake_storage, handshake_id, "");
    const handshake_packet: bedwire.Packet = .{ .kind = .server_to_client_handshake, .id = handshake_id, .bytes = handshake_bytes };
    try std.testing.expectError(error.EndOfStream, client.acceptServerHandshakePacket(std.testing.allocator, handshake_packet, key.secret_key));
    try std.testing.expectEqual(bedwire.State.disconnected, client.state);
}

test "malformed control payload cannot advance the session" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var server = try bedwire.Session.init(.server, .{ .pool = &pool });
    defer server.deinit();

    var packet_storage: [8]u8 = undefined;
    var frame_storage: [16]u8 = undefined;
    const malformed = support.packet(&packet_storage, control.PacketKind.request_network_settings.id(), "");
    try std.testing.expectError(error.EndOfStream, server.ingest(frame(&frame_storage, malformed)));
    try std.testing.expectEqual(bedwire.State.disconnected, server.state);
    try std.testing.expect(!server.didReceive(.request_network_settings));

    var client = try bedwire.Session.init(.client, .{ .pool = &pool });
    defer client.deinit();
    try std.testing.expectError(error.EndOfStream, client.encodeOne(malformed));
    try std.testing.expectEqual(bedwire.State.transport_ready, client.state);
    try std.testing.expect(!client.didSend(.request_network_settings));

    var trailing_storage: [8]u8 = undefined;
    const trailing = support.packet(&trailing_storage, control.PacketKind.request_network_settings.id(), "\x00\x00\x00\x01\x00");
    try std.testing.expectError(error.TrailingData, client.encodeOne(trailing));
    try std.testing.expectEqual(bedwire.State.transport_ready, client.state);
}

test "resource pack responses are decoded on ingress and egress" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var sender = try bedwire.Session.init(.client, .{ .pool = &pool });
    defer sender.deinit();
    sender.state = .resource_packs;
    sender.received.insert(.resource_packs_info);
    var packet_storage: [16]u8 = undefined;
    const malformed = support.packet(&packet_storage, control.PacketKind.resource_pack_client_response.id(), "");
    try std.testing.expectError(error.EndOfStream, sender.encodeOne(malformed));
    try std.testing.expectEqual(bedwire.State.resource_packs, sender.state);
    try std.testing.expect(!sender.didSend(.resource_pack_client_response));

    var receiver = try bedwire.Session.init(.server, .{ .pool = &pool });
    defer receiver.deinit();
    receiver.state = .resource_packs;
    receiver.sent.insert(.resource_packs_info);
    var frame_storage: [32]u8 = undefined;
    try std.testing.expectError(error.EndOfStream, receiver.ingest(frame(&frame_storage, malformed)));
    try std.testing.expectEqual(bedwire.State.disconnected, receiver.state);
    try std.testing.expect(!receiver.didReceive(.resource_pack_client_response));
}

test "version specific pack offers pass through undecoded" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var server = try bedwire.Session.init(.server, .{ .pool = &pool });
    defer server.deinit();
    server.state = .resource_packs;
    var storage: [16]u8 = undefined;
    for ([_]bedwire.PacketKind{ .resource_packs_info, .resource_pack_stack }) |kind| {
        const sent = try server.encodeOne(support.packet(&storage, kind.id(), "any layout"));
        sent.release();
        try std.testing.expect(server.didSend(kind));
    }
}

test "a non-default protocol version completes negotiation authentication crypto and spawn flow" {
    const allocator = std.testing.allocator;
    var pair = try support.Pair.init(allocator, external);
    defer pair.deinit();
    var build: support.Builder = .{};
    var second: support.Builder = .{};

    const client_keys = [3]support.Ecdsa.KeyPair{
        try support.deterministicKey(1),
        try support.deterministicKey(2),
        try support.deterministicKey(3),
    };
    const server_key = try support.deterministicKey(4);
    const salt: [16]u8 = @splat(9);
    const chain_json = try support.buildChain(allocator, client_keys);
    defer allocator.free(chain_json);
    const client_data = try support.buildClientData(allocator, client_keys[0]);
    defer allocator.free(client_data);
    const auth_envelope = try support.buildEnvelope(allocator, 0, chain_json, null);
    defer allocator.free(auth_envelope);
    const connection_request = try support.buildConnectionRequest(allocator, auth_envelope, client_data);
    defer allocator.free(connection_request);

    try pair.clientToServerDiscard(&.{build.make(external, .request_network_settings)});
    var settings_packets = try pair.serverToClient(&.{build.make(external, .network_settings)});
    try pair.client.negotiateFromSettings(settings_packets.next().?);
    settings_packets.deinit();
    try pair.server.negotiateCompression(.snappy, 0);

    var login_storage: [4096]u8 = undefined;
    const login_bytes = support.encode(&login_storage, control.Login{ .protocol_version = 7, .connection_request = connection_request });
    var login_packets = try pair.clientToServer(&.{login_bytes});
    const login = login_packets.next().?;
    try std.testing.expectEqual(@as(i32, 7), (try pair.server.decodeControl(control.Login, login)).protocol_version);
    var identity = try pair.server.authenticateLoginPacket(allocator, login, .{ .certificate_chain = .{
        .now = 100,
        .root = client_keys[1].public_key,
    } });
    defer identity.deinit();
    login_packets.deinit();
    try std.testing.expectEqualStrings("Steve", identity.display_name);

    const handshake_token = try bedwire.auth.login.serverHandshake(allocator, server_key, salt, support.limits);
    defer allocator.free(handshake_token);
    var handshake_storage: [4096]u8 = undefined;
    const handshake_bytes = support.encode(&handshake_storage, control.ServerToClientHandshake{ .token = handshake_token });
    var handshake_packets = try pair.serverToClient(&.{handshake_bytes});
    const handshake = handshake_packets.next().?;
    try pair.client.acceptServerHandshakePacket(allocator, handshake, client_keys[0].secret_key);
    try pair.server.installServerCrypto(server_key.secret_key, salt);
    handshake_packets.deinit();

    try pair.clientToServerDiscard(&.{build.make(external, .client_to_server_handshake)});
    try pair.client.advance(.resource_packs);
    try pair.server.advance(.resource_packs);
    try pair.serverToClientDiscard(&.{build.make(external, .resource_packs_info)});
    try pair.serverToClientDiscard(&.{build.make(external, .resource_pack_stack)});
    try pair.clientToServerDiscard(&.{build.make(external, .resource_packs_ready_for_validation)});
    try pair.clientToServerDiscard(&.{build.make(external, .resource_pack_client_response)});
    try pair.client.advance(.waiting_for_start_game);
    try pair.server.advance(.waiting_for_start_game);
    try pair.serverToClientDiscard(&.{build.make(external, .start_game)});
    try pair.client.advance(.spawn_ready);
    try pair.server.advance(.spawn_ready);
    try pair.clientToServerDiscard(&.{build.make(external, .request_chunk_radius)});
    try pair.serverToClientDiscard(&.{ build.make(external, .chunk_radius_updated), second.spawn(external) });
    try std.testing.expectError(error.InvalidState, pair.client.advance(.in_game));
    try pair.clientToServerDiscard(&.{build.make(external, .set_local_player_as_initialised)});
    try pair.client.advance(.in_game);
    try pair.server.advance(.in_game);

    var gameplay_storage: [32]u8 = undefined;
    const gameplay = support.packet(&gameplay_storage, support.opaque_packet_id, "external gameplay");
    var gameplay_packets = try pair.clientToServer(&.{gameplay});
    try std.testing.expectEqualSlices(u8, gameplay, gameplay_packets.next().?.bytes);
    gameplay_packets.deinit();
}

test "a direction table refuses packet IDs the sender may not send" {
    var directions: bedwire.Directions = .{};
    directions.client = .empty;
    directions.client.set(support.opaque_packet_id);

    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var client = try support.open(.client, .{ .pool = &pool, .policy = .{ .directions = &directions } });
    defer client.deinit();
    var server = try support.open(.server, .{ .pool = &pool, .policy = .{ .directions = &directions } });
    defer server.deinit();
    for ([_]*bedwire.Session{ &client, &server }) |session| session.state = .in_game;

    var allowed_storage: [16]u8 = undefined;
    var refused_storage: [16]u8 = undefined;
    const allowed = support.packet(&allowed_storage, support.opaque_packet_id, "ok");
    const refused = support.packet(&refused_storage, support.opaque_packet_id_2, "no");

    try std.testing.expectError(error.InvalidState, client.encodeOne(refused));
    try std.testing.expectError(error.InvalidState, client.encode(&.{ allowed, refused }));
    try std.testing.expectEqual(bedwire.State.in_game, client.state);

    var copy: [64]u8 = undefined;
    {
        const sent = try client.encodeOne(allowed);
        defer sent.release();
        @memcpy(copy[0..sent.bytes.len], sent.bytes);
        var packets = try server.ingest(copy[0..sent.bytes.len]);
        defer packets.deinit();
        try std.testing.expectEqualSlices(u8, allowed, packets.next().?.bytes);
    }

    // Control kinds keep their fixed rules whatever the table says.
    var builder: support.Builder = .{};
    (try client.encodeOne(builder.make(support.modern, .request_chunk_radius))).release();
    (try server.encodeOne(refused)).release();

    var frame_storage: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidState, server.ingest(frame(&frame_storage, refused)));
    try std.testing.expectEqual(bedwire.State.disconnected, server.state);
    try std.testing.expect(pool.isIdle());

    var silent: bedwire.Directions = .{};
    silent.server = .empty;
    var muted = try support.open(.server, .{ .pool = &pool, .policy = .{ .directions = &silent } });
    defer muted.deinit();
    muted.state = .in_game;
    try std.testing.expectError(error.InvalidState, muted.encodeOne(allowed));
    (try muted.encodeOne(builder.make(support.modern, .play_status))).release();
}

test "a direction table also gates gameplay before the game starts" {
    var directions: bedwire.Directions = .{};
    directions.server = .empty;
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var server = try support.open(.server, .{ .pool = &pool, .policy = .{ .directions = &directions } });
    defer server.deinit();
    var storage: [16]u8 = undefined;
    const gameplay = support.packet(&storage, support.opaque_packet_id, "x");
    for ([_]bedwire.State{ .waiting_for_start_game, .spawn_ready, .in_game }) |state| {
        server.state = state;
        try std.testing.expectError(error.InvalidState, server.encodeOne(gameplay));
    }
    directions.server.set(support.opaque_packet_id);
    for ([_]bedwire.State{ .waiting_for_start_game, .spawn_ready, .in_game }) |state| {
        server.state = state;
        (try server.encodeOne(gameplay)).release();
    }
}
