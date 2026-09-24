const std = @import("std");
const bedwire = @import("bedwire");
const protocol = @import("bedrock_protocol");
const support = @import("../support.zig");

const External = struct {
    pub const protocol_number: u32 = 7;
    pub const features: protocol.SessionFeatures = .{ .login_flow = .certificate_chain };

    pub fn packetKind(id: u10) ?protocol.PacketKind {
        if (id == 1000) return .network_settings;
        if (id == protocol.Current.packetId(.network_settings).?) return null;
        return protocol.Current.packetKind(id);
    }

    pub fn packetId(kind: protocol.PacketKind) ?u10 {
        if (kind == .network_settings) return 1000;
        return protocol.Current.packetId(kind);
    }

    pub const packetDirection = protocol.Current.packetDirection;

    pub fn decodeBorrowed(input: []const u8, limits: protocol.DecodeLimits) protocol.DecodeError!protocol.BorrowedEnvelope {
        const raw = try protocol.packet.decode(input, limits);
        if (raw.header.packet_id == protocol.Current.packetId(.network_settings).?) {
            return .{ .header = raw.header, .kind = null, .payload = raw.payload, .value = .unknown };
        }
        if (raw.header.packet_id != 1000) return protocol.Current.decodeBorrowed(input, limits);
        var reader = try protocol.Reader.init(raw.payload, limits);
        const algorithm = try reader.readU8();
        const threshold = try reader.readU16();
        try reader.finish();
        return .{
            .header = raw.header,
            .kind = .network_settings,
            .payload = raw.payload,
            .value = .{ .typed = .{ .network_settings = .{
                .compression_algorithm = algorithm,
                .compression_threshold = threshold,
                .client_throttle = false,
                .client_throttle_threshold = 0,
                .client_throttle_scalar = 0,
            } } },
        };
    }

    pub fn encode(writer: *protocol.Writer, envelope: protocol.BorrowedEnvelope) protocol.EncodeError!void {
        if (envelope.kind != .network_settings) return protocol.Current.encode(writer, envelope);
        if (envelope.header.packet_id != 1000 or envelope.value != .typed or envelope.value.typed != .network_settings) return error.InvalidValue;
        const settings = envelope.value.typed.network_settings;
        if (settings.compression_algorithm > 255) return error.InvalidValue;
        if (writer.remainingCapacity() < 5) return error.NoSpaceLeft;
        try writer.writeVarU32(envelope.header.toWire());
        try writer.writeU8(@intCast(settings.compression_algorithm));
        try writer.writeU16(settings.compression_threshold);
    }
};

test "default and supplied profile sessions start independently" {
    const limits: bedwire.Limits = .{
        .max_frame_bytes = 4096,
        .max_batch_bytes = 4096,
        .max_packet_bytes = 2048,
    };
    var pool = try bedwire.BufferPool.init(std.testing.allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();

    var current = try bedwire.Session.init(std.testing.allocator, .server, .{ .pool = &pool });
    defer current.deinit();
    var historical = try bedwire.SessionWithProfile(External).init(std.testing.allocator, .server, .{ .pool = &pool });
    defer historical.deinit();
    try std.testing.expectEqual(protocol.Current.protocol_number, current.version());
    try std.testing.expectEqual(@as(u32, 7), historical.version());
}

test "current and external sessions decode different network settings wire layouts" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var current = try bedwire.Session.init(std.testing.allocator, .client, .{ .pool = &pool });
    defer current.deinit();
    var external = try bedwire.SessionWithProfile(External).init(std.testing.allocator, .client, .{ .pool = &pool });
    defer external.deinit();
    current.state = .network_settings;
    external.state = .network_settings;

    const settings: protocol.packets.network_settings.NetworkSettingsPacket = .{
        .compression_threshold = 70,
        .compression_algorithm = 1,
        .client_throttle = false,
        .client_throttle_threshold = 0,
        .client_throttle_scalar = 0,
    };
    var current_storage: [128]u8 = undefined;
    var current_writer = protocol.Writer.init(&current_storage);
    try protocol.typed.encode(&current_writer, .{
        .header = .{ .packet_id = protocol.Current.packetId(.network_settings).? },
        .packet = .{ .network_settings = settings },
    });
    var external_storage: [128]u8 = undefined;
    var external_writer = protocol.Writer.init(&external_storage);
    try External.encode(&external_writer, .{
        .header = .{ .packet_id = External.packetId(.network_settings).? },
        .kind = .network_settings,
        .payload = &.{},
        .value = .{ .typed = .{ .network_settings = settings } },
    });

    var current_frame: [160]u8 = undefined;
    var external_frame: [160]u8 = undefined;
    var current_packets = try current.ingest(frame(&current_frame, current_writer.written()));
    defer current_packets.deinit();
    var external_packets = try external.ingest(frame(&external_frame, external_writer.written()));
    defer external_packets.deinit();
    const current_packet = current_packets.next().?;
    const external_packet = external_packets.next().?;
    try std.testing.expectEqual(protocol.PacketKind.network_settings, current_packet.kind);
    try std.testing.expectEqual(protocol.PacketKind.network_settings, external_packet.kind);
    try std.testing.expect(current_packet.id != external_packet.id);
    try std.testing.expect(current_packet.bytes.len != external_packet.bytes.len);

    var truncated_storage: [8]u8 = undefined;
    var truncated = external_packet;
    truncated.bytes = support.packet(&truncated_storage, 1000, "");
    try std.testing.expectError(error.EndOfStream, external.negotiateFromSettings(truncated));
    try std.testing.expectEqual(bedwire.State.network_settings, external.state);
    try std.testing.expect(!external.compression.negotiated);

    try current.negotiateFromSettings(current_packet);
    try external.negotiateFromSettings(external_packet);
    try std.testing.expectEqual(@as(u16, 70), current.compression.threshold);
    try std.testing.expectEqual(@as(u16, 70), external.compression.threshold);
    try std.testing.expectEqual(bedwire.State.authenticating, current.state);
    try std.testing.expectEqual(bedwire.State.authenticating, external.state);
}

fn frame(storage: []u8, packet: []const u8) []const u8 {
    storage[0] = 0xfe;
    const length_bytes = bedwire.framing.varint.writeU32(storage[1..], @intCast(packet.len)) catch unreachable;
    @memcpy(storage[1 + length_bytes ..][0..packet.len], packet);
    return storage[0 .. 1 + length_bytes + packet.len];
}

test "session consumes normalized network settings from the selected profile" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 2, .tx_slots = 2 });
    defer pool.deinit();
    var session = try bedwire.Session.init(std.testing.allocator, .client, .{ .pool = &pool });
    defer session.deinit();
    session.state = .network_settings;
    session.received.insert(.network_settings);

    var storage: [128]u8 = undefined;
    var writer = protocol.Writer.init(&storage);
    const id = protocol.Current.packetId(.network_settings).?;
    try protocol.typed.encode(&writer, .{
        .header = .{ .packet_id = id },
        .packet = .{ .network_settings = .{
            .compression_threshold = 64,
            .compression_algorithm = 1,
            .client_throttle = false,
            .client_throttle_threshold = 0,
            .client_throttle_scalar = 0,
        } },
    });
    const packet: bedwire.Packet = .{ .kind = .network_settings, .id = id, .bytes = writer.written() };
    try session.negotiateFromSettings(packet);
    try std.testing.expectEqual(bedwire.State.authenticating, session.state);
    try std.testing.expectEqual(bedwire.compression.Algorithm.snappy, session.compression.algorithm);
    try std.testing.expectEqual(@as(u16, 64), session.compression.threshold);
}

test "network settings accept none and reject unknown compression algorithms without changing state" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var session = try bedwire.Session.init(std.testing.allocator, .client, .{ .pool = &pool });
    defer session.deinit();
    session.state = .network_settings;
    session.received.insert(.network_settings);

    var storage: [128]u8 = undefined;
    for ([_]u16{ 2, 0xffff }) |algorithm| {
        var writer = protocol.Writer.init(&storage);
        const id = protocol.Current.packetId(.network_settings).?;
        try protocol.typed.encode(&writer, .{
            .header = .{ .packet_id = id },
            .packet = .{ .network_settings = .{
                .compression_threshold = 0,
                .compression_algorithm = algorithm,
                .client_throttle = false,
                .client_throttle_threshold = 0,
                .client_throttle_scalar = 0,
            } },
        });
        const packet: bedwire.Packet = .{ .kind = .network_settings, .id = id, .bytes = writer.written() };
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

test "malformed profile-decoded authentication packets close the session" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();

    var server = try support.Session.init(std.testing.allocator, .server, .{ .pool = &pool });
    defer server.deinit();
    server.state = .authenticating;
    server.received.insert(.login);
    var login_storage: [8]u8 = undefined;
    const login_id = support.modern.packetId(.login).?;
    const login_bytes = support.packet(&login_storage, login_id, "");
    const login_packet: support.Session.Packet = .{ .kind = .login, .id = login_id, .bytes = login_bytes };
    try std.testing.expectError(error.EndOfStream, server.authenticateLoginPacket(std.testing.allocator, login_packet, .{ .certificate_chain = .{ .now = 0 } }));
    try std.testing.expectEqual(bedwire.State.disconnected, server.state);

    var client = try bedwire.Session.init(std.testing.allocator, .client, .{ .pool = &pool });
    defer client.deinit();
    client.state = .authenticating;
    client.received.insert(.server_to_client_handshake);
    const key = try support.deterministicKey(1);
    var handshake_storage: [8]u8 = undefined;
    const handshake_id = protocol.Current.packetId(.server_to_client_handshake).?;
    const handshake_bytes = support.packet(&handshake_storage, handshake_id, "");
    const handshake_packet: bedwire.Packet = .{ .kind = .server_to_client_handshake, .id = handshake_id, .bytes = handshake_bytes };
    try std.testing.expectError(error.EndOfStream, client.acceptServerHandshakePacket(std.testing.allocator, handshake_packet, key.secret_key));
    try std.testing.expectEqual(bedwire.State.disconnected, client.state);
}

test "malformed control payload cannot advance the session" {
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var server = try bedwire.Session.init(std.testing.allocator, .server, .{ .pool = &pool });
    defer server.deinit();

    var packet_storage: [8]u8 = undefined;
    var frame_storage: [16]u8 = undefined;
    const malformed = support.packet(&packet_storage, protocol.Current.packetId(.request_network_settings).?, "");
    try std.testing.expectError(error.EndOfStream, server.ingest(frame(&frame_storage, malformed)));
    try std.testing.expectEqual(bedwire.State.disconnected, server.state);
    try std.testing.expect(!server.didReceive(.request_network_settings));

    var client = try bedwire.Session.init(std.testing.allocator, .client, .{ .pool = &pool });
    defer client.deinit();
    try std.testing.expectError(error.EndOfStream, client.encodeOne(malformed));
    try std.testing.expectEqual(bedwire.State.transport_ready, client.state);
    try std.testing.expect(!client.didSend(.request_network_settings));

    var external = try bedwire.SessionWithProfile(External).init(std.testing.allocator, .client, .{ .pool = &pool });
    defer external.deinit();
    external.state = .network_settings;
    const malformed_external = support.packet(&packet_storage, External.packetId(.network_settings).?, "");
    try std.testing.expectError(error.EndOfStream, external.ingest(frame(&frame_storage, malformed_external)));
    try std.testing.expectEqual(bedwire.State.disconnected, external.state);
    try std.testing.expect(!external.didReceive(.network_settings));
}

test "resource pack session packets require profile decoding on ingress and egress" {
    const cases = [_]struct { kind: bedwire.PacketKind, sender: bedwire.Role }{
        .{ .kind = .resource_packs_info, .sender = .server },
        .{ .kind = .resource_pack_stack, .sender = .server },
        .{ .kind = .resource_pack_client_response, .sender = .client },
    };
    var pool = try bedwire.BufferPool.init(std.testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    for (cases) |case| {
        var sender = try bedwire.Session.init(std.testing.allocator, case.sender, .{ .pool = &pool });
        defer sender.deinit();
        sender.state = .resource_packs;
        var packet_storage: [16]u8 = undefined;
        const malformed = support.packet(&packet_storage, support.packetId(support.modern, case.kind), "");
        try std.testing.expectError(error.EndOfStream, sender.encodeOne(malformed));
        try std.testing.expectEqual(bedwire.State.resource_packs, sender.state);
        try std.testing.expect(!sender.didSend(case.kind));

        var receiver = try bedwire.Session.init(std.testing.allocator, case.sender.peer(), .{ .pool = &pool });
        defer receiver.deinit();
        receiver.state = .resource_packs;
        var frame_storage: [32]u8 = undefined;
        try std.testing.expectError(error.EndOfStream, receiver.ingest(frame(&frame_storage, malformed)));
        try std.testing.expectEqual(bedwire.State.disconnected, receiver.state);
        try std.testing.expect(!receiver.didReceive(case.kind));
    }
}

test "external profile completes negotiation authentication crypto and spawn flow" {
    const allocator = std.testing.allocator;
    var pair = try support.Pair.init(allocator, External);
    defer pair.deinit();
    var build: support.Builder = .{};

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

    try pair.clientToServerDiscard(&.{build.make(External, .request_network_settings)});
    var settings_packets = try pair.serverToClient(&.{build.make(External, .network_settings)});
    const settings = settings_packets.next().?;
    try std.testing.expect(settings.id == 1000);
    try pair.client.negotiateFromSettings(settings);
    settings_packets.deinit();
    try pair.server.negotiateCompression(.snappy, 0);

    var login_storage: [4096]u8 = undefined;
    var login_writer = protocol.Writer.init(&login_storage);
    try External.encode(&login_writer, .{
        .header = .{ .packet_id = External.packetId(.login).? },
        .kind = .login,
        .payload = &.{},
        .value = .{ .typed = .{ .login = .{
            .client_protocol = @intCast(External.protocol_number),
            .connection_request = connection_request,
        } } },
    });
    var login_packets = try pair.clientToServer(&.{login_writer.written()});
    const login = login_packets.next().?;
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
    var handshake_writer = protocol.Writer.init(&handshake_storage);
    try External.encode(&handshake_writer, .{
        .header = .{ .packet_id = External.packetId(.server_to_client_handshake).? },
        .kind = .server_to_client_handshake,
        .payload = &.{},
        .value = .{ .typed = .{ .server_to_client_handshake = .{ .jwt = handshake_token } } },
    });
    var handshake_packets = try pair.serverToClient(&.{handshake_writer.written()});
    const handshake = handshake_packets.next().?;
    try pair.client.acceptServerHandshakePacket(allocator, handshake, client_keys[0].secret_key);
    try pair.server.installServerCrypto(server_key.secret_key, salt);
    handshake_packets.deinit();

    try pair.clientToServerDiscard(&.{build.make(External, .client_to_server_handshake)});
    try pair.client.advance(.resource_packs);
    try pair.server.advance(.resource_packs);
    try pair.serverToClientDiscard(&.{build.make(External, .resource_packs_info)});
    try pair.clientToServerDiscard(&.{build.make(External, .resource_pack_client_response)});
    try pair.serverToClientDiscard(&.{build.make(External, .resource_pack_stack)});
    try pair.clientToServerDiscard(&.{build.make(External, .resource_packs_ready_for_validation)});
    try pair.client.advance(.waiting_for_start_game);
    try pair.server.advance(.waiting_for_start_game);
    try pair.serverToClientDiscard(&.{build.make(External, .start_game)});
    try pair.client.advance(.spawn_ready);
    try pair.server.advance(.spawn_ready);
    try pair.clientToServerDiscard(&.{build.make(External, .request_chunk_radius)});
    try pair.serverToClientDiscard(&.{build.make(External, .chunk_radius_updated)});
    try pair.client.advance(.in_game);
    try pair.server.advance(.in_game);

    var gameplay_storage: [32]u8 = undefined;
    const gameplay = support.packet(&gameplay_storage, support.opaque_packet_id, "external gameplay");
    var gameplay_packets = try pair.clientToServer(&.{gameplay});
    try std.testing.expectEqualSlices(u8, gameplay, gameplay_packets.next().?.bytes);
    gameplay_packets.deinit();
}
