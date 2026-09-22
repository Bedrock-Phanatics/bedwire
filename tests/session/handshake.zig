const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const State = bedwire.State;

/// Drives the whole modern handshake, checking both sides at every stage.
fn completeHandshake(allocator: std.mem.Allocator, algorithm: bedwire.compression.Algorithm) !void {
    var pair = try support.Pair.init(allocator, &support.modern);
    defer pair.deinit();

    var build: support.Builder = .{};
    const descriptor = &support.modern;

    const client_keys = [3]support.Ecdsa.KeyPair{
        try support.deterministicKey(1),
        try support.deterministicKey(2),
        try support.deterministicKey(3),
    };
    const server_key = try support.deterministicKey(4);

    const chain = try support.buildChain(allocator, client_keys);
    defer allocator.free(chain);

    const client_data = try support.buildClientData(allocator, client_keys[0]);
    defer allocator.free(client_data);

    const handshake_token = try bedwire.auth.login.serverHandshake(allocator, server_key, @splat(9), support.limits);
    defer allocator.free(handshake_token);

    // Negotiation.
    try testing.expectEqual(State.transport_ready, pair.client.state);
    try pair.clientToServerDiscard(&.{build.make(descriptor, .request_network_settings)});
    try testing.expectEqual(State.network_settings, pair.client.state);
    try testing.expectEqual(State.network_settings, pair.server.state);

    try pair.serverToClientDiscard(&.{build.make(descriptor, .network_settings)});
    try pair.server.negotiateCompression(algorithm, 0);
    try pair.client.negotiateCompression(algorithm, 0);
    try testing.expectEqual(State.authenticating, pair.server.state);
    try testing.expectEqual(State.authenticating, pair.client.state);

    // Authentication.
    try pair.clientToServerDiscard(&.{build.make(descriptor, .login)});
    var identity = try pair.server.authenticateChain(allocator, chain, client_data, .{
        .now = 100,
        .root = client_keys[1].public_key,
    });
    defer identity.deinit();
    try testing.expectEqualStrings("Steve", identity.display_name);
    try testing.expect(identity.online);

    // handshake packet travels in the clear before crypto kicks in
    try testing.expect(!pair.server.encrypted());
    try pair.serverToClientDiscard(&.{build.make(descriptor, .server_to_client_handshake)});
    try pair.server.installServerCrypto(server_key.secret_key, @splat(9));
    try pair.client.acceptServerHandshake(allocator, handshake_token, client_keys[0].secret_key);

    try testing.expectEqual(State.encrypted_handshake, pair.server.state);
    try testing.expectEqual(State.encrypted_handshake, pair.client.state);
    try testing.expect(pair.server.encrypted() and pair.client.encrypted());

    try pair.clientToServerDiscard(&.{build.make(descriptor, .client_to_server_handshake)});
    try pair.client.advance(.resource_packs);
    try pair.server.advance(.resource_packs);

    // Resource packs, then spawn.
    try pair.serverToClientDiscard(&.{build.make(descriptor, .resource_packs_info)});
    try pair.clientToServerDiscard(&.{build.make(descriptor, .resource_pack_client_response)});
    try pair.serverToClientDiscard(&.{build.make(descriptor, .resource_pack_stack)});
    try pair.clientToServerDiscard(&.{build.make(descriptor, .resource_packs_ready_for_validation)});

    try pair.client.advance(.waiting_for_start_game);
    try pair.server.advance(.waiting_for_start_game);

    try pair.serverToClientDiscard(&.{build.make(descriptor, .start_game)});
    try pair.client.advance(.spawn_ready);
    try pair.server.advance(.spawn_ready);

    try pair.clientToServerDiscard(&.{build.make(descriptor, .request_chunk_radius)});
    try pair.serverToClientDiscard(&.{build.make(descriptor, .chunk_radius_updated)});

    try pair.client.advance(.in_game);
    try pair.server.advance(.in_game);

    // gameplay traffic encrypted in both directions
    var gameplay: [3][]const u8 = undefined;
    var storage: [3][64]u8 = undefined;
    for (&gameplay, 0..) |*slot, i| {
        slot.* = support.packet(&storage[i], 60 + @as(u16, @intCast(i)), "payload");
    }

    var packets = try pair.serverToClient(&gameplay);
    var seen: usize = 0;
    while (packets.next()) |packet| : (seen += 1) {
        try testing.expectEqual(bedwire.PacketKind.other, packet.kind);
        try testing.expectEqualSlices(u8, gameplay[seen], packet.bytes);
    }
    try testing.expectEqual(@as(usize, 3), seen);
    packets.deinit();

    // Either side may disconnect at any time.
    try pair.serverToClientDiscard(&.{build.make(descriptor, .disconnect)});
    try testing.expectEqual(State.closing, pair.server.state);
    try testing.expectEqual(State.closing, pair.client.state);
}

test "modern handshake completes over DEFLATE and Snappy" {
    try completeHandshake(testing.allocator, .deflate);
    try completeHandshake(testing.allocator, .snappy);
}

test "legacy profile skips negotiation and starts authenticating" {
    var pair = try support.Pair.init(testing.allocator, &support.legacy);
    defer pair.deinit();

    var build: support.Builder = .{};
    const descriptor = &support.legacy;

    try testing.expectEqual(State.authenticating, pair.client.state);
    try testing.expectEqual(State.authenticating, pair.server.state);
    try testing.expectError(error.InvalidState, pair.client.negotiateCompression(.deflate, 0));

    // legacy mode compresses with deflate without marker bytes
    var packets = try pair.clientToServer(&.{build.make(descriptor, .login)});
    defer packets.deinit();
    try testing.expectEqual(bedwire.PacketKind.login, packets.next().?.kind);

    // RequestNetworkSettings does not exist in this profile.
    try testing.expect(!descriptor.features.uses_request_network_settings);
    try testing.expectError(error.InvalidState, pair.client.encodeOne(build.make(descriptor, .request_network_settings)));
}

test "sessions on different versions run side by side" {
    var modern = try support.Pair.init(testing.allocator, &support.modern);
    defer modern.deinit();

    var legacy = try support.Pair.init(testing.allocator, &support.legacy);
    defer legacy.deinit();

    var build: support.Builder = .{};

    try testing.expectEqual(@as(u32, 818), modern.server.version());
    try testing.expectEqual(@as(u32, 440), legacy.server.version());

    try modern.clientToServerDiscard(&.{build.make(&support.modern, .request_network_settings)});
    try legacy.clientToServerDiscard(&.{build.make(&support.legacy, .login)});

    try testing.expectEqual(State.network_settings, modern.server.state);
    try testing.expectEqual(State.authenticating, legacy.server.state);
}

test "out-of-stage packets are refused and close the session" {
    var build: support.Builder = .{};

    // Login before negotiation.
    {
        var pair = try support.Pair.init(testing.allocator, &support.modern);
        defer pair.deinit();
        try testing.expectError(error.InvalidState, pair.client.encodeOne(build.make(&support.modern, .login)));
        try testing.expectEqual(State.transport_ready, pair.client.state);
    }

    // A peer sending a stage-appropriate packet from the wrong side.
    {
        var pair = try support.Pair.init(testing.allocator, &support.modern);
        defer pair.deinit();
        pair.server.state = .in_game;
        pair.client.state = .resource_packs;

        try testing.expectError(error.InvalidState, pair.serverToClient(&.{build.makeId(60)}));
        try testing.expectEqual(State.disconnected, pair.client.state);
    }

    // Handshake packets are gone for good once in game.
    {
        var pair = try support.Pair.init(testing.allocator, &support.modern);
        defer pair.deinit();
        pair.server.state = .in_game;
        pair.client.state = .in_game;

        try testing.expectError(error.InvalidState, pair.clientToServer(&.{build.make(&support.modern, .login)}));
    }
}

test "handshake stages accept exactly one packet per batch" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    var build: support.Builder = .{};
    var extra: [16]u8 = undefined;
    const request = build.make(&support.modern, .request_network_settings);
    const second = support.packet(&extra, support.idOf(&support.modern, .request_network_settings), "\x01");

    try testing.expectError(error.InvalidState, pair.client.encode(&.{ request, second }));
    try testing.expectEqual(State.transport_ready, pair.client.state);
    try testing.expectError(error.MalformedBatch, pair.client.encode(&.{}));
}

test "subclient IDs other than 0 are rejected" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    var storage: [16]u8 = undefined;
    const id = support.idOf(&support.modern, .request_network_settings);
    const split = support.subclientPacket(&storage, id, 1, 0);

    try testing.expectError(error.InvalidState, pair.client.encodeOne(split));

    pair.client.state = .in_game;
    pair.server.state = .in_game;

    // primary subclient (0) is fine
    var normal_storage: [16]u8 = undefined;
    var packets = try pair.clientToServer(&.{support.subclientPacket(&normal_storage, 60, 0, 0)});
    defer packets.deinit();
    try testing.expectEqual(bedwire.PacketKind.other, packets.next().?.kind);

    // non-zero subclients not supported yet
    var sender_storage: [16]u8 = undefined;
    const bad_sender = support.subclientPacket(&sender_storage, 60, 1, 0);
    try testing.expectError(error.InvalidState, pair.client.encodeOne(bad_sender));

    var target_storage: [16]u8 = undefined;
    const bad_target = support.subclientPacket(&target_storage, 60, 0, 2);
    try testing.expectError(error.InvalidState, pair.client.encodeOne(bad_target));
}

test "every invalid advance is refused" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    const unreachable_targets = [_]State{
        .transport_ready,
        .network_settings,
        .authenticating,
        .encrypted_handshake,
        .disconnected,
    };

    for (std.enums.values(State)) |from| {
        for (unreachable_targets) |to| {
            pair.server.state = from;
            try testing.expectError(error.InvalidState, pair.server.advance(to));
        }
    }

    // Reachable targets still need their stage and their packet exchange.
    pair.server.state = .resource_packs;
    try testing.expectError(error.InvalidState, pair.server.advance(.spawn_ready));
    try testing.expectError(error.InvalidState, pair.server.advance(.in_game));
    try pair.server.advance(.waiting_for_start_game);
    try testing.expectError(error.InvalidState, pair.server.advance(.spawn_ready));

    pair.server.state = .encrypted_handshake;
    try testing.expectError(error.InvalidState, pair.server.advance(.resource_packs));

    pair.server.state = .disconnected;
    try testing.expectError(error.InvalidState, pair.server.advance(.closing));
}

test "optional encryption lets a session skip the encrypted handshake" {
    const descriptor: bedwire.Descriptor = comptime bedwire.protocol.describeWith(818, .{ .encryption = .optional }) catch unreachable;

    var pair = try support.Pair.init(testing.allocator, &descriptor);
    defer pair.deinit();

    var build: support.Builder = .{};
    try pair.clientToServerDiscard(&.{build.make(&descriptor, .request_network_settings)});
    try pair.serverToClientDiscard(&.{build.make(&descriptor, .network_settings)});
    try pair.server.negotiateCompression(.snappy, 0);
    try pair.client.negotiateCompression(.snappy, 0);
    try pair.clientToServerDiscard(&.{build.make(&descriptor, .login)});

    try pair.server.advance(.resource_packs);
    try testing.expect(!pair.server.encrypted());
    try pair.client.advance(.resource_packs);
    try testing.expect(!pair.client.encrypted());
}

test "crypto installation refuses to run out of order" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    var build: support.Builder = .{};
    const server_key = try support.deterministicKey(4);
    const client_key = try support.deterministicKey(1);

    const token = try bedwire.auth.login.serverHandshake(testing.allocator, server_key, @splat(9), support.limits);
    defer testing.allocator.free(token);

    try pair.clientToServerDiscard(&.{build.make(&support.modern, .request_network_settings)});
    try pair.serverToClientDiscard(&.{build.make(&support.modern, .network_settings)});
    try pair.server.negotiateCompression(.deflate, 0);
    try pair.client.negotiateCompression(.deflate, 0);
    try pair.clientToServerDiscard(&.{build.make(&support.modern, .login)});

    // Before the handshake packet has been sent.
    try testing.expectError(error.InvalidState, pair.server.installServerCrypto(server_key.secret_key, @splat(9)));

    // Sent, but no verified client key.
    try pair.serverToClientDiscard(&.{build.make(&support.modern, .server_to_client_handshake)});
    try testing.expectError(error.Unauthenticated, pair.server.installServerCrypto(server_key.secret_key, @splat(9)));

    // A proxy may vouch for the key itself.
    try pair.server.installVerifiedClientKey(client_key.public_key);
    try pair.server.installServerCrypto(server_key.secret_key, @splat(9));
    try testing.expectError(error.InvalidState, pair.server.installServerCrypto(server_key.secret_key, @splat(9)));

    // The client side is role-gated the same way.
    try testing.expectError(error.InvalidState, pair.server.acceptServerHandshake(testing.allocator, token, server_key.secret_key));
    try pair.client.acceptServerHandshake(testing.allocator, token, client_key.secret_key);
    try testing.expectError(error.InvalidState, pair.client.acceptServerHandshake(testing.allocator, token, client_key.secret_key));
}

test "authentication is gated by stage, role and login flow" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    const allocator = testing.allocator;
    const policy: bedwire.auth.ChainPolicy = .{ .now = 100 };
    const dummy_keys = bedwire.auth.jwks.KeySet{
        .allocator = allocator,
        .backing = &.{},
        .count = 0,
    };
    const oidc: bedwire.auth.OidcPolicy = .{ .now = 100, .keys = &dummy_keys };

    try testing.expectError(error.InvalidState, pair.server.authenticateChain(allocator, "{}", "", policy));
    try testing.expectError(error.InvalidState, pair.client.authenticateChain(allocator, "{}", "", policy));

    pair.server.state = .authenticating;
    try testing.expectError(error.InvalidState, pair.server.authenticateChain(allocator, "{}", "", policy));
    try testing.expectError(error.InvalidState, pair.server.installVerifiedClientKey((try support.deterministicKey(1)).public_key));

    pair.server.received.insert(.login);
    try testing.expectError(error.UnsupportedProtocol, pair.server.authenticateOidc(allocator, "", "", oidc));
    try testing.expectError(error.InvalidClaims, pair.server.authenticateChain(allocator, "{}", "", policy));
    try testing.expectEqual(State.disconnected, pair.server.state);
}

test "a closed session refuses further traffic" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    var build: support.Builder = .{};
    pair.client.close();

    try testing.expectError(error.TransportClosed, pair.client.encodeOne(build.make(&support.modern, .request_network_settings)));
    try testing.expectError(error.TransportClosed, pair.client.ingest(&.{ 0xfe, 2, 0xc1, 1 }));
    try testing.expect(!pair.client.encrypted());
}

test "closing still carries a disconnect in both directions" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    var build: support.Builder = .{};
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    try pair.clientToServerDiscard(&.{build.make(&support.modern, .disconnect)});
    try testing.expectEqual(State.closing, pair.client.state);
    try testing.expectEqual(State.closing, pair.server.state);

    var packets = try pair.serverToClient(&.{build.make(&support.modern, .disconnect)});
    defer packets.deinit();
    try testing.expectEqual(bedwire.PacketKind.disconnect, packets.next().?.kind);
    try testing.expectError(error.InvalidState, pair.server.encodeOne(build.makeId(60)));
}

test "gameplay enforces known packet directions between client and server" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    var build: support.Builder = .{};
    const descriptor = &support.modern;

    pair.client.state = .in_game;
    pair.server.state = .in_game;

    // client -> server only
    var p1 = try pair.clientToServer(&.{build.make(descriptor, .request_chunk_radius)});
    try testing.expectEqual(bedwire.PacketKind.request_chunk_radius, p1.next().?.kind);
    p1.deinit();

    // server can't send this
    try testing.expectError(error.InvalidState, pair.server.encodeOne(build.make(descriptor, .request_chunk_radius)));

    // server -> client only
    var storage1: [16]u8 = undefined;
    var storage2: [16]u8 = undefined;
    const pkt_status = support.packet(&storage1, support.idOf(descriptor, .play_status), "\x00");
    const pkt_radius = support.packet(&storage2, support.idOf(descriptor, .chunk_radius_updated), "\x00");
    var p2 = try pair.serverToClient(&.{ pkt_status, pkt_radius });
    try testing.expectEqual(bedwire.PacketKind.play_status, p2.next().?.kind);
    try testing.expectEqual(bedwire.PacketKind.chunk_radius_updated, p2.next().?.kind);
    p2.deinit();

    // client can't send these
    try testing.expectError(error.InvalidState, pair.client.encodeOne(build.make(descriptor, .play_status)));
    try testing.expectError(error.InvalidState, pair.client.encodeOne(build.make(descriptor, .chunk_radius_updated)));

    // .other is bidirectional
    var p3 = try pair.clientToServer(&.{build.makeId(60)});
    try testing.expectEqual(bedwire.PacketKind.other, p3.next().?.kind);
    p3.deinit();

    var p4 = try pair.serverToClient(&.{build.makeId(60)});
    try testing.expectEqual(bedwire.PacketKind.other, p4.next().?.kind);
    p4.deinit();
}

test "authenticateLogin succeeds with modern OIDC envelope (protocol >= 898)" {
    const allocator = testing.allocator;
    var pair = try support.Pair.init(allocator, &support.modern_oidc);
    defer pair.deinit();

    var key_set = try bedwire.auth.jwks.KeySet.parse(allocator, support.test_jwks_json, support.limits);
    defer key_set.deinit();

    const client_key = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client_key.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"https://authorization.franchise.minecraft-services.net/\",\"aud\":\"api://auth-minecraft-services/multiplayer\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{cpk_b64},
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client_key);
    defer allocator.free(client_data);

    const envelope = try support.buildEnvelope(allocator, 0, null, token);
    defer allocator.free(envelope);

    const wire_bytes = try support.buildConnectionRequest(allocator, envelope, client_data);
    defer allocator.free(wire_bytes);

    var build: support.Builder = .{};
    try pair.clientToServerDiscard(&.{build.make(&support.modern_oidc, .request_network_settings)});
    try pair.serverToClientDiscard(&.{build.make(&support.modern_oidc, .network_settings)});
    try pair.server.negotiateCompression(.snappy, 0);
    try pair.client.negotiateCompression(.snappy, 0);
    try pair.clientToServerDiscard(&.{build.make(&support.modern_oidc, .login)});

    const policy: bedwire.auth.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };

    var id = try pair.server.authenticateLogin(allocator, wire_bytes, .{ .oidc = policy });
    defer id.deinit();

    try testing.expectEqualStrings("Alex", id.display_name);
    try testing.expectEqualStrings("987654321", id.xuid);
    try testing.expect(id.online);
    try testing.expect(pair.server.peer_key != null);

    const server_key = try support.deterministicKey(4);
    try pair.serverToClientDiscard(&.{build.make(&support.modern_oidc, .server_to_client_handshake)});
    try pair.server.installServerCrypto(server_key.secret_key, @splat(9));
    try testing.expect(pair.server.encrypted());
}

test "authenticateLogin succeeds with envelope-framed certificate chain (818 <= protocol < 898)" {
    const allocator = testing.allocator;
    var pair = try support.Pair.init(allocator, &support.modern);
    defer pair.deinit();

    const keys = [3]support.Ecdsa.KeyPair{
        try support.deterministicKey(1),
        try support.deterministicKey(2),
        try support.deterministicKey(3),
    };

    const chain_json = try support.buildChain(allocator, keys);
    defer allocator.free(chain_json);

    const client_data = try support.buildClientData(allocator, keys[0]);
    defer allocator.free(client_data);

    const envelope = try support.buildEnvelope(allocator, 0, chain_json, null);
    defer allocator.free(envelope);

    const wire_bytes = try support.buildConnectionRequest(allocator, envelope, client_data);
    defer allocator.free(wire_bytes);

    var build: support.Builder = .{};
    try pair.clientToServerDiscard(&.{build.make(&support.modern, .request_network_settings)});
    try pair.serverToClientDiscard(&.{build.make(&support.modern, .network_settings)});
    try pair.server.negotiateCompression(.deflate, 0);
    try pair.client.negotiateCompression(.deflate, 0);
    try pair.clientToServerDiscard(&.{build.make(&support.modern, .login)});

    const policy: bedwire.auth.ChainPolicy = .{
        .now = 100,
        .root = keys[1].public_key,
    };

    var id = try pair.server.authenticateLogin(allocator, wire_bytes, .{ .certificate_chain = policy });
    defer id.deinit();

    try testing.expectEqualStrings("Steve", id.display_name);
    try testing.expectEqualStrings("1234", id.xuid);
    try testing.expect(id.online);
    try testing.expect(pair.server.peer_key != null);
}

test "authenticateLogin succeeds with legacy wire certificate chain (protocol < 818)" {
    const allocator = testing.allocator;
    var pair = try support.Pair.init(allocator, &support.legacy);
    defer pair.deinit();

    const keys = [3]support.Ecdsa.KeyPair{
        try support.deterministicKey(1),
        try support.deterministicKey(2),
        try support.deterministicKey(3),
    };

    const chain_json = try support.buildChain(allocator, keys);
    defer allocator.free(chain_json);

    const client_data = try support.buildClientData(allocator, keys[0]);
    defer allocator.free(client_data);

    const wire_bytes = try support.buildConnectionRequest(allocator, chain_json, client_data);
    defer allocator.free(wire_bytes);

    var build: support.Builder = .{};
    try pair.serverToClientDiscard(&.{build.make(&support.legacy, .play_status)});
    pair.server.state = .authenticating;
    pair.client.state = .authenticating;
    try pair.clientToServerDiscard(&.{build.make(&support.legacy, .login)});

    const policy: bedwire.auth.ChainPolicy = .{
        .now = 100,
        .root = keys[1].public_key,
    };

    var id = try pair.server.authenticateLogin(allocator, wire_bytes, .{ .certificate_chain = policy });
    defer id.deinit();

    try testing.expectEqualStrings("Steve", id.display_name);
    try testing.expectEqualStrings("1234", id.xuid);
    try testing.expect(id.online);
    try testing.expect(pair.server.peer_key != null);
}

test "authenticateLogin prevents protocol downgrade between OIDC and CertificateChain" {
    const allocator = testing.allocator;

    const dummy_keys = bedwire.auth.jwks.KeySet{
        .allocator = allocator,
        .backing = &.{},
        .count = 0,
    };

    {
        var pair = try support.Pair.init(allocator, &support.modern_oidc);
        defer pair.deinit();

        pair.server.state = .authenticating;
        pair.server.received.insert(.login);

        const policy: bedwire.auth.ChainPolicy = .{ .now = 100 };
        try testing.expectError(error.UnsupportedProtocol, pair.server.authenticateLogin(allocator, "", .{ .certificate_chain = policy }));
    }

    {
        var pair = try support.Pair.init(allocator, &support.modern);
        defer pair.deinit();

        pair.server.state = .authenticating;
        pair.server.received.insert(.login);

        const policy: bedwire.auth.OidcPolicy = .{ .now = 100, .keys = &dummy_keys };
        try testing.expectError(error.UnsupportedProtocol, pair.server.authenticateLogin(allocator, "", .{ .oidc = policy }));
    }

    {
        var pair = try support.Pair.init(allocator, &support.legacy);
        defer pair.deinit();

        pair.server.state = .authenticating;
        pair.server.received.insert(.login);

        const policy: bedwire.auth.OidcPolicy = .{ .now = 100, .keys = &dummy_keys };
        try testing.expectError(error.UnsupportedProtocol, pair.server.authenticateLogin(allocator, "", .{ .oidc = policy }));
    }
}

test "authenticateLogin rejects wire format mismatch against session features" {
    const allocator = testing.allocator;

    {
        var pair = try support.Pair.init(allocator, &support.legacy);
        defer pair.deinit();

        pair.server.state = .authenticating;
        pair.server.received.insert(.login);

        const envelope = "{\"AuthenticationType\":0,\"Certificate\":\"\"}";
        const wire_bytes = try support.buildConnectionRequest(allocator, envelope, "raw");
        defer allocator.free(wire_bytes);

        const policy: bedwire.auth.ChainPolicy = .{ .now = 100 };
        try testing.expectError(error.UnsupportedProtocol, pair.server.authenticateLogin(allocator, wire_bytes, .{ .certificate_chain = policy }));
        try testing.expectEqual(State.disconnected, pair.server.state);
    }

    {
        var pair = try support.Pair.init(allocator, &support.modern_oidc);
        defer pair.deinit();

        var key_set = try bedwire.auth.jwks.KeySet.parse(allocator, support.test_jwks_json, support.limits);
        defer key_set.deinit();

        pair.server.state = .authenticating;
        pair.server.received.insert(.login);

        const legacy_chain = "{\"chain\":[]}";
        const wire_bytes = try support.buildConnectionRequest(allocator, legacy_chain, "raw");
        defer allocator.free(wire_bytes);

        const policy: bedwire.auth.OidcPolicy = .{ .now = 100, .keys = &key_set };
        try testing.expectError(error.UnsupportedProtocol, pair.server.authenticateLogin(allocator, wire_bytes, .{ .oidc = policy }));
        try testing.expectEqual(State.disconnected, pair.server.state);
    }
}

test "authenticateLogin enforces AuthenticationType policy" {
    const allocator = testing.allocator;

    {
        var pair = try support.Pair.init(allocator, &support.modern_oidc);
        defer pair.deinit();

        var key_set = try bedwire.auth.jwks.KeySet.parse(allocator, support.test_jwks_json, support.limits);
        defer key_set.deinit();

        pair.server.state = .authenticating;
        pair.server.received.insert(.login);

        const envelope = try support.buildEnvelope(allocator, 1, null, "token");
        defer allocator.free(envelope);

        const wire_bytes = try support.buildConnectionRequest(allocator, envelope, "raw");
        defer allocator.free(wire_bytes);

        const policy: bedwire.auth.OidcPolicy = .{ .now = 100, .keys = &key_set };
        try testing.expectError(error.UnsupportedAuthenticationType, pair.server.authenticateLogin(allocator, wire_bytes, .{ .oidc = policy }));
        try testing.expectEqual(State.disconnected, pair.server.state);
    }

    {
        var pair = try support.Pair.init(allocator, &support.modern);
        defer pair.deinit();

        pair.server.state = .authenticating;
        pair.server.received.insert(.login);

        const envelope = try support.buildEnvelope(allocator, 2, "{\"chain\":[]}", null);
        defer allocator.free(envelope);

        const wire_bytes = try support.buildConnectionRequest(allocator, envelope, "raw");
        defer allocator.free(wire_bytes);

        const policy: bedwire.auth.ChainPolicy = .{ .now = 100, .allow_offline = false };
        try testing.expectError(error.UntrustedChain, pair.server.authenticateLogin(allocator, wire_bytes, .{ .certificate_chain = policy }));
        try testing.expectEqual(State.disconnected, pair.server.state);
    }

    {
        var pair = try support.Pair.init(allocator, &support.modern_oidc);
        defer pair.deinit();

        var key_set = try bedwire.auth.jwks.KeySet.parse(allocator, support.test_jwks_json, support.limits);
        defer key_set.deinit();

        pair.server.state = .authenticating;
        pair.server.received.insert(.login);

        const envelope = try support.buildEnvelope(allocator, 2, null, "token");
        defer allocator.free(envelope);

        const wire_bytes = try support.buildConnectionRequest(allocator, envelope, "raw");
        defer allocator.free(wire_bytes);

        const policy: bedwire.auth.OidcPolicy = .{ .now = 100, .keys = &key_set };
        try testing.expectError(error.UntrustedChain, pair.server.authenticateLogin(allocator, wire_bytes, .{ .oidc = policy }));
        try testing.expectEqual(State.disconnected, pair.server.state);
    }

    {
        var pair = try support.Pair.init(allocator, &support.modern_oidc);
        defer pair.deinit();

        var key_set = try bedwire.auth.jwks.KeySet.parse(allocator, support.test_jwks_json, support.limits);
        defer key_set.deinit();

        pair.server.state = .authenticating;
        pair.server.received.insert(.login);

        const envelope = try support.buildEnvelope(allocator, 3, null, "token");
        defer allocator.free(envelope);

        const wire_bytes = try support.buildConnectionRequest(allocator, envelope, "raw");
        defer allocator.free(wire_bytes);

        const policy: bedwire.auth.OidcPolicy = .{ .now = 100, .keys = &key_set };
        try testing.expectError(error.UnsupportedAuthenticationType, pair.server.authenticateLogin(allocator, wire_bytes, .{ .oidc = policy }));
        try testing.expectEqual(State.disconnected, pair.server.state);
    }
}

test "authenticateLogin guarantees failure atomicity (peer_key remains null and session disconnected)" {
    const allocator = testing.allocator;
    var pair = try support.Pair.init(allocator, &support.modern_oidc);
    defer pair.deinit();

    var key_set = try bedwire.auth.jwks.KeySet.parse(allocator, support.test_jwks_json, support.limits);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"https://authorization.franchise.minecraft-services.net/\",\"aud\":\"api://auth-minecraft-services/multiplayer\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{cpk_b64},
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    var tampered_token = try allocator.dupe(u8, token);
    defer allocator.free(tampered_token);
    tampered_token[tampered_token.len - 5] ^= 0x01;

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const envelope = try support.buildEnvelope(allocator, 0, null, tampered_token);
    defer allocator.free(envelope);

    const wire_bytes = try support.buildConnectionRequest(allocator, envelope, client_data);
    defer allocator.free(wire_bytes);

    pair.server.state = .authenticating;
    pair.server.received.insert(.login);

    const policy: bedwire.auth.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };

    try testing.expectError(error.InvalidSignature, pair.server.authenticateLogin(allocator, wire_bytes, .{ .oidc = policy }));

    try testing.expect(pair.server.peer_key == null);
    try testing.expectEqual(State.disconnected, pair.server.state);
}

fn testAuthenticateLoginAllocations(allocator: std.mem.Allocator) !void {
    var key_set = try bedwire.auth.jwks.KeySet.parse(allocator, support.test_jwks_json, support.limits);
    defer key_set.deinit();

    const client = try support.deterministicKey(10);
    const cpk_b64 = support.encodedKey(client.public_key);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"https://authorization.franchise.minecraft-services.net/\",\"aud\":\"api://auth-minecraft-services/multiplayer\",\"exp\":2000,\"cpk\":\"{s}\",\"xname\":\"Alex\",\"xid\":\"987654321\"}}",
        .{cpk_b64},
    );
    defer allocator.free(payload);

    const token = try support.signRsaToken(allocator, "{\"alg\":\"RS256\",\"kid\":\"test-rsa-key-1\"}", payload);
    defer allocator.free(token);

    const client_data = try support.buildClientData(allocator, client);
    defer allocator.free(client_data);

    const envelope = try support.buildEnvelope(allocator, 0, null, token);
    defer allocator.free(envelope);

    const wire_bytes = try support.buildConnectionRequest(allocator, envelope, client_data);
    defer allocator.free(wire_bytes);

    var pair = try support.Pair.init(allocator, &support.modern_oidc);
    defer pair.deinit();

    pair.server.state = .authenticating;
    pair.server.received.insert(.login);

    const policy: bedwire.auth.OidcPolicy = .{
        .now = 1100,
        .keys = &key_set,
    };

    try pair.server.installVerifiedClientKey(client.public_key);
    var id = pair.server.authenticateLogin(allocator, wire_bytes, .{ .oidc = policy }) catch |err| {
        try testing.expectEqual(State.disconnected, pair.server.state);
        try testing.expect(pair.server.peer_key == null);
        try testing.expect(pair.server.crypto == null);
        try testing.expect(pair.pool.isIdle());
        return err;
    };
    id.deinit();
}

test "authenticateLogin handles allocation failures cleanly" {
    try std.testing.checkAllAllocationFailures(testing.allocator, testAuthenticateLoginAllocations, .{});
}
