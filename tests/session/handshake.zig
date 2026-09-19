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
    _ = try pair.clientToServer(&.{build.make(descriptor, .request_network_settings)});
    try testing.expectEqual(State.network_settings, pair.client.state);
    try testing.expectEqual(State.network_settings, pair.server.state);

    _ = try pair.serverToClient(&.{build.make(descriptor, .network_settings)});
    try pair.server.negotiateCompression(algorithm, 0);
    try pair.client.negotiateCompression(algorithm, 0);
    try testing.expectEqual(State.authenticating, pair.server.state);
    try testing.expectEqual(State.authenticating, pair.client.state);

    // Authentication.
    _ = try pair.clientToServer(&.{build.make(descriptor, .login)});
    var identity = try pair.server.authenticateChain(allocator, chain, client_data, .{
        .now = 100,
        .root = client_keys[1].public_key,
    });
    defer identity.deinit();
    try testing.expectEqualStrings("Steve", identity.display_name);
    try testing.expect(identity.online);

    // handshake packet travels in the clear before crypto kicks in
    try testing.expect(!pair.server.encrypted());
    _ = try pair.serverToClient(&.{build.make(descriptor, .server_to_client_handshake)});
    try pair.server.installServerCrypto(server_key.secret_key, @splat(9));
    try pair.client.acceptServerHandshake(allocator, handshake_token, client_keys[0].secret_key);

    try testing.expectEqual(State.encrypted_handshake, pair.server.state);
    try testing.expectEqual(State.encrypted_handshake, pair.client.state);
    try testing.expect(pair.server.encrypted() and pair.client.encrypted());

    _ = try pair.clientToServer(&.{build.make(descriptor, .client_to_server_handshake)});
    try pair.client.advance(.resource_packs);
    try pair.server.advance(.resource_packs);

    // Resource packs, then spawn.
    _ = try pair.serverToClient(&.{build.make(descriptor, .resource_packs_info)});
    _ = try pair.clientToServer(&.{build.make(descriptor, .resource_pack_client_response)});
    _ = try pair.serverToClient(&.{build.make(descriptor, .resource_pack_stack)});
    _ = try pair.clientToServer(&.{build.make(descriptor, .resource_packs_ready_for_validation)});

    try pair.client.advance(.waiting_for_start_game);
    try pair.server.advance(.waiting_for_start_game);

    _ = try pair.serverToClient(&.{build.make(descriptor, .start_game)});
    try pair.client.advance(.spawn_ready);
    try pair.server.advance(.spawn_ready);

    _ = try pair.clientToServer(&.{build.make(descriptor, .request_chunk_radius)});
    _ = try pair.serverToClient(&.{build.make(descriptor, .chunk_radius_updated)});

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

    // Either side may disconnect at any time.
    _ = try pair.serverToClient(&.{build.make(descriptor, .disconnect)});
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

    _ = try modern.clientToServer(&.{build.make(&support.modern, .request_network_settings)});
    _ = try legacy.clientToServer(&.{build.make(&support.legacy, .login)});

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

test "split screen subclients are refused outside gameplay" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    var storage: [16]u8 = undefined;
    const id = support.idOf(&support.modern, .request_network_settings);
    const split = support.subclientPacket(&storage, id, 1, 0);

    try testing.expectError(error.InvalidState, pair.client.encodeOne(split));

    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var gameplay: [16]u8 = undefined;
    var packets = try pair.clientToServer(&.{support.subclientPacket(&gameplay, 60, 1, 2)});
    try testing.expectEqual(bedwire.PacketKind.other, packets.next().?.kind);
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
    _ = try pair.clientToServer(&.{build.make(&descriptor, .request_network_settings)});
    _ = try pair.serverToClient(&.{build.make(&descriptor, .network_settings)});
    try pair.server.negotiateCompression(.snappy, 0);
    try pair.client.negotiateCompression(.snappy, 0);
    _ = try pair.clientToServer(&.{build.make(&descriptor, .login)});

    try pair.server.advance(.resource_packs);
    try testing.expect(!pair.server.encrypted());
    try testing.expectError(error.InvalidState, pair.client.advance(.resource_packs));
}

test "crypto installation refuses to run out of order" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    var build: support.Builder = .{};
    const server_key = try support.deterministicKey(4);
    const client_key = try support.deterministicKey(1);

    const token = try bedwire.auth.login.serverHandshake(testing.allocator, server_key, @splat(9), support.limits);
    defer testing.allocator.free(token);

    _ = try pair.clientToServer(&.{build.make(&support.modern, .request_network_settings)});
    _ = try pair.serverToClient(&.{build.make(&support.modern, .network_settings)});
    try pair.server.negotiateCompression(.deflate, 0);
    try pair.client.negotiateCompression(.deflate, 0);
    _ = try pair.clientToServer(&.{build.make(&support.modern, .login)});

    // Before the handshake packet has been sent.
    try testing.expectError(error.InvalidState, pair.server.installServerCrypto(server_key.secret_key, @splat(9)));

    // Sent, but no verified client key.
    _ = try pair.serverToClient(&.{build.make(&support.modern, .server_to_client_handshake)});
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
    const oidc: bedwire.auth.OidcPolicy = .{ .now = 100, .issuer = "", .audience = "", .keys = &.{} };

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

    _ = try pair.clientToServer(&.{build.make(&support.modern, .disconnect)});
    try testing.expectEqual(State.closing, pair.client.state);
    try testing.expectEqual(State.closing, pair.server.state);

    var packets = try pair.serverToClient(&.{build.make(&support.modern, .disconnect)});
    try testing.expectEqual(bedwire.PacketKind.disconnect, packets.next().?.kind);
    try testing.expectError(error.InvalidState, pair.server.encodeOne(build.makeId(60)));
}
