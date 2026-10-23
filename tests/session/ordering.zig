const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const State = bedwire.State;
const modern = support.modern;

test "a repeated login is refused on both sides" {
    var pair = try support.Pair.init(testing.allocator, modern);
    defer pair.deinit();
    pair.client.state = .authenticating;
    pair.server.state = .authenticating;

    var build: support.Builder = .{};
    const login = build.make(modern, .login);
    try pair.clientToServerDiscard(&.{login});
    try testing.expectError(error.InvalidState, pair.client.encodeOne(login));

    pair.client.sent.remove(.login);
    try testing.expectError(error.InvalidState, pair.clientToServer(&.{login}));
    try testing.expectEqual(State.disconnected, pair.server.state);
}

test "a second NetworkSettings before negotiation is refused" {
    var pair = try support.Pair.init(testing.allocator, modern);
    defer pair.deinit();
    pair.client.state = .network_settings;
    pair.server.state = .network_settings;
    pair.client.sent.insert(.request_network_settings);
    pair.server.received.insert(.request_network_settings);

    var build: support.Builder = .{};
    const settings = build.make(modern, .network_settings);
    try pair.serverToClientDiscard(&.{settings});
    pair.server.sent.remove(.network_settings);
    try testing.expectError(error.InvalidState, pair.serverToClient(&.{settings}));
    try testing.expectEqual(State.disconnected, pair.client.state);
}

test "StartGame and the initialization ack happen once" {
    var pair = try support.Pair.init(testing.allocator, modern);
    defer pair.deinit();
    pair.server.state = .waiting_for_start_game;
    pair.client.state = .waiting_for_start_game;

    var a: [8]u8 = undefined;
    var b: [8]u8 = undefined;
    const start = support.packet(&a, support.packetId(modern, .start_game), "\x00");
    const again = support.packet(&b, support.packetId(modern, .start_game), "\x00");
    try testing.expectError(error.InvalidState, pair.server.encode(&.{ start, again }));
    try testing.expect(!pair.server.didSend(.start_game));

    pair.server.state = .in_game;
    pair.server.received.insert(.set_local_player_as_initialised);
    pair.client.state = .in_game;
    pair.client.sent.insert(.set_local_player_as_initialised);
    var c: [8]u8 = undefined;
    const ack = support.packet(&c, support.packetId(modern, .set_local_player_as_initialised), "\x01");
    try testing.expectError(error.InvalidState, pair.client.encodeOne(ack));
    pair.client.sent.remove(.set_local_player_as_initialised);
    try testing.expectError(error.InvalidState, pair.clientToServer(&.{ack}));
}

test "resource pack control packets follow the offer" {
    var build: support.Builder = .{};
    var storage: [3][8]u8 = undefined;
    const data_info = support.packet(&storage[0], support.packetId(modern, .resource_pack_data_info), "\x00");
    const chunk_data = support.packet(&storage[1], support.packetId(modern, .resource_pack_chunk_data), "\x00");
    const chunk_request = support.packet(&storage[2], support.packetId(modern, .resource_pack_chunk_request), "\x00");

    var pair = try support.Pair.init(testing.allocator, modern);
    defer pair.deinit();
    pair.server.state = .resource_packs;
    pair.client.state = .resource_packs;

    for ([_][]const u8{ build.make(modern, .resource_pack_stack), data_info, chunk_data }) |early| {
        try testing.expectError(error.InvalidState, pair.server.encodeOne(early));
    }
    try testing.expectError(error.InvalidState, pair.client.encodeOne(build.make(modern, .resource_pack_client_response)));
    try testing.expectError(error.InvalidState, pair.client.encodeOne(chunk_request));

    var info: support.Builder = .{};
    var stack: support.Builder = .{};
    try pair.serverToClientDiscard(&.{ info.make(modern, .resource_packs_info), stack.make(modern, .resource_pack_stack) });
    try testing.expectError(error.InvalidState, pair.client.encodeOne(chunk_request));
    try pair.serverToClientDiscard(&.{data_info});
    try pair.clientToServerDiscard(&.{chunk_request});
    try pair.clientToServerDiscard(&.{build.make(modern, .resource_pack_client_response)});
}

test "server crypto waits for the handshake frame to be released" {
    var pair = try support.Pair.init(testing.allocator, modern);
    defer pair.deinit();
    pair.server.state = .authenticating;
    pair.server.received.insert(.login);
    try pair.server.installVerifiedClientKey((try support.deterministicKey(2)).public_key);

    var build: support.Builder = .{};
    const frame = try pair.server.encodeOne(build.make(modern, .server_to_client_handshake));
    try testing.expectError(error.InvalidState, pair.server.installServerKey(@splat(1)));
    try testing.expectError(error.InvalidState, pair.server.installServerCrypto((try support.deterministicKey(4)).secret_key, @splat(9)));
    try testing.expect(!pair.server.encrypted());
    frame.release();
    try pair.server.installServerKey(@splat(1));
    try testing.expectEqual(State.encrypted_handshake, pair.server.state);
    try testing.expectError(error.InvalidState, pair.server.installServerKey(@splat(2)));
}
