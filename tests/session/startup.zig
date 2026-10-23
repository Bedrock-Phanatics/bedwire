const std = @import("std");
const bedwire = @import("bedwire");
const protocol = @import("bedrock_protocol");
const support = @import("../support.zig");

const testing = std.testing;
const State = bedwire.State;
const modern = support.modern;

const Packets = struct {
    storage: [6][32]u8 = undefined,

    fn startGame(self: *Packets, runtime_id: u8) []const u8 {
        return support.packet(&self.storage[0], support.packetId(modern, .start_game), &.{ 2, runtime_id });
    }

    fn status(self: *Packets, value: protocol.packets.play_status.PlayStatusType) []const u8 {
        return self.typed(1, .{ .play_status = .{ .status = value } });
    }

    fn initialized(self: *Packets, runtime_id: u64) []const u8 {
        return self.typed(2, .{ .set_local_player_as_initialised = .{ .player_id = runtime_id } });
    }

    fn gameplay(self: *Packets) []const u8 {
        return support.packet(&self.storage[3], support.opaque_packet_id, "x");
    }

    fn typed(self: *Packets, slot: usize, value: protocol.typed.Packet) []const u8 {
        var writer = protocol.Writer.init(&self.storage[slot]);
        protocol.typed.encode(&writer, .{ .header = .{ .packet_id = modern.packetId(protocol.typed.packetKind(value)).? }, .packet = value }) catch unreachable;
        return writer.written();
    }
};

fn startingPair() !support.PairFor(modern) {
    var pair = try support.Pair.init(testing.allocator, modern);
    pair.server.state = .waiting_for_start_game;
    pair.client.state = .waiting_for_start_game;
    return pair;
}

test "both sides record the runtime ID, the spawn and the matching ack" {
    var pair = try startingPair();
    defer pair.deinit();
    var p: Packets = .{};

    try pair.serverToClientDiscard(&.{ p.startGame(7), p.gameplay() });
    for ([_]*support.Session{ &pair.server, &pair.client }) |session| {
        try testing.expectEqual(@as(?u64, 7), session.startup.runtime_id);
        try testing.expectEqual(State.spawn_ready, session.settle());
    }

    try pair.serverToClientDiscard(&.{p.status(.loginsuccess)});
    try testing.expect(!pair.client.startup.spawned);
    try pair.serverToClientDiscard(&.{p.status(.playerspawn)});
    try pair.clientToServerDiscard(&.{p.initialized(7)});
    for ([_]*support.Session{ &pair.server, &pair.client }) |session| {
        try testing.expect(session.startup.spawned and session.startup.initialized);
        try testing.expectEqual(State.in_game, session.settle());
    }
}

test "a spawn that arrives before StartGame still counts" {
    var pair = try startingPair();
    defer pair.deinit();
    var p: Packets = .{};

    try pair.serverToClientDiscard(&.{p.status(.playerspawn)});
    try pair.serverToClientDiscard(&.{p.startGame(3)});
    try pair.client.advance(.spawn_ready);
    try pair.server.advance(.spawn_ready);
    try pair.clientToServerDiscard(&.{p.initialized(3)});
    try pair.client.advance(.in_game);
    try pair.server.advance(.in_game);
}

test "the ack must name the StartGame runtime ID and follow the spawn" {
    var pair = try startingPair();
    defer pair.deinit();
    var p: Packets = .{};

    try pair.serverToClientDiscard(&.{p.startGame(5)});
    _ = pair.server.settle();
    _ = pair.client.settle();
    try testing.expectError(error.InvalidState, pair.client.encodeOne(p.initialized(5)));
    try pair.serverToClientDiscard(&.{p.status(.playerspawn)});
    try testing.expectError(error.InvalidState, pair.client.encodeOne(p.initialized(6)));
    try testing.expect(!pair.client.startup.initialized);

    pair.client.startup.runtime_id = 6;
    try testing.expectError(error.InvalidState, pair.clientToServer(&.{p.initialized(6)}));
    try testing.expectEqual(State.disconnected, pair.server.state);
}

test "advance refuses to skip startup conditions" {
    var pair = try support.Pair.init(testing.allocator, modern);
    defer pair.deinit();
    var build: support.Builder = .{};
    var p: Packets = .{};
    pair.server.state = .resource_packs;
    pair.client.state = .resource_packs;

    try pair.serverToClientDiscard(&.{build.make(modern, .resource_packs_info)});
    try testing.expectError(error.InvalidState, pair.server.advance(.waiting_for_start_game));
    try testing.expectError(error.InvalidState, pair.client.encodeOne(build.make(modern, .resource_pack_client_response)));
    try pair.serverToClientDiscard(&.{build.make(modern, .resource_pack_stack)});
    try pair.clientToServerDiscard(&.{build.make(modern, .resource_pack_client_response)});
    try testing.expect(pair.server.startup.packs_completed and pair.client.startup.packs_completed);
    try testing.expectEqual(State.waiting_for_start_game, pair.server.settle());
    try testing.expectError(error.InvalidState, pair.server.advance(.spawn_ready));

    pair.client.state = .waiting_for_start_game;
    try pair.serverToClientDiscard(&.{ p.startGame(9), p.status(.playerspawn) });
    try testing.expectEqual(State.spawn_ready, pair.server.settle());
    try testing.expectError(error.InvalidState, pair.server.advance(.in_game));
    try testing.expectEqual(State.spawn_ready, pair.server.settle());
}

test "a startup without a pack offer can move on directly" {
    var pair = try support.Pair.init(testing.allocator, modern);
    defer pair.deinit();
    pair.server.state = .resource_packs;
    try testing.expectEqual(State.resource_packs, pair.server.settle());
    try pair.server.advance(.waiting_for_start_game);
}

test "a truncated StartGame is refused" {
    var pair = try startingPair();
    defer pair.deinit();
    var storage: [8]u8 = undefined;
    const truncated = support.packet(&storage, support.packetId(modern, .start_game), "\x02");
    try testing.expectError(error.EndOfStream, pair.server.encodeOne(truncated));
    try testing.expectEqual(@as(?u64, null), pair.server.startup.runtime_id);
    try testing.expectError(error.EndOfStream, pair.serverToClient(&.{truncated}));
}

test "random startup traffic never reaches the game without its conditions" {
    const cases = @max(64, @import("build_options").fuzz_iterations / 100);
    var prng = std.Random.DefaultPrng.init(0x57a7);
    const random = prng.random();
    const targets = [_]State{ .waiting_for_start_game, .spawn_ready, .in_game };

    for (0..cases) |_| {
        var pair = try support.Pair.init(testing.allocator, modern);
        defer pair.deinit();
        pair.server.state = .resource_packs;
        pair.client.state = .resource_packs;

        for (0..24) |_| {
            var p: Packets = .{};
            var build: support.Builder = .{};
            const from_server = random.boolean();
            const packet: []const u8 = switch (random.uintLessThan(u8, 9)) {
                0 => p.startGame(random.intRangeAtMost(u8, 1, 3)),
                1 => p.status(.playerspawn),
                2 => p.status(.loginsuccess),
                3 => p.initialized(random.intRangeAtMost(u8, 1, 3)),
                4 => build.make(modern, .resource_packs_info),
                5 => build.make(modern, .resource_pack_stack),
                6 => build.make(modern, .resource_pack_client_response),
                7 => build.make(modern, .request_chunk_radius),
                else => p.gameplay(),
            };
            const sent = if (from_server) pair.serverToClient(&.{packet}) else pair.clientToServer(&.{packet});
            if (sent) |packets| {
                var received = packets;
                received.deinit();
            } else |_| {}

            for ([_]*support.Session{ &pair.server, &pair.client }) |session| {
                switch (random.uintLessThan(u8, 3)) {
                    0 => _ = session.settle(),
                    1 => session.advance(targets[random.uintLessThan(usize, targets.len)]) catch {},
                    else => {},
                }
                if (session.state == .in_game) try testing.expect(session.startup.initialized and session.startup.spawned and session.startup.runtime_id != null);
                if (session.state == .spawn_ready) try testing.expect(session.startup.runtime_id != null);
                if (session.startup.initialized) try testing.expect(session.startup.spawned);
            }
            if (pair.server.state == .disconnected or pair.client.state == .disconnected) break;
        }
        try testing.expect(pair.pool.isIdle());
    }
}
