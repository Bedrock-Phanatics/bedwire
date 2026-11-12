const std = @import("std");

const control = @import("../wire/control.zig");
const PacketKind = control.PacketKind;
const PacketDirection = control.Direction;
const SessionFeatures = @import("features.zig").SessionFeatures;

pub const Role = enum {
    client,
    server,

    pub fn peer(self: Role) Role {
        return switch (self) {
            .client => .server,
            .server => .client,
        };
    }
};

pub const State = enum {
    transport_ready,
    network_settings,
    authenticating,
    encrypted_handshake,
    resource_packs,
    waiting_for_start_game,
    spawn_ready,
    in_game,
    closing,
    disconnected,

    pub fn initial(session_features: SessionFeatures) State {
        return if (session_features.uses_request_network_settings) .transport_ready else .authenticating;
    }

    pub fn active(self: State) bool {
        return self != .closing and self != .disconnected;
    }

    pub fn singlePacketBatch(self: State) bool {
        return switch (self) {
            .transport_ready, .network_settings, .authenticating, .encrypted_handshake => true,
            else => false,
        };
    }

    /// Other packet IDs pass as `null` and may travel either way here; `Directions` narrows them.
    pub fn permits(self: State, session_features: SessionFeatures, sender: Role, kind: ?PacketKind) bool {
        if (self == .disconnected) return false;
        if (kind == .disconnect) return true;
        if (self == .closing) return false;
        const effective_direction: PacketDirection = if (kind) |known| known.direction() else .bidirectional;
        return switch (self) {
            .transport_ready => sender == .client and
                kind == .request_network_settings and
                session_features.uses_request_network_settings,

            // An outdated client is told so with a PlayStatus in place of the settings.
            .network_settings => sender == .server and (kind == .network_settings or kind == .play_status),

            .authenticating => switch (sender) {
                .client => kind == .login,
                .server => kind == .server_to_client_handshake or kind == .play_status,
            },

            .encrypted_handshake => switch (sender) {
                .client => kind == .client_to_server_handshake,
                .server => kind == .play_status,
            },

            .resource_packs => switch (sender) {
                .client => kind == .resource_pack_client_response or
                    kind == .resource_pack_chunk_request or
                    kind == .client_cache_status or
                    (kind == .resource_packs_ready_for_validation and
                        session_features.resource_pack_flow == .with_validation),
                .server => kind == .resource_packs_info or
                    kind == .resource_pack_stack or
                    kind == .resource_pack_data_info or
                    kind == .resource_pack_chunk_data or
                    kind == .play_status,
            },

            .waiting_for_start_game => if (kind == .start_game or kind == .play_status)
                sender == .server
            else
                sender == .server and isGenericGameplay(kind) and permitsDirection(effective_direction, sender),

            .spawn_ready => switch (sender) {
                .client => kind == .request_chunk_radius or
                    kind == .set_local_player_as_initialised or
                    kind == .client_cache_status or
                    (isGenericGameplay(kind) and permitsDirection(effective_direction, sender)),
                .server => kind == .chunk_radius_updated or kind == .play_status or
                    (isGenericGameplay(kind) and permitsDirection(effective_direction, sender)),
            },

            .in_game => !isHandshake(kind) and permitsDirection(effective_direction, sender),

            .closing, .disconnected => false,
        };
    }
};

/// Which non-control packet IDs each side may send. Shared read-only between sessions.
pub const Directions = struct {
    pub const IdSet = std.StaticBitSet(1 << @bitSizeOf(control.PacketId));

    client: IdSet = .full,
    server: IdSet = .full,

    pub fn permits(self: *const Directions, sender: Role, id: control.PacketId) bool {
        return switch (sender) {
            .client => self.client.isSet(id),
            .server => self.server.isSet(id),
        };
    }
};

pub const Startup = struct {
    packs_completed: bool = false,
    runtime_id: ?u64 = null,
    spawned: bool = false,
    initialized: bool = false,
};

pub fn oncePerSession(kind: PacketKind) bool {
    return switch (kind) {
        .request_network_settings, .network_settings, .login, .server_to_client_handshake, .client_to_server_handshake, .start_game => true,
        else => false,
    };
}

fn permitsDirection(packet_direction: PacketDirection, sender: Role) bool {
    return switch (packet_direction) {
        .client_to_server => sender == .client,
        .server_to_client => sender == .server,
        .bidirectional => true,
    };
}

fn isHandshake(kind: ?PacketKind) bool {
    return switch (kind orelse return false) {
        .request_network_settings, .network_settings, .login, .server_to_client_handshake, .client_to_server_handshake, .resource_packs_info, .resource_pack_stack, .resource_pack_client_response, .resource_pack_data_info, .resource_pack_chunk_data, .resource_pack_chunk_request, .resource_packs_ready_for_validation, .start_game => true,
        else => false,
    };
}

// Every control kind has its own stage rule, so only other IDs count as gameplay.
fn isGenericGameplay(kind: ?PacketKind) bool {
    return kind == null;
}

const testing = std.testing;
const modern: SessionFeatures = .{};
const legacy: SessionFeatures = .{
    .uses_request_network_settings = false,
    .compression_mode = .implicit,
    .supports_snappy = false,
    .initial_algorithm = .deflate,
    .resource_pack_flow = .classic,
};

test "initial stage follows the version profile" {
    try testing.expectEqual(State.transport_ready, State.initial(modern));
    try testing.expectEqual(State.authenticating, State.initial(legacy));
}

test "disconnect is admitted from every live stage and refused once closed" {
    for (std.enums.values(State)) |state| {
        const expected = state != .disconnected;
        try testing.expectEqual(expected, state.permits(modern, .client, .disconnect));
        try testing.expectEqual(expected, state.permits(modern, .server, .disconnect));
    }
}

test "handshake stages admit exactly their own step from exactly one side" {
    try testing.expect(State.transport_ready.permits(modern, .client, .request_network_settings));
    try testing.expect(!State.transport_ready.permits(modern, .server, .request_network_settings));
    try testing.expect(!State.transport_ready.permits(modern, .client, .login));
    try testing.expect(!State.transport_ready.permits(legacy, .client, .request_network_settings));

    try testing.expect(State.network_settings.permits(modern, .server, .network_settings));
    try testing.expect(!State.network_settings.permits(modern, .client, .network_settings));

    try testing.expect(State.authenticating.permits(modern, .client, .login));
    try testing.expect(State.authenticating.permits(modern, .server, .server_to_client_handshake));
    try testing.expect(!State.authenticating.permits(modern, .client, .client_to_server_handshake));

    try testing.expect(State.encrypted_handshake.permits(modern, .client, .client_to_server_handshake));
    try testing.expect(!State.encrypted_handshake.permits(modern, .client, .login));
}

test "validation acknowledgement follows the resource pack flow feature" {
    try testing.expect(State.resource_packs.permits(modern, .client, .resource_packs_ready_for_validation));
    try testing.expect(!State.resource_packs.permits(legacy, .client, .resource_packs_ready_for_validation));
    try testing.expect(State.resource_packs.permits(legacy, .client, .resource_pack_client_response));
    try testing.expect(!State.resource_packs.permits(modern, .server, .resource_pack_client_response));
    try testing.expect(!State.resource_packs.permits(modern, .client, null));
}

test "gameplay stages refuse every handshake kind" {
    for (std.enums.values(PacketKind)) |kind| {
        if (!isHandshake(kind)) continue;
        try testing.expect(!State.in_game.permits(modern, .client, kind));
        try testing.expect(!State.in_game.permits(modern, .server, kind));
    }

    try testing.expect(State.in_game.permits(modern, .client, null));
    try testing.expect(State.in_game.permits(modern, .server, null));
    try testing.expect(State.in_game.permits(modern, .server, .play_status));
    try testing.expect(State.network_settings.permits(modern, .server, .play_status));
    try testing.expect(!State.network_settings.permits(modern, .client, .play_status));
    try testing.expect(!State.in_game.permits(modern, .client, .play_status));
    try testing.expect(State.in_game.permits(modern, .server, .chunk_radius_updated));
    try testing.expect(!State.in_game.permits(modern, .client, .chunk_radius_updated));
    try testing.expect(State.in_game.permits(modern, .client, .client_cache_status));
    try testing.expect(!State.in_game.permits(modern, .server, .client_cache_status));
    try testing.expect(State.in_game.permits(modern, .client, .set_local_player_as_initialised));
    try testing.expect(!State.in_game.permits(modern, .server, .set_local_player_as_initialised));
    try testing.expect(State.waiting_for_start_game.permits(modern, .server, .start_game));
    try testing.expect(!State.waiting_for_start_game.permits(modern, .client, null));
    try testing.expect(State.spawn_ready.permits(modern, .client, .set_local_player_as_initialised));
}

test "pre-game stages keep session packet directions" {
    try testing.expect(!State.waiting_for_start_game.permits(modern, .server, .client_cache_status));
    try testing.expect(!State.spawn_ready.permits(modern, .server, .request_chunk_radius));
    try testing.expect(!State.spawn_ready.permits(modern, .client, .chunk_radius_updated));
    try testing.expect(State.spawn_ready.permits(modern, .server, null));
    try testing.expect(!State.waiting_for_start_game.permits(modern, .client, null));
    try testing.expect(State.in_game.permits(modern, .server, .request_chunk_radius));
    try testing.expect(State.in_game.permits(modern, .client, .request_chunk_radius));
}

test "closing and disconnected admit nothing but disconnect" {
    for (std.enums.values(PacketKind)) |kind| {
        if (kind == .disconnect) continue;
        try testing.expect(!State.closing.permits(modern, .client, kind));
        try testing.expect(!State.disconnected.permits(modern, .server, kind));
    }
    try testing.expect(!State.disconnected.permits(modern, .server, .disconnect));
}

test "single-packet batching covers exactly the handshake stages" {
    try testing.expect(State.transport_ready.singlePacketBatch());
    try testing.expect(State.authenticating.singlePacketBatch());
    try testing.expect(State.encrypted_handshake.singlePacketBatch());
    try testing.expect(!State.resource_packs.singlePacketBatch());
    try testing.expect(!State.in_game.singlePacketBatch());
}

test "direction tables default to permitting every ID from both sides" {
    var directions: Directions = .{};
    try testing.expect(directions.permits(.client, 1023) and directions.permits(.server, 0));
    directions.client = .empty;
    directions.client.set(144);
    try testing.expect(directions.permits(.client, 144));
    try testing.expect(!directions.permits(.client, 145));
    try testing.expect(directions.permits(.server, 145));
}
