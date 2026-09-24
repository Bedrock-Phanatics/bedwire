const std = @import("std");

const protocol = @import("bedrock_protocol");
const PacketKind = protocol.PacketKind;
const PacketDirection = protocol.PacketDirection;
const SessionFeatures = protocol.SessionFeatures;

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

/// bedrock connection phases
///
/// sequence of handshake packets
/// transport_ready -> RequestNetworkSettings
/// network_settings -> NetworkSettings (compression algo/threshold)
/// authenticating -> Login (mojang cert chain or xbox oidc)
/// encrypted_handshake -> ServerToClientHandshake / ClientToServerHandshake
/// resource_packs -> ResourcePacksInfo, Stack, etc
/// waiting_for_start_game -> StartGame
/// spawn_ready -> RequestChunkRadius, SetLocalPlayerAsInitialised
/// in_game -> gameplay traffic
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

    /// older versions without network settings start directly at auth
    pub fn initial(session_features: SessionFeatures) State {
        return if (session_features.uses_request_network_settings) .transport_ready else .authenticating;
    }

    pub fn active(self: State) bool {
        return self != .closing and self != .disconnected;
    }

    // early handshake only allows 1 packet per batch to prevent smuggling or cipher desync
    pub fn singlePacketBatch(self: State) bool {
        return switch (self) {
            .transport_ready, .network_settings, .authenticating, .encrypted_handshake => true,
            else => false,
        };
    }

    /// whether a given packet type can be sent in the current phase
    pub fn permits(self: State, session_features: SessionFeatures, sender: Role, kind: ?PacketKind) bool {
        const packet_direction = if (kind) |known| protocol.Current.packetDirection(known) else .bidirectional;
        return self.permitsWithDirection(session_features, sender, kind, packet_direction);
    }

    /// Profile-aware state admission; unknown packet IDs remain application-owned.
    pub fn permitsWithDirection(self: State, session_features: SessionFeatures, sender: Role, kind: ?PacketKind, packet_direction: PacketDirection) bool {
        if (self == .disconnected) return false;
        if (kind == .disconnect) return true;
        if (self == .closing) return false;
        const effective_direction: PacketDirection = if (kind) |known| switch (known) {
            .client_cache_status, .set_local_player_as_initialised => .client_to_server,
            else => packet_direction,
        } else packet_direction;
        return self.permitsKnown(session_features, sender, kind, effective_direction);
    }

    fn permitsKnown(self: State, session_features: SessionFeatures, sender: Role, kind: ?PacketKind, packet_direction: PacketDirection) bool {
        const effective_direction = packet_direction;
        return switch (self) {
            .transport_ready => sender == .client and
                kind == .request_network_settings and
                session_features.uses_request_network_settings,

            .network_settings => sender == .server and kind == .network_settings,

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

fn isGenericGameplay(kind: ?PacketKind) bool {
    return switch (kind orelse return true) {
        .request_network_settings, .network_settings, .login, .play_status, .server_to_client_handshake, .client_to_server_handshake, .disconnect, .resource_packs_info, .resource_pack_stack, .resource_pack_client_response, .resource_pack_data_info, .resource_pack_chunk_data, .resource_pack_chunk_request, .resource_packs_ready_for_validation, .client_cache_status, .start_game, .request_chunk_radius, .chunk_radius_updated, .set_local_player_as_initialised => false,
        else => true,
    };
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
    try testing.expect(!State.in_game.permits(modern, .client, .play_status));
    try testing.expect(State.in_game.permits(modern, .client, .request_chunk_radius));
    try testing.expect(!State.in_game.permits(modern, .server, .request_chunk_radius));
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
    try testing.expect(State.spawn_ready.permits(modern, .server, .set_time));
    try testing.expect(!State.in_game.permits(modern, .client, .set_time));
    try testing.expect(State.in_game.permits(modern, .server, .set_time));
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
