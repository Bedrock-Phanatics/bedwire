const std = @import("std");

/// semantic packet tags used by the handshake state machine
/// gameplay packets not checked by bedwire map to .other
pub const PacketKind = enum {
    request_network_settings,
    network_settings,
    login,
    play_status,
    server_to_client_handshake,
    client_to_server_handshake,
    disconnect,
    resource_packs_info,
    resource_pack_stack,
    resource_pack_client_response,
    resource_pack_data_info,
    resource_pack_chunk_data,
    resource_pack_chunk_request,
    resource_packs_ready_for_validation,
    client_cache_status,
    start_game,
    request_chunk_radius,
    chunk_radius_updated,
    set_local_player_as_initialised,
    other,

    /// handshake packets not allowed in active gameplay
    pub fn isHandshake(self: PacketKind) bool {
        return switch (self) {
            .request_network_settings,
            .network_settings,
            .login,
            .server_to_client_handshake,
            .client_to_server_handshake,
            .resource_packs_info,
            .resource_pack_stack,
            .resource_pack_client_response,
            .resource_pack_data_info,
            .resource_pack_chunk_data,
            .resource_pack_chunk_request,
            .resource_packs_ready_for_validation,
            .start_game,
            => true,
            else => false,
        };
    }
};

// all mapped kinds excluding .other
pub const mapped = blk: {
    const all = std.enums.values(PacketKind);
    var list: [all.len - 1]PacketKind = undefined;
    var count: usize = 0;
    for (all) |kind| {
        if (kind == .other) continue;
        list[count] = kind;
        count += 1;
    }
    break :blk list;
};

test "handshake classification covers every stage-gated kind" {
    try std.testing.expect(PacketKind.login.isHandshake());
    try std.testing.expect(PacketKind.start_game.isHandshake());
    try std.testing.expect(!PacketKind.other.isHandshake());
    try std.testing.expect(!PacketKind.disconnect.isHandshake());
    try std.testing.expectEqual(std.enums.values(PacketKind).len - 1, mapped.len);
}
