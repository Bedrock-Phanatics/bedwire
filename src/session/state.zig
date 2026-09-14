pub const Role = enum { client, server };
pub const State = enum {
    handshake,
    authenticating,
    encrypted_handshake,
    resource_packs,
    waiting_for_start_game,
    spawn_ready,
    in_game,
    disconnected,

    pub fn permits(self: State, sender: Role, id: u10) bool {
        if (self == .disconnected) return false;
        if (id == 5) return true;
        return switch (self) {
            .handshake => if (sender == .client) id == 193 else id == 143,
            .authenticating => if (sender == .client) id == 1 else id == 3 or id == 2,
            .encrypted_handshake => if (sender == .client) id == 4 else id == 2,
            .resource_packs => if (sender == .client) id == 8 or id == 84 or id == 129 else id == 6 or id == 7 or id == 82 or id == 83 or id == 2,
            .waiting_for_start_game => sender == .server and (id == 11 or id == 162 or id == 122),
            .spawn_ready => if (sender == .client) id == 69 or id == 23 or id == 113 else id == 70 or id == 58 or id == 2 or id == 162 or id == 122,
            .in_game => switch (id) {
                1, 3, 4, 6, 7, 8, 82, 83, 84, 143, 193 => false,
                else => true,
            },
            .disconnected => false,
        };
    }
};
