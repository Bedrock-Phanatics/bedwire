const std = @import("std");
const zigrock = @import("zigrock");
test "server rejects gameplay until in-game and repeated negotiation afterwards" {
    for ([_]zigrock.session.State{ .handshake, .authenticating, .encrypted_handshake, .resource_packs, .waiting_for_start_game, .spawn_ready }) |state| {
        try std.testing.expect(!state.permits(.client, 19));
    }
    try std.testing.expect(zigrock.session.State.in_game.permits(.client, 19));
    try std.testing.expect(!zigrock.session.State.in_game.permits(.client, 1));
}
