const std = @import("std");
const bedwire = @import("bedwire");
test "server rejects gameplay until in-game and repeated negotiation afterwards" {
    for ([_]bedwire.session.State{ .handshake, .authenticating, .encrypted_handshake, .resource_packs, .waiting_for_start_game, .spawn_ready }) |state| {
        try std.testing.expect(!state.permits(.client, 19));
    }
    try std.testing.expect(bedwire.session.State.in_game.permits(.client, 19));
    try std.testing.expect(!bedwire.session.State.in_game.permits(.client, 1));
}
