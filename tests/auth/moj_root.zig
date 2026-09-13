const std = @import("std");
const bedwire = @import("bedwire");
test "pinned Mojang root is canonical P384 SPKI" {
    const der = bedwire.spki.encode(bedwire.auth.moj_root.key());
    try std.testing.expectEqual(@as(u8, 9), der[24]);
}
