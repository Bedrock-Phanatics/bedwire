const std = @import("std");
const n = @import("network");
test "pinned Mojang root is canonical P384 SPKI" {
    const der = n.spki.encode(n.auth.moj_root.key());
    try std.testing.expectEqual(@as(u8, 9), der[24]);
}
