const std = @import("std");
const zigrock = @import("zigrock");
test "pinned Mojang root is canonical P384 SPKI" {
    const der = zigrock.spki.encode(zigrock.auth.moj_root.key());
    try std.testing.expectEqual(@as(u8, 9), der[24]);
}
