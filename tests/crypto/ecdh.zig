const std = @import("std");
const zigrock = @import("zigrock");

test "P384 ECDH derives identical salted keys on both peers" {
    const a = try zigrock.spki.Ecdsa.KeyPair.generateDeterministic(@splat(1));
    const b = try zigrock.spki.Ecdsa.KeyPair.generateDeterministic(@splat(2));
    const first = try zigrock.ecdh.derive(a.secret_key, b.public_key, @splat(3));
    const second = try zigrock.ecdh.derive(b.secret_key, a.public_key, @splat(3));
    try std.testing.expectEqualSlices(u8, &first, &second);
    try std.testing.expect(!std.mem.eql(u8, &first, &try zigrock.ecdh.derive(a.secret_key, b.public_key, @splat(4))));
}
