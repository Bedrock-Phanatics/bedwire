const std = @import("std");
const bedwire = @import("bedwire");

test "P384 ECDH derives identical salted keys on both peers" {
    const a = try bedwire.spki.Ecdsa.KeyPair.generateDeterministic(@splat(1));
    const b = try bedwire.spki.Ecdsa.KeyPair.generateDeterministic(@splat(2));
    const first = try bedwire.ecdh.derive(a.secret_key, b.public_key, @splat(3));
    const second = try bedwire.ecdh.derive(b.secret_key, a.public_key, @splat(3));
    try std.testing.expectEqualSlices(u8, &first, &second);
    try std.testing.expect(!std.mem.eql(u8, &first, &try bedwire.ecdh.derive(a.secret_key, b.public_key, @splat(4))));
}
