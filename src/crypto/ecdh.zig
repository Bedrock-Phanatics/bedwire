const std = @import("std");
const Ecdsa = @import("spki.zig").Ecdsa;

/// derives 32-byte shared secret via p-384 ecdh and sha256(salt ++ x)
pub fn derive(secret: Ecdsa.SecretKey, peer: Ecdsa.PublicKey, salt: [16]u8) ![32]u8 {
    const point = try std.crypto.ecc.P384.fromSec1(&peer.toUncompressedSec1());
    const shared = try point.mul(secret.toBytes(), .big);
    var x = shared.affineCoordinates().x.toBytes(.big);
    defer std.crypto.secureZero(u8, &x);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&salt);
    hash.update(&x);
    return hash.finalResult();
}
