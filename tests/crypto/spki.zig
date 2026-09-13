const std = @import("std");
const n = @import("network");

test "SPKI exact DER, truncation, altered OID, and invalid points" {
    const key = try n.spki.Ecdsa.KeyPair.generateDeterministic(@splat(1));
    var der = n.spki.encode(key.public_key);
    try std.testing.expectEqualSlices(u8, &key.public_key.toUncompressedSec1(), &(try n.spki.decode(&der)).toUncompressedSec1());
    for (0..der.len) |end| try std.testing.expectError(error.InvalidPublicKey, n.spki.decode(der[0..end]));
    for (0..24) |i| {
        der[i] ^= 1;
        try std.testing.expectError(error.InvalidPublicKey, n.spki.decode(&der));
        der[i] ^= 1;
    }
    @memset(der[24..], 0);
    try std.testing.expectError(error.InvalidPublicKey, n.spki.decode(&der));
}
