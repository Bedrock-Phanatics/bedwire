const std = @import("std");
const zigrock = @import("zigrock");

test "SPKI exact DER, truncation, altered OID, and invalid points" {
    const key = try zigrock.spki.Ecdsa.KeyPair.generateDeterministic(@splat(1));
    var der = zigrock.spki.encode(key.public_key);
    try std.testing.expectEqualSlices(u8, &key.public_key.toUncompressedSec1(), &(try zigrock.spki.decode(&der)).toUncompressedSec1());
    for (0..der.len) |end| try std.testing.expectError(error.InvalidPublicKey, zigrock.spki.decode(der[0..end]));
    for (0..24) |i| {
        der[i] ^= 1;
        try std.testing.expectError(error.InvalidPublicKey, zigrock.spki.decode(&der));
        der[i] ^= 1;
    }
    @memset(der[24..], 0);
    try std.testing.expectError(error.InvalidPublicKey, zigrock.spki.decode(&der));
}
