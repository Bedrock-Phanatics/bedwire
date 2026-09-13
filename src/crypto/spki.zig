const std = @import("std");
pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
pub const prefix = [_]u8{ 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00 };

pub fn decode(der: []const u8) !Ecdsa.PublicKey {
    const valid = der.len == 120 and std.mem.eql(u8, der[0..prefix.len], &prefix) and der[23] == 4;
    if (!valid) return error.InvalidPublicKey;
    return Ecdsa.PublicKey.fromSec1(der[23..]) catch return error.InvalidPublicKey;
}

pub fn encode(key: Ecdsa.PublicKey) [120]u8 {
    var der: [120]u8 = undefined;
    @memcpy(der[0..prefix.len], &prefix);
    @memcpy(der[23..], &key.toUncompressedSec1());
    return der;
}

pub fn fromBase64(encoded: []const u8) !Ecdsa.PublicKey {
    if (encoded.len != 160) return error.InvalidPublicKey;
    var der: [120]u8 = undefined;
    std.base64.standard.Decoder.decode(&der, encoded) catch return error.InvalidPublicKey;
    return decode(&der);
}
