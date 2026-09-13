const std = @import("std");
const bedwire = @import("bedwire");

test "CTR matches stdlib across every block remainder and packet length" {
    const key = [_]u8{0x37} ** 32;
    for (0..16) |remainder| {
        for (0..65) |len| {
            var sender = bedwire.SessionCrypto.init(key);
            defer sender.deinit();
            var receiver = bedwire.SessionCrypto.init(key);
            defer receiver.deinit();
            var plain: [96]u8 = undefined;
            var wire: [96]u8 = undefined;
            var total: usize = 0;
            for ([_]usize{ remainder, len }, 0..) |payload_len, counter| {
                var packet: [80]u8 = @splat(0x5a);
                @memcpy(plain[total..][0..payload_len], packet[0..payload_len]);
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                var encoded: [8]u8 = undefined;
                std.mem.writeInt(u64, &encoded, counter, .little);
                hash.update(&encoded);
                hash.update(packet[0..payload_len]);
                hash.update(&key);
                @memcpy(plain[total + payload_len ..][0..8], hash.finalResult()[0..8]);
                const sealed = try sender.seal(&packet, payload_len);
                @memcpy(wire[total..][0..sealed.len], sealed);
                try std.testing.expectEqualSlices(u8, plain[total..][0..payload_len], try receiver.open(sealed));
                total += sealed.len;
            }
            var iv: [16]u8 = undefined;
            @memcpy(iv[0..12], key[0..12]);
            std.mem.writeInt(u32, iv[12..16], 2, .big);
            var expected: [96]u8 = undefined;
            std.crypto.core.modes.ctr(std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256), std.crypto.core.aes.Aes256.initEnc(key), expected[0..total], plain[0..total], iv, .big);
            try std.testing.expectEqualSlices(u8, expected[0..total], wire[0..total]);
        }
    }
}

test "continuous CTR matches stdlib with independent LE checksum counters" {
    const key = [_]u8{0x42} ** 32;
    var sender = bedwire.SessionCrypto.init(key);
    defer sender.deinit();
    var receiver = bedwire.SessionCrypto.init(key);
    defer receiver.deinit();
    var plain: [64]u8 = undefined;
    var wire: [64]u8 = undefined;
    var total: usize = 0;
    for ([_][]const u8{ "abc", "12345678901234567", "hi" }, 0..) |payload, counter| {
        var packet: [40]u8 = undefined;
        @memcpy(packet[0..payload.len], payload);
        const encrypted = try sender.seal(&packet, payload.len);
        @memcpy(wire[total..][0..encrypted.len], encrypted);
        @memcpy(plain[total..][0..payload.len], payload);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var count: [8]u8 = undefined;
        std.mem.writeInt(u64, &count, counter, .little);
        hash.update(&count);
        hash.update(payload);
        hash.update(&key);
        @memcpy(plain[total + payload.len ..][0..8], hash.finalResult()[0..8]);
        total += encrypted.len;
        try std.testing.expectEqualStrings(payload, try receiver.open(encrypted));
    }
    var iv: [16]u8 = undefined;
    @memcpy(iv[0..12], key[0..12]);
    std.mem.writeInt(u32, iv[12..16], 2, .big);
    var expected: [64]u8 = undefined;
    std.crypto.core.modes.ctr(std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256), std.crypto.core.aes.Aes256.initEnc(key), expected[0..total], plain[0..total], iv, .big);
    try std.testing.expectEqualSlices(u8, expected[0..total], wire[0..total]);
}

test "every ciphertext bit corruption fails closed without modifying buffer" {
    for (0..88) |bit| {
        var sender = bedwire.SessionCrypto.init(@splat(1));
        var receiver = bedwire.SessionCrypto.init(@splat(1));
        var bytes = [_]u8{ 1, 2, 3 } ++ ([_]u8{0} ** 8);
        _ = try sender.seal(&bytes, 3);
        bytes[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        const original = bytes;
        try std.testing.expectError(error.ChecksumMismatch, receiver.open(&bytes));
        try std.testing.expectEqualSlices(u8, &original, &bytes);
        try std.testing.expectError(error.ConnectionClosed, receiver.open(&bytes));
    }
}

test "counter exhaustion, short destination and truncated checksum are bounded" {
    var crypto = bedwire.SessionCrypto.init(@splat(1));
    var bytes = [_]u8{0xaa} ** 16;
    try std.testing.expectError(error.NoSpaceLeft, crypto.seal(bytes[0..7], 0));
    try std.testing.expectEqual(@as(u64, 0), crypto.send_counter);
    crypto.send_counter = std.math.maxInt(u64);
    try std.testing.expectError(error.CounterExhausted, crypto.seal(&bytes, 1));
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 16), &bytes);
    crypto.send_counter = 0;
    crypto.outbound.counter = @as(u64, 1) << 32;
    try std.testing.expectError(error.CounterExhausted, crypto.seal(&bytes, 1));
    try std.testing.expectError(error.EndOfStream, crypto.open(bytes[0..7]));
    try std.testing.expect(crypto.closed);
}
