//! cross-language test fixtures generated from Go reference implementations

const std = @import("std");
const bedwire = @import("bedwire");

const testing = std.testing;

const limits: bedwire.Limits = .{
    .max_frame_bytes = 1 << 20,
    .max_batch_bytes = 1 << 20,
    .max_packet_bytes = 1 << 20,
};

const Fixture = struct {
    plain: []const u8,
    snappy: []const u8,
    flate: []const u8,
    ciphertext: []const []const u8,
    ecdh_key: []const u8,
};

fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const bytes = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(bytes);

    return std.fmt.hexToBytes(bytes, hex);
}

test "Go Snappy and DEFLATE output decodes byte for byte" {
    const allocator = testing.allocator;

    const parsed = try std.json.parseFromSlice(Fixture, allocator, @embedFile("interop.json"), .{});
    defer parsed.deinit();

    const plain = try decodeHex(allocator, parsed.value.plain);
    defer allocator.free(plain);

    const output = try allocator.alloc(u8, plain.len);
    defer allocator.free(output);

    const snappy_bytes = try decodeHex(allocator, parsed.value.snappy);
    defer allocator.free(snappy_bytes);
    try testing.expectEqualSlices(u8, plain, try bedwire.compression.snappy.decompress(snappy_bytes, output, limits));

    const flate_bytes = try decodeHex(allocator, parsed.value.flate);
    defer allocator.free(flate_bytes);

    var history: [bedwire.compression.flate.history_len]u8 = undefined;
    try testing.expectEqualSlices(u8, plain, try bedwire.compression.flate.decompress(flate_bytes, output, &history, limits));
}

test "Go continuous AES-256-CTR sessions open in sequence" {
    const allocator = testing.allocator;

    const parsed = try std.json.parseFromSlice(Fixture, allocator, @embedFile("interop.json"), .{});
    defer parsed.deinit();

    var crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    defer crypto.deinit();

    const payloads = [_][]const u8{ "abc", "12345678901234567", "hi" };
    try testing.expectEqual(payloads.len, parsed.value.ciphertext.len);

    for (parsed.value.ciphertext, payloads) |hex, expected| {
        const bytes = try decodeHex(allocator, hex);
        defer allocator.free(bytes);

        try testing.expectEqualStrings(expected, try crypto.open(bytes));
    }

    try testing.expectEqual(@as(u64, payloads.len), crypto.recv_counter);
}

test "Go P-384 ECDH derives the same session key" {
    const allocator = testing.allocator;

    const parsed = try std.json.parseFromSlice(Fixture, allocator, @embedFile("interop.json"), .{});
    defer parsed.deinit();

    var scalar_a = [_]u8{0} ** 48;
    var scalar_b = scalar_a;
    scalar_a[47] = 1;
    scalar_b[47] = 2;

    const a = try bedwire.crypto.spki.Ecdsa.KeyPair.fromSecretKey(try .fromBytes(scalar_a));
    const b = try bedwire.crypto.spki.Ecdsa.KeyPair.fromSecretKey(try .fromBytes(scalar_b));

    const derived = try bedwire.crypto.ecdh.derive(a.secret_key, b.public_key, @splat(3));

    const expected = try decodeHex(allocator, parsed.value.ecdh_key);
    defer allocator.free(expected);

    try testing.expectEqualSlices(u8, expected, &derived);
}
