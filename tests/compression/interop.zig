const std = @import("std");
const bedwire = @import("bedwire");

test "independent Go raw compression, P384 and continuous AES-CTR fixtures" {
    const Fixture = struct { plain: []const u8, snappy: []const u8, flate: []const u8, ciphertext: []const []const u8, ecdh_key: []const u8 };
    const parsed = try std.json.parseFromSlice(Fixture, std.testing.allocator, @embedFile("interop.json"), .{});
    defer parsed.deinit();
    const fixture = parsed.value;
    var plain: [4096]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&plain, fixture.plain);
    var compressed: [1024]u8 = undefined;
    var output: [4096]u8 = undefined;
    const snappy = try std.fmt.hexToBytes(&compressed, fixture.snappy);
    try std.testing.expectEqualSlices(u8, expected, try bedwire.snappy.decompress(snappy, &output, .{}));
    const workspace = try bedwire.FlateWorkspace.create(std.testing.allocator, 4096);
    defer workspace.destroy();
    const flate = try std.fmt.hexToBytes(&compressed, fixture.flate);
    try std.testing.expectEqualSlices(u8, expected, try workspace.decompress(flate, .{}));
    var crypto = bedwire.SessionCrypto.init(@splat(0x42));
    defer crypto.deinit();
    for (fixture.ciphertext, [_][]const u8{ "abc", "12345678901234567", "hi" }) |hex, payload| {
        const bytes = try std.fmt.hexToBytes(&compressed, hex);
        try std.testing.expectEqualStrings(payload, try crypto.open(bytes));
    }
    var scalar_a = [_]u8{0} ** 48;
    var scalar_b = scalar_a;
    scalar_a[47] = 1;
    scalar_b[47] = 2;
    const a = try bedwire.spki.Ecdsa.KeyPair.fromSecretKey(try .fromBytes(scalar_a));
    const b = try bedwire.spki.Ecdsa.KeyPair.fromSecretKey(try .fromBytes(scalar_b));
    const derived = try bedwire.ecdh.derive(a.secret_key, b.public_key, @splat(3));
    try std.testing.expectEqualSlices(u8, try std.fmt.hexToBytes(&compressed, fixture.ecdh_key), &derived);
}
