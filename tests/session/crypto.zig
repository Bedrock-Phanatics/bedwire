const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const SessionCrypto = bedwire.crypto.SessionCrypto;

/// An encrypted pair in gameplay, both sides holding the same session key.
fn encrypted(allocator: std.mem.Allocator, key: [32]u8) !support.Pair {
    var pair = try support.Pair.init(allocator, &support.modern);
    errdefer pair.deinit();

    try pair.server.compression.negotiate(.snappy, 0);
    try pair.client.compression.negotiate(.snappy, 0);
    pair.server.crypto = SessionCrypto.init(key);
    pair.client.crypto = SessionCrypto.init(key);
    pair.server.state = .in_game;
    pair.client.state = .in_game;

    return pair;
}

test "an encrypted session stays in step over many batches" {
    var pair = try encrypted(testing.allocator, @splat(0x42));
    defer pair.deinit();

    var storage: [256]u8 = undefined;

    for (0..64) |i| {
        const packet = support.packet(&storage, 60, &[_]u8{@intCast(i % 251)});

        var packets = try pair.clientToServer(&.{packet});
        defer packets.deinit();
        try testing.expectEqualSlices(u8, packet, packets.next().?.bytes);
    }

    try testing.expectEqual(@as(u64, 64), pair.client.crypto.?.send_counter);
    try testing.expectEqual(@as(u64, 64), pair.server.crypto.?.recv_counter);
}

test "tampering with any byte of an encrypted frame is detected" {
    var storage: [64]u8 = undefined;

    for (1..20) |index| {
        var pair = try encrypted(testing.allocator, @splat(0x42));
        defer pair.deinit();

        const frame = try pair.client.encode(&.{support.packet(&storage, 60, "tamper")});
        defer frame.release();
        @memcpy(pair.relay[0..frame.bytes.len], frame.bytes);
        const captured = pair.relay[0..frame.bytes.len];
        if (index >= captured.len) continue;

        captured[index] ^= 0x01;
        try testing.expectError(error.ChecksumMismatch, pair.server.ingest(captured));
        try testing.expectEqual(bedwire.State.disconnected, pair.server.state);
    }
}

test "a wrong session key never decrypts" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();

    try pair.server.compression.negotiate(.snappy, 0);
    try pair.client.compression.negotiate(.snappy, 0);
    pair.client.crypto = SessionCrypto.init(@splat(0x42));
    pair.server.crypto = SessionCrypto.init(@splat(0x43));
    pair.client.state = .in_game;
    pair.server.state = .in_game;

    var storage: [64]u8 = undefined;
    try testing.expectError(error.ChecksumMismatch, pair.clientToServer(&.{support.packet(&storage, 60, "x")}));
}

test "a frame shorter than the checksum is refused" {
    var pair = try encrypted(testing.allocator, @splat(0x42));
    defer pair.deinit();

    try testing.expectError(error.MalformedBatch, pair.server.ingest(&.{ 0xfe, 1, 2, 3 }));
    try testing.expectEqual(bedwire.State.disconnected, pair.server.state);
}

test "a failed open closes the session permanently" {
    var crypto = SessionCrypto.init(@splat(0x42));
    defer crypto.deinit();

    var bytes = [_]u8{0} ** 16;
    try testing.expectError(error.ChecksumMismatch, crypto.open(&bytes));
    try testing.expectError(error.SessionClosed, crypto.open(&bytes));
    try testing.expectError(error.SessionClosed, crypto.seal(&bytes, 4));
}

test "a rejected frame is restored so nothing observes plaintext" {
    var sender = SessionCrypto.init(@splat(0x42));
    defer sender.deinit();
    var receiver = SessionCrypto.init(@splat(0x42));
    defer receiver.deinit();

    var storage = [_]u8{0} ** 32;
    @memcpy(storage[0..5], "hello");
    const sealed = try sender.seal(&storage, 5);

    var corrupted: [32]u8 = undefined;
    @memcpy(corrupted[0..sealed.len], sealed);
    corrupted[0] ^= 0xff;

    try testing.expectError(error.ChecksumMismatch, receiver.open(corrupted[0..sealed.len]));
    try testing.expectEqual(corrupted[0], sealed[0] ^ 0xff);
    try testing.expectEqual(@as(u64, 0), receiver.recv_counter);
}

test "seal leaves counters untouched when it cannot fit the checksum" {
    var crypto = SessionCrypto.init(@splat(7));
    defer crypto.deinit();

    var storage = [_]u8{0} ** 8;
    try testing.expectError(error.NoSpaceLeft, crypto.seal(&storage, 4));
    try testing.expectEqual(@as(u64, 0), crypto.send_counter);
    try testing.expectEqual([_]u8{0} ** 8, storage);
}

test "the counters refuse to wrap" {
    var crypto = SessionCrypto.init(@splat(1));
    defer crypto.deinit();
    crypto.send_counter = std.math.maxInt(u64);
    crypto.recv_counter = std.math.maxInt(u64);

    var storage = [_]u8{0} ** 32;
    try testing.expectError(error.CounterExhausted, crypto.seal(&storage, 8));
    try testing.expectError(error.CounterExhausted, crypto.open(&storage));
}

test "the keystream refuses to reuse a block counter" {
    var crypto = SessionCrypto.init(@splat(1));
    defer crypto.deinit();

    var storage = [_]u8{0} ** 64;
    crypto.outbound.counter = (@as(u64, 1) << 32) - 1;
    try testing.expectError(error.CounterExhausted, crypto.seal(&storage, 56));
}

test "deriving a session key matches on both sides and depends on the salt" {
    const server = try support.deterministicKey(11);
    const client = try support.deterministicKey(12);

    const salt: [16]u8 = @splat(3);
    const server_view = try bedwire.crypto.ecdh.derive(server.secret_key, client.public_key, salt);
    const client_view = try bedwire.crypto.ecdh.derive(client.secret_key, server.public_key, salt);
    try testing.expectEqualSlices(u8, &server_view, &client_view);

    const other_salt: [16]u8 = @splat(4);
    const different = try bedwire.crypto.ecdh.derive(server.secret_key, client.public_key, other_salt);
    try testing.expect(!std.mem.eql(u8, &server_view, &different));
}

test "handshake tokens carry a 16-byte salt and reject malformed ones" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(6);

    const token = try bedwire.auth.login.serverHandshake(allocator, key, @splat(7), support.limits);
    defer allocator.free(token);

    const handshake = try bedwire.auth.login.Handshake.verify(allocator, token, support.limits);
    try testing.expectEqual([_]u8{7} ** 16, handshake.salt);

    const header = try std.fmt.allocPrint(allocator, "{{\"alg\":\"ES384\",\"x5u\":\"{s}\"}}", .{support.encodedKey(key.public_key)});
    defer allocator.free(header);

    // Padded, unpadded, over-padded, invalid alphabet, wrong length.
    const salts = [_][]const u8{
        "CQkJCQkJCQkJCQkJCQkJCQ",
        "CQkJCQkJCQkJCQkJCQkJCQ==",
        "CQkJCQkJCQkJCQkJCQkJCQ=",
        "CQkJCQkJCQkJCQkJCQkJC!",
        "CQkJ",
    };

    for (salts, 0..) |salt, i| {
        const payload = try std.fmt.allocPrint(allocator, "{{\"salt\":\"{s}\"}}", .{salt});
        defer allocator.free(payload);

        const signed = try support.signToken(allocator, key, header, payload);
        defer allocator.free(signed);

        if (i < 2) {
            const parsed = try bedwire.auth.login.Handshake.verify(allocator, signed, support.limits);
            try testing.expectEqual([_]u8{9} ** 16, parsed.salt);
        } else {
            try testing.expectError(error.InvalidSalt, bedwire.auth.login.Handshake.verify(allocator, signed, support.limits));
        }
    }
}

test "a handshake token signed by another key is refused" {
    const allocator = testing.allocator;
    const key = try support.deterministicKey(6);
    const impostor = try support.deterministicKey(8);

    const header = try std.fmt.allocPrint(allocator, "{{\"alg\":\"ES384\",\"x5u\":\"{s}\"}}", .{support.encodedKey(key.public_key)});
    defer allocator.free(header);

    const forged = try support.signToken(allocator, impostor, header, "{\"salt\":\"CQkJCQkJCQkJCQkJCQkJCQ==\"}");
    defer allocator.free(forged);

    try testing.expectError(error.InvalidSignature, bedwire.auth.login.Handshake.verify(allocator, forged, support.limits));
}
