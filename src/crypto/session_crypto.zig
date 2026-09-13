const std = @import("std");
const Aes = std.crypto.core.aes.Aes256;

/// Exclusive caller access is required. Never log this struct or copy live sessions.
pub const SessionCrypto = struct {
    key: [32]u8,
    inbound: Stream,
    outbound: Stream,
    recv_counter: u64 = 0,
    send_counter: u64 = 0,
    closed: bool = false,

    pub fn init(key: [32]u8) SessionCrypto {
        return .{ .key = key, .inbound = .init(key), .outbound = .init(key) };
    }

    pub fn deinit(self: *SessionCrypto) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.closed = true;
    }

    /// Encrypts payload plus checksum; caller must exclude the 0xFE frame prefix.
    /// Storage and counters are unchanged on failure.
    pub fn seal(self: *SessionCrypto, storage: []u8, payload_len: usize) ![]u8 {
        if (self.closed) return error.ConnectionClosed;
        if (payload_len > storage.len or storage.len - payload_len < 8) return error.NoSpaceLeft;
        if (self.send_counter == std.math.maxInt(u64)) return error.CounterExhausted;

        const bytes = storage[0 .. payload_len + 8];
        try self.outbound.check(bytes.len);

        @memcpy(bytes[payload_len..], &self.checksum(self.send_counter, bytes[0..payload_len]));
        self.outbound.xor(bytes);
        self.send_counter += 1;

        return bytes;
    }

    /// Excludes 0xFE. On failure restores ciphertext and permanently closes the session.
    pub fn open(self: *SessionCrypto, bytes: []u8) ![]u8 {
        if (self.closed) return error.ConnectionClosed;
        errdefer self.closed = true;
        if (bytes.len < 8) return error.EndOfStream;
        if (self.recv_counter == std.math.maxInt(u64)) return error.CounterExhausted;
        try self.inbound.check(bytes.len);

        var original = self.inbound;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&original));

        self.inbound.xor(bytes);

        const payload = bytes[0 .. bytes.len - 8];
        const actual: [8]u8 = bytes[bytes.len - 8 ..][0..8].*;
        const expected = self.checksum(self.recv_counter, payload);

        if (!std.crypto.timing_safe.eql([8]u8, actual, expected)) {
            original.xor(bytes);
            return error.ChecksumMismatch;
        }

        self.recv_counter += 1;
        return payload;
    }

    fn checksum(self: *const SessionCrypto, counter: u64, payload: []const u8) [8]u8 {
        var encoded: [8]u8 = undefined;
        std.mem.writeInt(u64, &encoded, counter, .little);

        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(&encoded);
        hash.update(payload);
        hash.update(&self.key);
        return hash.finalResult()[0..8].*;
    }
};

const Stream = struct {
    aes: std.crypto.core.aes.AesEncryptCtx(Aes),
    nonce: [12]u8,
    counter: u64 = 2,
    block: [16]u8 = undefined,
    position: usize = 16,

    fn init(key: [32]u8) Stream {
        return .{ .aes = Aes.initEnc(key), .nonce = key[0..12].* };
    }

    fn check(self: *const Stream, len: usize) !void {
        const remaining = 16 - self.position;
        const needed = len -| remaining;
        const blocks = needed / 16 + @intFromBool(needed % 16 != 0);
        if (blocks > (@as(u64, 1) << 32) - self.counter) return error.CounterExhausted;
    }

    fn xor(self: *Stream, bytes: []u8) void {
        for (bytes) |*byte| {
            if (self.position == 16) {
                var iv: [16]u8 = undefined;
                @memcpy(iv[0..12], &self.nonce);
                std.mem.writeInt(u32, iv[12..16], @intCast(self.counter), .big);
                self.aes.encrypt(&self.block, &iv);
                self.counter += 1;
                self.position = 0;
            }
            byte.* ^= self.block[self.position];
            self.position += 1;
        }
    }
};
