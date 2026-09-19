const std = @import("std");
const Aes = std.crypto.core.aes.Aes256;

/// continuous aes-256-ctr stream cipher with 8-byte sha256 mac trailer
///
/// keystream is continuous across packet batches for the lifetime of the session.
/// mac is first 8 bytes of sha256(le_u64(counter) ++ payload ++ key).
/// counter increments after every batch sealed or opened.
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

    /// encrypts storage[0..payload_len] in place and appends the 8-byte mac
    /// caller must slice past the 0xfe header byte before passing storage here
    pub fn seal(self: *SessionCrypto, storage: []u8, payload_len: usize) ![]u8 {
        if (self.closed) return error.SessionClosed;
        if (payload_len > storage.len or storage.len - payload_len < 8) return error.NoSpaceLeft;
        if (self.send_counter == std.math.maxInt(u64)) return error.CounterExhausted;

        const bytes = storage[0 .. payload_len + 8];
        try self.outbound.check(bytes.len);

        @memcpy(bytes[payload_len..], &self.checksum(self.send_counter, bytes[0..payload_len]));
        self.outbound.xor(bytes);
        self.send_counter += 1;

        return bytes;
    }

    /// decrypts in place and checks the 8-byte mac trailer
    /// if the mac doesn't match we roll back ciphertext and kill the crypto context
    pub fn open(self: *SessionCrypto, bytes: []u8) ![]u8 {
        if (self.closed) return error.SessionClosed;
        errdefer self.closed = true;
        if (bytes.len < 8) return error.MalformedBatch;
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
        var cursor: usize = 0;
        while (cursor < bytes.len) {
            if (self.position == 16) {
                var iv: [16]u8 = undefined;
                @memcpy(iv[0..12], &self.nonce);
                std.mem.writeInt(u32, iv[12..16], @intCast(self.counter), .big);
                self.aes.encrypt(&self.block, &iv);
                self.counter += 1;
                self.position = 0;
            }
            const count = @min(bytes.len - cursor, self.block.len - self.position);
            for (bytes[cursor..][0..count], self.block[self.position..][0..count]) |*byte, key_byte| {
                byte.* ^= key_byte;
            }
            self.position += count;
            cursor += count;
        }
    }
};
