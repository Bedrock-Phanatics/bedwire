const std = @import("std");
const Aes = std.crypto.core.aes.Aes256;

/// The AES-256-CTR keystream continues across batches for the whole session.
/// MAC is sha256(le_u64(counter) ++ payload ++ key)[0..8].
pub const SessionCrypto = struct {
    key: [32]u8,
    aes: Ctx,
    inbound: Stream = .{},
    outbound: Stream = .{},
    recv_counter: u64 = 0,
    send_counter: u64 = 0,
    closed: bool = false,

    pub fn init(key: [32]u8) SessionCrypto {
        return .{ .key = key, .aes = Aes.initEnc(key) };
    }

    pub fn deinit(self: *SessionCrypto) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.closed = true;
    }

    /// Encrypts storage[0..payload_len] in place and appends the MAC.
    pub fn seal(self: *SessionCrypto, storage: []u8, payload_len: usize) ![]u8 {
        if (self.closed) return error.SessionClosed;
        if (payload_len > storage.len or storage.len - payload_len < 8) return error.NoSpaceLeft;
        if (self.send_counter == std.math.maxInt(u64)) return error.CounterExhausted;

        const bytes = storage[0 .. payload_len + 8];
        try self.outbound.check(bytes.len);

        @memcpy(bytes[payload_len..], &self.checksum(self.send_counter, bytes[0..payload_len]));
        self.outbound.xor(self.aes, self.key[0..12].*, bytes);
        self.send_counter += 1;

        return bytes;
    }

    /// Any failure closes the context; a bad MAC also restores the ciphertext.
    pub fn open(self: *SessionCrypto, bytes: []u8) ![]u8 {
        if (self.closed) return error.SessionClosed;
        errdefer self.closed = true;
        if (bytes.len < 8) return error.MalformedBatch;
        if (self.recv_counter == std.math.maxInt(u64)) return error.CounterExhausted;
        try self.inbound.check(bytes.len);

        var original = self.inbound;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&original));

        self.inbound.xor(self.aes, self.key[0..12].*, bytes);

        const payload = bytes[0 .. bytes.len - 8];
        const actual: [8]u8 = bytes[bytes.len - 8 ..][0..8].*;
        const expected = self.checksum(self.recv_counter, payload);

        if (!std.crypto.timing_safe.eql([8]u8, actual, expected)) {
            original.xor(self.aes, self.key[0..12].*, bytes);
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

const Ctx = std.crypto.core.aes.AesEncryptCtx(Aes);

/// Both directions share the key schedule and nonce; only their positions differ.
const Stream = struct {
    counter: u64 = 2,
    block: [16]u8 = undefined,
    position: usize = 16,

    fn check(self: *const Stream, len: usize) !void {
        const remaining = 16 - self.position;
        const needed = len -| remaining;
        const blocks = needed / 16 + @intFromBool(needed % 16 != 0);
        if (blocks > (@as(u64, 1) << 32) - self.counter) return error.CounterExhausted;
    }

    fn xor(self: *Stream, aes: Ctx, nonce: [12]u8, bytes: []u8) void {
        var rest = bytes;
        if (self.position != 16) {
            const count = @min(rest.len, 16 - self.position);
            xorInto(rest[0..count], self.block[self.position..][0..count]);
            self.position += count;
            rest = rest[count..];
        }

        const whole = rest.len & ~@as(usize, 15);
        if (whole != 0) {
            std.crypto.core.modes.ctrSlice(Ctx, aes, rest[0..whole], rest[0..whole], self.iv(nonce), .big, 12, 4);
            self.counter += whole / 16;
            rest = rest[whole..];
        }

        if (rest.len != 0) {
            aes.encrypt(&self.block, &self.iv(nonce));
            self.counter += 1;
            xorInto(rest, self.block[0..rest.len]);
            self.position = rest.len;
        }
    }

    fn iv(self: *const Stream, nonce: [12]u8) [16]u8 {
        var block: [16]u8 = undefined;
        block[0..12].* = nonce;
        std.mem.writeInt(u32, block[12..16], @intCast(self.counter), .big);
        return block;
    }
};

fn xorInto(bytes: []u8, keystream: []const u8) void {
    for (bytes, keystream) |*byte, key_byte| byte.* ^= key_byte;
}
