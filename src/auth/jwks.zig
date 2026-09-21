const std = @import("std");

const Limits = @import("../limits.zig").Limits;
const jwt = @import("jwt.zig");

pub const KeyEntry = struct {
    kid: [64]u8,
    kid_len: u8,
    key: std.crypto.Certificate.rsa.PublicKey,

    pub fn kidSlice(self: *const KeyEntry) []const u8 {
        return self.kid[0..self.kid_len];
    }
};

pub const KeySet = struct {
    allocator: std.mem.Allocator,
    backing: []KeyEntry,
    count: usize,

    pub fn entries(self: KeySet) []const KeyEntry {
        return self.backing[0..self.count];
    }

    pub fn deinit(self: *KeySet) void {
        self.allocator.free(self.backing);
        self.* = undefined;
    }

    pub fn find(self: KeySet, kid: []const u8) !std.crypto.Certificate.rsa.PublicKey {
        var match: ?std.crypto.Certificate.rsa.PublicKey = null;
        for (self.entries()) |entry| {
            if (std.mem.eql(u8, entry.kidSlice(), kid)) {
                if (match != null) return error.AmbiguousKey;
                match = entry.key;
            }
        }
        return match orelse error.UnknownKey;
    }

    pub fn parse(allocator: std.mem.Allocator, json_bytes: []const u8, limits: Limits) !KeySet {
        if (json_bytes.len == 0) return error.InvalidJwks;
        if (json_bytes.len > limits.max_jwks_bytes) return error.LimitExceeded;

        if (!std.unicode.utf8ValidateSlice(json_bytes)) return error.InvalidUtf8;

        var depth: usize = 0;
        var quoted = false;
        var escaped = false;

        for (json_bytes) |byte| {
            if (quoted) {
                if (escaped) {
                    escaped = false;
                    continue;
                }
                if (byte == '\\') {
                    escaped = true;
                } else if (byte == '"') {
                    quoted = false;
                }
                continue;
            }

            switch (byte) {
                '"' => quoted = true,
                '{', '[' => {
                    depth += 1;
                    if (depth > limits.max_json_nesting) return error.LimitExceeded;
                },
                '}', ']' => {
                    if (depth == 0) return error.InvalidJson;
                    depth -= 1;
                },
                else => {},
            }
        }
        if (depth != 0) return error.InvalidJson;

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{
            .max_value_len = limits.max_jwks_bytes,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidJson,
        };
        defer parsed.deinit();

        if (parsed.value != .object) return error.InvalidJwks;

        const keys_val = parsed.value.object.get("keys") orelse return error.InvalidJwks;
        if (keys_val != .array) return error.InvalidJwks;
        const items = keys_val.array.items;
        if (items.len > limits.max_jwks_keys) return error.LimitExceeded;

        const backing = try allocator.alloc(KeyEntry, items.len);
        errdefer allocator.free(backing);

        var count: usize = 0;
        for (items) |item| {
            if (item != .object) return error.InvalidJwks;

            const kty = jwt.string(item, "kty") catch return error.InvalidJwks;
            if (!std.mem.eql(u8, kty, "RSA")) continue;

            if (item.object.get("use")) |u| {
                if (u != .string or !std.mem.eql(u8, u.string, "sig")) continue;
            }

            if (item.object.get("alg")) |a| {
                if (a != .string or !std.mem.eql(u8, a.string, "RS256")) continue;
            }

            const kid_str = jwt.string(item, "kid") catch return error.InvalidJwks;
            if (kid_str.len == 0 or kid_str.len > limits.max_kid_bytes or kid_str.len > 64) return error.InvalidJwks;

            const n_str = jwt.string(item, "n") catch return error.InvalidJwks;
            var n_bytes: [256]u8 = undefined;
            const n_decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(n_str) catch return error.InvalidJwks;
            if (n_decoded_len != 256) return error.InvalidJwks;
            std.base64.url_safe_no_pad.Decoder.decode(&n_bytes, n_str) catch return error.InvalidJwks;

            const e_str = jwt.string(item, "e") catch return error.InvalidJwks;
            var e_buf: [4]u8 = undefined;
            const e_decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(e_str) catch return error.InvalidJwks;
            if (e_decoded_len == 0 or e_decoded_len > 4) return error.InvalidJwks;
            std.base64.url_safe_no_pad.Decoder.decode(e_buf[0..e_decoded_len], e_str) catch return error.InvalidJwks;

            const pub_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(e_buf[0..e_decoded_len], &n_bytes) catch return error.InvalidJwks;

            var entry: KeyEntry = undefined;
            @memcpy(entry.kid[0..kid_str.len], kid_str);
            entry.kid_len = @intCast(kid_str.len);
            entry.key = pub_key;

            backing[count] = entry;
            count += 1;
        }

        if (count == 0) return error.EmptyKeySet;

        return .{
            .allocator = allocator,
            .backing = backing,
            .count = count,
        };
    }
};
