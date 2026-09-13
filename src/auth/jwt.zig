const std = @import("std");
const Limits = @import("../framing/limits.zig").DecodeLimits;
const spki = @import("../crypto/spki.zig");

/// Owns decoded JSON. Header and payload remain untrusted until verify succeeds.
pub const Token = struct {
    allocator: std.mem.Allocator,
    header_bytes: []u8,
    payload_bytes: []u8,
    header: std.json.Parsed(std.json.Value),
    payload: std.json.Parsed(std.json.Value),
    signed: []const u8,
    signature: [96]u8,

    pub fn parse(allocator: std.mem.Allocator, input: []const u8, limits: Limits) !Token {
        const max_size = try std.math.add(usize, try std.math.mul(usize, try std.math.add(usize, limits.max_jwt_header_bytes, limits.max_jwt_payload_bytes), 2), 130);
        if (input.len > max_size) return error.LimitExceeded;
        var parts = std.mem.splitScalar(u8, input, '.');
        const h = parts.next() orelse return error.InvalidJwt;
        const p = parts.next() orelse return error.InvalidJwt;
        const s = parts.next() orelse return error.InvalidJwt;
        if (parts.next() != null or s.len != 128) return error.InvalidJwt;
        const header_bytes = try decode(allocator, h, limits.max_jwt_header_bytes);
        errdefer allocator.free(header_bytes);
        const payload_bytes = try decode(allocator, p, limits.max_jwt_payload_bytes);
        errdefer allocator.free(payload_bytes);
        const header = try parseJson(allocator, header_bytes, limits);
        errdefer header.deinit();
        const payload = try parseJson(allocator, payload_bytes, limits);
        errdefer payload.deinit();
        if (!std.mem.eql(u8, try string(header.value, "alg"), "ES384")) return error.UnsupportedAlgorithm;
        if (header.value.object.contains("crit") or header.value.object.contains("b64")) return error.UnsupportedAlgorithm;
        var signature: [96]u8 = undefined;
        std.base64.url_safe_no_pad.Decoder.decode(&signature, s) catch return error.InvalidJwt;
        return .{ .allocator = allocator, .header_bytes = header_bytes, .payload_bytes = payload_bytes, .header = header, .payload = payload, .signed = input[0 .. h.len + 1 + p.len], .signature = signature };
    }

    pub fn deinit(self: *Token) void {
        self.header.deinit();
        self.payload.deinit();
        self.allocator.free(self.header_bytes);
        self.allocator.free(self.payload_bytes);
        self.* = undefined;
    }

    pub fn verify(self: *const Token, key: spki.Ecdsa.PublicKey) !void {
        spki.Ecdsa.Signature.fromBytes(self.signature).verify(self.signed, key) catch return error.InvalidSignature;
    }

    pub fn validateTime(self: *const Token, now: i64, required: bool) !void {
        if (self.payload.value.object.get("exp")) |exp| {
            if (exp != .integer or exp.integer <= now) return error.ExpiredToken;
        } else if (required) return error.InvalidClaims;
        if (self.payload.value.object.get("nbf")) |nbf| {
            if (nbf != .integer or nbf.integer > now) return error.TokenNotYetValid;
        }
    }
};

fn decode(allocator: std.mem.Allocator, input: []const u8, limit: usize) ![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const len = decoder.calcSizeForSlice(input) catch return error.InvalidJwt;
    if (len == 0) return error.InvalidJwt;
    if (len > limit) return error.LimitExceeded;
    const bytes = try allocator.alloc(u8, len);
    errdefer allocator.free(bytes);
    decoder.decode(bytes, input) catch return error.InvalidJwt;
    return bytes;
}

/// Bounds nesting before the JSON DOM parser allocates. Duplicate keys are rejected.
pub fn parseJson(allocator: std.mem.Allocator, bytes: []const u8, limits: Limits) !std.json.Parsed(std.json.Value) {
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidUtf8;
    var depth: usize = 0;
    var quoted = false;
    var escaped = false;
    for (bytes) |byte| {
        if (quoted) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (byte == '\\') escaped = true else if (byte == '"') quoted = false;
        } else switch (byte) {
            '"' => quoted = true,
            '{', '[' => {
                depth += 1;
                if (depth > limits.protocol.max_nesting_depth) return error.LimitExceeded;
            },
            '}', ']' => {
                if (depth == 0) return error.InvalidJson;
                depth -= 1;
            },
            else => {},
        }
    }
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .max_value_len = limits.max_jwt_payload_bytes });
    errdefer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJson;
    return parsed;
}

pub fn string(value: std.json.Value, name: []const u8) ![]const u8 {
    if (value != .object) return error.InvalidClaims;
    const field = value.object.get(name) orelse return error.InvalidClaims;
    if (field != .string) return error.InvalidClaims;
    return field.string;
}
