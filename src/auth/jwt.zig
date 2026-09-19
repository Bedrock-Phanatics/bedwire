const std = @import("std");

const Limits = @import("../limits.zig").Limits;
const spki = @import("../crypto/spki.zig");

// bedrock uses es384 for all tokens
pub const algorithm = "ES384";

/// parsed compact jwt (header.payload.signature)
pub const Token = struct {
    allocator: std.mem.Allocator,
    header_bytes: []u8,
    payload_bytes: []u8,
    header: std.json.Parsed(std.json.Value),
    payload: std.json.Parsed(std.json.Value),
    signed: []const u8,
    signature: [96]u8,

    pub fn parse(allocator: std.mem.Allocator, input: []const u8, limits: Limits) !Token {
        const json_limit = try std.math.add(usize, limits.max_jwt_header_bytes, limits.max_jwt_payload_bytes);
        const encoded_limit = try std.math.mul(usize, json_limit, 2);
        const max_size = try std.math.add(usize, encoded_limit, 130);
        if (input.len > max_size) return error.LimitExceeded;

        var parts = std.mem.splitScalar(u8, input, '.');
        const encoded_header = parts.next() orelse return error.InvalidToken;
        const encoded_payload = parts.next() orelse return error.InvalidToken;
        const encoded_signature = parts.next() orelse return error.InvalidToken;
        if (parts.next() != null or encoded_signature.len != 128) return error.InvalidToken;

        const header_bytes = try decodeSegment(allocator, encoded_header, limits.max_jwt_header_bytes);
        errdefer allocator.free(header_bytes);

        const payload_bytes = try decodeSegment(allocator, encoded_payload, limits.max_jwt_payload_bytes);
        errdefer allocator.free(payload_bytes);

        const header = try parseJson(allocator, header_bytes, limits);
        errdefer header.deinit();

        const payload = try parseJson(allocator, payload_bytes, limits);
        errdefer payload.deinit();

        if (!std.mem.eql(u8, try string(header.value, "alg"), algorithm)) return error.UnsupportedAlgorithm;
        if (header.value.object.contains("crit") or header.value.object.contains("b64")) return error.UnsupportedAlgorithm;

        var signature: [96]u8 = undefined;
        std.base64.url_safe_no_pad.Decoder.decode(&signature, encoded_signature) catch return error.InvalidToken;

        return .{
            .allocator = allocator,
            .header_bytes = header_bytes,
            .payload_bytes = payload_bytes,
            .header = header,
            .payload = payload,
            .signed = input[0 .. encoded_header.len + 1 + encoded_payload.len],
            .signature = signature,
        };
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

    /// check exp and nbf timestamps
    pub fn validateTime(self: *const Token, now: i64, required: bool) !void {
        if (self.payload.value.object.get("exp")) |exp| {
            if (exp != .integer or exp.integer <= now) return error.ExpiredToken;
        } else if (required) return error.InvalidClaims;

        if (self.payload.value.object.get("nbf")) |nbf| {
            if (nbf != .integer or nbf.integer > now) return error.TokenNotYetValid;
        }
    }
};

/// checks json nesting depth before parsing so malicious tokens don't blow the stack
pub fn parseJson(allocator: std.mem.Allocator, bytes: []const u8, limits: Limits) !std.json.Parsed(std.json.Value) {
    if (bytes.len > @max(limits.max_jwt_header_bytes, limits.max_jwt_payload_bytes)) return error.LimitExceeded;
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

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .max_value_len = limits.max_jwt_payload_bytes }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
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

fn decodeSegment(allocator: std.mem.Allocator, input: []const u8, limit: usize) ![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const len = decoder.calcSizeForSlice(input) catch return error.InvalidToken;
    if (len == 0) return error.InvalidToken;
    if (len > limit) return error.LimitExceeded;

    const bytes = try allocator.alloc(u8, len);
    errdefer allocator.free(bytes);
    decoder.decode(bytes, input) catch return error.InvalidToken;

    return bytes;
}
