const std = @import("std");
const Limits = @import("../limits.zig").Limits;
const jwt = @import("jwt.zig");

pub const ConnectionRequest = struct {
    chain_data: []const u8,
    client_data: []const u8,
};

pub const AuthEnvelope = struct {
    parsed: std.json.Parsed(std.json.Value),
    authentication_type: u8,
    token: ?[]const u8,
    certificate: ?[]const u8,
    is_legacy_chain: bool,

    pub fn deinit(self: *AuthEnvelope, allocator: std.mem.Allocator) void {
        _ = allocator;
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub fn decodeConnectionRequest(bytes: []const u8, limits: Limits) !ConnectionRequest {
    if (bytes.len > limits.max_connection_request_bytes) return error.LimitExceeded;
    if (bytes.len < 8) return error.MalformedConnectionRequest;

    const chain_len_i32 = std.mem.readInt(i32, bytes[0..4], .little);
    if (chain_len_i32 <= 0) return error.MalformedConnectionRequest;
    const chain_len = std.math.cast(usize, chain_len_i32) orelse return error.MalformedConnectionRequest;

    const raw_len_offset = std.math.add(usize, 4, chain_len) catch return error.MalformedConnectionRequest;
    const raw_len_end = std.math.add(usize, raw_len_offset, 4) catch return error.MalformedConnectionRequest;
    if (raw_len_end > bytes.len) return error.MalformedConnectionRequest;

    const chain_data = bytes[4..raw_len_offset];

    const raw_len_i32 = std.mem.readInt(i32, bytes[raw_len_offset..][0..4], .little);
    if (raw_len_i32 <= 0) return error.MalformedConnectionRequest;
    const raw_len = std.math.cast(usize, raw_len_i32) orelse return error.MalformedConnectionRequest;

    const total_len = std.math.add(usize, raw_len_end, raw_len) catch return error.MalformedConnectionRequest;
    if (total_len != bytes.len) return error.MalformedConnectionRequest;

    const client_data = bytes[raw_len_end..total_len];
    return .{
        .chain_data = chain_data,
        .client_data = client_data,
    };
}

pub fn parseChainEnvelope(allocator: std.mem.Allocator, chain_json: []const u8, limits: Limits) !AuthEnvelope {
    const parsed = try jwt.parseJson(allocator, chain_json, limits);
    errdefer parsed.deinit();

    if (parsed.value != .object) {
        return error.InvalidClaims;
    }

    if (parsed.value.object.contains("chain")) {
        return .{
            .parsed = parsed,
            .authentication_type = 0,
            .token = null,
            .certificate = null,
            .is_legacy_chain = true,
        };
    }

    var auth_type: u8 = 0;
    if (parsed.value.object.get("AuthenticationType")) |val| {
        if (val == .integer) {
            if (val.integer < 0 or val.integer > std.math.maxInt(u8)) {
                return error.InvalidClaims;
            }
            auth_type = @intCast(val.integer);
        } else {
            return error.InvalidClaims;
        }
    }

    const token_val = if (parsed.value.object.get("Token")) |t|
        (if (t == .string) t.string else null)
    else
        null;

    const cert_val = if (parsed.value.object.get("Certificate")) |c|
        (if (c == .string) c.string else null)
    else
        null;

    return .{
        .parsed = parsed,
        .authentication_type = auth_type,
        .token = token_val,
        .certificate = cert_val,
        .is_legacy_chain = false,
    };
}
