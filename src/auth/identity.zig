const std = @import("std");
const Limits = @import("../limits.zig").Limits;
const spki = @import("../crypto/spki.zig");

/// Owns its strings; copies share those allocations.
pub const Identity = struct {
    allocator: std.mem.Allocator,
    display_name: []u8,
    uuid: []u8,
    xuid: []u8,
    public_key: spki.Ecdsa.PublicKey,
    online: bool,

    pub fn deinit(self: *Identity) void {
        self.allocator.free(self.display_name);
        self.allocator.free(self.uuid);
        self.allocator.free(self.xuid);
        self.* = undefined;
    }
};

pub const Claims = struct {
    display_name: []const u8,
    uuid: []const u8,
    xuid: []const u8,
    key: spki.Ecdsa.PublicKey,
    online: bool,
};

// validates whether a given string is a standard 36-character hyphenated uuid
// format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (8-4-4-4-12)
pub fn validateUuid(uuid: []const u8) bool {
    if (uuid.len != 36) return false;
    for (uuid, 0..) |byte, i| {
        const separator = i == 8 or i == 13 or i == 18 or i == 23;
        if (separator) {
            if (byte != '-') return false;
        } else if (!std.ascii.isHex(byte)) {
            return false;
        }
    }
    return true;
}

pub fn validateAndCreate(allocator: std.mem.Allocator, claims: Claims, limits: Limits) !Identity {
    if (claims.display_name.len == 0 or claims.display_name.len > limits.max_identity_bytes) return error.InvalidClaims;
    if (!validateUuid(claims.uuid)) return error.InvalidClaims;

    if (claims.online) {
        _ = std.fmt.parseInt(u64, claims.xuid, 10) catch return error.InvalidClaims;
    }
    if (claims.xuid.len > limits.max_identity_bytes) return error.InvalidClaims;

    const display_name = try allocator.dupe(u8, claims.display_name);
    errdefer allocator.free(display_name);

    const uuid = try allocator.dupe(u8, claims.uuid);
    errdefer allocator.free(uuid);

    const xuid = try allocator.dupe(u8, claims.xuid);
    errdefer allocator.free(xuid);

    return .{
        .allocator = allocator,
        .display_name = display_name,
        .uuid = uuid,
        .xuid = xuid,
        .public_key = claims.key,
        .online = claims.online,
    };
}

// derives an RFC 4122 version 3 (MD5-based) UUID from an XUID string,
// using the namespace prefix "pocket-auth-1-xuid:"
// dest must be a pointer to a 36-byte array
pub fn deriveUuidV3(dest: *[36]u8, xuid: []const u8) void {
    var md5 = std.crypto.hash.Md5.init(.{});
    md5.update("pocket-auth-1-xuid:");
    md5.update(xuid);
    var digest: [16]u8 = undefined;
    md5.final(&digest);

    // RFC 4122 section 4.3: version 3 (0x30)
    digest[6] = (digest[6] & 0x0f) | 0x30;
    // RFC 4122 variant 1 (0x80)
    digest[8] = (digest[8] & 0x3f) | 0x80;

    const hex_digits = "0123456789abcdef";
    var out_idx: usize = 0;
    for (digest, 0..) |byte, in_idx| {
        if (in_idx == 4 or in_idx == 6 or in_idx == 8 or in_idx == 10) {
            dest[out_idx] = '-';
            out_idx += 1;
        }
        dest[out_idx] = hex_digits[byte >> 4];
        dest[out_idx + 1] = hex_digits[byte & 0x0f];
        out_idx += 2;
    }
}

test "deriveUuidV3 produces valid RFC 4122 v3 UUID matching test vector" {
    var dest: [36]u8 = undefined;
    deriveUuidV3(&dest, "123456789");
    try std.testing.expectEqualStrings("fa207011-346c-3a82-8499-98ef4bf3e075", &dest);
    try std.testing.expect(validateUuid(&dest));
}

test "validateUuid accepts valid UUID and rejects malformed ones" {
    try std.testing.expect(validateUuid("fa207011-346c-3a82-8499-98ef4bf3e075"));
    try std.testing.expect(validateUuid("b1b01c3d-6df3-3635-b286-9a2cfbcf76be"));
    try std.testing.expect(!validateUuid("b1b01c3d6df33635b2869a2cfbcf76be")); // no hyphens
    try std.testing.expect(!validateUuid("b1b01c3d-6df3-3635-b286-9a2cfbcf76b")); // 35 chars
    try std.testing.expect(!validateUuid("b1b01c3d-6df3-3635-b286-9a2cfbcf76bee")); // 37 chars
    try std.testing.expect(!validateUuid("b1b01c3d-6df3-3635-b286-9a2cfbcf76bg")); // non-hex 'g'
    try std.testing.expect(!validateUuid("b1b01c3d_6df3_3635_b286_9a2cfbcf76be")); // underscores
}
