const std = @import("std");
const Limits = @import("../limits.zig").Limits;
const spki = @import("../crypto/spki.zig");

pub const Identity = struct {
    allocator: std.mem.Allocator,
    display_name: []u8,
    uuid: []u8,
    xuid: []u8,
    public_key: spki.Ecdsa.PublicKey,
    online: bool,
    /// Unix seconds from the verified token's `pfcd`, when it carried a well-formed one.
    playfab_created_s: ?i64 = null,

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
    playfab_created_s: ?i64 = null,
};

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

/// Digits only, since parseInt alone also takes a sign and underscores.
pub fn validXuid(xuid: []const u8) bool {
    for (xuid) |byte| if (!std.ascii.isDigit(byte)) return false;
    _ = std.fmt.parseInt(u64, xuid, 10) catch return false;
    return true;
}

pub fn validateAndCreate(allocator: std.mem.Allocator, claims: Claims, limits: Limits) !Identity {
    if (claims.display_name.len == 0 or claims.display_name.len > limits.max_identity_bytes) return error.InvalidClaims;
    if (!validateUuid(claims.uuid)) return error.InvalidClaims;

    if (claims.online and !validXuid(claims.xuid)) return error.InvalidClaims;
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
        .playfab_created_s = claims.playfab_created_s,
    };
}

/// A claim of Unix seconds or an ISO 8601 UTC time (`2021-03-09T20:36:00.067Z`), as null when it is anything else.
pub fn parseTimestamp(value: std.json.Value) ?i64 {
    const text = switch (value) {
        .integer => |seconds| return if (seconds > 0) seconds else null,
        .string => |text| text,
        else => return null,
    };
    if (text.len == 0) return null;
    if (std.ascii.isDigit(text[0])) if (std.fmt.parseInt(i64, text, 10)) |seconds| return if (seconds > 0) seconds else null else |_| {};
    return parseIso(text);
}

fn parseIso(text: []const u8) ?i64 {
    if (text.len < 20 or text[text.len - 1] != 'Z') return null;
    const shape = "dddd-dd-ddTdd:dd:dd";
    for (shape, text[0..shape.len]) |kind, byte| {
        if (kind == 'd' and !std.ascii.isDigit(byte)) return null else if (kind != 'd' and kind != byte) return null;
    }
    const fraction = text[shape.len .. text.len - 1];
    if (fraction.len != 0) {
        if (fraction[0] != '.' or fraction.len == 1) return null;
        for (fraction[1..]) |byte| if (!std.ascii.isDigit(byte)) return null;
    }
    const year = std.fmt.parseInt(i64, text[0..4], 10) catch return null;
    const month = std.fmt.parseInt(u8, text[5..7], 10) catch return null;
    const day = std.fmt.parseInt(u8, text[8..10], 10) catch return null;
    const hour = std.fmt.parseInt(u8, text[11..13], 10) catch return null;
    const minute = std.fmt.parseInt(u8, text[14..16], 10) catch return null;
    const second = std.fmt.parseInt(u8, text[17..19], 10) catch return null;
    if (year < 1970 or month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59) return null;
    if (year > std.math.maxInt(std.time.epoch.Year)) return null;
    if (day < 1 or day > std.time.epoch.getDaysInMonth(@intCast(year), @fromBackingInt(@intCast(month)))) return null;
    // Days since the epoch, counting years from March so the leap day ends the cycle
    const shifted = if (month <= 2) year - 1 else year;
    const era = @divFloor(shifted, 400);
    const year_of_era = shifted - era * 400;
    const day_of_year = @divFloor(153 * (@as(i64, month) + (if (month > 2) @as(i64, -3) else 9)) + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    const days = era * 146097 + day_of_era - 719468;
    return days * std.time.s_per_day + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

pub fn deriveUuidV3(dest: *[36]u8, xuid: []const u8) void {
    var md5 = std.crypto.hash.Md5.init(.{});
    md5.update("pocket-auth-1-xuid:");
    md5.update(xuid);
    var digest: [16]u8 = undefined;
    md5.final(&digest);

    digest[6] = (digest[6] & 0x0f) | 0x30;
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
    try std.testing.expect(!validateUuid("b1b01c3d6df33635b2869a2cfbcf76be"));
    try std.testing.expect(!validateUuid("b1b01c3d-6df3-3635-b286-9a2cfbcf76b"));
    try std.testing.expect(!validateUuid("b1b01c3d-6df3-3635-b286-9a2cfbcf76bee"));
    try std.testing.expect(!validateUuid("b1b01c3d-6df3-3635-b286-9a2cfbcf76bg"));
    try std.testing.expect(!validateUuid("b1b01c3d_6df3_3635_b286_9a2cfbcf76be"));
}

test "timestamps accept Unix seconds and ISO 8601 UTC, and nothing else" {
    const parse = struct {
        fn of(text: []const u8) ?i64 {
            return parseTimestamp(.{ .string = text });
        }
    }.of;
    try std.testing.expectEqual(@as(?i64, 1), parseTimestamp(.{ .integer = 1 }));
    try std.testing.expectEqual(@as(?i64, 1_615_322_160), parse("2021-03-09T20:36:00Z"));
    try std.testing.expectEqual(@as(?i64, 1_615_322_160), parse("2021-03-09T20:36:00.067Z"));
    try std.testing.expectEqual(@as(?i64, 1_709_164_800), parse("2024-02-29T00:00:00Z"));
    try std.testing.expectEqual(@as(?i64, 1_615_322_160), parse("1615322160"));
    for ([_][]const u8{ "", "now", "2021-03-09", "2021-03-09T20:36:00", "2021-03-09T20:36:00+01:00", "2021-13-09T20:36:00Z", "2023-02-29T00:00:00Z", "2021-03-09T24:00:00Z", "2021-03-09T20:36:00.Z", "2021-03-09T20:36:0xZ", "1969-12-31T23:59:59Z", "-5", "0" }) |text| {
        try std.testing.expectEqual(@as(?i64, null), parse(text));
    }
    try std.testing.expectEqual(@as(?i64, null), parseTimestamp(.{ .integer = -1 }));
    try std.testing.expectEqual(@as(?i64, null), parseTimestamp(.{ .bool = true }));
    try std.testing.expectEqual(@as(?i64, null), parseTimestamp(.null));
}
