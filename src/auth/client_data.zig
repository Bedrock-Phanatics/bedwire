const std = @import("std");

const Limits = @import("../limits.zig").Limits;
const identity = @import("identity.zig");

const text_fields = [_][]const u8{
    "ThirdPartyName", "DeviceId",          "DeviceModel",      "GameVersion",       "LanguageCode",
    "ServerAddress",  "SkinId",            "CapeId",           "PlayFabId",         "SelfSignedId",
    "ArmSize",        "SkinColor",         "PlatformOnlineId", "PlatformOfflineId", "PartyId",
    "PlatformUserId", "SkinAnimationData",
};

const list_fields = [_][]const u8{ "PersonaPieces", "PieceTintColors" };

const integer_fields = [_][]const u8{
    "ClientRandomId",  "CurrentInputMode", "DefaultInputMode", "GuiScale",     "UIProfile",
    "MaxViewDistance", "MemoryTier",       "PlatformType",     "GraphicsMode",
};

const flag_fields = [_][]const u8{
    "PersonaSkin", "PremiumSkin", "CapeOnClassicSkin", "IsEditorMode", "TrustedSkin", "OverrideSkin",
};

pub const max_image_edge = 4096;

/// Images must decode to exactly width * height * 4 bytes so a malformed skin can't reach other players.
pub fn validate(claims: std.json.Value, limits: Limits) !void {
    if (claims != .object) return error.InvalidClientData;
    const object = claims.object;

    inline for (text_fields) |name| {
        if (try text(object, name)) |value| if (value.len > limits.max_identity_bytes) return error.InvalidClientData;
    }
    inline for (list_fields) |name| {
        if (object.get(name)) |value| if (value != .array) return error.InvalidClientData;
    }
    inline for (integer_fields) |name| _ = try integer(object, name, std.math.minInt(i64), std.math.maxInt(i64));
    inline for (flag_fields) |name| {
        if (object.get(name)) |value| if (value != .bool) return error.InvalidClientData;
    }

    _ = try integer(object, "DeviceOS", 0, std.math.maxInt(u8));
    if (try text(object, "SelfSignedId")) |id| if (id.len != 0 and !identity.validateUuid(id)) return error.InvalidClientData;
    if (try text(object, "PlatformOnlineId")) |id| for (id) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidClientData;
    if (try text(object, "PlayFabId")) |id| for (id) |byte| if (!std.ascii.isHex(byte)) return error.InvalidClientData;

    try image(object, "SkinData", "SkinImageWidth", "SkinImageHeight", false);
    try image(object, "CapeData", "CapeImageWidth", "CapeImageHeight", true);
    if (object.get("AnimatedImageData")) |frames| {
        if (frames != .array) return error.InvalidClientData;
        for (frames.array.items) |frame| {
            if (frame != .object) return error.InvalidClientData;
            if (frame.object.get("Image") == null) return error.InvalidClientData;
            try image(frame.object, "Image", "ImageWidth", "ImageHeight", false);
            _ = try integer(frame.object, "Type", 0, std.math.maxInt(u8));
        }
    }
}

fn text(object: std.json.ObjectMap, name: []const u8) !?[]const u8 {
    const value = object.get(name) orelse return null;
    return if (value == .string) value.string else error.InvalidClientData;
}

fn integer(object: std.json.ObjectMap, name: []const u8, min: i64, max: i64) !?i64 {
    const value = object.get(name) orelse return null;
    if (value != .integer or value.integer < min or value.integer > max) return error.InvalidClientData;
    return value.integer;
}

fn image(object: std.json.ObjectMap, data_name: []const u8, width_name: []const u8, height_name: []const u8, may_be_empty: bool) !void {
    const encoded = try text(object, data_name) orelse return;
    const width = try integer(object, width_name, 0, max_image_edge) orelse return error.InvalidClientData;
    const height = try integer(object, height_name, 0, max_image_edge) orelse return error.InvalidClientData;
    if (!may_be_empty and (width == 0 or height == 0)) return error.InvalidClientData;
    if (try decodedLen(encoded) != @as(usize, @intCast(width * height * 4))) return error.InvalidClientData;
}

fn decodedLen(encoded: []const u8) !usize {
    const decoder = std.base64.standard.Decoder;
    const len = decoder.calcSizeForSlice(encoded) catch return error.InvalidClientData;
    if (std.mem.indexOfScalar(u8, encoded[0..encoded.len -| 2], '=') != null) return error.InvalidClientData;
    var scratch: [3 * 256]u8 = undefined;
    var rest = encoded;
    while (rest.len != 0) {
        const piece = rest[0..@min(rest.len, 4 * 256)];
        decoder.decode(scratch[0 .. decoder.calcSizeForSlice(piece) catch return error.InvalidClientData], piece) catch return error.InvalidClientData;
        rest = rest[piece.len..];
    }
    return len;
}

const testing = std.testing;

fn check(json: []const u8) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    return validate(parsed.value, .{});
}

test "present claims need the right shape and absent ones are fine" {
    try check("{}");
    try check("{\"DeviceOS\":7,\"ThirdPartyName\":\"Steve\",\"PlayFabId\":\"5eb65e0f1d2c3a4b\",\"SelfSignedId\":\"b1b01c3d-6df3-3635-b286-9a2cfbcf76be\",\"PlatformOnlineId\":\"\",\"PremiumSkin\":false}");

    const bad = [_][]const u8{
        "{\"DeviceOS\":\"7\"}",
        "{\"DeviceOS\":-1}",
        "{\"DeviceOS\":256}",
        "{\"ThirdPartyName\":7}",
        "{\"SelfSignedId\":\"not-a-uuid\"}",
        "{\"PlatformOnlineId\":\"+1\"}",
        "{\"PlayFabId\":\"xyz\"}",
        "{\"PremiumSkin\":0}",
        "{\"GuiScale\":1.5}",
        "{\"PersonaPieces\":\"x\"}",
    };
    for (bad) |json| try testing.expectError(error.InvalidClientData, check(json));
}

test "images must decode to exactly their declared size" {
    try check("{\"SkinData\":\"AAAAAAAAAAA=\",\"SkinImageWidth\":2,\"SkinImageHeight\":1,\"CapeData\":\"\",\"CapeImageWidth\":0,\"CapeImageHeight\":0}");
    try check("{\"AnimatedImageData\":[{\"Image\":\"AAAAAA==\",\"ImageWidth\":1,\"ImageHeight\":1,\"Type\":1,\"Frames\":2.0}]}");

    const bad = [_][]const u8{
        "{\"SkinData\":\"AAAAAAAAAAA=\",\"SkinImageWidth\":3,\"SkinImageHeight\":1}",
        "{\"SkinData\":\"AAAAAAAAAAA=\"}",
        "{\"SkinData\":\"AAAA!AAAAAA=\",\"SkinImageWidth\":2,\"SkinImageHeight\":1}",
        "{\"SkinData\":\"AAAAAAAAAAA\",\"SkinImageWidth\":2,\"SkinImageHeight\":1}",
        "{\"SkinData\":\"AA==AAAAAAA=\",\"SkinImageWidth\":2,\"SkinImageHeight\":1}",
        "{\"SkinData\":\"\",\"SkinImageWidth\":0,\"SkinImageHeight\":0}",
        "{\"SkinData\":\"\",\"SkinImageWidth\":5000,\"SkinImageHeight\":5000}",
        "{\"CapeData\":\"AAAA\",\"CapeImageWidth\":0,\"CapeImageHeight\":0}",
        "{\"AnimatedImageData\":{}}",
        "{\"AnimatedImageData\":[{\"ImageWidth\":1,\"ImageHeight\":1}]}",
        "{\"AnimatedImageData\":[{\"Image\":\"AAAAAA==\",\"ImageWidth\":1,\"ImageHeight\":1,\"Type\":-2}]}",
    };
    for (bad) |json| try testing.expectError(error.InvalidClientData, check(json));
}

test "large images validate in pieces" {
    const pixels = 64 * 64 * 4;
    var encoded: [std.base64.standard.Encoder.calcSize(pixels)]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &@as([pixels]u8, @splat(0x5a)));
    try testing.expectEqual(@as(usize, pixels), try decodedLen(&encoded));
    encoded[2000] = '*';
    try testing.expectError(error.InvalidClientData, decodedLen(&encoded));
}
