const std = @import("std");

const features_mod = @import("features.zig");
const kind_mod = @import("kind.zig");

pub const PacketKind = kind_mod.PacketKind;
pub const SessionFeatures = features_mod.SessionFeatures;

// bedrock packet headers use a 10-bit id
pub const id_space = 1 << 10;
pub const PacketId = u10;

pub const Entry = struct { kind: PacketKind, id: PacketId };

/// mapping of semantic PacketKind to raw wire PacketId (u10) for a protocol version
pub const Descriptor = struct {
    version: u32,
    features: SessionFeatures,
    ids: [kind_mod.mapped.len]?PacketId,
    kinds: [id_space]PacketKind,

    pub fn kindOf(self: *const Descriptor, id: PacketId) PacketKind {
        return self.kinds[id];
    }

    /// wire packet id for a kind, or null if this version doesn't support it
    pub fn idOf(self: *const Descriptor, kind: PacketKind) ?PacketId {
        if (kind == .other) return null;
        return self.ids[index(kind)];
    }

    pub fn has(self: *const Descriptor, kind: PacketKind) bool {
        return self.idOf(kind) != null;
    }
};

/// construct and validate a protocol descriptor
pub fn build(version: u32, session_features: SessionFeatures, entries: []const Entry) !Descriptor {
    try session_features.validate();

    var descriptor: Descriptor = .{
        .version = version,
        .features = session_features,
        .ids = @splat(null),
        .kinds = @splat(.other),
    };

    for (entries) |entry| {
        if (entry.kind == .other) return error.UnsupportedProtocol;
        if (descriptor.ids[index(entry.kind)] != null) return error.UnsupportedProtocol;
        if (descriptor.kinds[entry.id] != .other) return error.UnsupportedProtocol;

        descriptor.ids[index(entry.kind)] = entry.id;
        descriptor.kinds[entry.id] = entry.kind;
    }

    if (descriptor.idOf(.disconnect) == null) return error.UnsupportedProtocol;
    if (descriptor.idOf(.login) == null) return error.UnsupportedProtocol;

    const negotiation = session_features.uses_request_network_settings;
    if (negotiation and descriptor.idOf(.request_network_settings) == null) return error.UnsupportedProtocol;
    if (negotiation and descriptor.idOf(.network_settings) == null) return error.UnsupportedProtocol;

    return descriptor;
}

fn index(kind: PacketKind) usize {
    return @intFromEnum(kind);
}

const testing = std.testing;

test "descriptor maps identity in both directions" {
    const descriptor = try build(800, .{}, &.{
        .{ .kind = .login, .id = 1 },
        .{ .kind = .disconnect, .id = 5 },
        .{ .kind = .network_settings, .id = 143 },
        .{ .kind = .request_network_settings, .id = 193 },
    });

    try testing.expectEqual(PacketKind.login, descriptor.kindOf(1));
    try testing.expectEqual(PacketKind.other, descriptor.kindOf(2));
    try testing.expectEqual(@as(?PacketId, 143), descriptor.idOf(.network_settings));
    try testing.expectEqual(@as(?PacketId, null), descriptor.idOf(.start_game));
    try testing.expectEqual(@as(?PacketId, null), descriptor.idOf(.other));
    try testing.expect(!descriptor.has(.start_game));
}

test "descriptor rejects malformed maps" {
    const base = [_]Entry{
        .{ .kind = .login, .id = 1 },
        .{ .kind = .disconnect, .id = 5 },
        .{ .kind = .network_settings, .id = 143 },
        .{ .kind = .request_network_settings, .id = 193 },
    };

    try testing.expectError(error.UnsupportedProtocol, build(800, .{}, &(base ++ [_]Entry{.{ .kind = .start_game, .id = 1 }})));
    try testing.expectError(error.UnsupportedProtocol, build(800, .{}, &(base ++ [_]Entry{.{ .kind = .login, .id = 70 }})));
    try testing.expectError(error.UnsupportedProtocol, build(800, .{}, &(base ++ [_]Entry{.{ .kind = .other, .id = 70 }})));
    try testing.expectError(error.UnsupportedProtocol, build(800, .{}, base[0..2]));
    try testing.expectError(error.UnsupportedProtocol, build(800, .{}, base[1..]));
}

test "legacy profiles may omit the negotiation packets" {
    const descriptor = try build(400, .{
        .uses_request_network_settings = false,
        .compression_mode = .implicit,
        .supports_snappy = false,
        .initial_algorithm = .deflate,
    }, &.{
        .{ .kind = .login, .id = 1 },
        .{ .kind = .disconnect, .id = 5 },
    });

    try testing.expect(!descriptor.has(.request_network_settings));
}
