const std = @import("std");
const protocol = @import("bedrock_protocol");

const descriptor_mod = @import("descriptor.zig");
const features_mod = @import("features.zig");
const kind_mod = @import("kind.zig");

const Descriptor = descriptor_mod.Descriptor;
const Entry = descriptor_mod.Entry;
const PacketKind = kind_mod.PacketKind;
const SessionFeatures = features_mod.SessionFeatures;

// match PacketKind tags with bedrock_protocol.PacketId enum names at comptime
const mapped_count = blk: {
    var count: usize = 0;
    for (kind_mod.mapped) |kind| {
        if (@hasField(protocol.PacketId, @tagName(kind))) count += 1;
    }
    break :blk count;
};

const table: [mapped_count]Entry = blk: {
    var list: [mapped_count]Entry = undefined;
    var index: usize = 0;
    for (kind_mod.mapped) |kind| {
        if (!@hasField(protocol.PacketId, @tagName(kind))) continue;
        list[index] = .{ .kind = kind, .id = @intFromEnum(@field(protocol.PacketId, @tagName(kind))) };
        index += 1;
    }
    break :blk list;
};

pub const entries: []const Entry = &table;

fn entriesFor(version: u32) []const Entry {
    _ = version;
    return entries;
}

/// builds descriptor for version, can run at comptime
pub fn describe(version: u32) !Descriptor {
    return describeWith(version, features_mod.forVersion(version));
}

/// build descriptor with custom session flags (e.g. for proxies)
pub fn describeWith(version: u32, session_features: SessionFeatures) !Descriptor {
    return descriptor_mod.build(version, session_features, entriesFor(version));
}

const testing = std.testing;

test "registry resolves every session kind from protocol-zig names" {
    const descriptor = try describe(800);

    inline for (kind_mod.mapped) |kind| {
        try testing.expect(descriptor.has(kind));
        const id = descriptor.idOf(kind).?;
        try testing.expectEqual(kind, descriptor.kindOf(id));
        try testing.expectEqual(@intFromEnum(@field(protocol.PacketId, @tagName(kind))), id);
    }
}

test "descriptors resolve at comptime and stay independent per version" {
    const modern = comptime describe(800) catch unreachable;
    const legacy = comptime describe(440) catch unreachable;

    try testing.expect(modern.features.uses_request_network_settings);
    try testing.expect(!legacy.features.uses_request_network_settings);
    try testing.expectEqual(@as(u32, 800), modern.version);
    try testing.expectEqual(@as(u32, 440), legacy.version);
    try testing.expectEqual(modern.idOf(.login), legacy.idOf(.login));
}

test "callers may override the resolved capability profile" {
    const descriptor = try describeWith(800, .{ .supports_snappy = false, .resource_pack_flow = .classic });

    try testing.expect(!descriptor.features.supports_snappy);
    try testing.expectEqual(features_mod.ResourcePackFlow.classic, descriptor.features.resource_pack_flow);
}
