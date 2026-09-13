const std = @import("std");
const zigrock = @import("zigrock");

test "manifest reuses bounded protocol codec and validates truncation" {
    var bytes: [128]u8 = undefined;
    var writer = zigrock.protocol.Writer.init(&bytes);
    try zigrock.protocol.codecs.resource_pack.encodeInfo(&writer, .{ .texture_pack_required = false, .has_addons = false, .has_scripts = false, .force_disable_vibrant_visuals = false, .world_template_uuid = @splat(0), .world_template_version = "", .texture_packs = &.{} });
    var manifest = try zigrock.resource_packs.Manifest.decode(std.testing.allocator, writer.written(), .{});
    defer manifest.deinit();
    try std.testing.expectEqual(@as(usize, 0), manifest.info.texture_packs.len);
    for (0..writer.cursor) |end| {
        if (zigrock.resource_packs.Manifest.decode(std.testing.allocator, bytes[0..end], .{})) |value| {
            var owned = value;
            owned.deinit();
            return error.AcceptedTruncation;
        } else |_| {}
    }
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    var negotiation = try zigrock.resource_packs.Negotiation.init(allocator, &.{ "a", "b" }, .{});
    defer negotiation.deinit();
}

test "pack negotiation forbids unknown, duplicate, and premature completion" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
    var negotiation = try zigrock.resource_packs.Negotiation.init(std.testing.allocator, &.{ "a", "b" }, .{});
    defer negotiation.deinit();
    try std.testing.expectError(error.InvalidState, negotiation.respond(.{ .response = .completed, .packs_to_download = &.{} }));
    try std.testing.expectError(error.UnknownPack, negotiation.respond(.{ .response = .send_packs, .packs_to_download = &.{"c"} }));
    try std.testing.expectError(error.DuplicatePack, negotiation.respond(.{ .response = .send_packs, .packs_to_download = &.{ "a", "a" } }));
    try negotiation.respond(.{ .response = .send_packs, .packs_to_download = &.{"a"} });
    try std.testing.expectError(error.IncompleteTransfer, negotiation.respond(.{ .response = .all_packs_downloaded, .packs_to_download = &.{} }));
    try negotiation.verified("a");
    try negotiation.respond(.{ .response = .all_packs_downloaded, .packs_to_download = &.{} });
    try negotiation.respond(.{ .response = .completed, .packs_to_download = &.{} });
    try std.testing.expectEqual(.complete, negotiation.phase);
}

fn decodeCase(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var manifest = try zigrock.resource_packs.Manifest.decode(allocator, bytes, .{});
    defer manifest.deinit();
    try std.testing.expectEqual(@as(usize, 1), manifest.info.texture_packs.len);
}

test "nonempty manifest allocation failures, truncation and resource caps" {
    var packs = [_]zigrock.protocol.packets.resource_pack.TexturePackInfo{.{ .uuid = @splat(1), .version = "1.0.0", .size = 10, .content_key = "", .sub_pack_name = "", .content_identity = "", .has_scripts = false, .addon_pack = false, .rtx_enabled = false, .download_url = "" }};
    var bytes: [256]u8 = undefined;
    var writer = zigrock.protocol.Writer.init(&bytes);
    try zigrock.protocol.codecs.resource_pack.encodeInfo(&writer, .{ .texture_pack_required = true, .has_addons = false, .has_scripts = false, .force_disable_vibrant_visuals = false, .world_template_uuid = @splat(0), .world_template_version = "", .texture_packs = &packs });
    try std.testing.checkAllAllocationFailures(std.testing.allocator, decodeCase, .{writer.written()});
    try std.testing.expectError(error.LimitExceeded, zigrock.resource_packs.Manifest.decode(std.testing.allocator, writer.written(), .{ .max_resource_pack_bytes = 9 }));
    for (0..writer.cursor) |end| {
        if (zigrock.resource_packs.Manifest.decode(std.testing.allocator, bytes[0..end], .{})) |value| {
            var owned = value;
            owned.deinit();
            return error.AcceptedTruncation;
        } else |_| {}
    }
}
