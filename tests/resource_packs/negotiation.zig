const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const packs = bedwire.resource_packs;

const offers: []const packs.Offer = &.{
    .{ .id = "alpha", .size = 1024 },
    .{ .id = "beta", .size = 2048 },
};

test "a full negotiation walks offered, downloading, stack and complete" {
    var negotiation = try packs.Negotiation.init(testing.allocator, offers, support.limits);
    defer negotiation.deinit();

    try testing.expectEqual(packs.Phase.offered, negotiation.phase);

    try negotiation.respond(.send_packs, &.{ "alpha", "beta" });
    try testing.expectEqual(packs.Phase.downloading, negotiation.phase);

    try negotiation.markVerified("alpha");
    try testing.expectError(error.IncompleteTransfer, negotiation.respond(.all_packs_downloaded, &.{}));

    try negotiation.markVerified("beta");
    try negotiation.respond(.all_packs_downloaded, &.{});
    try testing.expectEqual(packs.Phase.stack, negotiation.phase);

    try negotiation.respond(.completed, &.{});
    try testing.expect(negotiation.done());
}

test "a client may decline every pack" {
    var negotiation = try packs.Negotiation.init(testing.allocator, offers, support.limits);
    defer negotiation.deinit();

    try negotiation.respond(.refused, &.{});
    try testing.expect(negotiation.done());
    try testing.expectError(error.InvalidState, negotiation.respond(.refused, &.{}));
}

test "a client with nothing to download skips straight to the stack" {
    var negotiation = try packs.Negotiation.init(testing.allocator, offers, support.limits);
    defer negotiation.deinit();

    try negotiation.respond(.all_packs_downloaded, &.{});
    try negotiation.respond(.completed, &.{});
    try testing.expectEqual(packs.Phase.complete, negotiation.phase);
}

test "responses are refused out of order" {
    var negotiation = try packs.Negotiation.init(testing.allocator, offers, support.limits);
    defer negotiation.deinit();

    try testing.expectError(error.InvalidState, negotiation.respond(.completed, &.{}));
    try testing.expectError(error.InvalidState, negotiation.markVerified("alpha"));
    try testing.expectError(error.InvalidState, negotiation.respond(.send_packs, &.{}));

    try negotiation.respond(.send_packs, &.{"alpha"});
    try testing.expectError(error.InvalidState, negotiation.respond(.send_packs, &.{"beta"}));
    try testing.expectError(error.InvalidState, negotiation.respond(.completed, &.{}));
}

test "a download list may only name offered packs, once each" {
    var negotiation = try packs.Negotiation.init(testing.allocator, offers, support.limits);
    defer negotiation.deinit();

    try testing.expectError(error.UnknownPack, negotiation.respond(.send_packs, &.{"gamma"}));
    try testing.expectError(error.DuplicatePack, negotiation.respond(.send_packs, &.{ "alpha", "alpha" }));
    try testing.expectError(error.LimitExceeded, negotiation.respond(.send_packs, &.{ "alpha", "beta", "alpha" }));

    // A rejected list leaves nothing marked.
    try testing.expectEqual(packs.Phase.offered, negotiation.phase);
    for (negotiation.packs) |pack| try testing.expect(!pack.requested);
}

test "only requested packs may be verified, and only once" {
    var negotiation = try packs.Negotiation.init(testing.allocator, offers, support.limits);
    defer negotiation.deinit();

    try negotiation.respond(.send_packs, &.{"alpha"});
    try testing.expectError(error.InvalidState, negotiation.markVerified("beta"));
    try testing.expectError(error.UnknownPack, negotiation.markVerified("gamma"));

    try negotiation.markVerified("alpha");
    try testing.expectError(error.InvalidState, negotiation.markVerified("alpha"));
}

test "a response carrying downloads for the wrong verb is refused" {
    var negotiation = try packs.Negotiation.init(testing.allocator, offers, support.limits);
    defer negotiation.deinit();

    try testing.expectError(error.InvalidState, negotiation.respond(.refused, &.{"alpha"}));
    try testing.expectError(error.InvalidState, negotiation.respond(.all_packs_downloaded, &.{"alpha"}));
    try testing.expectError(error.InvalidState, negotiation.respond(.completed, &.{"alpha"}));
}

test "duplicate offers are refused" {
    const duplicated: []const packs.Offer = &.{
        .{ .id = "alpha", .size = 1 },
        .{ .id = "alpha", .size = 2 },
    };

    try testing.expectError(error.DuplicatePack, packs.Negotiation.init(testing.allocator, duplicated, support.limits));
}

test "offer count, per-pack size and aggregate size are all bounded" {
    var tight = support.limits;
    tight.max_resource_packs = 1;
    try testing.expectError(error.LimitExceeded, packs.Negotiation.init(testing.allocator, offers, tight));

    tight = support.limits;
    tight.max_resource_pack_bytes = 1500;
    try testing.expectError(error.LimitExceeded, packs.Negotiation.init(testing.allocator, offers, tight));

    // Each pack fits, but together they do not.
    tight = support.limits;
    tight.max_resource_pack_bytes = 2500;
    try testing.expectError(error.LimitExceeded, packs.Negotiation.init(testing.allocator, offers, tight));

    // A size that would overflow the running total.
    const huge: []const packs.Offer = &.{
        .{ .id = "alpha", .size = std.math.maxInt(u64) },
    };
    try testing.expectError(error.LimitExceeded, packs.Negotiation.init(testing.allocator, huge, support.limits));
}

test "pack ids are validated before they are stored" {
    const empty: []const packs.Offer = &.{.{ .id = "", .size = 1 }};
    try testing.expectError(error.LimitExceeded, packs.Negotiation.init(testing.allocator, empty, support.limits));

    const invalid: []const packs.Offer = &.{.{ .id = "\xff\xfe", .size = 1 }};
    try testing.expectError(error.InvalidUtf8, packs.Negotiation.init(testing.allocator, invalid, support.limits));

    var tight = support.limits;
    tight.max_pack_id_bytes = 2;
    try testing.expectError(error.LimitExceeded, packs.Negotiation.init(testing.allocator, offers, tight));
}

fn initCase(allocator: std.mem.Allocator) !void {
    var negotiation = try packs.Negotiation.init(allocator, offers, support.limits);
    negotiation.deinit();
}

test "negotiation setup unwinds every allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, initCase, .{});
}

test "pack ids are owned, not borrowed from the packet" {
    var id = [_]u8{ 'a', 'l', 'p', 'h', 'a' };
    const borrowed: []const packs.Offer = &.{.{ .id = &id, .size = 1 }};

    var negotiation = try packs.Negotiation.init(testing.allocator, borrowed, support.limits);
    defer negotiation.deinit();

    @memset(&id, 'z');
    try testing.expectEqualStrings("alpha", negotiation.packs[0].id);
    try testing.expect(negotiation.find("alpha") != null);
    try testing.expect(negotiation.find("zzzzz") == null);
}
