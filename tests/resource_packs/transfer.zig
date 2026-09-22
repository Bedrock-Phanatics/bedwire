const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const packs = bedwire.resource_packs;

const archive = [_]u8{'p'} ** 700;

fn metadata() packs.Metadata {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&archive, &hash, .{});

    return .{
        .pack_id = "alpha",
        .chunk_size = 256,
        .chunk_count = 3,
        .size = archive.len,
        .hash = hash,
    };
}

test "a complete transfer verifies its hash and reports completion" {
    var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits);
    defer transfer.deinit();

    while (!transfer.complete) {
        const request = try transfer.request();
        const chunk = try packs.serve(metadata(), &archive, request, support.limits);
        try transfer.accept(chunk);
    }

    try testing.expectEqual(@as(u64, archive.len), transfer.progress());
    try testing.expectError(error.InvalidState, transfer.request());
    try testing.expectError(error.InvalidState, transfer.accept(.{ .pack_id = "alpha", .index = 0, .offset = 0, .data = "" }));
}

test "chunks must arrive in order, at the right offset and length" {
    const meta = metadata();

    const bad = [_]packs.Chunk{
        .{ .pack_id = "alpha", .index = 1, .offset = 0, .data = archive[0..256] },
        .{ .pack_id = "alpha", .index = 0, .offset = 256, .data = archive[0..256] },
        .{ .pack_id = "alpha", .index = 0, .offset = 0, .data = archive[0..255] },
        .{ .pack_id = "alpha", .index = 0, .offset = 0, .data = archive[0..257] },
        .{ .pack_id = "beta", .index = 0, .offset = 0, .data = archive[0..256] },
    };

    for (bad) |chunk| {
        var transfer = try packs.Transfer.init(testing.allocator, meta, support.limits);
        defer transfer.deinit();

        try testing.expectError(error.InvalidChunk, transfer.accept(chunk));
        try testing.expect(transfer.failed);
        try testing.expectError(error.InvalidState, transfer.request());
    }
}

test "the final chunk must complete the announced hash" {
    var meta = metadata();
    meta.hash[0] ^= 0xff;

    var transfer = try packs.Transfer.init(testing.allocator, meta, support.limits);
    defer transfer.deinit();

    try transfer.accept(.{ .pack_id = "alpha", .index = 0, .offset = 0, .data = archive[0..256] });
    try transfer.accept(.{ .pack_id = "alpha", .index = 1, .offset = 256, .data = archive[256..512] });
    const before_hash = transfer.hash;
    try testing.expectError(error.IntegrityMismatch, transfer.accept(.{
        .pack_id = "alpha",
        .index = 2,
        .offset = 512,
        .data = archive[512..700],
    }));

    try testing.expect(transfer.failed);
    try testing.expect(!transfer.complete);
    try testing.expectEqual(@as(u64, 512), transfer.progress());
    try testing.expectEqual(@as(u32, 2), transfer.next_index);
    try testing.expectEqualDeep(before_hash, transfer.hash);
}

test "substituted chunk contents are caught by the hash, not by length" {
    var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits);
    defer transfer.deinit();

    const forged = [_]u8{'x'} ** 256;
    try transfer.accept(.{ .pack_id = "alpha", .index = 0, .offset = 0, .data = &forged });
    try transfer.accept(.{ .pack_id = "alpha", .index = 1, .offset = 256, .data = archive[256..512] });
    try testing.expectError(error.IntegrityMismatch, transfer.accept(.{
        .pack_id = "alpha",
        .index = 2,
        .offset = 512,
        .data = archive[512..700],
    }));
}

test "announced geometry must be internally consistent" {
    const base = metadata();

    var wrong_count = base;
    wrong_count.chunk_count = 2;
    try testing.expectError(error.InvalidChunk, packs.Transfer.init(testing.allocator, wrong_count, support.limits));

    var zero_size = base;
    zero_size.size = 0;
    zero_size.chunk_count = 0;
    try testing.expectError(error.InvalidChunk, packs.Transfer.init(testing.allocator, zero_size, support.limits));

    var zero_chunk = base;
    zero_chunk.chunk_size = 0;
    try testing.expectError(error.InvalidChunk, packs.Transfer.init(testing.allocator, zero_chunk, support.limits));

    var empty_id = base;
    empty_id.pack_id = "";
    try testing.expectError(error.LimitExceeded, packs.Transfer.init(testing.allocator, empty_id, support.limits));

    var invalid_id = base;
    invalid_id.pack_id = "\xff";
    try testing.expectError(error.InvalidUtf8, packs.Transfer.init(testing.allocator, invalid_id, support.limits));
}

test "announced size and chunk size are bounded by the session limits" {
    const base = metadata();

    var tight = support.limits;
    tight.max_resource_pack_bytes = 128;
    try testing.expectError(error.LimitExceeded, packs.Transfer.init(testing.allocator, base, tight));

    tight = support.limits;
    tight.max_resource_pack_chunk_bytes = 64;
    try testing.expectError(error.LimitExceeded, packs.Transfer.init(testing.allocator, base, tight));
}

test "serving refuses requests that do not match the archive" {
    const meta = metadata();

    try testing.expectError(error.InvalidChunk, packs.serve(meta, &archive, .{ .pack_id = "beta", .index = 0 }, support.limits));
    try testing.expectError(error.InvalidChunk, packs.serve(meta, &archive, .{ .pack_id = "alpha", .index = 3 }, support.limits));
    try testing.expectError(error.InvalidChunk, packs.serve(meta, archive[0..100], .{ .pack_id = "alpha", .index = 0 }, support.limits));
}

test "the last served chunk is short, not padded" {
    const meta = metadata();
    const last = try packs.serve(meta, &archive, .{ .pack_id = "alpha", .index = 2 }, support.limits);

    try testing.expectEqual(@as(usize, 188), last.data.len);
    try testing.expectEqual(@as(u64, 512), last.offset);
}

test "a pack id is owned for the life of the transfer" {
    var id = [_]u8{ 'a', 'l', 'p', 'h', 'a' };
    var meta = metadata();
    meta.pack_id = &id;

    var transfer = try packs.Transfer.init(testing.allocator, meta, support.limits);
    defer transfer.deinit();

    @memset(&id, 'z');
    try testing.expectEqualStrings("alpha", (try transfer.request()).pack_id);
}

test "a single-chunk pack completes on its first chunk" {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(archive[0..16], &hash, .{});

    var transfer = try packs.Transfer.init(testing.allocator, .{
        .pack_id = "small",
        .chunk_size = 256,
        .chunk_count = 1,
        .size = 16,
        .hash = hash,
    }, support.limits);
    defer transfer.deinit();

    try transfer.accept(.{ .pack_id = "small", .index = 0, .offset = 0, .data = archive[0..16] });
    try testing.expect(transfer.complete);
}

test "transfer setup unwinds every allocation failure" {
    const Case = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var transfer = try packs.Transfer.init(allocator, metadata(), support.limits);
            transfer.deinit();
        }
    };

    try testing.checkAllAllocationFailures(testing.allocator, Case.run, .{});
}

test "negotiation and transfer agree on completion" {
    const offers: []const packs.Offer = &.{.{ .id = "alpha", .size = archive.len }};

    var negotiation = try packs.Negotiation.init(testing.allocator, offers, support.limits);
    defer negotiation.deinit();

    try negotiation.respond(.send_packs, &.{"alpha"});

    var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits);
    defer transfer.deinit();

    while (!transfer.complete) {
        const request = try transfer.request();
        try transfer.accept(try packs.serve(metadata(), &archive, request, support.limits));
    }

    try negotiation.markVerified("alpha");
    try negotiation.respond(.all_packs_downloaded, &.{});
    try negotiation.respond(.completed, &.{});
    try testing.expect(negotiation.done());
}
