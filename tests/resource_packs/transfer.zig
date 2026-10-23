const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const packs = bedwire.resource_packs;

const archive = blk: {
    @setEvalBranchQuota(10_000);
    var bytes: [2500]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(i *% 31 +% i / 7);
    break :blk bytes;
};

fn digest(bytes: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    return hash;
}

fn metadata() packs.Metadata {
    return .{ .pack_id = "alpha_1.0.0", .chunk_size = 256, .chunk_count = 10, .size = archive.len, .hash = digest(&archive) };
}

fn chunk(index: u32) packs.Chunk {
    return packs.serve(metadata(), &archive, .{ .pack_id = "alpha_1.0.0", .index = index }, support.limits) catch unreachable;
}

test "an in-order transfer fills caller storage and verifies the hash" {
    var stored: [archive.len]u8 = undefined;
    var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits, .{ .window = 1 });
    defer transfer.deinit();

    var accepted: usize = 0;
    while (transfer.nextRequest()) |request| : (accepted += 1) {
        try testing.expectEqual(@as(?packs.Request, null), transfer.nextRequest());
        try testing.expectEqual(@as(u32, 1), transfer.outstanding());
        const progress = try transfer.accept(chunk(request.index), packs.Memory{ .bytes = &stored });
        try testing.expectEqual(if (accepted == 9) packs.Progress.complete else .stored, progress);
    }

    try testing.expect(transfer.complete);
    try testing.expectEqual(@as(u64, archive.len), transfer.progress());
    try testing.expectEqualSlices(u8, &archive, &stored);
    try testing.expectError(error.InvalidState, transfer.accept(chunk(0), packs.Memory{ .bytes = &stored }));
}

test "a pipelined window accepts chunks out of order and hashes them once the gap fills" {
    var stored: [archive.len]u8 = undefined;
    const storage: packs.Memory = .{ .bytes = &stored };
    var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits, .{ .window = 3 });
    defer transfer.deinit();

    for (0..3) |i| try testing.expectEqual(@as(u32, @intCast(i)), transfer.nextRequest().?.index);
    try testing.expectEqual(@as(?packs.Request, null), transfer.nextRequest());

    try testing.expectEqual(packs.Progress.stored, try transfer.accept(chunk(2), storage));
    try testing.expectEqual(packs.Progress.stored, try transfer.accept(chunk(1), storage));
    try testing.expectEqual(@as(u64, 0), transfer.progress());
    try testing.expectEqual(@as(u32, 1), transfer.outstanding());
    try testing.expectEqual(@as(?packs.Request, null), transfer.nextRequest());

    try testing.expectEqual(packs.Progress.stored, try transfer.accept(chunk(0), storage));
    try testing.expectEqual(@as(u64, 768), transfer.progress());
    try testing.expectEqual(@as(u32, 0), transfer.outstanding());
    try testing.expectEqual(packs.Progress.duplicate, try transfer.accept(chunk(1), storage));

    while (transfer.nextRequest()) |request| _ = try transfer.accept(chunk(request.index), storage);
    try testing.expect(transfer.complete);
    try testing.expectEqualSlices(u8, &archive, &stored);
}

test "randomized arrival orders with repeats always reproduce the archive" {
    var prng = std.Random.DefaultPrng.init(0x7ac5);
    const random = prng.random();

    for (0..200) |_| {
        var stored: [archive.len]u8 = undefined;
        const storage: packs.Memory = .{ .bytes = &stored };
        const window = random.intRangeAtMost(u8, 1, 12);
        var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits, .{ .window = window });
        defer transfer.deinit();

        var pending: [16]u32 = undefined;
        var count: usize = 0;
        while (!transfer.complete) {
            while (transfer.nextRequest()) |request| : (count += 1) pending[count] = request.index;
            const pick = random.uintLessThan(usize, count);
            const index = pending[pick];
            pending[pick] = pending[count - 1];
            count -= 1;
            _ = try transfer.accept(chunk(index), storage);
            if (!transfer.complete and random.boolean()) try testing.expectEqual(packs.Progress.duplicate, try transfer.accept(chunk(index), storage));
            try testing.expect(transfer.outstanding() <= window);
        }
        try testing.expectEqualSlices(u8, &archive, &stored);
    }
}

test "unsolicited, misplaced and foreign chunks fail the transfer" {
    var stored: [archive.len]u8 = undefined;
    const bad = [_]struct { chunk: packs.Chunk, err: anyerror }{
        .{ .chunk = chunk(1), .err = error.UnsolicitedChunk },
        .{ .chunk = .{ .pack_id = "alpha_1.0.0", .index = 0, .offset = 256, .data = archive[0..256] }, .err = error.InvalidChunk },
        .{ .chunk = .{ .pack_id = "alpha_1.0.0", .index = 0, .offset = 0, .data = archive[0..255] }, .err = error.InvalidChunk },
        .{ .chunk = .{ .pack_id = "alpha_1.0.0", .index = 0, .offset = 0, .data = archive[0..257] }, .err = error.InvalidChunk },
        .{ .chunk = .{ .pack_id = "beta_1.0.0", .index = 0, .offset = 0, .data = archive[0..256] }, .err = error.InvalidChunk },
    };

    for (bad) |case| {
        var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits, .{ .window = 1 });
        defer transfer.deinit();
        _ = transfer.nextRequest();

        try testing.expectError(case.err, transfer.accept(case.chunk, packs.Memory{ .bytes = &stored }));
        try testing.expect(transfer.failed);
        try testing.expectEqual(@as(?packs.Request, null), transfer.nextRequest());
        try testing.expectError(error.InvalidState, transfer.accept(chunk(0), packs.Memory{ .bytes = &stored }));
    }
}

test "substituted contents are caught by the final hash, even when they arrived early" {
    var stored: [archive.len]u8 = undefined;
    const storage: packs.Memory = .{ .bytes = &stored };
    var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits, .{ .window = 4 });
    defer transfer.deinit();
    while (transfer.nextRequest()) |_| {}

    const forged = @as([256]u8, @splat('x'));
    _ = try transfer.accept(.{ .pack_id = "alpha_1.0.0", .index = 2, .offset = 512, .data = &forged }, storage);
    for ([_]u32{ 0, 1, 3 }) |index| _ = try transfer.accept(chunk(index), storage);
    while (transfer.nextRequest()) |request| {
        if (request.index == 9) {
            try testing.expectError(error.IntegrityMismatch, transfer.accept(chunk(9), storage));
            break;
        }
        _ = try transfer.accept(chunk(request.index), storage);
    }
    try testing.expect(transfer.failed and !transfer.complete);
}

test "a pack without a usable hash still downloads" {
    var info: packs.DataInfo = .{
        .resource_name = "alpha_1.0.0",
        .chunk_size = 256,
        .number_of_chunks = 10,
        .file_size = archive.len,
        .file_hash = "",
        .is_premium_pack = false,
        .pack_type = 6,
    };
    try testing.expectEqual(@as(?[32]u8, null), packs.Metadata.fromDataInfo(info).hash);
    info.file_hash = &@as([32]u8, @splat(0));
    try testing.expectEqual(@as(?[32]u8, null), packs.Metadata.fromDataInfo(info).hash);
    const hash = digest(&archive);
    info.file_hash = &hash;
    try testing.expectEqualDeep(metadata(), packs.Metadata.fromDataInfo(info));

    info.file_hash = "";
    var stored: [archive.len]u8 = undefined;
    var transfer = try packs.Transfer.init(testing.allocator, packs.Metadata.fromDataInfo(info), support.limits, .{});
    defer transfer.deinit();
    while (transfer.nextRequest()) |request| _ = try transfer.accept(chunk(request.index), packs.Memory{ .bytes = &stored });
    try testing.expect(transfer.complete);
}

test "a storage failure fails the transfer" {
    var stored: [512]u8 = undefined;
    var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits, .{ .window = 4 });
    defer transfer.deinit();
    while (transfer.nextRequest()) |_| {}

    _ = try transfer.accept(chunk(1), packs.Memory{ .bytes = &stored });
    try testing.expectError(error.NoSpaceLeft, transfer.accept(chunk(2), packs.Memory{ .bytes = &stored }));
    try testing.expect(transfer.failed);
}

test "the request window is bounded and the widest window still reorders" {
    try testing.expectError(error.InvalidLimits, packs.Transfer.init(testing.allocator, metadata(), support.limits, .{ .window = 0 }));
    try testing.expectError(error.InvalidLimits, packs.Transfer.init(testing.allocator, metadata(), support.limits, .{ .window = packs.max_window + 1 }));

    var bytes: [64 * 16 + 5]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(i);
    const meta = try packs.Metadata.init("wide", bytes.len, 16, digest(&bytes));
    try testing.expectEqual(@as(u32, 65), meta.chunk_count);

    var stored: [bytes.len]u8 = undefined;
    var transfer = try packs.Transfer.init(testing.allocator, meta, support.limits, .{ .window = packs.max_window });
    defer transfer.deinit();
    var requested: u32 = 0;
    while (transfer.nextRequest()) |_| requested += 1;
    try testing.expectEqual(@as(u32, 64), requested);

    var index: u32 = 64;
    while (index > 0) {
        index -= 1;
        _ = try transfer.accept(try packs.serve(meta, &bytes, .{ .pack_id = "wide", .index = index }, support.limits), packs.Memory{ .bytes = &stored });
    }
    try testing.expectEqual(@as(u32, 64), transfer.nextRequest().?.index);
    try testing.expectEqual(packs.Progress.complete, try transfer.accept(try packs.serve(meta, &bytes, .{ .pack_id = "wide", .index = 64 }, support.limits), packs.Memory{ .bytes = &stored }));
    try testing.expectEqualSlices(u8, &bytes, &stored);
}

test "a canceled transfer refuses further chunks" {
    var stored: [archive.len]u8 = undefined;
    var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits, .{});
    defer transfer.deinit();
    _ = transfer.nextRequest();
    transfer.cancel();
    try testing.expectEqual(@as(?packs.Request, null), transfer.nextRequest());
    try testing.expectError(error.InvalidState, transfer.accept(chunk(0), packs.Memory{ .bytes = &stored }));
}

test "announced geometry must be internally consistent" {
    const base = metadata();

    var wrong_count = base;
    wrong_count.chunk_count = 2;
    try testing.expectError(error.InvalidChunk, packs.Transfer.init(testing.allocator, wrong_count, support.limits, .{}));

    var zero_size = base;
    zero_size.size = 0;
    zero_size.chunk_count = 0;
    try testing.expectError(error.InvalidChunk, packs.Transfer.init(testing.allocator, zero_size, support.limits, .{}));

    var zero_chunk = base;
    zero_chunk.chunk_size = 0;
    try testing.expectError(error.InvalidChunk, packs.Transfer.init(testing.allocator, zero_chunk, support.limits, .{}));

    var empty_id = base;
    empty_id.pack_id = "";
    try testing.expectError(error.LimitExceeded, packs.Transfer.init(testing.allocator, empty_id, support.limits, .{}));

    var invalid_id = base;
    invalid_id.pack_id = "\xff";
    try testing.expectError(error.InvalidUtf8, packs.Transfer.init(testing.allocator, invalid_id, support.limits, .{}));

    try testing.expectError(error.InvalidChunk, packs.Metadata.init("x", 0, 1, null));
    try testing.expectError(error.LimitExceeded, packs.Metadata.init("x", 1 << 40, 1, null));
}

test "announced size and chunk size are bounded by the session limits" {
    const base = metadata();

    var tight = support.limits;
    tight.max_resource_pack_bytes = 128;
    try testing.expectError(error.LimitExceeded, packs.Transfer.init(testing.allocator, base, tight, .{}));

    tight = support.limits;
    tight.max_resource_pack_chunk_bytes = 64;
    try testing.expectError(error.LimitExceeded, packs.Transfer.init(testing.allocator, base, tight, .{}));
    try testing.expectError(error.LimitExceeded, packs.Delivery.init(testing.allocator, base, tight));
}

test "a pack id is owned for the life of the transfer" {
    var id = [_]u8{ 'a', 'l', 'p', 'h', 'a' };
    var meta = metadata();
    meta.pack_id = &id;

    var transfer = try packs.Transfer.init(testing.allocator, meta, support.limits, .{});
    defer transfer.deinit();

    @memset(&id, 'z');
    try testing.expectEqualStrings("alpha", transfer.nextRequest().?.pack_id);
}

test "a single-chunk pack completes on its first chunk" {
    const meta = try packs.Metadata.init("small", 16, 256, digest(archive[0..16]));
    var stored: [16]u8 = undefined;
    var transfer = try packs.Transfer.init(testing.allocator, meta, support.limits, .{});
    defer transfer.deinit();

    const request = transfer.nextRequest().?;
    try testing.expectEqual(@as(?packs.Request, null), transfer.nextRequest());
    try testing.expectEqual(packs.Progress.complete, try transfer.accept(try packs.serve(meta, archive[0..16], request, support.limits), packs.Memory{ .bytes = &stored }));
}

test "transfer and delivery setup unwind every allocation failure" {
    const Case = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var transfer = try packs.Transfer.init(allocator, metadata(), support.limits, .{});
            transfer.deinit();
            var delivery = try packs.Delivery.init(allocator, metadata(), support.limits);
            delivery.deinit();
        }
    };

    try testing.checkAllAllocationFailures(testing.allocator, Case.run, .{});
}

test "a delivery feeds a pipelined transfer from an external source" {
    var delivery = try packs.Delivery.init(testing.allocator, metadata(), support.limits);
    defer delivery.deinit();
    var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits, .{ .window = 4 });
    defer transfer.deinit();

    var stored: [archive.len]u8 = undefined;
    var scratch: [256]u8 = undefined;
    var queue: [4]packs.Request = undefined;
    while (!transfer.complete) {
        var count: usize = 0;
        while (transfer.nextRequest()) |request| : (count += 1) queue[count] = request;
        while (count > 0) {
            count -= 1;
            const served = try delivery.serve(queue[count], packs.Archive{ .bytes = &archive }, &scratch);
            _ = try transfer.accept(served, packs.Memory{ .bytes = &stored });
        }
    }
    try testing.expect(delivery.done());
    try testing.expectEqualSlices(u8, &archive, &stored);
}

test "a delivery refuses repeats, strangers and requests it cannot hold" {
    var delivery = try packs.Delivery.init(testing.allocator, metadata(), support.limits);
    defer delivery.deinit();
    const source: packs.Archive = .{ .bytes = &archive };
    var scratch: [256]u8 = undefined;

    try testing.expectError(error.InvalidChunk, delivery.serve(.{ .pack_id = "beta_1.0.0", .index = 0 }, source, &scratch));
    try testing.expectError(error.InvalidChunk, delivery.serve(.{ .pack_id = "alpha_1.0.0", .index = 10 }, source, &scratch));
    try testing.expectError(error.InvalidChunk, delivery.serve(.{ .pack_id = "alpha_1.0", .index = 0 }, source, &scratch));
    try testing.expectError(error.NoSpaceLeft, delivery.serve(.{ .pack_id = "alpha_1.0.0", .index = 0 }, source, scratch[0..255]));
    try testing.expectError(error.EndOfStream, delivery.serve(.{ .pack_id = "alpha_1.0.0", .index = 9 }, packs.Archive{ .bytes = archive[0..2400] }, &scratch));

    const by_uuid = try delivery.serve(.{ .pack_id = "alpha", .index = 9 }, source, &scratch);
    try testing.expectEqualStrings("alpha", by_uuid.pack_id);
    try testing.expectEqualSlices(u8, archive[2304..], by_uuid.data);
    try testing.expectError(error.DuplicateRequest, delivery.serve(.{ .pack_id = "alpha_1.0.0", .index = 9 }, source, &scratch));

    for (0..9) |i| _ = try delivery.serve(.{ .pack_id = "alpha_1.0.0", .index = @intCast(i) }, source, &scratch);
    try testing.expect(delivery.done());
}

test "chunk packets convert to transfer types" {
    try testing.expectError(error.InvalidChunk, packs.Request.fromPacket(.{ .resource_name = "alpha", .chunk = -1 }));
    const request = try packs.Request.fromPacket(.{ .resource_name = "alpha", .chunk = 7 });
    try testing.expectEqual(@as(u32, 7), request.index);
    const converted = packs.Chunk.fromPacket(.{ .resource_name = "alpha", .chunk_id = 2, .byte_offset = 512, .chunk_data = "abc" });
    try testing.expectEqualStrings("abc", converted.data);
    try testing.expectEqual(@as(u64, 512), converted.offset);
}

test "serving refuses requests that do not match the archive" {
    const meta = metadata();

    try testing.expectError(error.InvalidChunk, packs.serve(meta, &archive, .{ .pack_id = "beta", .index = 0 }, support.limits));
    try testing.expectError(error.InvalidChunk, packs.serve(meta, &archive, .{ .pack_id = "alpha_1.0.0", .index = 10 }, support.limits));
    try testing.expectError(error.InvalidChunk, packs.serve(meta, archive[0..100], .{ .pack_id = "alpha_1.0.0", .index = 0 }, support.limits));
}

test "the last served chunk is short, not padded" {
    const last = chunk(9);
    try testing.expectEqual(@as(usize, 196), last.data.len);
    try testing.expectEqual(@as(u64, 2304), last.offset);
}

test "negotiation and transfer agree on completion" {
    const offers: []const packs.Offer = &.{.{ .id = "alpha_1.0.0", .size = archive.len }};

    var negotiation = try packs.Negotiation.init(testing.allocator, offers, support.limits);
    defer negotiation.deinit();

    try negotiation.respond(.send_packs, &.{"alpha_1.0.0"});
    try testing.expect(!negotiation.downloaded());

    var stored: [archive.len]u8 = undefined;
    var transfer = try packs.Transfer.init(testing.allocator, metadata(), support.limits, .{});
    defer transfer.deinit();
    while (transfer.nextRequest()) |request| _ = try transfer.accept(chunk(request.index), packs.Memory{ .bytes = &stored });

    try negotiation.markVerified("alpha_1.0.0");
    try testing.expect(negotiation.downloaded());
    try negotiation.respond(.all_packs_downloaded, &.{});
    try negotiation.respond(.completed, &.{});
    try testing.expect(negotiation.done());
}

test "random geometry, arrival order and junk never corrupt a completed pack" {
    const cases = @max(64, @import("build_options").fuzz_iterations / 100);
    var prng = std.Random.DefaultPrng.init(0xb0a7);
    const random = prng.random();
    var bytes: [5000]u8 = undefined;
    var stored: [5000]u8 = undefined;
    var junk: [800]u8 = undefined;

    for (0..cases) |_| {
        const size = random.intRangeAtMost(usize, 1, bytes.len);
        random.bytes(bytes[0..size]);
        const meta = try packs.Metadata.init("fuzz_1", size, random.intRangeAtMost(u32, 1, 700), if (random.boolean()) digest(bytes[0..size]) else null);
        var transfer = try packs.Transfer.init(testing.allocator, meta, support.limits, .{ .window = random.intRangeAtMost(u8, 1, packs.max_window) });
        defer transfer.deinit();
        const storage: packs.Memory = .{ .bytes = stored[0..size] };

        var pending: [packs.max_window]u32 = undefined;
        var count: usize = 0;
        while (!transfer.complete and !transfer.failed) {
            while (transfer.nextRequest()) |request| : (count += 1) pending[count] = request.index;
            if (random.uintLessThan(u8, 40) == 0) {
                random.bytes(&junk);
                const forged: packs.Chunk = .{
                    .pack_id = if (random.boolean()) "fuzz_1" else "other",
                    .index = random.uintLessThan(u32, meta.chunk_count + 4),
                    .offset = random.uintLessThan(u64, size + 800),
                    .data = junk[0..random.uintLessThan(usize, junk.len)],
                };
                _ = transfer.accept(forged, storage) catch {
                    try testing.expect(transfer.failed);
                    try testing.expectError(error.InvalidState, transfer.accept(forged, storage));
                };
                continue;
            }
            const pick = random.uintLessThan(usize, count);
            const index = pending[pick];
            pending[pick] = pending[count - 1];
            count -= 1;
            _ = try transfer.accept(try packs.serve(meta, bytes[0..size], .{ .pack_id = "fuzz_1", .index = index }, support.limits), storage);
        }
        if (transfer.complete) try testing.expectEqualSlices(u8, bytes[0..size], stored[0..size]);
    }
}
