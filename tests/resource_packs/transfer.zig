const std = @import("std");
const bedwire = @import("bedwire");
const archive = "abcdefghij";
fn metadata() bedwire.transfer.Metadata {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(archive, &hash, .{});
    return .{ .pack_id = "pack_1.0.0", .chunk_size = 4, .chunk_count = 3, .size = 10, .hash = hash };
}

test "metadata and chunks round trip with exact SHA256 and no archive allocation" {
    const m = metadata();
    var bytes: [128]u8 = undefined;
    const encoded = try m.encode(&bytes, .{});
    try std.testing.expectEqual(m.encodedSize(), encoded.len);
    const decoded = try bedwire.transfer.Metadata.decode(encoded, .{});
    try std.testing.expectEqual(m.size, decoded.size);
    for (0..encoded.len) |end| {
        if (bedwire.transfer.Metadata.decode(encoded[0..end], .{})) |_| return error.AcceptedTruncation else |_| {}
    }
    var transfer = try bedwire.transfer.Transfer.init(std.testing.allocator, m, .{});
    defer transfer.deinit();
    while (!transfer.complete) {
        const request = try transfer.request();
        const request_bytes = try request.encode(&bytes, .{});
        const decoded_request = try bedwire.transfer.Request.decode(request_bytes, .{});
        const chunk = try bedwire.transfer.Transfer.serve(m, archive, decoded_request, .{});
        const chunk_bytes = try chunk.encode(&bytes, .{});
        try transfer.accept(try bedwire.transfer.Chunk.decode(chunk_bytes, .{}));
    }
    try std.testing.expectEqual(@as(u64, archive.len), transfer.offset);
    try std.testing.expectError(error.InvalidState, transfer.request());
}

test "resource transfer rejects bad count, chunk order, offsets, and final hash" {
    var m = metadata();
    m.chunk_count = 2;
    try std.testing.expectError(error.InvalidPack, m.validate(.{}));
    m = metadata();
    try std.testing.expectError(error.LimitExceeded, m.validate(.{ .max_resource_pack_bytes = 9 }));
    for (0..4) |case| {
        var transfer = try bedwire.transfer.Transfer.init(std.testing.allocator, m, .{});
        defer transfer.deinit();
        var chunk = try bedwire.transfer.Transfer.serve(m, archive, try transfer.request(), .{});
        switch (case) {
            0 => chunk.index = 1,
            1 => chunk.offset = 1,
            2 => chunk.pack_id = "other",
            3 => chunk.data = "abc",
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidChunk, transfer.accept(chunk));
        try std.testing.expectError(error.InvalidState, transfer.request());
    }
    m.hash[0] ^= 1;
    var transfer = try bedwire.transfer.Transfer.init(std.testing.allocator, m, .{});
    defer transfer.deinit();
    for (0..2) |_| try transfer.accept(try bedwire.transfer.Transfer.serve(m, archive, try transfer.request(), .{}));
    try std.testing.expectError(error.IntegrityMismatch, transfer.accept(try bedwire.transfer.Transfer.serve(m, archive, try transfer.request(), .{})));
    try std.testing.expect(!transfer.complete);
    var dest = [_]u8{0xaa} ** 8;
    try std.testing.expectError(error.NoSpaceLeft, m.encode(&dest, .{}));
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 8), &dest);
}
