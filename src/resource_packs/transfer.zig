const std = @import("std");

const Limits = @import("../limits.zig").Limits;
const negotiation = @import("negotiation.zig");

/// metadata from ResourcePackDataInfo
pub const Metadata = struct {
    pack_id: []const u8,
    chunk_size: u32,
    chunk_count: u32,
    size: u64,
    hash: [32]u8,

    // check chunk count matches total pack size
    pub fn validate(self: Metadata, limits: Limits) !void {
        try negotiation.validateId(self.pack_id, limits);
        if (self.size > limits.max_resource_pack_bytes) return error.LimitExceeded;
        if (self.chunk_size > limits.max_resource_pack_chunk_bytes) return error.LimitExceeded;
        if (self.size == 0 or self.chunk_size == 0) return error.InvalidChunk;

        const count = self.size / self.chunk_size + @intFromBool(self.size % self.chunk_size != 0);
        if (count != self.chunk_count) return error.InvalidChunk;
    }
};

/// one chunk from ResourcePackChunkData (data borrowed from packet)
pub const Chunk = struct {
    pack_id: []const u8,
    index: u32,
    offset: u64,
    data: []const u8,
};

/// chunk request from client
pub const Request = struct {
    pack_id: []const u8,
    index: u32,
};

/// streams and hashes incoming chunks with sha256 so we don't have to buffer the whole pack in ram
pub const Transfer = struct {
    allocator: std.mem.Allocator,
    metadata: Metadata,
    hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
    next_index: u32 = 0,
    offset: u64 = 0,
    failed: bool = false,
    complete: bool = false,

    pub fn init(allocator: std.mem.Allocator, metadata: Metadata, limits: Limits) !Transfer {
        try metadata.validate(limits);

        var owned = metadata;
        owned.pack_id = try allocator.dupe(u8, metadata.pack_id);

        return .{ .allocator = allocator, .metadata = owned };
    }

    pub fn deinit(self: *Transfer) void {
        self.allocator.free(self.metadata.pack_id);
        self.* = undefined;
    }

    pub fn request(self: *const Transfer) !Request {
        if (self.failed or self.complete) return error.InvalidState;
        return .{ .pack_id = self.metadata.pack_id, .index = self.next_index };
    }

    /// consume the next sequential chunk and update running sha256 hash
    pub fn accept(self: *Transfer, chunk: Chunk) !void {
        if (self.failed or self.complete) return error.InvalidState;
        errdefer self.failed = true;

        const expected = @min(self.metadata.chunk_size, self.metadata.size - self.offset);
        const valid =
            std.mem.eql(u8, chunk.pack_id, self.metadata.pack_id) and
            chunk.index == self.next_index and
            chunk.offset == self.offset and
            chunk.data.len == expected;
        if (!valid) return error.InvalidChunk;

        var hash = self.hash;
        hash.update(chunk.data);

        const done = self.next_index + 1 == self.metadata.chunk_count;
        if (done and !std.crypto.timing_safe.eql([32]u8, hash.finalResult(), self.metadata.hash)) {
            return error.IntegrityMismatch;
        }

        self.hash = hash;
        self.next_index += 1;
        self.offset += chunk.data.len;
        self.complete = done;
    }

    pub fn progress(self: *const Transfer) u64 {
        return self.offset;
    }
};

/// slices out a chunk from an in-memory pack archive to respond to a client request
pub fn serve(metadata: Metadata, archive: []const u8, request: Request, limits: Limits) !Chunk {
    try metadata.validate(limits);

    const valid =
        std.mem.eql(u8, metadata.pack_id, request.pack_id) and
        request.index < metadata.chunk_count and
        archive.len == metadata.size;
    if (!valid) return error.InvalidChunk;

    const offset: usize = @intCast(@as(u64, request.index) * metadata.chunk_size);

    return .{
        .pack_id = metadata.pack_id,
        .index = request.index,
        .offset = offset,
        .data = archive[offset..][0..@min(metadata.chunk_size, archive.len - offset)],
    };
}
