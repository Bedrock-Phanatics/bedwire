const std = @import("std");
const protocol = @import("bedrock_protocol");

const Limits = @import("../limits.zig").Limits;
const negotiation = @import("negotiation.zig");

pub const DataInfo = @FieldType(protocol.typed.Packet, "resource_pack_data_info");
pub const ChunkData = @FieldType(protocol.typed.Packet, "resource_pack_chunk_data");
pub const ChunkRequest = @FieldType(protocol.typed.Packet, "resource_pack_chunk_request");

pub const Metadata = struct {
    pack_id: []const u8,
    chunk_size: u32,
    chunk_count: u32,
    size: u64,
    /// SHA-256 of the archive. Null skips verification for peers that send none.
    hash: ?[32]u8,

    pub fn init(pack_id: []const u8, size: u64, chunk_size: u32, hash: ?[32]u8) !Metadata {
        if (size == 0 or chunk_size == 0) return error.InvalidChunk;
        const count = std.math.cast(u32, std.math.divCeil(u64, size, chunk_size) catch unreachable) orelse return error.LimitExceeded;
        return .{ .pack_id = pack_id, .chunk_size = chunk_size, .chunk_count = count, .size = size, .hash = hash };
    }

    /// `pack_id` borrows the packet. A hash that isn't 32 bytes or is all zeroes counts as absent.
    pub fn fromDataInfo(info: DataInfo) Metadata {
        const hashed = info.file_hash.len == 32 and !std.mem.allEqual(u8, info.file_hash, 0);
        return .{
            .pack_id = info.resource_name,
            .chunk_size = info.chunk_size,
            .chunk_count = info.number_of_chunks,
            .size = info.file_size,
            .hash = if (hashed) info.file_hash[0..32].* else null,
        };
    }

    pub fn validate(self: Metadata, limits: Limits) !void {
        try negotiation.validateId(self.pack_id, limits);
        if (self.size > limits.max_resource_pack_bytes) return error.LimitExceeded;
        if (self.chunk_size > limits.max_resource_pack_chunk_bytes) return error.LimitExceeded;
        if (self.size == 0 or self.chunk_size == 0) return error.InvalidChunk;

        const count = self.size / self.chunk_size + @intFromBool(self.size % self.chunk_size != 0);
        if (count != self.chunk_count) return error.InvalidChunk;
    }

    pub fn chunkOffset(self: Metadata, index: u32) u64 {
        return @as(u64, index) * self.chunk_size;
    }

    pub fn chunkLen(self: Metadata, index: u32) usize {
        return @intCast(@min(self.chunk_size, self.size - self.chunkOffset(index)));
    }
};

/// `data` borrows the packet.
pub const Chunk = struct {
    pack_id: []const u8,
    index: u32,
    offset: u64,
    data: []const u8,

    pub fn fromPacket(packet: ChunkData) Chunk {
        return .{ .pack_id = packet.resource_name, .index = packet.chunk_id, .offset = packet.byte_offset, .data = packet.chunk_data };
    }
};

pub const Request = struct {
    pack_id: []const u8,
    index: u32,

    pub fn fromPacket(packet: ChunkRequest) !Request {
        return .{ .pack_id = packet.resource_name, .index = std.math.cast(u32, packet.chunk) orelse return error.InvalidChunk };
    }
};

pub const Memory = struct {
    bytes: []u8,

    pub fn writeAt(self: Memory, offset: u64, data: []const u8) !void {
        if (offset > self.bytes.len or data.len > self.bytes.len - offset) return error.NoSpaceLeft;
        @memcpy(self.bytes[@intCast(offset)..][0..data.len], data);
    }

    pub fn readAt(self: Memory, offset: u64, dest: []u8) !void {
        if (offset > self.bytes.len or dest.len > self.bytes.len - offset) return error.EndOfStream;
        @memcpy(dest, self.bytes[@intCast(offset)..][0..dest.len]);
    }
};

pub const Archive = struct {
    bytes: []const u8,

    pub fn readAt(self: Archive, offset: u64, dest: []u8) !void {
        if (offset > self.bytes.len or dest.len > self.bytes.len - offset) return error.EndOfStream;
        @memcpy(dest, self.bytes[@intCast(offset)..][0..dest.len]);
    }
};

pub const max_window = 64;

pub const Options = struct {
    /// Chunk requests kept in flight, 1 through `max_window`.
    window: u8 = 8,
};

pub const Progress = enum { stored, duplicate, complete };

pub const Transfer = struct {
    allocator: std.mem.Allocator,
    metadata: Metadata,
    window: u8,
    hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
    prefix: u32 = 0,
    requested: u32 = 0,
    /// Bit n marks chunk prefix + n as stored but not yet hashed.
    ahead: u64 = 0,
    failed: bool = false,
    complete: bool = false,

    pub fn init(allocator: std.mem.Allocator, metadata: Metadata, limits: Limits, options: Options) !Transfer {
        try metadata.validate(limits);
        if (options.window == 0 or options.window > max_window) return error.InvalidLimits;

        var owned = metadata;
        owned.pack_id = try allocator.dupe(u8, metadata.pack_id);

        return .{ .allocator = allocator, .metadata = owned, .window = options.window };
    }

    pub fn deinit(self: *Transfer) void {
        self.allocator.free(self.metadata.pack_id);
        self.* = undefined;
    }

    pub fn nextRequest(self: *Transfer) ?Request {
        if (self.failed or self.complete) return null;
        if (self.requested == self.metadata.chunk_count or self.requested - self.prefix == self.window) return null;
        defer self.requested += 1;
        return .{ .pack_id = self.metadata.pack_id, .index = self.requested };
    }

    /// Repeats come back as duplicate and are ignored. Any other rejection, including a storage error, fails the transfer for good.
    pub fn accept(self: *Transfer, chunk: Chunk, storage: anytype) !Progress {
        if (self.failed or self.complete) return error.InvalidState;
        errdefer self.failed = true;

        if (!std.mem.eql(u8, chunk.pack_id, self.metadata.pack_id)) return error.InvalidChunk;
        if (chunk.index >= self.requested) return error.UnsolicitedChunk;
        if (chunk.index < self.prefix or self.ahead & bit(chunk.index - self.prefix) != 0) return .duplicate;
        if (chunk.offset != self.metadata.chunkOffset(chunk.index) or
            chunk.data.len != self.metadata.chunkLen(chunk.index)) return error.InvalidChunk;

        try storage.writeAt(chunk.offset, chunk.data);
        if (chunk.index != self.prefix) {
            self.ahead |= bit(chunk.index - self.prefix);
            return .stored;
        }

        self.hash.update(chunk.data);
        self.prefix += 1;
        self.ahead >>= 1;
        while (self.ahead & 1 != 0) : (self.ahead >>= 1) {
            try self.hashStored(storage, self.prefix);
            self.prefix += 1;
        }
        if (self.prefix != self.metadata.chunk_count) return .stored;

        if (self.metadata.hash) |expected| {
            if (!std.crypto.timing_safe.eql([32]u8, self.hash.finalResult(), expected)) return error.IntegrityMismatch;
        }
        self.complete = true;
        return .complete;
    }

    pub fn cancel(self: *Transfer) void {
        if (!self.complete) self.failed = true;
    }

    pub fn outstanding(self: *const Transfer) u32 {
        return self.requested - self.prefix - @popCount(self.ahead);
    }

    pub fn progress(self: *const Transfer) u64 {
        return @min(self.metadata.size, self.metadata.chunkOffset(self.prefix));
    }

    fn hashStored(self: *Transfer, storage: anytype, index: u32) !void {
        var buffer: [4096]u8 = undefined;
        var offset = self.metadata.chunkOffset(index);
        var left = self.metadata.chunkLen(index);
        while (left != 0) {
            const piece = buffer[0..@min(left, buffer.len)];
            try storage.readAt(offset, piece);
            self.hash.update(piece);
            offset += piece.len;
            left -= piece.len;
        }
    }

    fn bit(distance: u32) u64 {
        return @as(u64, 1) << @intCast(distance);
    }
};

/// Each chunk is served at most once so a client can't make us resend the archive by repeating requests.
pub const Delivery = struct {
    allocator: std.mem.Allocator,
    metadata: Metadata,
    served: []u64,
    remaining: u32,

    pub fn init(allocator: std.mem.Allocator, metadata: Metadata, limits: Limits) !Delivery {
        try metadata.validate(limits);

        var owned = metadata;
        owned.pack_id = try allocator.dupe(u8, metadata.pack_id);
        errdefer allocator.free(owned.pack_id);

        const served = try allocator.alloc(u64, std.math.divCeil(u32, metadata.chunk_count, 64) catch unreachable);
        @memset(served, 0);

        return .{ .allocator = allocator, .metadata = owned, .served = served, .remaining = metadata.chunk_count };
    }

    pub fn deinit(self: *Delivery) void {
        self.allocator.free(self.metadata.pack_id);
        self.allocator.free(self.served);
        self.* = undefined;
    }

    pub fn done(self: *const Delivery) bool {
        return self.remaining == 0;
    }

    /// The chunk's `pack_id` echoes the request. DuplicateRequest and source errors leave the Delivery usable.
    pub fn serve(self: *Delivery, request: Request, source: anytype, dest: []u8) !Chunk {
        if (!self.matches(request.pack_id) or request.index >= self.metadata.chunk_count) return error.InvalidChunk;

        const word = &self.served[request.index / 64];
        const mask = @as(u64, 1) << @intCast(request.index % 64);
        if (word.* & mask != 0) return error.DuplicateRequest;

        const len = self.metadata.chunkLen(request.index);
        if (dest.len < len) return error.NoSpaceLeft;
        const offset = self.metadata.chunkOffset(request.index);
        try source.readAt(offset, dest[0..len]);

        word.* |= mask;
        self.remaining -= 1;
        return .{ .pack_id = request.pack_id, .index = request.index, .offset = offset, .data = dest[0..len] };
    }

    // Clients echo the whole name but some send only the UUID in front of the version.
    fn matches(self: *const Delivery, id: []const u8) bool {
        if (std.mem.eql(u8, id, self.metadata.pack_id)) return true;
        const end = std.mem.indexOfScalar(u8, self.metadata.pack_id, '_') orelse return false;
        return std.mem.eql(u8, id, self.metadata.pack_id[0..end]);
    }
};

/// Stateless, so repeated requests are served again. Prefer Delivery for clients you don't trust.
pub fn serve(metadata: Metadata, archive: []const u8, request: Request, limits: Limits) !Chunk {
    try metadata.validate(limits);

    const valid =
        std.mem.eql(u8, metadata.pack_id, request.pack_id) and
        request.index < metadata.chunk_count and
        archive.len == metadata.size;
    if (!valid) return error.InvalidChunk;

    const offset = metadata.chunkOffset(request.index);
    return .{
        .pack_id = metadata.pack_id,
        .index = request.index,
        .offset = offset,
        .data = archive[@intCast(offset)..][0..metadata.chunkLen(request.index)],
    };
}
