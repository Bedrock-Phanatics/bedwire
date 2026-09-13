const std = @import("std");
const protocol = @import("bedrock_protocol");
const Limits = @import("../framing/limits.zig").DecodeLimits;

pub const Metadata = struct {
    pack_id: []const u8,
    chunk_size: u32,
    chunk_count: u32,
    size: u64,
    hash: [32]u8,
    premium: bool = false,
    pack_type: u8 = 6,

    pub fn validate(self: Metadata, limits: Limits) !void {
        if (self.pack_id.len > std.math.maxInt(u32)) return error.LimitExceeded;
        if (self.pack_id.len == 0 or self.pack_id.len > limits.protocol.max_string_bytes) return error.InvalidPack;
        if (!std.unicode.utf8ValidateSlice(self.pack_id)) return error.InvalidUtf8;
        if (self.size > limits.max_resource_pack_bytes or self.chunk_size > limits.protocol.max_byte_array_bytes) return error.LimitExceeded;
        if (self.size == 0 or self.chunk_size == 0) return error.InvalidPack;
        const count = self.size / self.chunk_size + @intFromBool(self.size % self.chunk_size != 0);
        if (count > std.math.maxInt(i32) or count != self.chunk_count) return error.InvalidPack;
        if (self.pack_type < 1 or self.pack_type > 8) return error.InvalidPack;
    }

    pub fn decode(bytes: []const u8, limits: Limits) !Metadata {
        var reader = try protocol.Reader.init(bytes, limits.protocol);
        const id = try reader.readString();
        const chunk_size = try reader.readU32();
        const count = try reader.readU32();
        const size = try reader.readU64();
        const hash = try reader.readByteArray();
        if (hash.len != 32) return error.InvalidPack;
        const result: Metadata = .{ .pack_id = id, .chunk_size = chunk_size, .chunk_count = count, .size = size, .hash = hash[0..32].*, .premium = try reader.readBool(), .pack_type = try reader.readU8() };
        try reader.finish();
        try result.validate(limits);
        return result;
    }

    pub fn encodedSize(self: Metadata) usize {
        return stringSize(self.pack_id.len) + 51;
    }

    pub fn encode(self: Metadata, dest: []u8, limits: Limits) ![]u8 {
        try self.validate(limits);
        if (self.encodedSize() > limits.protocol.max_packet_bytes) return error.LimitExceeded;
        if (self.encodedSize() > dest.len) return error.NoSpaceLeft;
        var writer = protocol.Writer.init(dest);
        try writer.writeString(self.pack_id);
        try writer.writeU32(self.chunk_size);
        try writer.writeU32(self.chunk_count);
        try writer.writeU64(self.size);
        try writer.writeByteArray(&self.hash);
        try writer.writeBool(self.premium);
        try writer.writeU8(self.pack_type);
        return dest[0..writer.cursor];
    }
};

fn stringSize(len: usize) usize {
    var bytes: [10]u8 = undefined;
    var writer = protocol.Writer.init(&bytes);
    writer.writeVarU64(len) catch unreachable;
    return len + writer.cursor;
}

pub const Chunk = struct {
    pack_id: []const u8,
    index: u32,
    offset: u64,
    data: []const u8,

    pub fn decode(bytes: []const u8, limits: Limits) !Chunk {
        var reader = try protocol.Reader.init(bytes, limits.protocol);
        const result: Chunk = .{ .pack_id = try reader.readString(), .index = try reader.readU32(), .offset = try reader.readU64(), .data = try reader.readByteArray() };
        try reader.finish();
        return result;
    }

    pub fn size(self: Chunk) usize {
        return stringSize(self.pack_id.len) + 12 + stringSize(self.data.len);
    }

    /// Input slices must not overlap destination. Failure leaves destination unchanged.
    pub fn encode(self: Chunk, dest: []u8, limits: Limits) ![]u8 {
        const within_limits = self.pack_id.len <= limits.protocol.max_string_bytes and self.data.len <= limits.protocol.max_byte_array_bytes and
            self.pack_id.len <= std.math.maxInt(u32) and self.data.len <= std.math.maxInt(u32);
        if (!within_limits) return error.LimitExceeded;
        if (!std.unicode.utf8ValidateSlice(self.pack_id)) return error.InvalidUtf8;
        if (self.size() > limits.protocol.max_packet_bytes) return error.LimitExceeded;
        if (self.size() > dest.len) return error.NoSpaceLeft;
        var writer = protocol.Writer.init(dest);
        try writer.writeString(self.pack_id);
        try writer.writeU32(self.index);
        try writer.writeU64(self.offset);
        try writer.writeByteArray(self.data);
        return dest[0..writer.cursor];
    }
};

pub const Request = struct {
    pack_id: []const u8,
    index: u32,

    pub fn decode(bytes: []const u8, limits: Limits) !Request {
        var reader = try protocol.Reader.init(bytes, limits.protocol);
        const id = try reader.readString();
        const index = try reader.readI32();
        if (index < 0) return error.InvalidChunk;
        try reader.finish();
        return .{ .pack_id = id, .index = @intCast(index) };
    }

    pub fn size(self: Request) usize {
        return stringSize(self.pack_id.len) + 4;
    }

    pub fn encode(self: Request, dest: []u8, limits: Limits) ![]u8 {
        if (self.index > std.math.maxInt(i32)) return error.InvalidChunk;
        if (self.pack_id.len > limits.protocol.max_string_bytes or self.pack_id.len > std.math.maxInt(u32)) return error.LimitExceeded;
        if (!std.unicode.utf8ValidateSlice(self.pack_id)) return error.InvalidUtf8;
        if (self.size() > limits.protocol.max_packet_bytes) return error.LimitExceeded;
        if (self.size() > dest.len) return error.NoSpaceLeft;
        var writer = protocol.Writer.init(dest);
        try writer.writeString(self.pack_id);
        try writer.writeU32(self.index);
        return dest[0..writer.cursor];
    }
};

/// Streams sequential chunks into SHA256 without retaining archive contents.
/// Caller owns storage/delivery of accepted data and must wait for complete before use.
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

    pub fn accept(self: *Transfer, chunk: Chunk) !void {
        if (self.failed or self.complete) return error.InvalidState;
        errdefer self.failed = true;
        const expected = @min(self.metadata.chunk_size, self.metadata.size - self.offset);
        const valid = std.mem.eql(u8, chunk.pack_id, self.metadata.pack_id) and chunk.index == self.next_index and
            chunk.offset == self.offset and chunk.data.len == expected;
        if (!valid) return error.InvalidChunk;
        var hash = self.hash;
        hash.update(chunk.data);
        const done = self.next_index + 1 == self.metadata.chunk_count;
        if (done and !std.crypto.timing_safe.eql([32]u8, hash.finalResult(), self.metadata.hash)) return error.IntegrityMismatch;
        self.hash = hash;
        self.next_index += 1;
        self.offset += chunk.data.len;
        self.complete = done;
    }

    /// Validates a server-side chunk request and returns a borrowed archive slice.
    pub fn serve(metadata: Metadata, archive: []const u8, req: Request, limits: Limits) !Chunk {
        try metadata.validate(limits);
        const valid = std.mem.eql(u8, metadata.pack_id, req.pack_id) and req.index < metadata.chunk_count and archive.len == metadata.size;
        if (!valid) return error.InvalidChunk;
        const offset: usize = @intCast(@as(u64, req.index) * metadata.chunk_size);
        return .{ .pack_id = metadata.pack_id, .index = req.index, .offset = offset, .data = archive[offset..][0..@min(metadata.chunk_size, archive.len - offset)] };
    }
};
