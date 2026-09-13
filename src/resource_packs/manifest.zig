const std = @import("std");
const protocol = @import("bedrock_protocol");
const Limits = @import("../framing/limits.zig").DecodeLimits;

/// Owns the pack array; string slices borrow the original packet bytes.
pub const Manifest = struct {
    allocator: std.mem.Allocator,
    info: protocol.packets.resource_pack.ResourcePacksInfoPacket,

    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, limits: Limits) !Manifest {
        var bounded = limits.protocol;
        bounded.max_array_elements = @min(bounded.max_array_elements, limits.max_resource_packs);
        var reader = try protocol.Reader.init(bytes, bounded);
        const info = try protocol.codecs.resource_pack.decodeInfo(&reader, allocator);
        errdefer protocol.codecs.resource_pack.deinitInfo(allocator, info);
        try reader.finish();
        var total: u64 = 0;
        for (info.texture_packs, 0..) |pack, i| {
            if (pack.size > limits.max_resource_pack_bytes) return error.LimitExceeded;
            total = std.math.add(u64, total, pack.size) catch return error.LimitExceeded;
            if (total > limits.max_resource_pack_bytes) return error.LimitExceeded;
            for (info.texture_packs[0..i]) |previous| {
                if (std.mem.eql(u8, &pack.uuid, &previous.uuid)) return error.DuplicatePack;
            }
        }
        return .{ .allocator = allocator, .info = info };
    }

    pub fn deinit(self: *Manifest) void {
        protocol.codecs.resource_pack.deinitInfo(self.allocator, self.info);
        self.* = undefined;
    }
};

pub const Negotiation = struct {
    allocator: std.mem.Allocator,
    packs: []Pack,
    phase: enum { offered, downloading, stack, complete, refused } = .offered,
    const Pack = struct { id: []u8, requested: bool = false, verified: bool = false };

    pub fn init(allocator: std.mem.Allocator, ids: []const []const u8, limits: Limits) !Negotiation {
        if (ids.len > limits.max_resource_packs) return error.LimitExceeded;
        const packs = try allocator.alloc(Pack, ids.len);
        errdefer allocator.free(packs);
        var count: usize = 0;
        errdefer for (packs[0..count]) |pack| allocator.free(pack.id);
        for (ids, 0..) |id, i| {
            if (id.len == 0 or id.len > limits.protocol.max_string_bytes) return error.LimitExceeded;
            if (!std.unicode.utf8ValidateSlice(id)) return error.InvalidUtf8;
            for (ids[0..i]) |previous| if (std.mem.eql(u8, previous, id)) return error.DuplicatePack;
            packs[i] = .{ .id = try allocator.dupe(u8, id) };
            count += 1;
        }
        return .{ .allocator = allocator, .packs = packs };
    }

    pub fn deinit(self: *Negotiation) void {
        for (self.packs) |pack| self.allocator.free(pack.id);
        self.allocator.free(self.packs);
        self.* = undefined;
    }

    /// Application must have completed Transfer integrity verification for this pack.
    pub fn verified(self: *Negotiation, id: []const u8) !void {
        if (self.phase != .downloading) return error.InvalidState;
        for (self.packs) |*pack| {
            if (std.mem.eql(u8, pack.id, id)) {
                if (!pack.requested or pack.verified) return error.InvalidState;
                pack.verified = true;
                return;
            }
        }
        return error.UnknownPack;
    }

    pub fn respond(self: *Negotiation, response: protocol.packets.resource_pack.ResourcePackClientResponsePacket) !void {
        if (response.packs_to_download.len > self.packs.len) return error.LimitExceeded;
        if (response.response != .send_packs and response.packs_to_download.len != 0) return error.InvalidState;
        switch (response.response) {
            .refused => {
                if (self.phase == .complete or self.phase == .refused) return error.InvalidState;
                self.phase = .refused;
            },
            .send_packs => {
                if (self.phase != .offered or response.packs_to_download.len == 0) return error.InvalidState;
                for (response.packs_to_download, 0..) |id, i| {
                    var found = false;
                    for (self.packs) |pack| if (std.mem.eql(u8, pack.id, id)) {
                        found = true;
                        break;
                    };
                    if (!found) return error.UnknownPack;
                    for (response.packs_to_download[0..i]) |previous| if (std.mem.eql(u8, previous, id)) return error.DuplicatePack;
                }
                for (self.packs) |*pack| for (response.packs_to_download) |id| {
                    if (std.mem.eql(u8, pack.id, id)) pack.requested = true;
                };
                self.phase = .downloading;
            },
            .all_packs_downloaded => {
                if (self.phase != .offered and self.phase != .downloading) return error.InvalidState;
                for (self.packs) |pack| if (pack.requested and !pack.verified) return error.IncompleteTransfer;
                self.phase = .stack;
            },
            .completed => {
                if (self.phase != .stack) return error.InvalidState;
                self.phase = .complete;
            },
        }
    }
};
