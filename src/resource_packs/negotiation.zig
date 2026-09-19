const std = @import("std");

const Limits = @import("../limits.zig").Limits;

/// one pack offered in ResourcePacksInfo
pub const Offer = struct {
    id: []const u8,
    size: u64,
};

/// client response status
pub const Response = enum { refused, send_packs, all_packs_downloaded, completed };

pub const Phase = enum { offered, downloading, stack, complete, refused };

/// tracks resource pack downloads between client and server
pub const Negotiation = struct {
    allocator: std.mem.Allocator,
    packs: []Pack,
    phase: Phase = .offered,

    pub const Pack = struct {
        id: []u8,
        size: u64,
        requested: bool = false,
        verified: bool = false,
    };

    // validates total pack count, size limits, and checks for duplicate ids
    pub fn init(allocator: std.mem.Allocator, offers: []const Offer, limits: Limits) !Negotiation {
        if (offers.len > limits.max_resource_packs) return error.LimitExceeded;

        const packs = try allocator.alloc(Pack, offers.len);
        errdefer allocator.free(packs);

        var count: usize = 0;
        errdefer for (packs[0..count]) |pack| allocator.free(pack.id);

        var total: u64 = 0;
        for (offers, 0..) |offer, i| {
            try validateId(offer.id, limits);
            if (offer.size > limits.max_resource_pack_bytes) return error.LimitExceeded;

            total = std.math.add(u64, total, offer.size) catch return error.LimitExceeded;
            if (total > limits.max_resource_pack_bytes) return error.LimitExceeded;

            for (offers[0..i]) |previous| {
                if (std.mem.eql(u8, previous.id, offer.id)) return error.DuplicatePack;
            }

            packs[i] = .{ .id = try allocator.dupe(u8, offer.id), .size = offer.size };
            count += 1;
        }

        return .{ .allocator = allocator, .packs = packs };
    }

    pub fn deinit(self: *Negotiation) void {
        for (self.packs) |pack| self.allocator.free(pack.id);
        self.allocator.free(self.packs);
        self.* = undefined;
    }

    pub fn find(self: *const Negotiation, id: []const u8) ?*Pack {
        for (self.packs) |*pack| {
            if (std.mem.eql(u8, pack.id, id)) return pack;
        }
        return null;
    }

    /// marks pack as verified once sha256 matches
    pub fn markVerified(self: *Negotiation, id: []const u8) !void {
        if (self.phase != .downloading) return error.InvalidState;

        const pack = self.find(id) orelse return error.UnknownPack;
        if (!pack.requested or pack.verified) return error.InvalidState;

        pack.verified = true;
    }

    /// process client pack response packet
    pub fn respond(self: *Negotiation, response: Response, requested: []const []const u8) !void {
        if (response != .send_packs and requested.len != 0) return error.InvalidState;
        if (requested.len > self.packs.len) return error.LimitExceeded;

        switch (response) {
            .refused => {
                if (self.phase == .complete or self.phase == .refused) return error.InvalidState;
                self.phase = .refused;
            },
            .send_packs => {
                if (self.phase != .offered or requested.len == 0) return error.InvalidState;
                try self.request(requested);
                self.phase = .downloading;
            },
            .all_packs_downloaded => {
                if (self.phase != .offered and self.phase != .downloading) return error.InvalidState;
                for (self.packs) |pack| {
                    if (pack.requested and !pack.verified) return error.IncompleteTransfer;
                }
                self.phase = .stack;
            },
            .completed => {
                if (self.phase != .stack) return error.InvalidState;
                self.phase = .complete;
            },
        }
    }

    pub fn done(self: *const Negotiation) bool {
        return self.phase == .complete or self.phase == .refused;
    }

    // validate requested pack list before mutating state
    fn request(self: *Negotiation, requested: []const []const u8) !void {
        for (requested, 0..) |id, i| {
            if (self.find(id) == null) return error.UnknownPack;
            for (requested[0..i]) |previous| {
                if (std.mem.eql(u8, previous, id)) return error.DuplicatePack;
            }
        }

        for (requested) |id| self.find(id).?.requested = true;
    }
};

pub fn validateId(id: []const u8, limits: Limits) !void {
    if (id.len == 0 or id.len > limits.max_pack_id_bytes) return error.LimitExceeded;
    if (!std.unicode.utf8ValidateSlice(id)) return error.InvalidUtf8;
}
