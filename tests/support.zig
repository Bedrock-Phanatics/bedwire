const std = @import("std");
const bedwire = @import("bedwire");

pub const Ecdsa = bedwire.crypto.spki.Ecdsa;
pub const Session = bedwire.Session;
pub const PacketKind = bedwire.PacketKind;

/// Small enough that a session fits comfortably in a test, large enough to
/// exercise compression and multi-packet batches.
pub const limits: bedwire.Limits = .{
    .max_frame_bytes = 16 * 1024,
    .max_batch_bytes = 64 * 1024,
    .max_packet_bytes = 8 * 1024,
    .max_packets_per_batch = 32,
    .max_resource_pack_bytes = 1024 * 1024,
    .max_resource_packs = 8,
    .max_resource_pack_chunk_bytes = 4096,
};

/// A version that negotiates compression and uses the validation step.
pub const modern: bedwire.Descriptor = bedwire.protocol.describe(818) catch unreachable;
/// A version whose batches are implicitly DEFLATE with no marker byte.
pub const legacy: bedwire.Descriptor = bedwire.protocol.describe(440) catch unreachable;

pub fn idOf(descriptor: *const bedwire.Descriptor, kind: PacketKind) u16 {
    return descriptor.idOf(kind).?;
}

/// Writes `header ++ payload` for one packet. Bedwire does not read packet
/// bodies, so tests only need the semantic id to be right.
pub fn packet(dest: []u8, id: u16, payload: []const u8) []u8 {
    const len = bedwire.framing.varint.writeU32(dest, id) catch unreachable;
    @memcpy(dest[len..][0..payload.len], payload);
    return dest[0 .. len + payload.len];
}

/// Same, with explicit split-screen subclient fields.
pub fn subclientPacket(dest: []u8, id: u16, sender: u2, target: u2) []u8 {
    const wire = @as(u32, id) | (@as(u32, sender) << 10) | (@as(u32, target) << 12);
    const len = bedwire.framing.varint.writeU32(dest, wire) catch unreachable;
    return dest[0..len];
}

/// One packet buffer per test, so callers do not juggle scratch arrays.
pub const Builder = struct {
    storage: [4096]u8 = undefined,

    pub fn make(self: *Builder, descriptor: *const bedwire.Descriptor, kind: PacketKind) []u8 {
        return packet(&self.storage, idOf(descriptor, kind), "\x00");
    }

    pub fn makeId(self: *Builder, id: u16) []u8 {
        return packet(&self.storage, id, "\x00");
    }
};

/// A connected server and client sharing one descriptor, plus a copy buffer so
/// a frame survives the encode that produced it.
pub const Pair = struct {
    allocator: std.mem.Allocator,
    server: Session,
    client: Session,
    relay: []u8,

    pub fn init(allocator: std.mem.Allocator, descriptor: *const bedwire.Descriptor) !Pair {
        var server = try Session.init(allocator, .server, descriptor, .{ .limits = limits });
        errdefer server.deinit();

        var client = try Session.init(allocator, .client, descriptor, .{ .limits = limits });
        errdefer client.deinit();

        return .{
            .allocator = allocator,
            .server = server,
            .client = client,
            .relay = try allocator.alloc(u8, limits.max_frame_bytes),
        };
    }

    pub fn deinit(self: *Pair) void {
        self.server.deinit();
        self.client.deinit();
        self.allocator.free(self.relay);
        self.* = undefined;
    }

    /// Encodes on `from`, copies the frame, and ingests it on `to`.
    pub fn relayFrom(self: *Pair, from: *Session, to: *Session, packets: []const []const u8) !bedwire.Packets {
        const frame = try from.encode(packets);
        @memcpy(self.relay[0..frame.len], frame);

        return to.ingest(self.relay[0..frame.len]);
    }

    pub fn clientToServer(self: *Pair, packets: []const []const u8) !bedwire.Packets {
        return self.relayFrom(&self.client, &self.server, packets);
    }

    pub fn serverToClient(self: *Pair, packets: []const []const u8) !bedwire.Packets {
        return self.relayFrom(&self.server, &self.client, packets);
    }

    pub fn clientToServerDiscard(self: *Pair, packets: []const []const u8) !void {
        var iter = try self.clientToServer(packets);
        iter.deinit();
    }

    pub fn serverToClientDiscard(self: *Pair, packets: []const []const u8) !void {
        var iter = try self.serverToClient(packets);
        iter.deinit();
    }
};

pub fn deterministicKey(seed: u8) !Ecdsa.KeyPair {
    return Ecdsa.KeyPair.generateDeterministic(@splat(seed));
}

pub fn encodedKey(key: Ecdsa.PublicKey) [160]u8 {
    return bedwire.auth.login.encodedPublicKey(key);
}

/// Minimal ES384 signer, independent of Bedwire's own so a broken signer cannot
/// validate itself.
pub fn signToken(allocator: std.mem.Allocator, key: Ecdsa.KeyPair, header: []const u8, payload: []const u8) ![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const header_len = encoder.calcSize(header.len);
    const payload_len = encoder.calcSize(payload.len);

    const bytes = try allocator.alloc(u8, header_len + payload_len + 130);
    errdefer allocator.free(bytes);

    _ = encoder.encode(bytes[0..header_len], header);
    bytes[header_len] = '.';
    _ = encoder.encode(bytes[header_len + 1 ..][0..payload_len], payload);

    const end = header_len + 1 + payload_len;
    const signature = try key.sign(bytes[0..end], null);
    bytes[end] = '.';
    _ = encoder.encode(bytes[end + 1 ..], &signature.toBytes());

    return bytes;
}

pub fn signWithKeyHeader(allocator: std.mem.Allocator, key: Ecdsa.KeyPair, payload: []const u8) ![]u8 {
    const header = try std.fmt.allocPrint(allocator, "{{\"alg\":\"ES384\",\"x5u\":\"{s}\"}}", .{encodedKey(key.public_key)});
    defer allocator.free(header);

    return signToken(allocator, key, header, payload);
}

pub const chain_uuid = "b1b01c3d-6df3-3635-b286-9a2cfbcf76be";

/// builds a 3-link mojang auth chain for testing
pub fn buildChain(allocator: std.mem.Allocator, keys: [3]Ecdsa.KeyPair) ![]u8 {
    var tokens: [3][]u8 = undefined;
    var built: usize = 0;
    defer for (tokens[0..built]) |token| allocator.free(token);

    for (keys, 0..) |key, i| {
        const payload = try std.fmt.allocPrint(
            allocator,
            "{{\"iss\":\"Mojang\",\"exp\":200,\"certificateAuthority\":true,\"identityPublicKey\":\"{s}\"," ++
                "\"extraData\":{{\"displayName\":\"Steve\",\"identity\":\"" ++ chain_uuid ++ "\",\"XUID\":\"1234\"}}}}",
            .{encodedKey(keys[(i + 1) % 3].public_key)},
        );
        defer allocator.free(payload);

        tokens[i] = try signWithKeyHeader(allocator, key, payload);
        built += 1;
    }

    return std.fmt.allocPrint(allocator, "{{\"chain\":[\"{s}\",\"{s}\",\"{s}\"]}}", .{ tokens[0], tokens[1], tokens[2] });
}

/// The client-data token the last chain link must have signed.
pub fn buildClientData(allocator: std.mem.Allocator, key: Ecdsa.KeyPair) ![]u8 {
    return signToken(allocator, key, "{\"alg\":\"ES384\"}", "{}");
}
