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
    pool: *bedwire.BufferPool,
    server: Session,
    client: Session,
    relay: []u8,

    pub fn init(allocator: std.mem.Allocator, descriptor: *const bedwire.Descriptor) !Pair {
        const pool = try allocator.create(bedwire.BufferPool);
        errdefer allocator.destroy(pool);
        pool.* = try bedwire.BufferPool.init(allocator, limits, .{ .rx_slots = 2, .tx_slots = 2 });
        errdefer pool.deinit();

        var server = try Session.init(allocator, .server, descriptor, .{ .limits = limits, .pool = pool });
        errdefer server.deinit();

        var client = try Session.init(allocator, .client, descriptor, .{ .limits = limits, .pool = pool });
        errdefer client.deinit();

        return .{
            .allocator = allocator,
            .pool = pool,
            .server = server,
            .client = client,
            .relay = try allocator.alloc(u8, limits.max_frame_bytes),
        };
    }

    pub fn deinit(self: *Pair) void {
        self.server.deinit();
        self.client.deinit();
        self.pool.deinit();
        self.allocator.destroy(self.pool);
        self.allocator.free(self.relay);
        self.* = undefined;
    }

    /// Encodes on `from`, copies the frame, and ingests it on `to`.
    pub fn relayFrom(self: *Pair, from: *Session, to: *Session, packets: []const []const u8) !bedwire.Packets {
        const frame = try from.encode(packets);
        defer frame.release();
        @memcpy(self.relay[0..frame.bytes.len], frame.bytes);

        return to.ingest(self.relay[0..frame.bytes.len]);
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

// RSA Test Fixtures
pub const rsa_key1_kid = "test-rsa-key-1";
pub const rsa_key1_n_b64 = "bBa-stxXGXURryypmyW4-c0WAP_5vNLcUt2RQ-V_qRphHpDP5iihQYudWPUy-Ntuz-quLjqQMObRhONw5zy-bX73et7XslTlYzjgQKkTs4XULhKACmWzEwT6sM-LtEGwqDsLeBlTaxp98PipIVMyQVK-zVgx3wNTyO6qJ_L4SQvyWHtdQyTLA45gzjnjdyiixG5l0NJ32zlvTrJPzuD0bE0sGl_hUGNIdBJ1lDq3JbI4xNi58N-EIzbZebjs0BN-8HTIRvJE9V75R8eZ4pa6aCpDYx_NnF4HJB-tjav5Mw6m0Jiq_Yvo52nntyER8bXO53P8Cb2q8yWYtmSQTvsx9Q";
pub const rsa_key1_e_b64 = "AQAB";
pub const rsa_key1_n = [_]u8{
    0x6c, 0x16, 0xbe, 0xb2, 0xdc, 0x57, 0x19, 0x75, 0x11, 0xaf, 0x2c, 0xa9, 0x9b, 0x25, 0xb8, 0xf9,
    0xcd, 0x16, 0x00, 0xff, 0xf9, 0xbc, 0xd2, 0xdc, 0x52, 0xdd, 0x91, 0x43, 0xe5, 0x7f, 0xa9, 0x1a,
    0x61, 0x1e, 0x90, 0xcf, 0xe6, 0x28, 0xa1, 0x41, 0x8b, 0x9d, 0x58, 0xf5, 0x32, 0xf8, 0xdb, 0x6e,
    0xcf, 0xea, 0xae, 0x2e, 0x3a, 0x90, 0x30, 0xe6, 0xd1, 0x84, 0xe3, 0x70, 0xe7, 0x3c, 0xbe, 0x6d,
    0x7e, 0xf7, 0x7a, 0xde, 0xd7, 0xb2, 0x54, 0xe5, 0x63, 0x38, 0xe0, 0x40, 0xa9, 0x13, 0xb3, 0x85,
    0xd4, 0x2e, 0x12, 0x80, 0x0a, 0x65, 0xb3, 0x13, 0x04, 0xfa, 0xb0, 0xcf, 0x8b, 0xb4, 0x41, 0xb0,
    0xa8, 0x3b, 0x0b, 0x78, 0x19, 0x53, 0x6b, 0x1a, 0x7d, 0xf0, 0xf8, 0xa9, 0x21, 0x53, 0x32, 0x41,
    0x52, 0xbe, 0xcd, 0x58, 0x31, 0xdf, 0x03, 0x53, 0xc8, 0xee, 0xaa, 0x27, 0xf2, 0xf8, 0x49, 0x0b,
    0xf2, 0x58, 0x7b, 0x5d, 0x43, 0x24, 0xcb, 0x03, 0x8e, 0x60, 0xce, 0x39, 0xe3, 0x77, 0x28, 0xa2,
    0xc4, 0x6e, 0x65, 0xd0, 0xd2, 0x77, 0xdb, 0x39, 0x6f, 0x4e, 0xb2, 0x4f, 0xce, 0xe0, 0xf4, 0x6c,
    0x4d, 0x2c, 0x1a, 0x5f, 0xe1, 0x50, 0x63, 0x48, 0x74, 0x12, 0x75, 0x94, 0x3a, 0xb7, 0x25, 0xb2,
    0x38, 0xc4, 0xd8, 0xb9, 0xf0, 0xdf, 0x84, 0x23, 0x36, 0xd9, 0x79, 0xb8, 0xec, 0xd0, 0x13, 0x7e,
    0xf0, 0x74, 0xc8, 0x46, 0xf2, 0x44, 0xf5, 0x5e, 0xf9, 0x47, 0xc7, 0x99, 0xe2, 0x96, 0xba, 0x68,
    0x2a, 0x43, 0x63, 0x1f, 0xcd, 0x9c, 0x5e, 0x07, 0x24, 0x1f, 0xad, 0x8d, 0xab, 0xf9, 0x33, 0x0e,
    0xa6, 0xd0, 0x98, 0xaa, 0xfd, 0x8b, 0xe8, 0xe7, 0x69, 0xe7, 0xb7, 0x21, 0x11, 0xf1, 0xb5, 0xce,
    0xe7, 0x73, 0xfc, 0x09, 0xbd, 0xaa, 0xf3, 0x25, 0x98, 0xb6, 0x64, 0x90, 0x4e, 0xfb, 0x31, 0xf5,
};
pub const rsa_key1_e = [_]u8{ 0x01, 0x00, 0x01 };

pub const rsa_key2_kid = "test-rsa-key-2";
pub const rsa_key2_n_b64 = "qtdS_nkcFFs-KN2Z23P1xDcgIWHl7o5GCgn74U6Z4-_0FUHcygT1tl2mGSnwU8m6jXcF7IfgfTthBfu5w3c1ETzqsmn_D-fFLfQU9SEold_T-4QyNaqGtMEB63uZb3x3ZBmNSJt1RFsZx7h1OfY-7yt31ob5cK66_TkI4D7g5xVuqY-t3JsNi2KMk5n6aA0A1Z2mPor_lFal4wHRLojSNwG3XJcp4nUCNVCKJvywH3R-S3xd1tJL5VZhhKsjgOJJVKtSO2C-zT4cul4wnsJJUlK14sHTlCQa9ghxPI9JJioy1hD-kMpPRjXRSbfB8Ro2ji8G7HjToTEF6VNqGnItBw";
pub const rsa_key2_e_b64 = "AQAB";
pub const rsa_key2_n = [_]u8{
    0xaa, 0xd7, 0x52, 0xfe, 0x79, 0x1c, 0x14, 0x5b, 0x3e, 0x28, 0xdd, 0x99, 0xdb, 0x73, 0xf5, 0xc4,
    0x37, 0x20, 0x21, 0x61, 0xe5, 0xee, 0x8e, 0x46, 0x0a, 0x09, 0xfb, 0xe1, 0x4e, 0x99, 0xe3, 0xef,
    0xf4, 0x15, 0x41, 0xdc, 0xca, 0x04, 0xf5, 0xb6, 0x5d, 0xa6, 0x19, 0x29, 0xf0, 0x53, 0xc9, 0xba,
    0x8d, 0x77, 0x05, 0xec, 0x87, 0xe0, 0x7d, 0x3b, 0x61, 0x05, 0xfb, 0xb9, 0xc3, 0x77, 0x35, 0x11,
    0x3c, 0xea, 0xb2, 0x69, 0xff, 0x0f, 0xe7, 0xc5, 0x2d, 0xf4, 0x14, 0xf5, 0x21, 0x28, 0x95, 0xdf,
    0xd3, 0xfb, 0x84, 0x32, 0x35, 0xaa, 0x86, 0xb4, 0xc1, 0x01, 0xeb, 0x7b, 0x99, 0x6f, 0x7c, 0x77,
    0x64, 0x19, 0x8d, 0x48, 0x9b, 0x75, 0x44, 0x5b, 0x19, 0xc7, 0xb8, 0x75, 0x39, 0xf6, 0x3e, 0xef,
    0x2b, 0x77, 0xd6, 0x86, 0xf9, 0x70, 0xae, 0xba, 0xfd, 0x39, 0x08, 0xe0, 0x3e, 0xe0, 0xe7, 0x15,
    0x6e, 0xa9, 0x8f, 0xad, 0xdc, 0x9b, 0x0d, 0x8b, 0x62, 0x8c, 0x93, 0x99, 0xfa, 0x68, 0x0d, 0x00,
    0xd5, 0x9d, 0xa6, 0x3e, 0x8a, 0xff, 0x94, 0x56, 0xa5, 0xe3, 0x01, 0xd1, 0x2e, 0x88, 0xd2, 0x37,
    0x01, 0xb7, 0x5c, 0x97, 0x29, 0xe2, 0x75, 0x02, 0x35, 0x50, 0x8a, 0x26, 0xfc, 0xb0, 0x1f, 0x74,
    0x7e, 0x4b, 0x7c, 0x5d, 0xd6, 0xd2, 0x4b, 0xe5, 0x56, 0x61, 0x84, 0xab, 0x23, 0x80, 0xe2, 0x49,
    0x54, 0xab, 0x52, 0x3b, 0x60, 0xbe, 0xcd, 0x3e, 0x1c, 0xba, 0x5e, 0x30, 0x9e, 0xc2, 0x49, 0x52,
    0x52, 0xb5, 0xe2, 0xc1, 0xd3, 0x94, 0x24, 0x1a, 0xf6, 0x08, 0x71, 0x3c, 0x8f, 0x49, 0x26, 0x2a,
    0x32, 0xd6, 0x10, 0xfe, 0x90, 0xca, 0x4f, 0x46, 0x35, 0xd1, 0x49, 0xb7, 0xc1, 0xf1, 0x1a, 0x36,
    0x8e, 0x2f, 0x06, 0xec, 0x78, 0xd3, 0xa1, 0x31, 0x05, 0xe9, 0x53, 0x6a, 0x1a, 0x72, 0x2d, 0x07,
};
pub const rsa_key2_e = [_]u8{ 0x01, 0x00, 0x01 };

pub const rsa_valid_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhLWtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQiLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWRlbnRpdHkiOiIxMjM0NTY3ODkwIn0.RqWwwbzc61IrMq6z03w13KlmD3RqI6sD3JhjSkvPTH53ZEKmr1aiqcwjWWxD4H306mCJR2eAGAaWydEgoRjLzCgyGiQYFMmbNx_f8Rk2avoWqiBltLsrnd75N-QXF5AsmxIlob7KGiPRIHxRtYMSsgIpJKZntth7mX8dMwRCJYMsXLa2XJIVZislcfP1kDtJCw0f-ln2CbOcpU4Wf6_RwYdJPyW7GNki_1JLOskBoScewPTLdqiBNWV1l-ivojEpa1zv-OzZ83pdrTbdJSsQ43l3FAmuGI2A8iMPTeW_Rw6psjuUI7buuBKJLC2--sk40u7XiIkak3Ywg7C_dlwgTQ";
pub const rsa_expired_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhLWtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQiLCJleHAiOjEwMCwibmJmIjo1MCwiaWRlbnRpdHkiOiIxMjM0NTY3ODkwIn0.MrFBp8zrX4-TpptNeAmnq8ja9y35hGyV_JXS_tSqn4xgnS7-Yc-W7SnogYwnZ_xXrbAtQgd0ksnuWw5hAFVZ84l5QtKvMvA7Wj6WggIaJEOh0V7Tt2t8GElqwZl0UwReNgkcYO-3dThwK4_MSz9ay7DiBmRXzjElz-rnjetimsVqftey69McCw-GVkkw00Lw6Q-RIWp6R2PIc8lnnnYe-XeJmHZx0-8I6aW9bHOviTBWY8KTRyPSrl3kEFPnxSQFXmdea6qM6Ld_xi8ggd_4krChKCFyd784bhT3TIldhTdxCPLy8sjB3ECB61nTGa2sa-Sl-cpvfG9zH5BXdZn1Ng";
pub const rsa_key2_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhLWtleS0yIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQiLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWRlbnRpdHkiOiIxMjM0NTY3ODkwIn0.lzWuuCSNb2SBtwMKctfisdelo4ekwVUAaDIJiBXbc066Qj2WDLmzGn86lx0fX6oE9GGgUL5knDOxRgfv7vDA-7O7kZQ550yUCjJHechGEKPuxDXkkPnMBVM1YnQx2tdYAyQjCOjJ2svVKpiiez6CP4GH6teSqmdTkcc29XKKZXmGVrsawaAPcC-o2XSkKd2pvsuGsnn8r0DudDxrVb5iiPuKjf92j7lxyaVroXNOYOVRrEVaRNQ5wLeAewZ0Otf1PjIVWwfj5fer4Jpe8TbfYadBvmUZw9a-psh9Hlm9Yo1EKVFIZj1cHyfGsK1Rqjhc1vReV5nBaaYWtJKc33igdQ";
pub const test_jwks_json = "{\"keys\": [{\"kty\": \"RSA\", \"use\": \"sig\", \"kid\": \"test-rsa-key-1\", \"n\": \"bBa-stxXGXURryypmyW4-c0WAP_5vNLcUt2RQ-V_qRphHpDP5iihQYudWPUy-Ntuz-quLjqQMObRhONw5zy-bX73et7XslTlYzjgQKkTs4XULhKACmWzEwT6sM-LtEGwqDsLeBlTaxp98PipIVMyQVK-zVgx3wNTyO6qJ_L4SQvyWHtdQyTLA45gzjnjdyiixG5l0NJ32zlvTrJPzuD0bE0sGl_hUGNIdBJ1lDq3JbI4xNi58N-EIzbZebjs0BN-8HTIRvJE9V75R8eZ4pa6aCpDYx_NnF4HJB-tjav5Mw6m0Jiq_Yvo52nntyER8bXO53P8Cb2q8yWYtmSQTvsx9Q\", \"e\": \"AQAB\"}, {\"kty\": \"RSA\", \"use\": \"sig\", \"kid\": \"test-rsa-key-2\", \"n\": \"qtdS_nkcFFs-KN2Z23P1xDcgIWHl7o5GCgn74U6Z4-_0FUHcygT1tl2mGSnwU8m6jXcF7IfgfTthBfu5w3c1ETzqsmn_D-fFLfQU9SEold_T-4QyNaqGtMEB63uZb3x3ZBmNSJt1RFsZx7h1OfY-7yt31ob5cK66_TkI4D7g5xVuqY-t3JsNi2KMk5n6aA0A1Z2mPor_lFal4wHRLojSNwG3XJcp4nUCNVCKJvywH3R-S3xd1tJL5VZhhKsjgOJJVKtSO2C-zT4cul4wnsJJUlK14sHTlCQa9ghxPI9JJioy1hD-kMpPRjXRSbfB8Ro2ji8G7HjToTEF6VNqGnItBw\", \"e\": \"AQAB\"}]}";

pub fn rsaKey1() std.crypto.Certificate.rsa.PublicKey {
    return std.crypto.Certificate.rsa.PublicKey.fromBytes(&rsa_key1_e, &rsa_key1_n) catch unreachable;
}

pub fn rsaKey2() std.crypto.Certificate.rsa.PublicKey {
    return std.crypto.Certificate.rsa.PublicKey.fromBytes(&rsa_key2_e, &rsa_key2_n) catch unreachable;
}
