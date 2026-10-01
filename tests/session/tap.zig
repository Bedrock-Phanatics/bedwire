const std = @import("std");
const bedwire = @import("bedwire");
const protocol = @import("bedrock_protocol");
const support = @import("../support.zig");
const testing = std.testing;

const ReadOnlyLoginProfile = struct {
    pub const protocol_number = support.modern.protocol_number;
    pub const features = support.modern.features;
    pub const packetKind = support.modern.packetKind;
    pub fn packetId(kind: protocol.PacketKind) ?u10 {
        return if (kind == .login) null else support.modern.packetId(kind);
    }
    pub const packetDirection = support.modern.packetDirection;
    pub const decodeBorrowed = support.modern.decodeBorrowed;
    pub const encode = support.modern.encode;
};

fn plain(dest: []u8, packet: []const u8) ![]const u8 {
    dest[0] = bedwire.framing.batch.header;
    var writer = bedwire.framing.batch.Writer.init(dest[1..], support.limits);
    try writer.append(packet);
    return dest[0 .. 1 + writer.written().len];
}

fn compressed(dest: []u8, packet: []const u8, algorithm: bedwire.compression.Algorithm, threshold: u16) ![]const u8 {
    var raw: [support.limits.max_batch_bytes]u8 = undefined;
    var writer = bedwire.framing.batch.Writer.init(&raw, support.limits);
    try writer.append(packet);
    var codec = bedwire.compression.Compression.init(support.modern.features);
    try codec.negotiate(algorithm, threshold);
    var scratch: bedwire.compression.Scratch = undefined;
    const framed = try codec.encode(writer.written(), dest[2..], &scratch);
    dest[0] = bedwire.framing.batch.header;
    dest[1] = @intFromEnum(framed.algorithm);
    return dest[0 .. 2 + framed.bytes.len];
}

test "tap observes both directions, preserves forwarding bytes, and stops at encryption" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, bedwire.PoolConfig.observer());
    defer pool.deinit();
    try testing.expectEqual(@as(usize, 0), pool.tx_storage.len);
    var tap = try bedwire.TapWithProfile(support.modern).init(.{ .pool = &pool });
    defer tap.deinit();
    var other = try bedwire.TapWithProfile(support.modern).init(.{ .pool = &pool });
    defer other.deinit();
    var builder: support.Builder = .{};
    var storage: [support.limits.max_frame_bytes]u8 = undefined;

    const request = try plain(&storage, builder.make(support.modern, .request_network_settings));
    const original = try testing.allocator.dupe(u8, request);
    defer testing.allocator.free(original);
    var packets = try tap.observe(.client_to_server, request);
    try testing.expectEqual(bedwire.PacketKind.request_network_settings, packets.next().?.kind);
    try testing.expectEqual(bedwire.TapPhase.awaiting_settings, tap.phase());
    try testing.expectEqualSlices(u8, original, request);
    try testing.expectError(error.InvalidState, tap.observe(.client_to_server, request));
    try testing.expectError(error.PoolExhausted, other.observe(.client_to_server, request));
    var copy = packets;
    packets.deinit();
    try testing.expect(copy.next() == null);
    copy.deinit();
    try testing.expect(pool.isIdle());
    var reused = try other.observe(.client_to_server, request);
    reused.deinit();

    const settings = try plain(&storage, builder.make(support.modern, .network_settings));
    var settings_packets = try tap.observe(.server_to_client, settings);
    try testing.expectEqual(bedwire.PacketKind.network_settings, settings_packets.next().?.kind);
    settings_packets.deinit();
    try testing.expectEqual(bedwire.TapPhase.awaiting_login, tap.phase());

    const login = try compressed(&storage, builder.make(support.modern, .login), .snappy, 0);
    var login_packets = try tap.observe(.client_to_server, login);
    try testing.expectEqual(bedwire.PacketKind.login, login_packets.next().?.kind);
    login_packets.deinit();
    try testing.expectEqual(bedwire.TapPhase.awaiting_handshake, tap.phase());

    const handshake = try compressed(&storage, builder.make(support.modern, .server_to_client_handshake), .snappy, 0);
    var handshake_packets = try tap.observe(.server_to_client, handshake);
    try testing.expectEqual(bedwire.PacketKind.server_to_client_handshake, handshake_packets.next().?.kind);
    try testing.expectEqual(bedwire.TapPhase.encrypted, tap.phase());
    handshake_packets.deinit();
    try testing.expectError(error.Opaque, tap.observe(.client_to_server, &.{ 0xfe, 0xde, 0xad }));
    try testing.expect(pool.isIdle());
}

test "tap rejects wrong direction, order and malformed input without losing pool slots" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var tap = try bedwire.TapWithProfile(support.modern).init(.{ .pool = &pool });
    defer tap.deinit();
    var builder: support.Builder = .{};
    var storage: [support.limits.max_frame_bytes]u8 = undefined;

    const login = try plain(&storage, builder.make(support.modern, .login));
    try testing.expectError(error.InvalidState, tap.observe(.client_to_server, login));
    const unknown = try plain(&storage, builder.makeId(1020));
    var ignored = try tap.observe(.client_to_server, unknown);
    ignored.deinit();
    const request = try plain(&storage, builder.make(support.modern, .request_network_settings));
    try testing.expectError(error.InvalidState, tap.observe(.server_to_client, request));
    try testing.expectError(error.MalformedBatch, tap.observe(.client_to_server, &.{ 0xfe, 0 }));
    try testing.expectEqual(bedwire.TapPhase.awaiting_request, tap.phase());
    try testing.expect(pool.isIdle());

    var packets = try tap.observe(.client_to_server, request);
    packets.deinit();
    const settings = try plain(&storage, builder.make(support.modern, .network_settings));
    try testing.expectError(error.InvalidState, tap.observe(.client_to_server, settings));
    packets = try tap.observe(.server_to_client, settings);
    packets.deinit();
    const handshake = try compressed(&storage, builder.make(support.modern, .server_to_client_handshake), .snappy, 0);
    try testing.expectError(error.InvalidState, tap.observe(.server_to_client, handshake));
    try testing.expectError(error.UnsupportedCompression, tap.observe(.client_to_server, &.{ 0xfe, 2, 0 }));
    try testing.expectError(error.MalformedCompressedData, tap.observe(.client_to_server, &.{ 0xfe, 1, 0x80 }));
    try testing.expect(pool.isIdle());
}

test "tap authenticates observed Login with a receive-only profile" {
    const allocator = testing.allocator;
    var pool = try bedwire.BufferPool.init(allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var tap = try bedwire.TapWithProfile(ReadOnlyLoginProfile).init(.{ .pool = &pool });
    defer tap.deinit();
    var builder: support.Builder = .{};
    var storage: [support.limits.max_frame_bytes]u8 = undefined;

    var packets = try tap.observe(.client_to_server, try plain(&storage, builder.make(support.modern, .request_network_settings)));
    packets.deinit();
    packets = try tap.observe(.server_to_client, try plain(&storage, builder.make(support.modern, .network_settings)));
    packets.deinit();

    const keys = [3]support.Ecdsa.KeyPair{ try support.deterministicKey(1), try support.deterministicKey(2), try support.deterministicKey(3) };
    const chain = try support.buildChain(allocator, keys);
    defer allocator.free(chain);
    const client_data = try support.buildClientData(allocator, keys[0]);
    defer allocator.free(client_data);
    const envelope = try support.buildEnvelope(allocator, 0, chain, null);
    defer allocator.free(envelope);
    const request = try support.buildConnectionRequest(allocator, envelope, client_data);
    defer allocator.free(request);

    var packet_storage: [support.limits.max_packet_bytes]u8 = undefined;
    var writer = protocol.Writer.init(&packet_storage);
    try protocol.typed.encode(&writer, .{
        .header = .{ .packet_id = support.modern.packetId(.login).? },
        .packet = .{ .login = .{ .client_network_version = support.modern.protocol_number, .connection_request = request } },
    });
    const login = try compressed(&storage, writer.written(), .snappy, 0);
    packets = try tap.observe(.client_to_server, login);
    const observed = packets.next().?;
    var identity = try tap.authenticateLoginPacket(allocator, observed, .{ .certificate_chain = .{ .now = 100, .root = keys[1].public_key } });
    defer identity.deinit();
    try testing.expectEqualStrings("Steve", identity.display_name);
    packets.deinit();
    try testing.expectError(error.InvalidState, tap.authenticateLoginPacket(allocator, observed, .{ .certificate_chain = .{ .now = 100, .root = keys[1].public_key } }));
    try testing.expect(pool.isIdle());
}

test "legacy TapWithProfile starts at Login with implicit DEFLATE" {
    var pair = try support.Pair.init(testing.allocator, support.legacy);
    defer pair.deinit();
    var tap = try bedwire.TapWithProfile(support.legacy).init(.{
        .pool = pair.pool,
        .limits = support.limits,
        .policy = .{ .connection_request_format = .legacy_chain },
    });
    defer tap.deinit();
    try testing.expectEqual(bedwire.TapPhase.awaiting_login, tap.phase());
    var builder: support.Builder = .{};
    const frame = try pair.client.encodeOne(builder.make(support.legacy, .login));
    defer frame.release();
    var packets = try tap.observe(.client_to_server, frame.bytes);
    defer packets.deinit();
    try testing.expectEqual(bedwire.PacketKind.login, packets.next().?.kind);
    try testing.expectEqual(bedwire.TapPhase.awaiting_handshake, tap.phase());
}

test "tap follows DEFLATE and marked uncompressed negotiation" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, bedwire.PoolConfig.observer());
    defer pool.deinit();
    const WireAlgorithm = @FieldType(protocol.packets.network_settings.Packet, "compression_algorithm");
    const cases = .{
        .{ .wire = WireAlgorithm.zlib, .algorithm = bedwire.compression.Algorithm.deflate, .threshold = @as(u16, 0) },
        .{ .wire = WireAlgorithm.snappy, .algorithm = bedwire.compression.Algorithm.snappy, .threshold = @as(u16, 512) },
        .{ .wire = WireAlgorithm.none, .algorithm = bedwire.compression.Algorithm.none, .threshold = @as(u16, 0) },
    };
    inline for (cases) |case| {
        var tap = try bedwire.TapWithProfile(support.modern).init(.{ .pool = &pool });
        defer tap.deinit();
        var builder: support.Builder = .{};
        var storage: [support.limits.max_frame_bytes]u8 = undefined;
        var packets = try tap.observe(.client_to_server, try plain(&storage, builder.make(support.modern, .request_network_settings)));
        packets.deinit();

        var settings_storage: [128]u8 = undefined;
        var writer = protocol.Writer.init(&settings_storage);
        try protocol.typed.encode(&writer, .{
            .header = .{ .packet_id = support.modern.packetId(.network_settings).? },
            .packet = .{ .network_settings = .{
                .compression_threshold = case.threshold,
                .compression_algorithm = case.wire,
                .client_throttle_enabled = false,
                .client_throttle_threshold = 0,
                .client_throttle_scalar = 0,
            } },
        });
        packets = try tap.observe(.server_to_client, try plain(&storage, writer.written()));
        packets.deinit();

        const login = try compressed(&storage, builder.make(support.modern, .login), case.algorithm, case.threshold);
        if (case.threshold != 0 or case.algorithm == .none) try testing.expectEqual(@as(u8, 0xff), login[1]);
        packets = try tap.observe(.client_to_server, login);
        try testing.expectEqual(bedwire.PacketKind.login, packets.next().?.kind);
        packets.deinit();
        const handshake = try compressed(&storage, builder.make(support.modern, .server_to_client_handshake), case.algorithm, case.threshold);
        packets = try tap.observe(.server_to_client, handshake);
        try testing.expectEqual(bedwire.PacketKind.server_to_client_handshake, packets.next().?.kind);
        packets.deinit();
        try testing.expectEqual(bedwire.TapPhase.encrypted, tap.phase());
        try testing.expect(pool.isIdle());
    }
}

test "tap deinit releases a held packet lease" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, bedwire.PoolConfig.observer());
    defer pool.deinit();
    var tap = try bedwire.TapWithProfile(support.modern).init(.{ .pool = &pool });
    var builder: support.Builder = .{};
    var storage: [128]u8 = undefined;
    _ = try tap.observe(.client_to_server, try plain(&storage, builder.make(support.modern, .request_network_settings)));
    try testing.expect(!pool.isIdle());
    tap.deinit();
    try testing.expect(pool.isIdle());
}

test "mutated compressed Login leaves Tap state and pool reusable" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, bedwire.PoolConfig.observer());
    defer pool.deinit();
    var builder: support.Builder = .{};
    var storage: [support.limits.max_frame_bytes]u8 = undefined;
    const login = try compressed(&storage, builder.make(support.modern, .login), .snappy, 0);
    var valid: [support.limits.max_frame_bytes]u8 = undefined;
    @memcpy(valid[0..login.len], login);

    var prng = std.Random.DefaultPrng.init(0x7a91);
    const random = prng.random();
    const cases = @max(64, @import("build_options").fuzz_iterations / 40);
    for (0..cases) |i| {
        var tap = try bedwire.TapWithProfile(support.modern).init(.{ .pool = &pool });
        var packets = try tap.observe(.client_to_server, try plain(&storage, builder.make(support.modern, .request_network_settings)));
        packets.deinit();
        packets = try tap.observe(.server_to_client, try plain(&storage, builder.make(support.modern, .network_settings)));
        packets.deinit();

        var mutated = valid;
        const cut = if (i % 3 == 0) random.uintLessThan(usize, login.len + 1) else login.len;
        if (i % 3 != 0) mutated[random.uintLessThan(usize, login.len)] ^= @as(u8, 1) << @intCast(random.uintLessThan(u8, 8));
        if (tap.observe(.client_to_server, mutated[0..cut])) |admitted| {
            packets = admitted;
            while (packets.next()) |packet| try testing.expect(packet.bytes.len <= support.limits.max_packet_bytes);
            packets.deinit();
        } else |_| {
            try testing.expectEqual(bedwire.TapPhase.awaiting_login, tap.phase());
        }
        try testing.expect(pool.isIdle());
        tap.deinit();
    }
}
