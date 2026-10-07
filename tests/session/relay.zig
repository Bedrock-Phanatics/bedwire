const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");

const testing = std.testing;
const Session = support.Session;
const Algorithm = bedwire.compression.Algorithm;
const Compression = bedwire.compression.Compression;
const SessionCrypto = bedwire.crypto.SessionCrypto;

const Leg = struct {
    algorithm: Algorithm = .deflate,
    threshold: u16 = 0,
    encrypted: bool = true,
    compression: ?Compression = null,
};

/// peer -> inbound => outbound -> upstream
const Chain = struct {
    pool: bedwire.BufferPool,
    peer: Session,
    inbound: Session,
    outbound: Session,
    upstream: Session,

    fn init(self: *Chain, down: Leg, up: Leg) !void {
        self.pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 4, .tx_slots = 4 });
        self.peer = try Session.init(.client, .{ .pool = &self.pool });
        self.inbound = try Session.init(.server, .{ .pool = &self.pool });
        self.outbound = try Session.init(.client, .{ .pool = &self.pool });
        self.upstream = try Session.init(.server, .{ .pool = &self.pool });
        try setup(&self.peer, down, 1);
        try setup(&self.inbound, down, 1);
        try setup(&self.outbound, up, 2);
        try setup(&self.upstream, up, 2);
    }

    fn setup(session: *Session, leg: Leg, key: u8) !void {
        if (leg.compression) |c| session.compression = c else try session.compression.negotiate(leg.algorithm, leg.threshold);
        session.state = .in_game;
        if (leg.encrypted) session.crypto = SessionCrypto.init(@splat(key));
    }

    fn deinit(self: *Chain) void {
        self.peer.deinit();
        self.inbound.deinit();
        self.outbound.deinit();
        self.upstream.deinit();
        self.pool.deinit();
    }

    fn forward(self: *Chain, packets: []const []const u8) !Session.Packets {
        const sent = try self.peer.encode(packets);
        defer sent.release();
        const frame = try self.inbound.relayTo(&self.outbound, sent.bytes);
        defer frame.release();
        return self.upstream.ingest(frame.bytes);
    }

    fn backward(self: *Chain, packets: []const []const u8) !Session.Packets {
        const sent = try self.upstream.encode(packets);
        defer sent.release();
        const frame = try self.outbound.relayTo(&self.inbound, sent.bytes);
        defer frame.release();
        return self.peer.ingest(frame.bytes);
    }
};

fn expectPackets(packets: *Session.Packets, expected: []const []const u8) !void {
    defer packets.deinit();
    for (expected) |bytes| try testing.expectEqualSlices(u8, bytes, packets.next().?.bytes);
    try testing.expectEqual(@as(?Session.Packet, null), packets.next());
}

fn sized(storage: []u8, raw_len: usize) []u8 {
    const fill: [256]u8 = @splat('s');
    return support.packet(storage, support.opaque_packet_id, fill[0 .. raw_len - 3]);
}

test "encrypted deflate and snappy batches relay intact" {
    var noise: [3000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x4e1a7);
    prng.random().bytes(&noise);

    var a: [8192]u8 = undefined;
    var b: [8192]u8 = undefined;
    const compressible = support.packet(&a, support.opaque_packet_id, &@as([6000]u8, @splat('z')));
    const random = support.packet(&b, support.opaque_packet_id_2, &noise);

    for ([_]Algorithm{ .deflate, .snappy }) |algorithm| {
        var chain: Chain = undefined;
        try chain.init(.{ .algorithm = algorithm }, .{ .algorithm = algorithm });
        defer chain.deinit();

        try testing.expect(chain.inbound.canRelayTo(&chain.outbound));
        var forward = try chain.forward(&.{ compressible, random });
        try expectPackets(&forward, &.{ compressible, random });
        var back = try chain.backward(&.{random});
        try expectPackets(&back, &.{random});
    }
}

test "uncompressed batches follow the destination threshold, compressed ones keep their marker" {
    var chain: Chain = undefined;
    try chain.init(.{ .threshold = 256, .encrypted = false }, .{ .threshold = 64, .encrypted = false });
    defer chain.deinit();

    var storage: [256]u8 = undefined;
    for ([_]struct { raw: usize, marker: u8 }{
        .{ .raw = 63, .marker = 0xff },
        .{ .raw = 64, .marker = 0 },
        .{ .raw = 200, .marker = 0 },
    }) |case| {
        const packet = sized(&storage, case.raw);
        const sent = try chain.peer.encode(&.{packet});
        defer sent.release();
        try testing.expectEqual(@as(u8, 0xff), sent.bytes[1]);

        const frame = try chain.inbound.relayTo(&chain.outbound, sent.bytes);
        defer frame.release();
        try testing.expectEqual(case.marker, frame.bytes[1]);

        var packets = try chain.upstream.ingest(frame.bytes);
        try expectPackets(&packets, &.{packet});
    }

    const packet = sized(&storage, 100);
    const sent = try chain.upstream.encode(&.{packet});
    defer sent.release();
    try testing.expectEqual(@as(u8, 0), sent.bytes[1]);
    const frame = try chain.outbound.relayTo(&chain.inbound, sent.bytes);
    defer frame.release();
    try testing.expectEqual(@as(u8, 0), frame.bytes[1]);
    var packets = try chain.peer.ingest(frame.bytes);
    try expectPackets(&packets, &.{packet});
}

test "absent and implicit framing relay unchanged" {
    const absent: Compression = .{ .mode = .absent, .supports_deflate = false, .supports_snappy = false, .negotiated = true };
    const implicit = Compression.init(support.legacy.features);

    for ([_]Compression{ absent, implicit }) |compression| {
        var chain: Chain = undefined;
        try chain.init(.{ .compression = compression }, .{ .compression = compression });
        defer chain.deinit();

        var storage: [2048]u8 = undefined;
        const packet = support.packet(&storage, support.opaque_packet_id, &@as([1500]u8, @splat('q')));
        var packets = try chain.forward(&.{packet});
        try expectPackets(&packets, &.{packet});
    }
}

test "incompatible pairs are refused before either session changes" {
    const implicit = Compression.init(support.legacy.features);
    const unnegotiated = Compression.init(support.modern.features);
    for ([_]struct { down: Leg, up: Leg }{
        .{ .down = .{ .algorithm = .deflate }, .up = .{ .algorithm = .snappy } },
        .{ .down = .{}, .up = .{ .compression = implicit } },
        .{ .down = .{}, .up = .{ .compression = unnegotiated } },
    }) |case| {
        var chain: Chain = undefined;
        try chain.init(case.down, case.up);
        defer chain.deinit();

        var storage: [64]u8 = undefined;
        const packet = support.packet(&storage, support.opaque_packet_id, "x");
        const sent = try chain.peer.encode(&.{packet});
        defer sent.release();

        try testing.expect(!chain.inbound.canRelayTo(&chain.outbound));
        try testing.expectError(error.IncompatibleRelay, chain.inbound.relayTo(&chain.outbound, sent.bytes));
        try testing.expectEqual(@as(u64, 0), chain.inbound.crypto.?.recv_counter);
        try testing.expectEqual(@as(u64, 0), chain.outbound.crypto.?.send_counter);

        var packets = try chain.inbound.ingest(sent.bytes);
        try expectPackets(&packets, &.{packet});
    }
}

test "relay needs distinct in-game sessions facing opposite peers" {
    var chain: Chain = undefined;
    try chain.init(.{}, .{});
    defer chain.deinit();

    try testing.expect(chain.inbound.canRelayTo(&chain.outbound));
    try testing.expect(chain.outbound.canRelayTo(&chain.inbound));
    try testing.expect(!chain.inbound.canRelayTo(&chain.inbound));
    try testing.expect(!chain.inbound.canRelayTo(&chain.upstream));

    chain.outbound.state = .spawn_ready;
    try testing.expect(!chain.inbound.canRelayTo(&chain.outbound));
    chain.outbound.state = .in_game;
    chain.inbound.beginClose();
    try testing.expectError(error.IncompatibleRelay, chain.inbound.relayTo(&chain.outbound, &.{0xfe}));

    chain.inbound.state = .in_game;
    chain.upstream.close();
    try testing.expectError(error.TransportClosed, chain.outbound.relayTo(&chain.upstream, &.{0xfe}));
    try testing.expectEqual(bedwire.State.in_game, chain.outbound.state);
    chain.inbound.close();
    try testing.expectError(error.TransportClosed, chain.inbound.relayTo(&chain.outbound, &.{0xfe}));
    try testing.expectEqual(bedwire.State.in_game, chain.outbound.state);
}

test "relay crosses profiles only within one protocol version" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 2 });
    defer pool.deinit();

    var player = try bedwire.SessionWithProfile(support.Profile(818, .{ .login_flow = .oidc })).init(.server, .{ .pool = &pool });
    defer player.deinit();
    var backend = try Session.init(.client, .{ .pool = &pool });
    defer backend.deinit();
    var newer = try bedwire.SessionWithProfile(support.Profile(819, .{ .login_flow = .certificate_chain })).init(.client, .{ .pool = &pool });
    defer newer.deinit();
    for ([_]*bedwire.compression.Compression{ &player.compression, &backend.compression, &newer.compression }) |c| try c.negotiate(.deflate, 0);
    player.state = .in_game;
    backend.state = .in_game;
    newer.state = .in_game;

    try testing.expect(!player.canRelayTo(&newer));
    try testing.expect(player.canRelayTo(&backend));

    var storage: [64]u8 = undefined;
    const packet = support.packet(&storage, support.opaque_packet_id, "cross");
    var sender = try Session.init(.client, .{ .pool = &pool });
    defer sender.deinit();
    try sender.compression.negotiate(.deflate, 0);
    sender.state = .in_game;
    const sent = try sender.encode(&.{packet});
    defer sent.release();

    const frame = try player.relayTo(&backend, sent.bytes);
    defer frame.release();
    try testing.expectEqual(&backend, frame.session);
}

test "malformed markers fail closed without touching the destination" {
    for ([_]struct { body: []const u8, err: anyerror }{
        .{ .body = &.{}, .err = error.MalformedCompressedData },
        .{ .body = &.{ 0x07, 1, 2 }, .err = error.UnsupportedCompression },
        .{ .body = &.{ 0x01, 1, 2 }, .err = error.UnexpectedCompression },
    }) |case| {
        var chain: Chain = undefined;
        try chain.init(.{ .encrypted = false }, .{});
        defer chain.deinit();

        var frame: [8]u8 = undefined;
        frame[0] = 0xfe;
        @memcpy(frame[1..][0..case.body.len], case.body);
        try testing.expectError(case.err, chain.inbound.relayTo(&chain.outbound, frame[0 .. 1 + case.body.len]));
        try testing.expectEqual(bedwire.State.disconnected, chain.inbound.state);
        try testing.expectEqual(@as(u64, 0), chain.outbound.crypto.?.send_counter);
        try testing.expectEqual(@as(?bedwire.BufferPool.TxToken, null), chain.outbound.tx_slot);
    }

    var prefixed: Chain = undefined;
    try prefixed.init(.{ .encrypted = false }, .{ .encrypted = false });
    defer prefixed.deinit();
    try testing.expectError(error.MalformedBatch, prefixed.inbound.relayTo(&prefixed.outbound, &.{ 0xfd, 0xff }));
    try testing.expectEqual(bedwire.State.disconnected, prefixed.inbound.state);
}

test "corrupt deflate passes the relay but fails closed at the receiver" {
    var chain: Chain = undefined;
    try chain.init(.{ .encrypted = false }, .{});
    defer chain.deinit();

    const frame = try chain.inbound.relayTo(&chain.outbound, &.{ 0xfe, 0x00, 0xff, 0xff, 0xff });
    defer frame.release();
    if (chain.upstream.ingest(frame.bytes)) |packets| {
        var leaked = packets;
        leaked.deinit();
        return error.TestUnexpectedResult;
    } else |_| {}
    try testing.expectEqual(bedwire.State.disconnected, chain.upstream.state);
}

test "a corrupt MAC closes the source and leaves the destination alone" {
    var chain: Chain = undefined;
    try chain.init(.{}, .{});
    defer chain.deinit();

    var storage: [64]u8 = undefined;
    const packet = support.packet(&storage, support.opaque_packet_id, "hello");
    const sent = try chain.peer.encode(&.{packet});
    defer sent.release();
    var tampered: [64]u8 = undefined;
    @memcpy(tampered[0..sent.bytes.len], sent.bytes);
    tampered[sent.bytes.len - 1] ^= 1;

    try testing.expectError(error.ChecksumMismatch, chain.inbound.relayTo(&chain.outbound, tampered[0..sent.bytes.len]));
    try testing.expectEqual(bedwire.State.disconnected, chain.inbound.state);
    try testing.expectEqual(@as(u64, 0), chain.outbound.crypto.?.send_counter);
    try testing.expectEqual(@as(?bedwire.BufferPool.TxToken, null), chain.outbound.tx_slot);
}

test "frame and batch limits are enforced on both sides" {
    var chain: Chain = undefined;
    try chain.init(.{}, .{});
    defer chain.deinit();

    var storage: [2048]u8 = undefined;
    const packet = support.packet(&storage, support.opaque_packet_id, &@as([1024]u8, @splat('r')));
    {
        var noise: [1024]u8 = undefined;
        var prng = std.Random.DefaultPrng.init(7);
        prng.random().bytes(&noise);
        var big_storage: [2048]u8 = undefined;
        const big = support.packet(&big_storage, support.opaque_packet_id, &noise);
        const sent = try chain.peer.encode(&.{big});
        defer sent.release();

        chain.outbound.limits.max_frame_bytes = 512;
        try testing.expectError(error.LimitExceeded, chain.inbound.relayTo(&chain.outbound, sent.bytes));
        try testing.expectEqual(@as(u64, 0), chain.inbound.crypto.?.recv_counter);
        chain.outbound.limits.max_frame_bytes = support.limits.max_frame_bytes;
        var packets = try chain.inbound.ingest(sent.bytes);
        try expectPackets(&packets, &.{big});
    }

    var oversized: [support.limits.max_frame_bytes + 1]u8 = @splat(0);
    oversized[0] = 0xfe;
    try testing.expectError(error.LimitExceeded, chain.inbound.relayTo(&chain.outbound, &oversized));
    try testing.expectEqual(bedwire.State.disconnected, chain.inbound.state);

    var raw: Chain = undefined;
    try raw.init(.{ .threshold = 4096, .encrypted = false }, .{ .threshold = 4096 });
    defer raw.deinit();
    raw.outbound.limits.max_batch_bytes = 512;
    const sent = try raw.peer.encode(&.{packet});
    defer sent.release();
    try testing.expectError(error.LimitExceeded, raw.inbound.relayTo(&raw.outbound, sent.bytes));
    try testing.expectEqual(bedwire.State.disconnected, raw.inbound.state);
}

test "relay respects held leases" {
    var chain: Chain = undefined;
    try chain.init(.{}, .{});
    defer chain.deinit();

    var storage: [64]u8 = undefined;
    const packet = support.packet(&storage, support.opaque_packet_id, "lease");

    const first = try chain.peer.encode(&.{packet});
    var held = try chain.inbound.ingest(first.bytes);
    first.release();

    const blocker = try chain.outbound.encode(&.{packet});
    const sent = try chain.peer.encode(&.{packet});
    defer sent.release();
    try testing.expectError(error.PoolExhausted, chain.inbound.relayTo(&chain.outbound, sent.bytes));
    try testing.expectEqual(@as(u64, 1), chain.inbound.crypto.?.recv_counter);
    try testing.expectEqualSlices(u8, packet, held.next().?.bytes);
    held.deinit();

    // Keeps the upstream keystream in step.
    var drained = try chain.upstream.ingest(blocker.bytes);
    drained.deinit();
    blocker.release();

    const frame = try chain.inbound.relayTo(&chain.outbound, sent.bytes);
    try testing.expectError(error.PoolExhausted, chain.outbound.encode(&.{packet}));
    var packets = try chain.upstream.ingest(frame.bytes);
    try expectPackets(&packets, &.{packet});
    frame.release();
    frame.release();
    sent.release();
    try testing.expect(chain.pool.isIdle());
}

test "thousands of relays keep both keystreams in step" {
    var chain: Chain = undefined;
    try chain.init(.{ .threshold = 128 }, .{ .threshold = 64 });
    defer chain.deinit();

    var storage: [4096]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x7e1a);
    const random = prng.random();
    for (0..4000) |i| {
        const len = random.intRangeAtMost(usize, 1, 3000);
        random.bytes(storage[0..len]);
        if (i % 3 == 0) @memset(storage[0..len], 'g');
        var payload: [4096]u8 = undefined;
        const packet = support.packet(&payload, support.opaque_packet_id, storage[0..len]);

        var packets = if (i % 2 == 0) try chain.forward(&.{packet}) else try chain.backward(&.{packet});
        try expectPackets(&packets, &.{packet});
    }

    try testing.expectEqual(@as(u64, 2000), chain.inbound.crypto.?.recv_counter);
    try testing.expectEqual(@as(u64, 2000), chain.outbound.crypto.?.send_counter);
    try testing.expectEqual(@as(u64, 2000), chain.upstream.crypto.?.recv_counter);
    try testing.expectEqual(@as(u64, 2000), chain.peer.crypto.?.recv_counter);
    try testing.expect(chain.pool.isIdle());
}
