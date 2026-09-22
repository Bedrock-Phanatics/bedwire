const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");
const testing = std.testing;

test "deterministic malformed IO keeps commits and pool leases consistent" {
    const limits: bedwire.Limits = .{ .max_frame_bytes = 128, .max_batch_bytes = 128, .max_packet_bytes = 96 };
    var pool = try bedwire.BufferPool.init(testing.allocator, limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(0xbed004);
    const random = prng.random();
    for (0..@import("build_options").fuzz_iterations) |_| {
        var session = try bedwire.Session.init(testing.allocator, .client, &support.modern, .{ .pool = &pool });
        defer session.deinit();
        session.state = .in_game;
        session.peer_key = bedwire.auth.moj_root.key();
        session.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
        var input: [192]u8 = undefined;
        random.bytes(&input);
        const packet = input[0..random.uintLessThan(usize, input.len + 1)];
        var payload: [192]u8 = undefined;
        var payload_len: usize = undefined;
        var held: ?bedwire.Frame = null;
        if (session.encodeOne(packet)) |frame| {
            held = frame;
            payload_len = frame.bytes.len;
            @memcpy(payload[0..payload_len], frame.bytes);
            if (random.boolean()) payload[random.uintLessThan(usize, payload_len)] ^= 1;
        } else |_| {
            try testing.expectEqual(bedwire.State.in_game, session.state);
            try testing.expectEqual(@as(u64, 0), session.tx_token);
            try testing.expectEqual(@as(u64, 0), session.crypto.?.send_counter);
            try testing.expectEqual(@as(usize, 0), session.sent.count());
            try testing.expect(pool.isIdle());
            payload_len = packet.len;
            @memcpy(payload[0..payload_len], packet);
        }

        if (session.ingest(payload[0..payload_len])) |admitted| {
            var packets = admitted;
            while (packets.next()) |_| {}
            packets.deinit();
        } else |_| {
            try testing.expectEqual(bedwire.State.disconnected, session.state);
            try testing.expect(session.crypto == null);
            try testing.expect(session.peer_key == null);
            try testing.expectEqual(@as(usize, 0), session.received.count());
            try testing.expect(session.rx_slot == null);
        }
        if (held) |frame| frame.release();
        try testing.expect(pool.isIdle());
    }
}

test "held frame applies backpressure without changing bytes or crypto" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();
    pair.client.state = .in_game;
    pair.client.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    var builder: support.Builder = .{};
    const packet = builder.make(&support.modern, .client_cache_status);
    const frame = try pair.client.encodeOne(packet);
    defer frame.release();
    const saved = try testing.allocator.dupe(u8, frame.bytes);
    defer testing.allocator.free(saved);
    const token = pair.client.tx_token;
    const crypto = pair.client.crypto.?;
    for (0..8) |_| {
        try testing.expectError(error.PoolExhausted, pair.client.encodeOne(packet));
        try testing.expectEqualSlices(u8, saved, frame.bytes);
        try testing.expectEqual(token, pair.client.tx_token);
        try testing.expectEqualDeep(crypto, pair.client.crypto.?);
    }
}

test "close retains held frame until release and clears peer identity" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var session = try bedwire.Session.init(testing.allocator, .client, &support.modern, .{ .pool = &pool });
    defer session.deinit();
    session.state = .in_game;
    session.peer_key = bedwire.auth.moj_root.key();
    session.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    var builder: support.Builder = .{};
    const frame = try session.encodeOne(builder.make(&support.modern, .client_cache_status));
    defer frame.release();
    session.close();
    session.close();
    try testing.expectError(error.PoolExhausted, pool.acquireTx());
    try testing.expect(session.peer_key == null);
    try testing.expect(session.crypto == null);
    frame.release();
    const replacement = try pool.acquireTx();
    defer pool.releaseTx(replacement);
    frame.release();
    try testing.expectError(error.PoolExhausted, pool.acquireTx());
}

test "fatal authentication clears a previously installed peer key" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();
    pair.server.state = .authenticating;
    pair.server.received.insert(.login);
    try pair.server.installVerifiedClientKey(bedwire.auth.moj_root.key());
    try testing.expectError(error.MalformedConnectionRequest, pair.server.authenticateLogin(testing.allocator, &.{}, .{ .certificate_chain = .{ .now = 0 } }));
    try testing.expectEqual(bedwire.State.disconnected, pair.server.state);
    try testing.expect(pair.server.peer_key == null);
    try testing.expect(pair.server.crypto == null);
    try testing.expect(pair.pool.isIdle());
}

const Handler = struct {
    fail: bool = false,
    calls: usize = 0,

    pub fn onPacket(self: *@This(), _: *bedwire.Session, _: bedwire.Packet) !void {
        self.calls += 1;
        if (self.fail) return error.HandlerFailed;
    }
};

fn Carrier(comptime nether: bool) type {
    return struct {
        session: *bedwire.Session,
        reenter: bool = false,
        fail: bool = false,

        pub const send = if (nether) sendNether else sendRak;

        fn sendRak(self: *@This(), bytes: []const u8, _: anytype, _: u8) !void {
            try self.sendBytes(bytes);
        }

        fn sendNether(self: *@This(), bytes: []const u8, _: anytype) !void {
            try self.sendBytes(bytes);
        }

        fn sendBytes(self: *@This(), bytes: []const u8) !void {
            var saved: [128]u8 = undefined;
            @memcpy(saved[0..bytes.len], bytes);
            if (self.reenter) {
                var builder: support.Builder = .{};
                try testing.expectError(error.PoolExhausted, self.session.encodeOne(builder.make(&support.modern, .client_cache_status)));
                self.session.close();
                try testing.expectError(error.PoolExhausted, self.session.pool.acquireTx());
                try testing.expectEqualSlices(u8, saved[0..bytes.len], bytes);
            }
            if (self.fail) return error.WouldBlock;
        }
    };
}

test "both adapters close on handler failure and preserve send borrows during reentry" {
    inline for (.{ false, true }) |nether| {
        const Connection = Carrier(nether);
        const Adapter = if (nether) bedwire.transport.NetherNet(Connection, Handler) else bedwire.transport.RakNet(Connection, Handler);
        var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
        defer pool.deinit();
        var session = try bedwire.Session.init(testing.allocator, .client, &support.modern, .{ .pool = &pool });
        defer session.deinit();
        session.state = .in_game;
        var connection: Connection = .{ .session = &session };
        var handler: Handler = .{ .fail = true };
        var adapter: Adapter = if (nether)
            .{ .session = &session, .connection = &connection, .handler = &handler }
        else
            .{ .session = &session, .peer = &connection, .handler = &handler };

        var builder: support.Builder = .{};
        var raw: [128]u8 = undefined;
        raw[0] = 0xfe;
        var writer = bedwire.framing.batch.Writer.init(raw[1..], support.limits);
        const packet = builder.make(&support.modern, .play_status);
        try writer.append(packet);
        try writer.append(packet);
        try testing.expectError(error.HandlerFailed, adapter.deliver(raw[0 .. 1 + writer.written().len]));
        try testing.expectEqual(@as(usize, 1), handler.calls);
        try testing.expectEqual(bedwire.State.disconnected, session.state);
        try testing.expect(pool.isIdle());

        session.state = .in_game;
        connection.reenter = true;
        try adapter.sendOne(builder.make(&support.modern, .client_cache_status));
        try testing.expectEqual(bedwire.State.disconnected, session.state);
        try testing.expect(pool.isIdle());

        session.state = .in_game;
        connection.reenter = false;
        connection.fail = true;
        try testing.expectError(error.WouldBlock, adapter.sendOne(builder.make(&support.modern, .client_cache_status)));
        try testing.expectEqual(bedwire.State.disconnected, session.state);
        try testing.expect(pool.isIdle());
    }
}

const PumpChannel = struct {
    const Adapter = bedwire.transport.NetherNet(@This(), Handler);
    adapter: ?*Adapter = null,
    receives: usize = 0,
    payload: []const u8,

    pub fn receive(self: *@This()) anyerror!struct { data: []const u8, reliability: enum { reliable, unreliable } } {
        self.receives += 1;
        if (self.receives == 1) {
            if (self.adapter) |adapter| try testing.expectError(error.InvalidState, adapter.pump());
        }
        return .{ .data = self.payload, .reliability = .reliable };
    }
};

test "pump rejects reentry before receive and closes if consumed data cannot be admitted" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 1 });
    defer pool.deinit();
    var session = try bedwire.Session.init(testing.allocator, .client, &support.modern, .{ .pool = &pool });
    defer session.deinit();
    session.state = .in_game;
    var builder: support.Builder = .{};
    var raw: [128]u8 = undefined;
    raw[0] = 0xfe;
    var writer = bedwire.framing.batch.Writer.init(raw[1..], support.limits);
    try writer.append(builder.make(&support.modern, .play_status));
    var channel: PumpChannel = .{ .payload = raw[0 .. 1 + writer.written().len] };
    var handler: Handler = .{};
    var adapter: PumpChannel.Adapter = .{ .session = &session, .connection = &channel, .handler = &handler };
    channel.adapter = &adapter;
    try adapter.pump();
    try testing.expectEqual(@as(usize, 1), channel.receives);
    try testing.expectEqual(@as(usize, 1), handler.calls);

    var held = try session.ingest(channel.payload);
    defer held.deinit();
    try testing.expectError(error.InvalidState, adapter.pump());
    try testing.expectEqual(@as(usize, 1), channel.receives);
    held.deinit();

    const rx = try pool.acquireRx();
    defer pool.releaseRx(rx);
    try testing.expectError(error.PoolExhausted, adapter.pump());
    try testing.expectEqual(@as(usize, 2), channel.receives);
    try testing.expectEqual(bedwire.State.disconnected, session.state);
    try testing.expectError(error.TransportClosed, adapter.pump());
    try testing.expectEqual(@as(usize, 2), channel.receives);
}

test "recoverable encode failures preserve observations and crypto and return the lease" {
    var pair = try support.Pair.init(testing.allocator, &support.modern);
    defer pair.deinit();
    pair.client.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    pair.server.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    var builder: support.Builder = .{};
    const packet = builder.make(&support.modern, .request_network_settings);
    const before = pair.client.crypto.?;
    const token = pair.client.tx_token;
    for (0..8) |_| {
        try testing.expectError(error.InvalidState, pair.client.encode(&.{ packet, packet }));
        try testing.expectEqual(bedwire.State.transport_ready, pair.client.state);
        try testing.expect(!pair.client.didSend(.request_network_settings));
        try testing.expectEqualDeep(before, pair.client.crypto.?);
        try testing.expectEqual(token, pair.client.tx_token);
        try testing.expect(pair.pool.isIdle());
    }
    var admitted = try pair.clientToServer(&.{packet});
    defer admitted.deinit();
    try testing.expectEqual(bedwire.State.network_settings, pair.client.state);
    try testing.expectEqualSlices(u8, packet, admitted.next().?.bytes);

    pair.client.state = .in_game;
    pair.client.crypto.?.send_counter = std.math.maxInt(u64);
    const exhausted = pair.client.crypto.?;
    const committed_token = pair.client.tx_token;
    for (0..8) |_| {
        try testing.expectError(error.CounterExhausted, pair.client.encodeOne(builder.make(&support.modern, .client_cache_status)));
        try testing.expectEqualDeep(exhausted, pair.client.crypto.?);
        try testing.expectEqual(committed_token, pair.client.tx_token);
        try testing.expect(!pair.client.didSend(.client_cache_status));
        try testing.expect(pair.client.tx_slot == null);
    }
}

test "shared RX backpressure preserves ciphertext for retry and held packets survive close" {
    var pool = try bedwire.BufferPool.init(testing.allocator, support.limits, .{ .rx_slots = 1, .tx_slots = 2 });
    defer pool.deinit();
    var sessions: [3]bedwire.Session = undefined;
    for (&sessions) |*session| {
        session.* = try bedwire.Session.init(testing.allocator, .client, &support.modern, .{ .pool = &pool });
        session.state = .in_game;
        session.crypto = bedwire.crypto.SessionCrypto.init(@splat(0x42));
    }
    defer for (&sessions) |*session| session.deinit();
    sessions[0].role = .server;
    var builder: support.Builder = .{};
    const packet = builder.make(&support.modern, .play_status);
    const frame = try sessions[0].encodeOne(packet);
    defer frame.release();
    var held = try sessions[1].ingest(frame.bytes);
    defer held.deinit();
    const received = held.next().?;
    var stale = held;
    for (0..8) |_| {
        try testing.expectError(error.PoolExhausted, sessions[2].ingest(frame.bytes));
        try testing.expectEqual(@as(u64, 0), sessions[2].crypto.?.recv_counter);
        try testing.expect(!sessions[2].didReceive(.play_status));
    }
    sessions[1].close();
    try testing.expectEqualSlices(u8, packet, received.bytes);
    try testing.expectError(error.PoolExhausted, sessions[2].ingest(frame.bytes));
    held.deinit();
    var retried = try sessions[2].ingest(frame.bytes);
    defer retried.deinit();
    stale.deinit();
    stale.reset();
    try testing.expect(stale.next() == null);
    try testing.expectEqualSlices(u8, packet, retried.next().?.bytes);
}

test "compression negotiation failure leaves the old state intact" {
    const descriptor = comptime bedwire.protocol.describeWith(818, .{ .supports_snappy = false }) catch unreachable;
    var pair = try support.Pair.init(testing.allocator, &descriptor);
    defer pair.deinit();
    pair.client.state = .network_settings;
    pair.client.received.insert(.network_settings);
    const before = pair.client.compression;
    try testing.expectError(error.UnsupportedCompression, pair.client.negotiateCompression(.snappy, 512));
    try testing.expectEqualDeep(before, pair.client.compression);
    try testing.expectEqual(bedwire.State.network_settings, pair.client.state);
    try pair.client.negotiateCompression(.deflate, 512);
    try testing.expectEqual(bedwire.State.authenticating, pair.client.state);
}
