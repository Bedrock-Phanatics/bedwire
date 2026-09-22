const std = @import("std");
const protocol = @import("bedrock_protocol");

const Limits = @import("../limits.zig").Limits;
const batch = @import("../framing/batch.zig");
const varint = @import("../framing/varint.zig");
const compression = @import("../compression/algorithm.zig");
const chain = @import("../auth/chain.zig");
const oidc = @import("../auth/oidc.zig");
const login = @import("../auth/login.zig");
const ecdh = @import("../crypto/ecdh.zig");
const spki = @import("../crypto/spki.zig");
const SessionCrypto = @import("../crypto/session_crypto.zig").SessionCrypto;
const descriptor_mod = @import("../protocol/descriptor.zig");
const features_mod = @import("../protocol/features.zig");
const kind_mod = @import("../protocol/kind.zig");
const state_mod = @import("state.zig");

const pool_mod = @import("pool.zig");

const Descriptor = descriptor_mod.Descriptor;
const PacketId = descriptor_mod.PacketId;

pub const PacketKind = kind_mod.PacketKind;
pub const Role = state_mod.Role;
pub const State = state_mod.State;
pub const Algorithm = compression.Algorithm;

pub const BufferPool = pool_mod.BufferPool;
pub const PoolConfig = pool_mod.PoolConfig;
pub const RxToken = BufferPool.RxToken;
pub const TxToken = BufferPool.TxToken;
pub const RxSlot = pool_mod.RxSlot;
pub const TxSlot = pool_mod.TxSlot;

pub const Options = struct {
    limits: ?Limits = null,
    pool: *BufferPool,
};

/// Borrowed outbound wire frame slice valid until next encode or explicit release
pub const Frame = struct {
    bytes: []const u8,
    session: *Session,
    token: u64,

    pub fn release(self: Frame) void {
        self.session.releaseTxToken(self.token);
    }
};

/// Decoded packet from an ingested batch
pub const Packet = struct {
    kind: PacketKind,
    id: PacketId,
    bytes: []const u8,
};

/// Iterator over parsed packets in an admitted batch
pub const Packets = struct {
    reader: batch.Reader,
    descriptor: *const Descriptor,
    len: usize,
    session: *Session,
    generation: u64,
    exhausted: bool = false,
    deinitialized: bool = false,

    pub fn next(self: *Packets) ?Packet {
        if (self.deinitialized or self.exhausted) return null;
        if (self.session.state == .disconnected) return null;
        if (self.session.active_generation != self.generation) return null;

        const bytes = (self.reader.next() catch {
            self.exhausted = true;
            return null;
        }) orelse {
            self.exhausted = true;
            return null;
        };
        const header = parseHeader(bytes) catch {
            self.exhausted = true;
            return null;
        };
        return .{ .kind = self.descriptor.kindOf(header.packet_id), .id = header.packet_id, .bytes = bytes };
    }

    pub fn reset(self: *Packets) void {
        if (self.deinitialized or self.exhausted) return;
        if (self.session.state == .disconnected) return;
        if (self.session.active_generation != self.generation) return;

        self.reader.reset();
    }

    pub fn deinit(self: *Packets) void {
        if (self.deinitialized) return;
        self.deinitialized = true;

        const active = self.session.active_generation orelse return;
        if (active != self.generation) return;

        const token = self.session.rx_slot orelse return;
        self.session.active_generation = null;
        self.session.rx_slot = null;

        self.session.pool.releaseRx(token);
    }
};

/// Bedrock session state machine and framing engine
pub const Session = struct {
    allocator: std.mem.Allocator,
    descriptor: *const Descriptor,
    limits: Limits,
    role: Role,
    state: State,
    compression: compression.Compression,
    crypto: ?SessionCrypto = null,
    peer_key: ?spki.Ecdsa.PublicKey = null,
    sent: std.EnumSet(PacketKind) = .initEmpty(),
    received: std.EnumSet(PacketKind) = .initEmpty(),

    pool: *BufferPool,
    rx_slot: ?RxToken = null,
    tx_slot: ?TxToken = null,
    tx_token: u64 = 0,
    generation: u64 = 0,
    active_generation: ?u64 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        role: Role,
        descriptor: *const Descriptor,
        options: Options,
    ) !Session {
        try descriptor.features.validate();

        const limits = if (options.limits) |l| blk: {
            try l.validate();
            if (l.max_frame_bytes > options.pool.limits.max_frame_bytes) return error.IncompatibleLimits;
            if (l.max_batch_bytes > options.pool.limits.max_batch_bytes) return error.IncompatibleLimits;
            break :blk l;
        } else options.pool.limits;

        return .{
            .allocator = allocator,
            .descriptor = descriptor,
            .limits = limits,
            .role = role,
            .state = State.initial(descriptor.features),
            .compression = .init(descriptor.features),
            .pool = options.pool,
        };
    }

    pub fn deinit(self: *Session) void {
        self.close();
        if (self.rx_slot) |st| {
            self.rx_slot = null;
            self.active_generation = null;
            self.pool.releaseRx(st);
        }
        self.* = undefined;
    }

    /// Closes session and zeroes crypto keys without prematurely freeing active RX storage
    pub fn close(self: *Session) void {
        if (self.state == .disconnected) return;

        self.state = .disconnected;
        if (self.crypto) |*crypto| crypto.deinit();
        self.crypto = null;

        if (self.tx_slot) |st| {
            self.tx_slot = null;
            self.tx_token +%= 1;
            self.pool.releaseTx(st);
        }
    }

    /// Set state to closing
    pub fn beginClose(self: *Session) void {
        if (self.state.active()) self.state = .closing;
    }

    pub fn features(self: *const Session) features_mod.SessionFeatures {
        return self.descriptor.features;
    }

    pub fn version(self: *const Session) u32 {
        return self.descriptor.version;
    }

    pub fn encrypted(self: *const Session) bool {
        return self.crypto != null;
    }

    pub fn didSend(self: *const Session, kind: PacketKind) bool {
        return self.sent.contains(kind);
    }

    pub fn didReceive(self: *const Session, kind: PacketKind) bool {
        return self.received.contains(kind);
    }

    /// Ingests a raw datagram using pooled RX storage
    pub fn ingest(self: *Session, payload: []const u8) !Packets {
        if (self.state == .disconnected) return error.TransportClosed;
        if (self.active_generation != null or self.rx_slot != null) return error.InvalidState;

        const body = batch.strip(payload, self.limits) catch |err| {
            self.close();
            return err;
        };

        const rx_token = try self.pool.acquireRx();
        errdefer self.pool.releaseRx(rx_token);

        errdefer self.close();

        const rx_slot = self.pool.getRx(rx_token) orelse return error.InvalidState;
        if (body.len > rx_slot.frame.len or body.len > self.limits.max_frame_bytes) return error.LimitExceeded;
        @memcpy(rx_slot.frame[0..body.len], body);

        var session_payload: []const u8 = rx_slot.frame[0..body.len];
        if (self.crypto) |*crypto| session_payload = try crypto.open(rx_slot.frame[0..body.len]);

        const raw = try self.compression.decodeWith(
            session_payload,
            rx_slot.batch,
            &rx_slot.history,
            self.limits,
        );
        const observed = try self.admit(raw, self.role.peer());

        self.observe(observed.kinds, self.role.peer());

        const reader = try batch.Reader.init(raw, self.limits);
        self.generation +%= 1;
        self.active_generation = self.generation;
        self.rx_slot = rx_token;

        return .{
            .reader = reader,
            .descriptor = self.descriptor,
            .len = observed.count,
            .session = self,
            .generation = self.generation,
        };
    }

    /// Encodes packets into a wire frame using pooled TX storage
    pub fn encode(self: *Session, packets: []const []const u8) !Frame {
        if (self.state == .disconnected) return error.TransportClosed;

        const slot_token = self.tx_slot orelse try self.pool.acquireTx();
        self.tx_slot = slot_token;

        self.tx_token +%= 1;
        const current_token = self.tx_token;

        errdefer {
            if (self.tx_slot) |st| {
                self.tx_slot = null;
                self.tx_token +%= 1;
                self.pool.releaseTx(st);
            }
        }

        const slot = self.pool.getTx(slot_token) orelse return error.InvalidState;

        var writer = batch.Writer.init(slot.assembly, self.limits);
        var observed: std.EnumSet(PacketKind) = .initEmpty();

        for (packets) |packet| {
            const header = try parseHeader(packet);
            const kind = self.descriptor.kindOf(header.packet_id);
            try self.check(kind, header, self.role);
            try writer.append(packet);
            observed.insert(kind);
        }

        if (writer.count == 0) return error.MalformedBatch;
        if (self.state.singlePacketBatch() and writer.count != 1) return error.InvalidState;

        const max_egress = @min(slot.egress.len, self.limits.max_frame_bytes);
        const marker: usize = @intFromBool(self.compression.marks());
        const reserve = 1 + marker;
        const trailer: usize = if (self.crypto != null) 8 else 0;
        if (reserve + trailer >= max_egress) return error.LimitExceeded;

        const room = max_egress - reserve - trailer;
        const framed = try self.compression.encodeWith(
            writer.written(),
            slot.egress[reserve..][0..room],
            &slot.history,
            &slot.table,
        );

        slot.egress[0] = batch.header;
        if (marker != 0) slot.egress[1] = @intFromEnum(framed.algorithm);

        var len = reserve + framed.bytes.len;
        if (self.crypto) |*crypto| len = 1 + (try crypto.seal(slot.egress[1..max_egress], len - 1)).len;
        if (len > self.limits.max_frame_bytes) return error.LimitExceeded;

        self.observe(observed, self.role);

        return Frame{
            .bytes = slot.egress[0..len],
            .session = self,
            .token = current_token,
        };
    }

    pub fn encodeOne(self: *Session, packet: []const u8) !Frame {
        return self.encode(&.{packet});
    }

    pub fn releaseTxToken(self: *Session, token: u64) void {
        if (self.tx_token != token) return;
        if (self.tx_slot) |slot_token| {
            self.tx_slot = null;
            self.tx_token +%= 1;
            self.pool.releaseTx(slot_token);
        }
    }

    /// apply compression settings negotiated in NetworkSettings
    pub fn negotiateCompression(self: *Session, algorithm: Algorithm, threshold: u16) !void {
        if (self.state != .network_settings) return error.InvalidState;
        if (!self.exchanged(.network_settings, .server)) return error.InvalidState;

        try self.compression.negotiate(algorithm, threshold);
        self.state = .authenticating;
    }

    /// verify mojang auth chain and extract client public key for ecdh
    pub fn authenticateChain(
        self: *Session,
        allocator: std.mem.Allocator,
        chain_json: []const u8,
        client_data: []const u8,
        policy: chain.ChainPolicy,
    ) !chain.Identity {
        try self.readyToAuthenticate(.certificate_chain);
        errdefer self.close();

        const identity = try chain.verifyChain(allocator, chain_json, client_data, policy, self.limits);
        self.peer_key = identity.public_key;

        return identity;
    }

    /// verify xbox oidc token and extract client public key
    pub fn authenticateOidc(
        self: *Session,
        allocator: std.mem.Allocator,
        token: []const u8,
        client_data: []const u8,
        policy: oidc.OidcPolicy,
    ) !oidc.Identity {
        try self.readyToAuthenticate(.oidc);
        errdefer self.close();

        const identity = try oidc.verifyOidc(allocator, token, client_data, policy, self.limits);
        self.peer_key = identity.public_key;

        return identity;
    }

    /// set client public key directly if auth was done upstream (e.g. by a proxy)
    pub fn installVerifiedClientKey(self: *Session, key: spki.Ecdsa.PublicKey) !void {
        if (self.role != .server or self.state != .authenticating) return error.InvalidState;
        if (!self.didReceive(.login)) return error.InvalidState;

        self.peer_key = key;
    }

    /// derive shared secret and turn on encryption on server
    /// call after ServerToClientHandshake is sent (handshake itself goes in clear)
    pub fn installServerCrypto(self: *Session, secret: spki.Ecdsa.SecretKey, salt: [16]u8) !void {
        const ordered =
            self.role == .server and
            self.state == .authenticating and
            self.didSend(.server_to_client_handshake);
        if (!ordered) return error.InvalidState;
        if (self.crypto != null) return error.InvalidState;

        const peer = self.peer_key orelse return error.Unauthenticated;
        try self.enableCrypto(secret, peer, salt);
    }

    /// unpack server handshake token and turn on crypto on client side
    pub fn acceptServerHandshake(
        self: *Session,
        allocator: std.mem.Allocator,
        token: []const u8,
        secret: spki.Ecdsa.SecretKey,
    ) !void {
        const ordered =
            self.role == .client and
            self.state == .authenticating and
            self.didReceive(.server_to_client_handshake);
        if (!ordered) return error.InvalidState;
        if (self.crypto != null) return error.InvalidState;
        errdefer self.close();

        const handshake = try login.Handshake.verify(allocator, token, self.limits);
        self.peer_key = handshake.peer_key;
        try self.enableCrypto(secret, handshake.peer_key, handshake.salt);
    }

    /// advance state machine to next phase
    pub fn advance(self: *Session, next: State) !void {
        const allowed = switch (next) {
            .resource_packs => switch (self.state) {
                .encrypted_handshake => self.crypto != null and self.exchanged(.client_to_server_handshake, .client),
                .authenticating => self.descriptor.features.encryption == .optional and self.exchanged(.login, .client),
                else => false,
            },
            .waiting_for_start_game => self.state == .resource_packs,
            .spawn_ready => self.state == .waiting_for_start_game and self.exchanged(.start_game, .server),
            .in_game => self.state == .spawn_ready,
            .closing => self.state.active(),
            else => false,
        };
        if (!allowed) return error.InvalidState;

        self.state = next;
    }

    // Tracks observed packets and auto-transitions transport_ready -> network_settings
    fn observe(self: *Session, kinds: std.EnumSet(PacketKind), sender: Role) void {
        if (sender == self.role) {
            self.sent = self.sent.unionWith(kinds);
        } else {
            self.received = self.received.unionWith(kinds);
        }

        if (self.state == .transport_ready and kinds.contains(.request_network_settings)) {
            self.state = .network_settings;
        }
        if (kinds.contains(.disconnect)) self.beginClose();
    }

    fn exchanged(self: *const Session, kind: PacketKind, sender: Role) bool {
        return if (self.role == sender) self.didSend(kind) else self.didReceive(kind);
    }

    fn readyToAuthenticate(self: *const Session, flow: features_mod.LoginFlow) !void {
        if (self.role != .server or self.state != .authenticating) return error.InvalidState;
        if (!self.didReceive(.login)) return error.InvalidState;
        if (self.descriptor.features.login_flow != flow) return error.UnsupportedProtocol;
    }

    fn enableCrypto(
        self: *Session,
        secret: spki.Ecdsa.SecretKey,
        peer: spki.Ecdsa.PublicKey,
        salt: [16]u8,
    ) !void {
        var key = try ecdh.derive(secret, peer, salt);
        defer std.crypto.secureZero(u8, &key);

        self.crypto = SessionCrypto.init(key);
        self.state = .encrypted_handshake;
    }

    const Observed = struct { kinds: std.EnumSet(PacketKind), count: usize };

    // make sure all packets in this batch are valid for current state
    fn admit(self: *const Session, raw: []const u8, sender: Role) !Observed {
        var reader = try batch.Reader.init(raw, self.limits);
        var result: Observed = .{ .kinds = .initEmpty(), .count = 0 };

        while (try reader.next()) |packet| {
            const header = try parseHeader(packet);
            const kind = self.descriptor.kindOf(header.packet_id);
            try self.check(kind, header, sender);

            result.kinds.insert(kind);
            result.count += 1;
        }

        if (result.count == 0) return error.MalformedBatch;
        if (self.state.singlePacketBatch() and result.count != 1) return error.InvalidState;

        return result;
    }

    fn check(self: *const Session, kind: PacketKind, header: protocol.packet.Header, sender: Role) !void {
        if (!self.state.permits(self.descriptor.features, sender, kind)) return error.InvalidState;

        if (header.sender_subclient != 0 or header.target_subclient != 0) return error.InvalidState;
    }
};

fn parseHeader(packet: []const u8) !protocol.packet.Header {
    const decoded = varint.readU32(packet) catch return error.MalformedBatch;
    return protocol.packet.Header.fromWire(decoded.value) catch error.MalformedBatch;
}
