const std = @import("std");
const protocol = @import("bedrock_protocol");

const Limits = @import("../limits.zig").Limits;
const batch = @import("../framing/batch.zig");
const varint = @import("../framing/varint.zig");
const compression = @import("../compression/algorithm.zig");
const chain = @import("../auth/chain.zig");
const login = @import("../auth/login.zig");
const ecdh = @import("../crypto/ecdh.zig");
const spki = @import("../crypto/spki.zig");
const SessionCrypto = @import("../crypto/session_crypto.zig").SessionCrypto;
const descriptor_mod = @import("../protocol/descriptor.zig");
const features_mod = @import("../protocol/features.zig");
const kind_mod = @import("../protocol/kind.zig");
const state_mod = @import("state.zig");

const Descriptor = descriptor_mod.Descriptor;
const PacketId = descriptor_mod.PacketId;

pub const PacketKind = kind_mod.PacketKind;
pub const Role = state_mod.Role;
pub const State = state_mod.State;
pub const Algorithm = compression.Algorithm;

pub const Options = struct {
    limits: Limits = .{},
};

/// decoded packet from an ingested batch
/// bytes points into the session buffer, so it gets overwritten on the next ingest()
pub const Packet = struct {
    kind: PacketKind,
    id: PacketId,
    bytes: []const u8,
};

/// iterator over parsed packets in a batch
/// ingest() already verified these against state machine rules
pub const Packets = struct {
    reader: batch.Reader,
    descriptor: *const Descriptor,
    len: usize,

    pub fn next(self: *Packets) ?Packet {
        const bytes = (self.reader.next() catch unreachable) orelse return null;
        const header = parseHeader(bytes) catch unreachable;
        return .{ .kind = self.descriptor.kindOf(header.packet_id), .id = header.packet_id, .bytes = bytes };
    }

    pub fn reset(self: *Packets) void {
        self.reader.reset();
    }
};

/// bedrock session state machine and framing engine
///
/// handles 0xFE encapsulation, batching, snappy/deflate compression,
/// ecdh p-384 key exchange, aes-256-ctr encryption and the handshake sequence.
///
/// not thread safe, each connection should have its own session.
/// all working buffers are allocated up front in init() so the hot path
/// (ingest and encode) doesn't touch the heap.
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

    // inbound frames decrypt in place here
    ingress: []u8,
    // outbound wire frame buffer (0xfe + algo marker + payload + mac)
    egress: []u8,
    // staging buffer for uncompressed packets with varint lengths
    assembly: []u8,
    // scratchpad for deflate sliding window and snappy tables
    workspace: *compression.Workspace,

    pub fn init(
        allocator: std.mem.Allocator,
        role: Role,
        descriptor: *const Descriptor,
        options: Options,
    ) !Session {
        try options.limits.validate();
        try descriptor.features.validate();

        const ingress = try allocator.alloc(u8, options.limits.max_frame_bytes);
        errdefer allocator.free(ingress);

        const egress = try allocator.alloc(u8, options.limits.max_frame_bytes);
        errdefer allocator.free(egress);

        const assembly = try allocator.alloc(u8, options.limits.max_batch_bytes);
        errdefer allocator.free(assembly);

        const workspace = try compression.Workspace.create(allocator, options.limits.max_batch_bytes);

        return .{
            .allocator = allocator,
            .descriptor = descriptor,
            .limits = options.limits,
            .role = role,
            .state = State.initial(descriptor.features),
            .compression = .init(descriptor.features),
            .ingress = ingress,
            .egress = egress,
            .assembly = assembly,
            .workspace = workspace,
        };
    }

    pub fn deinit(self: *Session) void {
        self.close();
        self.workspace.destroy();
        self.allocator.free(self.ingress);
        self.allocator.free(self.egress);
        self.allocator.free(self.assembly);
        self.* = undefined;
    }

    /// closes session and zeroes out crypto keys
    pub fn close(self: *Session) void {
        if (self.state == .disconnected) return;

        self.state = .disconnected;
        if (self.crypto) |*crypto| crypto.deinit();
        self.crypto = null;
    }

    /// set state to closing (only disconnect packet allowed now)
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

    /// takes a raw datagram from carrier, strips 0xfe, decrypts, decompresses,
    /// and validates packet order against state machine.
    /// returns an iterator over the parsed packets. closes session on any error.
    pub fn ingest(self: *Session, payload: []const u8) !Packets {
        if (self.state == .disconnected) return error.TransportClosed;
        errdefer self.close();

        const body = try batch.strip(payload, self.limits);
        @memcpy(self.ingress[0..body.len], body);

        var session_payload: []const u8 = self.ingress[0..body.len];
        if (self.crypto) |*crypto| session_payload = try crypto.open(self.ingress[0..body.len]);

        const raw = try self.compression.decode(session_payload, self.workspace, self.limits);
        const observed = try self.admit(raw, self.role.peer());

        self.observe(observed.kinds, self.role.peer());

        return .{
            .reader = try batch.Reader.init(raw, self.limits),
            .descriptor = self.descriptor,
            .len = observed.count,
        };
    }

    /// packs uncompressed packets into a 0xfe batch frame, compresses and encrypts if active.
    /// returned slice borrows egress buffer, valid until next encode().
    pub fn encode(self: *Session, packets: []const []const u8) ![]const u8 {
        if (self.state == .disconnected) return error.TransportClosed;

        var writer = batch.Writer.init(self.assembly, self.limits);
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

        const marker: usize = @intFromBool(self.compression.marks());
        const reserve = 1 + marker;
        const trailer: usize = if (self.crypto != null) 8 else 0;
        if (reserve + trailer >= self.egress.len) return error.LimitExceeded;

        const room = self.egress.len - reserve - trailer;
        const framed = try self.compression.encode(writer.written(), self.egress[reserve..][0..room], self.workspace);

        self.egress[0] = batch.header;
        if (marker != 0) self.egress[1] = @intFromEnum(framed.algorithm);

        var len = reserve + framed.bytes.len;
        if (self.crypto) |*crypto| len = 1 + (try crypto.seal(self.egress[1..], len - 1)).len;

        self.observe(observed, self.role);

        return self.egress[0..len];
    }

    pub fn encodeOne(self: *Session, packet: []const u8) ![]const u8 {
        return self.encode(&.{packet});
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
        policy: chain.OidcPolicy,
    ) !chain.Identity {
        try self.readyToAuthenticate(.oidc);
        errdefer self.close();

        const identity = try chain.verifyOidc(allocator, token, client_data, policy, self.limits);
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
                .authenticating => self.descriptor.features.encryption == .optional and self.didReceive(.login),
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

        const split_screen = header.sender_subclient != 0 or header.target_subclient != 0;
        if (split_screen and self.state != .in_game) return error.InvalidState;
    }
};

fn parseHeader(packet: []const u8) !protocol.packet.Header {
    const decoded = varint.readU32(packet) catch return error.MalformedBatch;
    return protocol.packet.Header.fromWire(decoded.value) catch error.MalformedBatch;
}

