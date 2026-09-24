const std = @import("std");
const protocol = @import("bedrock_protocol");

const Limits = @import("../limits.zig").Limits;
const batch = @import("../framing/batch.zig");
const compression = @import("../compression/algorithm.zig");
const chain = @import("../auth/chain.zig");
const oidc = @import("../auth/oidc.zig");
const wire = @import("../auth/wire.zig");
const identity_mod = @import("../auth/identity.zig");
const login = @import("../auth/login.zig");
const ecdh = @import("../crypto/ecdh.zig");
const spki = @import("../crypto/spki.zig");
const SessionCrypto = @import("../crypto/session_crypto.zig").SessionCrypto;
const state_mod = @import("state.zig");

const pool_mod = @import("pool.zig");

const PacketId = u10;

pub const PacketKind = protocol.PacketKind;
pub const Role = state_mod.Role;
pub const State = state_mod.State;
pub const Algorithm = compression.Algorithm;

pub const BufferPool = pool_mod.BufferPool;
pub const PoolConfig = pool_mod.PoolConfig;
pub const RxToken = BufferPool.RxToken;
pub const TxToken = BufferPool.TxToken;
pub const RxSlot = pool_mod.RxSlot;
pub const TxSlot = pool_mod.TxSlot;

pub const LoginFlow = @FieldType(protocol.SessionFeatures, "login_flow");
pub const TrustPolicy = union(LoginFlow) {
    certificate_chain: chain.ChainPolicy,
    oidc: oidc.OidcPolicy,
};

pub const Options = struct {
    limits: ?Limits = null,
    pool: *BufferPool,
    policy: SessionPolicy = .{},
};

pub const Session = SessionWithProfile(protocol.Current);
pub const Frame = Session.Frame;
pub const Packets = Session.Packets;
pub const Packet = Session.Packet;

/// Bedwire policy that is independent of a profile's wire capabilities.
pub const SessionPolicy = struct {
    encryption: enum { required, optional } = .required,
    connection_request_format: enum { legacy_chain, envelope } = .envelope,
};

pub fn SessionWithProfile(comptime Profile: type) type {
    comptime protocol.validateProfile(Profile);
    return struct {
        const Self = @This();

        /// Outbound bytes remain valid until release or Session.deinit, including across close.
        /// Copies share one lease; the Session must stay at a stable address.
        pub const Frame = struct {
            bytes: []const u8,
            session: *Self,
            token: u64,

            pub fn release(self: @This()) void {
                self.session.releaseTxToken(self.token);
            }
        };

        /// Packet bytes borrow the RX lease until Packets.deinit or Session.deinit.
        pub const Packet = struct {
            kind: ?PacketKind,
            id: PacketId,
            bytes: []const u8,
        };

        /// Copies have separate cursors but share one RX lease; deinit of any copy
        /// invalidates every Packet slice from that lease. EOF and close retain storage.
        pub const Packets = struct {
            reader: batch.Reader,
            len: usize,
            session: *Self,
            generation: u64,
            exhausted: bool = false,
            deinitialized: bool = false,

            pub fn next(self: *@This()) ?Self.Packet {
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
                return .{ .kind = Profile.packetKind(header.packet_id), .id = header.packet_id, .bytes = bytes };
            }

            pub fn reset(self: *@This()) void {
                if (self.deinitialized or self.exhausted) return;
                if (self.session.state == .disconnected) return;
                if (self.session.active_generation != self.generation) return;

                self.reader.reset();
            }

            pub fn deinit(self: *@This()) void {
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

        /// Serialize access to each Session, including release. Independent Sessions
        /// may share a pool. Keep the Session at a stable address while leases exist.
        allocator: std.mem.Allocator,
        policy: SessionPolicy,
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
            options: Options,
        ) !Self {
            const limits = if (options.limits) |l| blk: {
                try l.validate();
                if (l.max_frame_bytes > options.pool.limits.max_frame_bytes) return error.IncompatibleLimits;
                if (l.max_batch_bytes > options.pool.limits.max_batch_bytes) return error.IncompatibleLimits;
                break :blk l;
            } else options.pool.limits;

            return .{
                .allocator = allocator,
                .policy = options.policy,
                .limits = limits,
                .role = role,
                .state = State.initial(Profile.features),
                .compression = .init(Profile.features),
                .pool = options.pool,
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.releaseTxToken(self.tx_token);
            if (self.rx_slot) |st| {
                self.rx_slot = null;
                self.active_generation = null;
                self.pool.releaseRx(st);
            }
            self.* = undefined;
        }

        /// Closes the Session without invalidating borrowed RX or TX storage.
        pub fn close(self: *Self) void {
            self.state = .disconnected;
            if (self.crypto) |*crypto| crypto.deinit();
            self.crypto = null;
            self.peer_key = null;
        }

        /// Set state to closing
        pub fn beginClose(self: *Self) void {
            if (self.state.active()) self.state = .closing;
        }

        pub fn features(_: *const Self) protocol.SessionFeatures {
            return Profile.features;
        }

        pub fn version(_: *const Self) u32 {
            return Profile.protocol_number;
        }

        pub fn encrypted(self: *const Self) bool {
            return self.crypto != null;
        }

        pub fn didSend(self: *const Self, kind: PacketKind) bool {
            return self.sent.contains(kind);
        }

        pub fn didReceive(self: *const Self, kind: PacketKind) bool {
            return self.received.contains(kind);
        }

        /// Ingests a raw datagram using pooled RX storage
        pub fn ingest(self: *Self, payload: []const u8) !Self.Packets {
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

            const reader = try batch.Reader.init(raw, self.limits);
            self.observe(observed.kinds, self.role.peer());
            self.generation +%= 1;
            self.active_generation = self.generation;
            self.rx_slot = rx_token;

            return .{
                .reader = reader,
                .len = observed.count,
                .session = self,
                .generation = self.generation,
            };
        }

        /// A held Frame returns PoolExhausted. Send successful frames in order;
        /// close the Session if a committed frame is abandoned or sending fails.
        pub fn encode(self: *Self, packets: []const []const u8) !Self.Frame {
            if (self.state == .disconnected) return error.TransportClosed;
            if (self.tx_slot != null) return error.PoolExhausted;

            const slot_token = try self.pool.acquireTx();
            errdefer self.pool.releaseTx(slot_token);

            const slot = self.pool.getTx(slot_token) orelse return error.InvalidState;

            var writer = batch.Writer.init(slot.assembly, self.limits);
            var observed: std.EnumSet(PacketKind) = .initEmpty();

            for (packets) |packet| {
                const header = try parseHeader(packet);
                const kind = Profile.packetKind(header.packet_id);
                try self.check(kind, header, self.role);
                try self.validateControl(packet, header, kind);
                try writer.append(packet);
                if (kind) |known| observed.insert(known);
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

            self.tx_slot = slot_token;
            self.tx_token +%= 1;
            self.observe(observed, self.role);

            return Self.Frame{
                .bytes = slot.egress[0..len],
                .session = self,
                .token = self.tx_token,
            };
        }

        pub fn encodeOne(self: *Self, packet: []const u8) !Self.Frame {
            return self.encode(&.{packet});
        }

        /// Decode a packet through this session's profile. Returned slices borrow
        /// the packet lease and expire when Packets.deinit is called.
        pub fn decodePacket(self: *const Self, packet: Self.Packet) !protocol.BorrowedEnvelope {
            if (packet.bytes.len > self.limits.max_packet_bytes) return error.LimitExceeded;
            if (Profile.packetKind(packet.id) != packet.kind) return error.InvalidProfile;
            const decoded = try Profile.decodeBorrowed(packet.bytes, protocolLimits(self.limits));
            if (decoded.header.packet_id != packet.id or decoded.kind != packet.kind) return error.InvalidProfile;
            return decoded;
        }

        /// Apply normalized NetworkSettings, leaving the state unchanged on failure.
        pub fn negotiateFromSettings(self: *Self, packet: Self.Packet) !void {
            if (packet.kind != .network_settings) return error.InvalidState;
            const decoded = try self.decodePacket(packet);
            if (decoded.value != .typed or decoded.value.typed != .network_settings) return error.InvalidProfile;
            const settings = decoded.value.typed.network_settings;
            const algorithm: Algorithm = switch (settings.compression_algorithm) {
                0 => .deflate,
                1 => .snappy,
                0xffff => .none,
                else => return error.UnsupportedCompression,
            };
            try self.negotiateCompression(algorithm, settings.compression_threshold);
        }

        pub fn authenticateLoginPacket(self: *Self, allocator: std.mem.Allocator, packet: Self.Packet, policy: TrustPolicy) !identity_mod.Identity {
            if (packet.kind != .login) return error.InvalidState;
            try self.readyToAuthenticate(@as(LoginFlow, policy));
            errdefer self.close();
            const decoded = try self.decodePacket(packet);
            if (decoded.value != .typed or decoded.value.typed != .login) return error.InvalidProfile;
            return self.authenticateLogin(allocator, decoded.value.typed.login.connection_request, policy);
        }

        pub fn acceptServerHandshakePacket(self: *Self, allocator: std.mem.Allocator, packet: Self.Packet, secret: spki.Ecdsa.SecretKey) !void {
            if (packet.kind != .server_to_client_handshake) return error.InvalidState;
            if (self.role != .client or self.state != .authenticating or
                !self.didReceive(.server_to_client_handshake) or self.crypto != null) return error.InvalidState;
            errdefer self.close();
            const decoded = try self.decodePacket(packet);
            if (decoded.value != .typed or decoded.value.typed != .server_to_client_handshake) return error.InvalidProfile;
            return self.acceptServerHandshake(allocator, decoded.value.typed.server_to_client_handshake.jwt, secret);
        }

        pub fn releaseTxToken(self: *Self, token: u64) void {
            if (self.tx_token != token) return;
            if (self.tx_slot) |slot_token| {
                self.tx_slot = null;
                self.tx_token +%= 1;
                self.pool.releaseTx(slot_token);
            }
        }

        /// apply compression settings negotiated in NetworkSettings
        pub fn negotiateCompression(self: *Self, algorithm: Algorithm, threshold: u16) !void {
            if (self.state != .network_settings) return error.InvalidState;
            if (!self.exchanged(.network_settings, .server)) return error.InvalidState;

            try self.compression.negotiate(algorithm, threshold);
            self.state = .authenticating;
        }

        /// verify mojang auth chain and extract client public key for ecdh
        pub fn authenticateChain(
            self: *Self,
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
            self: *Self,
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

        /// authenticates player login using unified TrustPolicy, enforcing wire format and flow
        pub fn authenticateLogin(
            self: *Self,
            allocator: std.mem.Allocator,
            connection_request_bytes: []const u8,
            policy: TrustPolicy,
        ) !identity_mod.Identity {
            try self.readyToAuthenticate(@as(LoginFlow, policy));
            errdefer self.close();

            // decode binary connection_request wire format
            const req = try wire.decodeConnectionRequest(connection_request_bytes, self.limits);

            var envelope = try wire.parseChainEnvelope(allocator, req.chain_data, self.limits);
            defer envelope.deinit(allocator);

            switch (self.policy.connection_request_format) {
                .legacy_chain => {
                    if (!envelope.is_legacy_chain) return error.UnsupportedProtocol;
                },
                .envelope => {
                    if (envelope.is_legacy_chain) return error.UnsupportedProtocol;
                },
            }

            const identity = switch (policy) {
                .oidc => |oidc_policy| blk: {
                    if (envelope.authentication_type == 1 or envelope.authentication_type > 2) {
                        return error.UnsupportedAuthenticationType;
                    }
                    if (envelope.authentication_type == 2) {
                        return error.UntrustedChain;
                    }

                    const id_token = envelope.token orelse return error.InvalidClaims;
                    break :blk try oidc.verifyOidc(allocator, id_token, req.client_data, oidc_policy, self.limits);
                },
                .certificate_chain => |chain_policy| blk: {
                    if (!envelope.is_legacy_chain) {
                        if (envelope.authentication_type == 1 or envelope.authentication_type > 2) {
                            return error.UnsupportedAuthenticationType;
                        }
                        if (envelope.authentication_type == 2 and !chain_policy.allow_offline) {
                            return error.UntrustedChain;
                        }
                    }

                    const chain_json = if (envelope.is_legacy_chain)
                        req.chain_data
                    else
                        (envelope.certificate orelse return error.InvalidClaims);

                    break :blk try chain.verifyChain(allocator, chain_json, req.client_data, chain_policy, self.limits);
                },
            };

            self.peer_key = identity.public_key;

            return identity;
        }

        /// set client public key directly if auth was done upstream (e.g. by a proxy)
        pub fn installVerifiedClientKey(self: *Self, key: spki.Ecdsa.PublicKey) !void {
            if (self.role != .server or self.state != .authenticating) return error.InvalidState;
            if (!self.didReceive(.login)) return error.InvalidState;

            self.peer_key = key;
        }

        /// derive shared secret and turn on encryption on server
        /// call after ServerToClientHandshake is sent (handshake itself goes in clear)
        pub fn installServerCrypto(self: *Self, secret: spki.Ecdsa.SecretKey, salt: [16]u8) !void {
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
            self: *Self,
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
            try self.enableCrypto(secret, handshake.peer_key, handshake.salt);
            self.peer_key = handshake.peer_key;
        }

        /// advance state machine to next phase
        pub fn advance(self: *Self, next: State) !void {
            const allowed = switch (next) {
                .resource_packs => switch (self.state) {
                    .encrypted_handshake => self.crypto != null and self.exchanged(.client_to_server_handshake, .client),
                    .authenticating => self.policy.encryption == .optional and self.exchanged(.login, .client),
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
        fn observe(self: *Self, kinds: std.EnumSet(PacketKind), sender: Role) void {
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

        fn exchanged(self: *const Self, kind: PacketKind, sender: Role) bool {
            return if (self.role == sender) self.didSend(kind) else self.didReceive(kind);
        }

        fn readyToAuthenticate(self: *const Self, flow: LoginFlow) !void {
            if (self.role != .server or self.state != .authenticating) return error.InvalidState;
            if (!self.didReceive(.login)) return error.InvalidState;
            if (Profile.features.login_flow != flow) return error.UnsupportedProtocol;
        }

        fn enableCrypto(
            self: *Self,
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
        fn admit(self: *const Self, raw: []const u8, sender: Role) !Observed {
            var reader = try batch.Reader.init(raw, self.limits);
            var result: Observed = .{ .kinds = .initEmpty(), .count = 0 };

            while (try reader.next()) |packet| {
                const header = try parseHeader(packet);
                const kind = Profile.packetKind(header.packet_id);
                try self.check(kind, header, sender);
                try self.validateControl(packet, header, kind);

                if (kind) |known| result.kinds.insert(known);
                result.count += 1;
            }

            if (result.count == 0) return error.MalformedBatch;
            if (self.state.singlePacketBatch() and result.count != 1) return error.InvalidState;

            return result;
        }

        fn check(self: *const Self, kind: ?PacketKind, header: protocol.packet.Header, sender: Role) !void {
            const direction = if (kind) |known| Profile.packetDirection(known) else .bidirectional;
            if (!self.state.permitsWithDirection(Profile.features, sender, kind, direction)) return error.InvalidState;

            if (header.sender_subclient != 0 or header.target_subclient != 0) return error.InvalidState;
        }

        fn validateControl(self: *const Self, bytes: []const u8, header: protocol.packet.Header, kind: ?PacketKind) !void {
            const known = kind orelse return;
            switch (known) {
                .request_network_settings,
                .network_settings,
                .login,
                .server_to_client_handshake,
                .client_to_server_handshake,
                .disconnect,
                .resource_packs_info,
                .resource_pack_stack,
                .resource_pack_client_response,
                => {},
                else => return,
            }
            if (bytes.len > self.limits.max_packet_bytes) return error.LimitExceeded;
            const decoded = try Profile.decodeBorrowed(bytes, protocolLimits(self.limits));
            if (decoded.header.toWire() != header.toWire() or decoded.kind != kind) return error.InvalidProfile;
            switch (known) {
                .resource_packs_info => if (decoded.value != .resource_packs_info) return error.InvalidProfile,
                .resource_pack_stack => if (decoded.value != .resource_pack_stack) return error.InvalidProfile,
                .resource_pack_client_response => if (decoded.value != .resource_pack_client_response) return error.InvalidProfile,
                else => {
                    if (decoded.value != .typed) return error.InvalidProfile;
                    if (protocol.typed.packetKind(decoded.value.typed) != known) return error.InvalidProfile;
                },
            }
        }
    };
}

fn parseHeader(packet: []const u8) !protocol.packet.Header {
    const decoded = protocol.packet.decode(packet, .{ .max_packet_bytes = @max(packet.len, 1) }) catch return error.MalformedBatch;
    return decoded.header;
}

fn protocolLimits(limits: Limits) protocol.DecodeLimits {
    return .{
        .max_packet_bytes = limits.max_packet_bytes,
        .max_string_bytes = limits.max_packet_bytes,
        .max_byte_array_bytes = limits.max_packet_bytes,
        .max_array_elements = @min(limits.max_packet_bytes, protocol.DecodeLimits.defaults.max_array_elements),
        .max_nbt_bytes = limits.max_packet_bytes,
        .max_nesting_depth = limits.max_json_nesting,
    };
}
