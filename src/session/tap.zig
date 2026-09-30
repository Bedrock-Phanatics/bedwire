const std = @import("std");
const protocol = @import("bedrock_protocol");
const Limits = @import("../limits.zig").Limits;
const batch = @import("../framing/batch.zig");
const compression_mod = @import("../compression/algorithm.zig");
const session = @import("session.zig");
const BufferPool = @import("pool.zig").BufferPool;

pub const Direction = enum { client_to_server, server_to_client };
pub const Phase = enum { awaiting_request, awaiting_settings, awaiting_login, awaiting_handshake, encrypted };

pub const Options = struct {
    pool: *BufferPool,
    limits: ?Limits = null,
    policy: session.SessionPolicy = .{},
};

pub const Tap = TapWithProfile(protocol.Current);

pub fn TapWithProfile(comptime Profile: type) type {
    comptime protocol.validateProfile(Profile);
    return struct {
        const Self = @This();

        pub const Packet = struct {
            kind: ?protocol.PacketKind,
            id: u10,
            bytes: []const u8,
        };

        /// Packet bytes expire when any copy of this lease is released.
        pub const Packets = struct {
            reader: batch.Reader,
            tap: *Self,
            generation: u64,
            exhausted: bool = false,
            deinitialized: bool = false,

            pub fn next(self: *@This()) ?Packet {
                if (self.deinitialized or self.exhausted or self.tap.active_generation != self.generation) return null;
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
                if (self.deinitialized or self.exhausted or self.tap.active_generation != self.generation) return;
                self.reader.reset();
            }

            pub fn deinit(self: *@This()) void {
                if (self.deinitialized) return;
                self.deinitialized = true;
                if (self.tap.active_generation != self.generation) return;
                self.tap.active_generation = null;
                self.tap.login_bytes = null;
                const token = self.tap.rx_slot orelse return;
                self.tap.rx_slot = null;
                self.tap.pool.releaseRx(token);
            }
        };

        pool: *BufferPool,
        limits: Limits,
        policy: session.SessionPolicy,
        compression: compression_mod.Compression,
        current_phase: Phase,
        rx_slot: ?BufferPool.RxToken = null,
        active_generation: ?u64 = null,
        generation: u64 = 0,
        login_bytes: ?[]const u8 = null,

        /// Serialize calls on one Tap; independent taps may share a pool.
        pub fn init(options: Options) !Self {
            const limits = if (options.limits) |l| blk: {
                try l.validate();
                if (l.max_frame_bytes > options.pool.limits.max_frame_bytes or
                    l.max_batch_bytes > options.pool.limits.max_batch_bytes) return error.IncompatibleLimits;
                break :blk l;
            } else options.pool.limits;
            return .{
                .pool = options.pool,
                .limits = limits,
                .policy = options.policy,
                .compression = .init(Profile.features),
                .current_phase = if (Profile.features.uses_request_network_settings) .awaiting_request else .awaiting_login,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.rx_slot) |token| self.pool.releaseRx(token);
            self.* = undefined;
        }

        pub fn phase(self: *const Self) Phase {
            return self.current_phase;
        }

        /// Decoded packets borrow the pool lease; the caller's payload stays untouched.
        pub fn observe(self: *Self, direction: Direction, payload: []const u8) !Packets {
            if (self.active_generation != null) return error.InvalidState;
            if (self.current_phase == .encrypted) return error.Opaque;
            const body = try batch.strip(payload, self.limits);
            const token = try self.pool.acquireRx();
            errdefer self.pool.releaseRx(token);
            const slot = self.pool.getRx(token) orelse return error.InvalidState;
            var raw = try self.compression.decode(body, slot.batch, &slot.history, self.limits);
            if (raw.ptr != slot.batch.ptr) {
                if (raw.len > slot.frame.len) return error.LimitExceeded;
                @memcpy(slot.frame[0..raw.len], raw);
                raw = slot.frame[0..raw.len];
            }

            var reader = try batch.Reader.init(raw, self.limits);
            var next_phase = self.current_phase;
            var next_compression = self.compression;
            var login_bytes: ?[]const u8 = null;
            var count: usize = 0;
            while (try reader.next()) |bytes| {
                count += 1;
                if (count != 1) return error.InvalidState;
                const header = try parseHeader(bytes);
                if (header.sender_subclient != 0 or header.target_subclient != 0) return error.InvalidState;
                const kind = Profile.packetKind(header.packet_id);
                switch (kind orelse continue) {
                    .request_network_settings => {
                        if (next_phase != .awaiting_request or direction != .client_to_server) return error.InvalidState;
                        const decoded = try self.decodeControl(bytes, header, kind);
                        if (decoded.value.typed.request_network_settings.client_network_version != Profile.protocol_number) return error.UnsupportedProtocol;
                        next_phase = .awaiting_settings;
                    },
                    .network_settings => {
                        if (next_phase != .awaiting_settings or direction != .server_to_client) return error.InvalidState;
                        const decoded = try self.decodeControl(bytes, header, kind);
                        const settings = decoded.value.typed.network_settings;
                        const algorithm: compression_mod.Algorithm = switch (settings.compression_algorithm) {
                            .zlib => .deflate,
                            .snappy => .snappy,
                            .none => .none,
                            else => return error.UnsupportedCompression,
                        };
                        try next_compression.negotiate(algorithm, settings.compression_threshold);
                        next_phase = .awaiting_login;
                    },
                    .login => {
                        if (next_phase != .awaiting_login or direction != .client_to_server) return error.InvalidState;
                        const decoded = try self.decodeControl(bytes, header, kind);
                        if (decoded.value.typed.login.client_network_version != Profile.protocol_number) return error.UnsupportedProtocol;
                        login_bytes = bytes;
                        next_phase = .awaiting_handshake;
                    },
                    .server_to_client_handshake => {
                        if (next_phase != .awaiting_handshake or direction != .server_to_client) return error.InvalidState;
                        _ = try self.decodeControl(bytes, header, kind);
                        next_phase = .encrypted;
                    },
                    else => {},
                }
            }
            if (count == 0) return error.MalformedBatch;

            reader.reset();
            self.current_phase = next_phase;
            self.compression = next_compression;
            self.login_bytes = login_bytes;
            self.generation +%= 1;
            self.active_generation = self.generation;
            self.rx_slot = token;
            return .{ .reader = reader, .tap = self, .generation = self.generation };
        }

        pub fn authenticateLoginPacket(self: *Self, allocator: std.mem.Allocator, packet: Packet, policy: session.TrustPolicy) !@import("../auth/identity.zig").Identity {
            if (self.current_phase != .awaiting_handshake or self.active_generation == null or packet.kind != .login) return error.InvalidState;
            const observed = self.login_bytes orelse return error.InvalidState;
            if (packet.bytes.ptr != observed.ptr or packet.bytes.len != observed.len or
                Profile.packetKind(packet.id) != .login) return error.InvalidState;
            if (Profile.features.login_flow != @as(session.LoginFlow, policy)) return error.UnsupportedProtocol;
            const decoded = try Profile.decodeBorrowed(packet.bytes, protocolLimits(self.limits));
            if (decoded.header.packet_id != packet.id or decoded.kind != .login or
                decoded.value != .typed or decoded.value.typed != .login) return error.InvalidProfile;
            return session.verifyLoginRequest(allocator, decoded.value.typed.login.connection_request, policy, self.policy, self.limits);
        }

        fn decodeControl(self: *const Self, bytes: []const u8, header: protocol.packet.Header, kind: ?protocol.PacketKind) !protocol.BorrowedEnvelope {
            const decoded = try Profile.decodeBorrowed(bytes, protocolLimits(self.limits));
            if (decoded.header.toWire() != header.toWire() or decoded.kind != kind or decoded.value != .typed) return error.InvalidProfile;
            if (protocol.typed.packetKind(decoded.value.typed) != kind) return error.InvalidProfile;
            return decoded;
        }
    };
}

fn parseHeader(bytes: []const u8) !protocol.packet.Header {
    const decoded = protocol.packet.decode(bytes, .{ .max_packet_bytes = @max(bytes.len, 1) }) catch return error.MalformedBatch;
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
