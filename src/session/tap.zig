const std = @import("std");
const control = @import("../wire/control.zig");
const SessionFeatures = @import("features.zig").SessionFeatures;
const Limits = @import("../limits.zig").Limits;
const batch = @import("../framing/batch.zig");
const compression_mod = @import("../compression/algorithm.zig");
const session = @import("session.zig");
const BufferPool = @import("pool.zig").BufferPool;

pub const Direction = enum { client_to_server, server_to_client };
pub const Phase = enum { awaiting_request, awaiting_settings, awaiting_login, awaiting_handshake, encrypted, established };

pub const Options = struct {
    pool: *BufferPool,
    limits: ?Limits = null,
    policy: session.SessionPolicy = .{},
    features: SessionFeatures = .{},
    /// The version both sides must announce.
    protocol_version: u32,
};

pub const Tap = struct {
    const Self = @This();

    pub const Packet = struct {
        kind: ?control.PacketKind,
        id: u10,
        bytes: []const u8,
    };

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
            return .{ .kind = control.PacketKind.fromId(header.packet_id), .id = header.packet_id, .bytes = bytes };
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
    features: SessionFeatures,
    protocol_version: u32,
    compression: compression_mod.Compression,
    current_phase: Phase,
    rx_slot: ?BufferPool.RxToken = null,
    active_generation: ?u64 = null,
    generation: u64 = 0,
    login_bytes: ?[]const u8 = null,

    pub fn init(options: Options) !Self {
        const limits = if (options.limits) |l| blk: {
            try l.validate();
            if (l.max_frame_bytes > options.pool.limits.max_frame_bytes or
                l.max_batch_bytes > options.pool.limits.max_batch_bytes) return error.IncompatibleLimits;
            break :blk l;
        } else options.pool.limits;
        try options.features.validate();
        return .{
            .pool = options.pool,
            .limits = limits,
            .policy = options.policy,
            .features = options.features,
            .protocol_version = options.protocol_version,
            .compression = .init(options.features),
            .current_phase = if (options.features.uses_request_network_settings) .awaiting_request else .awaiting_login,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.rx_slot) |token| self.pool.releaseRx(token);
        self.* = undefined;
    }

    pub fn phase(self: *const Self) Phase {
        return self.current_phase;
    }

    pub fn observe(self: *Self, direction: Direction, payload: []const u8) !Packets {
        if (self.active_generation != null) return error.InvalidState;
        if (self.current_phase == .encrypted) return error.Opaque;
        const body = try batch.body(payload, self.policy.batch_header, self.limits);
        const token = try self.pool.acquireRx();
        errdefer self.pool.releaseRx(token);
        const slot = self.pool.getRx(token) orelse return error.InvalidState;
        var raw = try self.compression.decodeWithContext(body, slot.batch, &slot.history, self.limits, slot.decoder);
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
            if (count != 1 and next_phase != .established) return error.InvalidState;
            const header = try parseHeader(bytes);
            if (header.sender_subclient != 0 or header.target_subclient != 0) return error.InvalidState;
            const kind = control.PacketKind.fromId(header.packet_id);
            switch (kind orelse continue) {
                .request_network_settings => {
                    if (next_phase != .awaiting_request or direction != .client_to_server) return error.InvalidState;
                    const request = try control.decode(control.RequestNetworkSettings, bytes, self.limits);
                    if (!self.announces(request.protocol_version)) return error.UnsupportedProtocol;
                    next_phase = .awaiting_settings;
                },
                .network_settings => {
                    if (next_phase != .awaiting_settings or direction != .server_to_client) return error.InvalidState;
                    const settings = try control.decode(control.NetworkSettings, bytes, self.limits);
                    const algorithm: compression_mod.Algorithm = switch (settings.compression_algorithm) {
                        .zlib => .deflate,
                        .snappy => .snappy,
                        .none => .none,
                        _ => return error.UnsupportedCompression,
                    };
                    try next_compression.negotiate(algorithm, settings.compression_threshold);
                    next_phase = .awaiting_login;
                },
                .login => {
                    if (next_phase != .awaiting_login or direction != .client_to_server) return error.InvalidState;
                    const login = try control.decode(control.Login, bytes, self.limits);
                    if (!self.announces(login.protocol_version)) return error.UnsupportedProtocol;
                    login_bytes = bytes;
                    next_phase = .awaiting_handshake;
                },
                .server_to_client_handshake => {
                    if (next_phase != .awaiting_handshake or direction != .server_to_client or
                        self.policy.encryption == .disabled) return error.InvalidState;
                    _ = try control.decode(control.ServerToClientHandshake, bytes, self.limits);
                    next_phase = .encrypted;
                },
                .play_status => if (next_phase == .awaiting_handshake and direction == .server_to_client and self.policy.encryption == .disabled) {
                    _ = try control.decode(control.PlayStatus, bytes, self.limits);
                    next_phase = .established;
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
            control.PacketKind.fromId(packet.id) != .login) return error.InvalidState;
        if (self.features.login_flow != @as(session.LoginFlow, policy)) return error.UnsupportedProtocol;
        const login = try control.decode(control.Login, packet.bytes, self.limits);
        return session.verifyLoginRequest(allocator, login.connection_request, policy, self.policy, self.limits);
    }

    fn announces(self: *const Self, version: i32) bool {
        return version >= 0 and @as(u32, @intCast(version)) == self.protocol_version;
    }
};

fn parseHeader(bytes: []const u8) !control.Header {
    const envelope = control.parse(bytes) catch return error.MalformedBatch;
    return envelope.header;
}
