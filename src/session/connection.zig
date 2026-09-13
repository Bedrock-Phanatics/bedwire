const std = @import("std");
const protocol = @import("bedrock_protocol");

const auth = @import("../auth/chain.zig");
const jwt = @import("../auth/jwt.zig");
const compression = @import("../compression/algorithm.zig");
const Workspace = @import("../compression/flate.zig").Workspace;
const snappy = @import("../compression/snappy.zig");
const ecdh = @import("../crypto/ecdh.zig");
const Crypto = @import("../crypto/session_crypto.zig").SessionCrypto;
const spki = @import("../crypto/spki.zig");
const batch = @import("../framing/batch.zig");
const Limits = @import("../framing/limits.zig").DecodeLimits;
const carrier_contract = @import("../transport/carrier.zig");
const state = @import("state.zig");

/// Single-owner connection. Carrier is borrowed; all scratch allocations happen
/// during init. Packet slices expire at the next receive, including failed calls.
pub fn Connection(comptime Carrier: type) type {
    comptime carrier_contract.validate(Carrier);
    return struct {
        allocator: std.mem.Allocator,
        carrier: *Carrier,
        limits: Limits,
        role: state.Role,
        state: state.State = .handshake,
        compression: compression.Settings = .{},
        crypto: ?Crypto = null,
        ingress: []u8,
        outgoing: []u8,
        batch_buffer: []u8,
        encoder: *Workspace,
        decoder: *Workspace,
        pending_id: ?u10 = null,
        last_sent_id: ?u10 = null,
        verified_key: ?spki.Ecdsa.PublicKey = null,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, carrier: *Carrier, role: state.Role, limits: Limits) !Self {
            try limits.validate();

            const ingress = try allocator.alloc(u8, limits.protocol.max_batch_bytes);
            errdefer allocator.free(ingress);

            const outgoing = try allocator.alloc(u8, limits.protocol.max_batch_bytes);
            errdefer allocator.free(outgoing);

            const batch_buffer = try allocator.alloc(u8, limits.protocol.max_decompressed_batch_bytes);
            errdefer allocator.free(batch_buffer);

            const encoded_capacity = try snappy.maxEncodedLen(limits.protocol.max_decompressed_batch_bytes);
            const encoder = try Workspace.create(allocator, @max(limits.protocol.max_batch_bytes, encoded_capacity));
            errdefer encoder.destroy();
            const decoder = try Workspace.create(allocator, limits.protocol.max_decompressed_batch_bytes);

            return .{
                .allocator = allocator,
                .carrier = carrier,
                .role = role,
                .limits = limits,
                .ingress = ingress,
                .outgoing = outgoing,
                .batch_buffer = batch_buffer,
                .encoder = encoder,
                .decoder = decoder,
            };
        }

        pub fn close(self: *Self) void {
            if (self.state == .disconnected) return;

            self.state = .disconnected;
            if (self.crypto) |*crypto| crypto.deinit();
            self.carrier.close();
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.encoder.destroy();
            self.decoder.destroy();
            self.allocator.free(self.ingress);
            self.allocator.free(self.outgoing);
            self.allocator.free(self.batch_buffer);
            self.* = undefined;
        }

        pub fn receive(self: *Self) !protocol.batch.Iterator {
            if (self.state == .disconnected) return error.ConnectionClosed;
            errdefer self.close();

            const single_packet_state =
                self.state == .handshake or
                self.state == .authenticating or
                self.state == .encrypted_handshake;
            if (single_packet_state and self.pending_id != null) return error.InvalidState;

            const frame = try self.carrier.receive();
            _ = try batch.unframed(frame, self.limits.protocol);
            @memcpy(self.ingress[0..frame.len], frame);

            var payload: []const u8 = self.ingress[1..frame.len];
            if (self.crypto) |*crypto| payload = try crypto.open(self.ingress[1..frame.len]);

            payload = try self.compression.decode(payload, self.decoder, self.limits.protocol);
            try batch.validate(payload, self.limits.protocol);

            var iterator = try protocol.batch.Iterator.init(payload, self.limits.protocol);
            const sender: state.Role = if (self.role == .server) .client else .server;
            var count: usize = 0;

            while (try iterator.next()) |packet| {
                const envelope = try protocol.packet.decode(packet, self.limits.protocol);
                if (!self.state.permits(sender, envelope.header.packet_id)) return error.InvalidState;

                const subclient_handshake =
                    self.state != .in_game and
                    (envelope.header.sender_subclient != 0 or envelope.header.target_subclient != 0);
                if (subclient_handshake) return error.InvalidState;

                try self.validateControl(envelope);
                if (envelope.header.packet_id == 5) return error.ConnectionClosed;

                count += 1;
                self.pending_id = envelope.header.packet_id;
            }

            if (single_packet_state and count != 1) return error.InvalidState;

            return protocol.batch.Iterator.init(payload, self.limits.protocol);
        }

        pub fn send(self: *Self, packets: []const []const u8) !void {
            if (self.state == .disconnected) return error.ConnectionClosed;

            for (packets) |packet| {
                const envelope = try protocol.packet.decode(packet, self.limits.protocol);
                if (!self.state.permits(self.role, envelope.header.packet_id)) return error.InvalidState;

                try self.validateControl(envelope);
            }

            const raw = try batch.encode(packets, self.batch_buffer, self.limits.protocol);
            const algorithm = self.compression.selected(raw.len);
            const payload = switch (algorithm) {
                .none => raw,
                .deflate => try self.encoder.compress(raw),
                .snappy => try snappy.compress(raw, self.encoder.output, &self.encoder.snappy_table),
            };

            const prefix: usize = 1 + @as(usize, @intFromBool(self.compression.enabled));
            const checksum: usize = if (self.crypto != null) 8 else 0;
            if (prefix + checksum > self.outgoing.len) return error.LimitExceeded;
            if (payload.len > self.outgoing.len - prefix - checksum) return error.LimitExceeded;

            self.outgoing[0] = 0xfe;
            if (self.compression.enabled) self.outgoing[1] = @intFromEnum(algorithm);
            @memcpy(self.outgoing[prefix..][0..payload.len], payload);

            var len = prefix + payload.len;
            if (self.crypto) |*crypto| len = 1 + (try crypto.seal(self.outgoing[1..], len - 1)).len;

            self.carrier.send(self.outgoing[0..len]) catch |err| {
                self.close();
                return err;
            };

            if (packets.len != 0) {
                const last_packet = try protocol.packet.decode(packets[packets.len - 1], self.limits.protocol);
                self.last_sent_id = last_packet.header.packet_id;
            }
        }

        /// Call only after the uncompressed NetworkSettings response is sent/decoded.
        pub fn enableCompression(self: *Self, algorithm: compression.Algorithm, threshold: u16) !void {
            const expected: u10 = if (self.role == .server) 193 else 143;
            const settings_sent = self.role == .client or self.last_sent_id == 143;
            const allowed =
                self.state == .handshake and
                self.pending_id == expected and
                algorithm != .none and
                settings_sent;
            if (!allowed) return error.InvalidState;

            self.compression = .{ .enabled = true, .algorithm = algorithm, .threshold = threshold };
            self.state = .authenticating;
            self.pending_id = null;
        }

        /// Advance only after the application has handled the named protocol event.
        pub fn advance(self: *Self, next: state.State) !void {
            const allowed = switch (self.state) {
                .encrypted_handshake => next == .resource_packs and self.crypto != null and (if (self.role == .client) self.last_sent_id == 4 else self.pending_id == 4),
                .resource_packs => next == .waiting_for_start_game,
                .waiting_for_start_game => next == .spawn_ready,
                .spawn_ready => next == .in_game,
                else => false,
            };
            if (!allowed) return error.InvalidState;

            self.state = next;
            self.pending_id = null;
        }

        /// Verifies identity and client data before installing derived session keys.
        /// Caller sends the server handshake before calling installServerCrypto.
        pub fn authenticateLegacy(self: *Self, allocator: std.mem.Allocator, chain_json: []const u8, client_data: []const u8, policy: auth.Policy) !auth.AuthData {
            if (self.state != .authenticating or self.pending_id != 1) return error.InvalidState;
            errdefer self.close();

            const identity = try auth.verifyLegacy(allocator, chain_json, client_data, policy, self.limits);
            self.verified_key = identity.public_key;

            return identity;
        }

        pub fn authenticateOidc(self: *Self, allocator: std.mem.Allocator, token: []const u8, client_data: []const u8, policy: auth.OidcPolicy) !auth.AuthData {
            if (self.state != .authenticating or self.pending_id != 1) return error.InvalidState;
            errdefer self.close();

            const identity = try auth.verifyOidc(allocator, token, client_data, policy, self.limits);
            self.verified_key = identity.public_key;

            return identity;
        }

        pub fn installServerCrypto(self: *Self, secret: spki.Ecdsa.SecretKey, salt: [16]u8) !void {
            const allowed =
                self.role == .server and
                self.state == .authenticating and
                self.pending_id == 1 and
                self.last_sent_id == 3;
            if (!allowed) return error.InvalidState;

            const peer = self.verified_key orelse return error.Unauthenticated;

            var key = try ecdh.derive(secret, peer, salt);
            defer std.crypto.secureZero(u8, &key);

            self.crypto = Crypto.init(key);
            self.state = .encrypted_handshake;
            self.pending_id = null;
        }

        /// Verify the signed server handshake before deriving and enabling encryption.
        pub fn acceptServerHandshake(self: *Self, allocator: std.mem.Allocator, encoded: []const u8, secret: spki.Ecdsa.SecretKey) !void {
            if (self.role != .client or self.state != .authenticating or self.pending_id != 3) return error.InvalidState;
            errdefer self.close();

            var token = try jwt.Token.parse(allocator, encoded, self.limits);
            defer token.deinit();

            const peer = try spki.fromBase64(try jwt.string(token.header.value, "x5u"));
            try token.verify(peer);

            const encoded_salt = try jwt.string(token.payload.value, "salt");
            const decoder = std.base64.standard.Decoder;
            if (try decoder.calcSizeForSlice(encoded_salt) != 16) return error.InvalidSalt;

            var salt: [16]u8 = undefined;
            try decoder.decode(&salt, encoded_salt);

            var key = try ecdh.derive(secret, peer, salt);
            defer std.crypto.secureZero(u8, &key);

            self.crypto = Crypto.init(key);
            self.state = .encrypted_handshake;
            self.pending_id = null;
        }

        fn validateControl(self: *const Self, envelope: protocol.packet.Envelope) !void {
            var reader = try protocol.Reader.init(envelope.payload, self.limits.protocol);
            switch (envelope.header.packet_id) {
                193 => _ = try protocol.codecs.network_settings.decodeRequest(&reader),
                143 => {
                    const settings = try protocol.codecs.network_settings.decode(&reader);
                    if (settings.compression_algorithm > 1) return error.UnsupportedCompression;
                },
                4 => {},
                2 => _ = try reader.readI32Be(),
                else => return,
            }

            try reader.finish();
        }
    };
}
