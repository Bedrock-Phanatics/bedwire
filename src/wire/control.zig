//! The protocol-version independent part of the Bedrock packet layer: the packet header and the handful of
//! control packets the session machine reads. Everything else is opaque bytes for the embedder to decode.
const std = @import("std");

const Limits = @import("../limits.zig").Limits;

pub const PacketId = u10;

pub const DecodeError = error{
    EndOfStream,
    VarIntOverflow,
    NonCanonicalVarInt,
    InvalidBoolean,
    InvalidUtf8,
    InvalidEnum,
    InvalidValue,
    InvalidPacketId,
    TrailingData,
    LimitExceeded,
};

pub const EncodeError = error{ NoSpaceLeft, InvalidValue };

pub const Direction = enum { client_to_server, server_to_client, bidirectional };

pub const PacketKind = enum(PacketId) {
    login = 1,
    play_status = 2,
    server_to_client_handshake = 3,
    client_to_server_handshake = 4,
    disconnect = 5,
    resource_packs_info = 6,
    resource_pack_stack = 7,
    resource_pack_client_response = 8,
    start_game = 11,
    request_chunk_radius = 69,
    chunk_radius_updated = 70,
    resource_pack_data_info = 82,
    resource_pack_chunk_data = 83,
    resource_pack_chunk_request = 84,
    set_local_player_as_initialised = 113,
    client_cache_status = 129,
    network_settings = 143,
    request_network_settings = 193,
    resource_packs_ready_for_validation = 340,

    const by_id = blk: {
        var table: [1 << @bitSizeOf(PacketId)]?PacketKind = @splat(null);
        for (std.enums.values(PacketKind)) |kind| table[@backingInt(kind)] = kind;
        break :blk table;
    };

    pub fn fromId(packet_id: PacketId) ?PacketKind {
        return by_id[packet_id];
    }

    pub fn id(self: PacketKind) PacketId {
        return @backingInt(self);
    }

    pub fn direction(self: PacketKind) Direction {
        return switch (self) {
            .play_status,
            .server_to_client_handshake,
            .resource_packs_info,
            .resource_pack_stack,
            .start_game,
            .chunk_radius_updated,
            .resource_pack_data_info,
            .resource_pack_chunk_data,
            .network_settings,
            => .server_to_client,
            .client_cache_status, .set_local_player_as_initialised, .resource_packs_ready_for_validation => .client_to_server,
            .login,
            .client_to_server_handshake,
            .disconnect,
            .resource_pack_client_response,
            .request_chunk_radius,
            .resource_pack_chunk_request,
            .request_network_settings,
            => .bidirectional,
        };
    }
};

/// The varint that starts every game packet: a 10-bit ID and two 2-bit split-screen sub-client indices.
pub const Header = packed struct(u14) {
    packet_id: PacketId,
    sender_subclient: u2 = 0,
    target_subclient: u2 = 0,

    pub fn fromWire(value: u32) error{InvalidPacketId}!Header {
        if (value > 0x3fff) return error.InvalidPacketId;
        return @bitCast(@as(u14, @intCast(value)));
    }

    pub fn toWire(self: Header) u32 {
        return @as(u14, @bitCast(self));
    }

    /// Fourteen bits fit two varint bytes, so a longer header is overlong or names no packet.
    pub fn read(packet: []const u8) ?Header {
        if (packet.len == 0) return null;
        const low = packet[0];
        if (low < 0x80) return @bitCast(@as(u14, low));
        if (packet.len == 1) return null;
        const high = packet[1];
        if (high == 0 or high >= 0x80) return null;
        return @bitCast(@as(u14, low & 0x7f) | @as(u14, high) << 7);
    }
};

pub const Envelope = struct { header: Header, payload: []const u8 };

pub fn parse(packet: []const u8) DecodeError!Envelope {
    var reader: Reader = .init(packet, packet.len);
    const header = try Header.fromWire(try reader.varU32());
    return .{ .header = header, .payload = reader.rest() };
}

/// Decodes a whole control packet, rejecting another kind or bytes past the last field.
pub fn decode(comptime T: type, packet: []const u8, limits: Limits) DecodeError!T {
    if (packet.len > limits.max_packet_bytes) return error.LimitExceeded;
    const envelope = try parse(packet);
    if (envelope.header.packet_id != T.kind.id()) return error.InvalidPacketId;
    var reader: Reader = .init(envelope.payload, limits.max_packet_bytes);
    const value = try T.read(&reader);
    if (T.kind != .start_game) try reader.finish();
    return value;
}

pub fn encode(dest: []u8, value: anytype) EncodeError![]u8 {
    var writer: Writer = .init(dest);
    try writer.varU32(@backingInt(@TypeOf(value).kind));
    try value.write(&writer);
    return writer.written();
}

pub const Reader = struct {
    input: []const u8,
    cursor: usize = 0,
    max_length: usize,

    pub fn init(input: []const u8, max_length: usize) Reader {
        return .{ .input = input, .max_length = max_length };
    }

    pub fn rest(self: *const Reader) []const u8 {
        return self.input[self.cursor..];
    }

    pub fn finish(self: *const Reader) DecodeError!void {
        if (self.cursor != self.input.len) return error.TrailingData;
    }

    pub fn take(self: *Reader, count: usize) DecodeError![]const u8 {
        if (count > self.input.len - self.cursor) return error.EndOfStream;
        defer self.cursor += count;
        return self.input[self.cursor..][0..count];
    }

    pub fn byte(self: *Reader) DecodeError!u8 {
        return (try self.take(1))[0];
    }

    pub fn boolean(self: *Reader) DecodeError!bool {
        return switch (try self.byte()) {
            0 => false,
            1 => true,
            else => error.InvalidBoolean,
        };
    }

    pub fn int(self: *Reader, comptime T: type, endian: std.builtin.Endian) DecodeError!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], endian);
    }

    pub fn varU32(self: *Reader) DecodeError!u32 {
        return self.varUnsigned(u32);
    }

    pub fn varU64(self: *Reader) DecodeError!u64 {
        return self.varUnsigned(u64);
    }

    pub fn varI64(self: *Reader) DecodeError!i64 {
        const value = try self.varU64();
        return @bitCast((value >> 1) ^ (0 -% (value & 1)));
    }

    fn varUnsigned(self: *Reader, comptime T: type) DecodeError!T {
        const max_bytes = (@bitSizeOf(T) + 6) / 7;
        const last_bits = @bitSizeOf(T) - 7 * (max_bytes - 1);
        var value: T = 0;
        for (0..max_bytes) |index| {
            const next = try self.byte();
            if (index == max_bytes - 1 and next >> last_bits != 0) return error.VarIntOverflow;
            value |= @as(T, next & 0x7f) << @intCast(7 * index);
            if (next & 0x80 == 0) {
                if (index != 0 and next == 0) return error.NonCanonicalVarInt;
                return value;
            }
        }
        return error.VarIntOverflow;
    }

    pub fn length(self: *Reader) DecodeError!usize {
        const len = try self.varU32();
        if (len > self.max_length) return error.LimitExceeded;
        return len;
    }

    pub fn bytes(self: *Reader) DecodeError![]const u8 {
        return self.take(try self.length());
    }

    pub fn string(self: *Reader) DecodeError![]const u8 {
        const text = try self.bytes();
        if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;
        return text;
    }
};

pub const Writer = struct {
    buffer: []u8,
    end: usize = 0,

    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer };
    }

    pub fn written(self: *const Writer) []u8 {
        return self.buffer[0..self.end];
    }

    pub fn raw(self: *Writer, data: []const u8) EncodeError!void {
        if (data.len > self.buffer.len - self.end) return error.NoSpaceLeft;
        @memcpy(self.buffer[self.end..][0..data.len], data);
        self.end += data.len;
    }

    pub fn byte(self: *Writer, value: u8) EncodeError!void {
        return self.raw(&.{value});
    }

    pub fn boolean(self: *Writer, value: bool) EncodeError!void {
        return self.byte(@intFromBool(value));
    }

    pub fn int(self: *Writer, comptime T: type, value: T, endian: std.builtin.Endian) EncodeError!void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, value, endian);
        return self.raw(&encoded);
    }

    pub fn varU32(self: *Writer, value: u32) EncodeError!void {
        return self.varU64(value);
    }

    pub fn varU64(self: *Writer, value: u64) EncodeError!void {
        var encoded: [10]u8 = undefined;
        var remaining = value;
        var len: usize = 0;
        while (true) {
            const low: u8 = @truncate(remaining & 0x7f);
            remaining >>= 7;
            encoded[len] = low | @as(u8, if (remaining != 0) 0x80 else 0);
            len += 1;
            if (remaining == 0) break;
        }
        return self.raw(encoded[0..len]);
    }

    pub fn varI64(self: *Writer, value: i64) EncodeError!void {
        const bits: u64 = @bitCast(value);
        return self.varU64((bits << 1) ^ @as(u64, @bitCast(value >> 63)));
    }

    pub fn bytes(self: *Writer, data: []const u8) EncodeError!void {
        const len = std.math.cast(u32, data.len) orelse return error.InvalidValue;
        if (data.len > self.buffer.len - self.end) return error.NoSpaceLeft;
        try self.varU32(len);
        return self.raw(data);
    }
};

pub const Login = struct {
    pub const kind: PacketKind = .login;
    pub const max_connection_request_bytes = 3 * 1024 * 1024;

    protocol_version: i32,
    connection_request: []const u8,

    pub fn read(reader: *Reader) DecodeError!Login {
        const version = try reader.int(i32, .big);
        const len = try reader.length();
        if (len > max_connection_request_bytes) return error.InvalidValue;
        return .{ .protocol_version = version, .connection_request = try reader.take(len) };
    }

    pub fn write(self: Login, writer: *Writer) EncodeError!void {
        if (self.connection_request.len > max_connection_request_bytes) return error.InvalidValue;
        try writer.int(i32, self.protocol_version, .big);
        try writer.bytes(self.connection_request);
    }
};

pub const PlayStatus = struct {
    pub const kind: PacketKind = .play_status;
    pub const login_success: i32 = 0;
    pub const player_spawn: i32 = 3;

    status: i32,

    pub fn read(reader: *Reader) DecodeError!PlayStatus {
        return .{ .status = try reader.int(i32, .big) };
    }

    pub fn write(self: PlayStatus, writer: *Writer) EncodeError!void {
        try writer.int(i32, self.status, .big);
    }
};

pub const ServerToClientHandshake = struct {
    pub const kind: PacketKind = .server_to_client_handshake;

    token: []const u8,

    pub fn read(reader: *Reader) DecodeError!ServerToClientHandshake {
        return .{ .token = try reader.string() };
    }

    pub fn write(self: ServerToClientHandshake, writer: *Writer) EncodeError!void {
        if (!std.unicode.utf8ValidateSlice(self.token)) return error.InvalidValue;
        try writer.bytes(self.token);
    }
};

pub const ClientToServerHandshake = struct {
    pub const kind: PacketKind = .client_to_server_handshake;

    pub fn read(_: *Reader) DecodeError!ClientToServerHandshake {
        return .{};
    }

    pub fn write(_: ClientToServerHandshake, _: *Writer) EncodeError!void {}
};

pub const ResourcePackClientResponse = struct {
    pub const kind: PacketKind = .resource_pack_client_response;
    pub const max_packs = 65535;

    pub const Status = enum(u32) { cancel = 0, downloading = 1, downloading_finished = 2, resource_pack_stack_finished = 3 };

    status: Status,
    /// The response text; for `downloading` the pack IDs follow it and are only validated.
    text: []const u8 = "",

    pub fn read(reader: *Reader) DecodeError!ResourcePackClientResponse {
        const status = std.enums.fromInt(Status, try reader.varU32()) orelse return error.InvalidEnum;
        const text = try reader.string();
        if (status == .downloading) {
            const count = try reader.varU32();
            if (count > reader.max_length) return error.LimitExceeded;
            if (count > max_packs) return error.InvalidValue;
            for (0..count) |_| _ = try reader.string();
        }
        return .{ .status = status, .text = text };
    }

    pub fn write(self: ResourcePackClientResponse, writer: *Writer) EncodeError!void {
        if (!std.unicode.utf8ValidateSlice(self.text)) return error.InvalidValue;
        try writer.varU32(@backingInt(self.status));
        try writer.bytes(self.text);
        if (self.status == .downloading) try writer.varU32(0);
    }
};

pub const SetLocalPlayerAsInitialised = struct {
    pub const kind: PacketKind = .set_local_player_as_initialised;

    runtime_id: u64,

    pub fn read(reader: *Reader) DecodeError!SetLocalPlayerAsInitialised {
        return .{ .runtime_id = try reader.varU64() };
    }

    pub fn write(self: SetLocalPlayerAsInitialised, writer: *Writer) EncodeError!void {
        try writer.varU64(self.runtime_id);
    }
};

/// Only the leading actor IDs, so `decode` leaves the rest of the packet unread.
pub const StartGame = struct {
    pub const kind: PacketKind = .start_game;

    unique_id: i64,
    runtime_id: u64,

    pub fn read(reader: *Reader) DecodeError!StartGame {
        return .{ .unique_id = try reader.varI64(), .runtime_id = try reader.varU64() };
    }

    pub fn write(self: StartGame, writer: *Writer) EncodeError!void {
        try writer.varI64(self.unique_id);
        try writer.varU64(self.runtime_id);
    }
};

pub const RequestNetworkSettings = struct {
    pub const kind: PacketKind = .request_network_settings;

    protocol_version: i32,

    pub fn read(reader: *Reader) DecodeError!RequestNetworkSettings {
        return .{ .protocol_version = try reader.int(i32, .big) };
    }

    pub fn write(self: RequestNetworkSettings, writer: *Writer) EncodeError!void {
        try writer.int(i32, self.protocol_version, .big);
    }
};

pub const NetworkSettings = struct {
    pub const kind: PacketKind = .network_settings;

    pub const Algorithm = enum(u16) { zlib = 0, snappy = 1, none = 0xffff, _ };

    compression_threshold: u16,
    compression_algorithm: Algorithm,
    client_throttle_enabled: bool = false,
    client_throttle_threshold: u8 = 0,
    client_throttle_scalar: f32 = 0,

    pub fn read(reader: *Reader) DecodeError!NetworkSettings {
        return .{
            .compression_threshold = try reader.int(u16, .little),
            .compression_algorithm = @fromBackingInt(try reader.int(u16, .little)),
            .client_throttle_enabled = try reader.boolean(),
            .client_throttle_threshold = try reader.byte(),
            .client_throttle_scalar = @bitCast(try reader.int(u32, .little)),
        };
    }

    pub fn write(self: NetworkSettings, writer: *Writer) EncodeError!void {
        try writer.int(u16, self.compression_threshold, .little);
        try writer.int(u16, @backingInt(self.compression_algorithm), .little);
        try writer.boolean(self.client_throttle_enabled);
        try writer.byte(self.client_throttle_threshold);
        try writer.int(u32, @bitCast(self.client_throttle_scalar), .little);
    }
};

pub const ResourcePackDataInfo = struct {
    pub const kind: PacketKind = .resource_pack_data_info;

    resource_name: []const u8,
    chunk_size: u32,
    number_of_chunks: u32,
    file_size: u64,
    file_hash: []const u8,
    is_premium_pack: bool = false,
    pack_type: u8 = 0,

    pub fn read(reader: *Reader) DecodeError!ResourcePackDataInfo {
        return .{
            .resource_name = try reader.string(),
            .chunk_size = try reader.int(u32, .little),
            .number_of_chunks = try reader.int(u32, .little),
            .file_size = try reader.int(u64, .little),
            .file_hash = try reader.bytes(),
            .is_premium_pack = try reader.boolean(),
            .pack_type = try reader.byte(),
        };
    }

    pub fn write(self: ResourcePackDataInfo, writer: *Writer) EncodeError!void {
        if (!std.unicode.utf8ValidateSlice(self.resource_name)) return error.InvalidValue;
        try writer.bytes(self.resource_name);
        try writer.int(u32, self.chunk_size, .little);
        try writer.int(u32, self.number_of_chunks, .little);
        try writer.int(u64, self.file_size, .little);
        try writer.bytes(self.file_hash);
        try writer.boolean(self.is_premium_pack);
        try writer.byte(self.pack_type);
    }
};

pub const ResourcePackChunkData = struct {
    pub const kind: PacketKind = .resource_pack_chunk_data;

    resource_name: []const u8,
    chunk_id: u32,
    byte_offset: u64,
    chunk_data: []const u8,

    pub fn read(reader: *Reader) DecodeError!ResourcePackChunkData {
        return .{
            .resource_name = try reader.string(),
            .chunk_id = try reader.int(u32, .little),
            .byte_offset = try reader.int(u64, .little),
            .chunk_data = try reader.bytes(),
        };
    }

    pub fn write(self: ResourcePackChunkData, writer: *Writer) EncodeError!void {
        if (!std.unicode.utf8ValidateSlice(self.resource_name)) return error.InvalidValue;
        try writer.bytes(self.resource_name);
        try writer.int(u32, self.chunk_id, .little);
        try writer.int(u64, self.byte_offset, .little);
        try writer.bytes(self.chunk_data);
    }
};

pub const ResourcePackChunkRequest = struct {
    pub const kind: PacketKind = .resource_pack_chunk_request;

    resource_name: []const u8,
    chunk: i32,

    pub fn read(reader: *Reader) DecodeError!ResourcePackChunkRequest {
        const name = try reader.string();
        const chunk = try reader.int(i32, .little);
        if (chunk < 0) return error.InvalidValue;
        return .{ .resource_name = name, .chunk = chunk };
    }

    pub fn write(self: ResourcePackChunkRequest, writer: *Writer) EncodeError!void {
        if (self.chunk < 0 or !std.unicode.utf8ValidateSlice(self.resource_name)) return error.InvalidValue;
        try writer.bytes(self.resource_name);
        try writer.int(i32, self.chunk, .little);
    }
};

const testing = std.testing;
const test_limits: Limits = .{ .max_packet_bytes = 64, .max_batch_bytes = 64, .max_frame_bytes = 64, .max_handshake_frame_bytes = 64 };

test "kinds keep their fixed IDs and round-trip through the lookup table" {
    for (std.enums.values(PacketKind)) |kind| try testing.expectEqual(kind, PacketKind.fromId(kind.id()).?);
    try testing.expectEqual(@as(PacketId, 143), PacketKind.network_settings.id());
    try testing.expectEqual(@as(?PacketKind, null), PacketKind.fromId(0));
    try testing.expectEqual(@as(?PacketKind, null), PacketKind.fromId(1023));
}

test "header splits the ID from the sub-client bits" {
    const envelope = try parse(&.{ 0x8f, 0x11, 0xaa });
    try testing.expectEqual(@as(PacketId, 143), envelope.header.packet_id);
    try testing.expectEqual(@as(u2, 2), envelope.header.sender_subclient);
    try testing.expectEqual(@as(u2, 0), envelope.header.target_subclient);
    try testing.expectEqualSlices(u8, &.{0xaa}, envelope.payload);

    const max = try parse(&.{ 0xff, 0x7f });
    try testing.expectEqual(@as(u32, 0x3fff), max.header.toWire());
}

test "header rejects truncated, overlong, overflowing and out of range varints" {
    try testing.expectError(error.EndOfStream, parse(&.{}));
    try testing.expectError(error.EndOfStream, parse(&.{0x80}));
    try testing.expectError(error.NonCanonicalVarInt, parse(&.{ 0x81, 0x00 }));
    try testing.expectError(error.VarIntOverflow, parse(&.{ 0x80, 0x80, 0x80, 0x80, 0x10 }));
    try testing.expectError(error.VarIntOverflow, parse(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }));
    try testing.expectError(error.InvalidPacketId, parse(&.{ 0x80, 0x80, 0x01 }));
}

test "control decoders reject truncation, trailing bytes, other kinds and huge lengths" {
    var storage: [64]u8 = undefined;
    const settings = try encode(&storage, NetworkSettings{ .compression_threshold = 256, .compression_algorithm = .snappy });
    const decoded = try decode(NetworkSettings, settings, test_limits);
    try testing.expectEqual(@as(u16, 256), decoded.compression_threshold);
    try testing.expectEqual(NetworkSettings.Algorithm.snappy, decoded.compression_algorithm);
    for (0..settings.len) |len| try testing.expect(std.meta.isError(decode(NetworkSettings, settings[0..len], test_limits)));

    var trailing: [64]u8 = undefined;
    @memcpy(trailing[0..settings.len], settings);
    trailing[settings.len] = 0;
    try testing.expectError(error.TrailingData, decode(NetworkSettings, trailing[0 .. settings.len + 1], test_limits));
    try testing.expectError(error.InvalidPacketId, decode(PlayStatus, settings, test_limits));

    var bad_bool: [64]u8 = undefined;
    @memcpy(bad_bool[0..settings.len], settings);
    bad_bool[6] = 2;
    try testing.expectError(error.InvalidBoolean, decode(NetworkSettings, bad_bool[0..settings.len], test_limits));

    try testing.expectError(error.LimitExceeded, decode(ServerToClientHandshake, &.{ 3, 0xff, 0xff, 0xff, 0xff, 0x0f }, test_limits));
    try testing.expectError(error.EndOfStream, decode(ServerToClientHandshake, &.{ 3, 4, 'a' }, test_limits));
    try testing.expectError(error.InvalidUtf8, decode(ServerToClientHandshake, &.{ 3, 1, 0xff }, test_limits));
    try testing.expectError(error.LimitExceeded, decode(PlayStatus, &(@as([65]u8, @splat(2))), test_limits));
    try testing.expectError(error.TrailingData, decode(ClientToServerHandshake, &.{ 4, 0 }, test_limits));
    _ = try decode(ClientToServerHandshake, &.{4}, test_limits);
}

test "login keeps the protocol version big endian and bounds the connection request" {
    var storage: [64]u8 = undefined;
    const bytes = try encode(&storage, Login{ .protocol_version = 0x01020304, .connection_request = "blob" });
    try testing.expectEqualSlices(u8, &.{ 1, 1, 2, 3, 4, 4, 'b', 'l', 'o', 'b' }, bytes);
    const login = try decode(Login, bytes, test_limits);
    try testing.expectEqual(@as(i32, 0x01020304), login.protocol_version);
    try testing.expectEqualStrings("blob", login.connection_request);
    try testing.expectError(error.EndOfStream, decode(Login, bytes[0..4], test_limits));
    try testing.expectError(error.EndOfStream, decode(Login, bytes[0 .. bytes.len - 1], test_limits));

    const huge: Limits = .{};
    try testing.expectError(error.InvalidValue, decode(Login, &.{ 1, 0, 0, 0, 0, 0x81, 0x80, 0xc0, 0x01 }, huge));
    try testing.expectError(error.LimitExceeded, decode(Login, &.{ 1, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x0f }, huge));
}

test "resource pack responses validate every variant like the full codec" {
    var storage: [64]u8 = undefined;
    const finished = try encode(&storage, ResourcePackClientResponse{ .status = .resource_pack_stack_finished, .text = "done" });
    try testing.expectEqual(ResourcePackClientResponse.Status.resource_pack_stack_finished, (try decode(ResourcePackClientResponse, finished, test_limits)).status);

    try testing.expectError(error.InvalidEnum, decode(ResourcePackClientResponse, &.{ 8, 4, 0 }, test_limits));
    try testing.expectError(error.EndOfStream, decode(ResourcePackClientResponse, &.{ 8, 3 }, test_limits));
    try testing.expectError(error.TrailingData, decode(ResourcePackClientResponse, &.{ 8, 3, 0, 0 }, test_limits));
    _ = try decode(ResourcePackClientResponse, &.{ 8, 1, 0, 2, 1, 'a', 0 }, test_limits);
    try testing.expectError(error.EndOfStream, decode(ResourcePackClientResponse, &.{ 8, 1, 0, 2, 1, 'a' }, test_limits));
    try testing.expectError(error.LimitExceeded, decode(ResourcePackClientResponse, &.{ 8, 1, 0, 0xff, 0x7f }, test_limits));
    try testing.expectError(error.InvalidValue, decode(ResourcePackClientResponse, &.{ 8, 1, 0, 0x80, 0x80, 0x04 }, .{}));
}

test "start game reads only the leading actor IDs" {
    const start = try decode(StartGame, &.{ 11, 0x03, 0x05, 0xaa, 0xbb }, test_limits);
    try testing.expectEqual(@as(i64, -2), start.unique_id);
    try testing.expectEqual(@as(u64, 5), start.runtime_id);
    try testing.expectError(error.EndOfStream, decode(StartGame, &.{ 11, 0x02 }, test_limits));
    try testing.expectError(error.VarIntOverflow, decode(StartGame, &.{ 11, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02 }, test_limits));
}

test "writers refuse to overrun their buffer" {
    var small: [3]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, encode(&small, Login{ .protocol_version = 1, .connection_request = "" }));
    try testing.expectError(error.NoSpaceLeft, encode(&small, ServerToClientHandshake{ .token = "toolong" }));
    var storage: [16]u8 = undefined;
    try testing.expectError(error.InvalidValue, encode(&storage, ResourcePackChunkRequest{ .resource_name = "a", .chunk = -1 }));
}

test "varints round-trip their boundaries" {
    var storage: [16]u8 = undefined;
    for ([_]u64{ 0, 1, 127, 128, 16383, 16384, std.math.maxInt(u32), std.math.maxInt(u64) }) |value| {
        var writer: Writer = .init(&storage);
        try writer.varU64(value);
        var reader: Reader = .init(writer.written(), 0);
        try testing.expectEqual(value, try reader.varU64());
        try reader.finish();
    }
    for ([_]i64{ 0, -1, 1, std.math.minInt(i64), std.math.maxInt(i64) }) |value| {
        var writer: Writer = .init(&storage);
        try writer.varI64(value);
        var reader: Reader = .init(writer.written(), 0);
        try testing.expectEqual(value, try reader.varI64());
    }
}

test "decoders survive arbitrary bytes" {
    var prng = std.Random.DefaultPrng.init(0xc0de);
    const random = prng.random();
    var input: [48]u8 = undefined;
    for (0..20_000) |_| {
        const len = random.uintAtMost(usize, input.len);
        random.bytes(input[0..len]);
        inline for (.{ Login, PlayStatus, ServerToClientHandshake, ClientToServerHandshake, ResourcePackClientResponse, SetLocalPlayerAsInitialised, StartGame, RequestNetworkSettings, NetworkSettings, ResourcePackDataInfo, ResourcePackChunkData, ResourcePackChunkRequest }) |T| {
            if (len != 0) input[0] = @intCast(T.kind.id() & 0x7f);
            if (T.kind.id() >= 0x80 and len > 1) {
                input[0] |= 0x80;
                input[1] = @intCast(T.kind.id() >> 7);
            }
            _ = decode(T, input[0..len], test_limits) catch {};
        }
    }
}

test "the two byte header read agrees with the varint reader" {
    for (0..256) |low| for (0..256) |high| for (1..4) |len| {
        const bytes = [_]u8{ @intCast(low), @intCast(high), 1 };
        const expected: ?Header = if (parse(bytes[0..len])) |envelope| envelope.header else |_| null;
        try std.testing.expectEqual(expected, Header.read(bytes[0..len]));
    };
    try std.testing.expectEqual(@as(?Header, null), Header.read(&.{}));
}
