const std = @import("std");
const protocol = @import("bedrock_protocol");
pub const unframed = protocol.batch.unframed;

/// Validates the entire batch before consumers can act on any borrowed packet.
pub fn validate(payload: []const u8, limits: protocol.DecodeLimits) !void {
    var iterator = try protocol.batch.Iterator.init(payload, limits);
    while (try iterator.next()) |packet| {
        _ = try protocol.packet.decode(packet, limits);
    }
}

/// Destination is unchanged on failure. Input packets must not alias destination.
pub fn encode(packets: []const []const u8, dest: []u8, limits: protocol.DecodeLimits) ![]u8 {
    if (packets.len > limits.max_packets_per_batch) return error.LimitExceeded;
    var size: usize = 0;
    for (packets) |packet| {
        _ = try protocol.packet.decode(packet, limits);
        if (packet.len > std.math.maxInt(u32)) return error.LimitExceeded;
        var prefix: [5]u8 = undefined;
        var writer = protocol.Writer.init(&prefix);
        try writer.writeVarU32(@intCast(packet.len));
        size = try std.math.add(usize, size, try std.math.add(usize, writer.cursor, packet.len));
    }
    if (size > limits.max_decompressed_batch_bytes) return error.LimitExceeded;
    if (size > dest.len) return error.NoSpaceLeft;

    var writer = protocol.Writer.init(dest);
    for (packets) |packet| try protocol.batch.writePacket(&writer, packet, limits);
    return dest[0..writer.cursor];
}
