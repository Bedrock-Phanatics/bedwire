const std = @import("std");
const zigrock = @import("zigrock");

test "login rejects negative or truncated nested lengths and trailing bytes" {
    var nested: [64]u8 = undefined;
    var request = zigrock.protocol.Writer.init(&nested);
    try request.writeI32(2);
    try request.writeRaw("{}");
    try request.writeI32(3);
    try request.writeRaw("jwt");
    var bytes: [100]u8 = undefined;
    var writer = zigrock.protocol.Writer.init(&bytes);
    try writer.writeI32Be(944);
    try writer.writeByteArray(request.written());
    const decoded = try zigrock.login.Login.decode(writer.written(), .{});
    try std.testing.expectEqualStrings("{}", decoded.identity_json);
    try std.testing.expectEqualStrings("jwt", decoded.client_data);
    for (0..writer.cursor) |end| {
        if (zigrock.login.Login.decode(bytes[0..end], .{})) |_| return error.AcceptedTruncation else |_| {}
    }
    @memset(bytes[5..9], 0xff);
    try std.testing.expectError(error.InvalidLogin, zigrock.login.Login.decode(writer.written(), .{}));
}

test "server handshake uses canonical SPKI and signed salt" {
    const key = try zigrock.spki.Ecdsa.KeyPair.generateDeterministic(@splat(6));
    const encoded = try zigrock.login.serverHandshake(std.testing.allocator, key, @splat(7), .{});
    defer std.testing.allocator.free(encoded);
    var token = try zigrock.jwt.Token.parse(std.testing.allocator, encoded, .{});
    defer token.deinit();
    try token.verify(key.public_key);
    try std.testing.expectEqualStrings("BwcHBwcHBwcHBwcHBwcHBw==", try zigrock.jwt.string(token.payload.value, "salt"));
}
