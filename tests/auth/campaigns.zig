const std = @import("std");
const bedwire = @import("bedwire");
const support = @import("../support.zig");
const testing = std.testing;

test "bounded auth input mutations clean up every accepted parse" {
    var prng = std.Random.DefaultPrng.init(0xa0175eed);
    const random = prng.random();
    const limits: bedwire.Limits = .{
        .max_jwt_header_bytes = 256,
        .max_jwt_payload_bytes = 512,
        .max_connection_request_bytes = 1024,
    };
    const key = try support.deterministicKey(1);
    const token = try support.signToken(testing.allocator, key, "{\"alg\":\"ES384\"}", "{\"exp\":200}");
    defer testing.allocator.free(token);
    const request = try support.buildConnectionRequest(testing.allocator, "{\"chain\":[]}", token);
    defer testing.allocator.free(request);
    const envelope = "{\"AuthenticationType\":2,\"Token\":\"abc\"}";
    const sources = [_][]const u8{ token, request, envelope, "{\"chain\":[]}" };
    const cases = @max(128, @import("build_options").fuzz_iterations / 10);

    for (0..cases) |i| {
        const source = sources[i % sources.len];
        var input: [1024]u8 = undefined;
        @memcpy(input[0..source.len], source);
        const len = if (i % 3 == 0) random.uintLessThan(usize, source.len + 1) else source.len;
        if (i % 3 != 0) input[random.uintLessThan(usize, len)] ^= @as(u8, 1) << @intCast(random.uintLessThan(u8, 8));
        const bytes = input[0..len];

        if (bedwire.auth.jwt.Token.parse(testing.allocator, bytes, limits)) |parsed| {
            var owned = parsed;
            _ = owned.verify(key.public_key) catch {};
            owned.deinit();
        } else |_| {}
        if (bedwire.auth.wire.parseChainEnvelope(testing.allocator, bytes, limits)) |parsed| {
            var owned = parsed;
            owned.deinit(testing.allocator);
        } else |_| {}
        if (bedwire.auth.wire.decodeConnectionRequest(bytes, limits)) |decoded| {
            try testing.expect(decoded.chain_data.len > 0);
            try testing.expect(decoded.client_data.len > 0);
            try testing.expectEqual(bytes.len, 8 + decoded.chain_data.len + decoded.client_data.len);
        } else |_| {}
        _ = bedwire.auth.chain.verifyChain(testing.allocator, bytes, token, .{ .now = 100 }, limits) catch {};
    }
}
