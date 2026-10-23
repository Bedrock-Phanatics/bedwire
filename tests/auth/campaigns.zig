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
            owned.deinit();
        } else |_| {}
        if (bedwire.auth.wire.decodeConnectionRequest(bytes, limits)) |decoded| {
            try testing.expect(decoded.chain_data.len > 0);
            try testing.expect(decoded.client_data.len > 0);
            try testing.expectEqual(bytes.len, 8 + decoded.chain_data.len + decoded.client_data.len);
        } else |_| {}
        _ = bedwire.auth.chain.verifyChain(testing.allocator, bytes, token, .{ .now = 100 }, limits) catch {};
    }
}

test "mutated ClientData claims are either valid or refused, never mishandled" {
    const base = "{\"DeviceOS\":7,\"ThirdPartyName\":\"Steve\",\"SkinData\":\"AAAAAAAAAAA=\",\"SkinImageWidth\":2,\"SkinImageHeight\":1," ++
        "\"CapeData\":\"\",\"CapeImageWidth\":0,\"CapeImageHeight\":0,\"AnimatedImageData\":[{\"Image\":\"AAAAAA==\",\"ImageWidth\":1,\"ImageHeight\":1,\"Type\":1}]," ++
        "\"PlayFabId\":\"5eb65e0f\",\"SelfSignedId\":\"b1b01c3d-6df3-3635-b286-9a2cfbcf76be\",\"PersonaPieces\":[],\"PremiumSkin\":false}";
    const cases = @max(256, @import("build_options").fuzz_iterations / 10);
    var prng = std.Random.DefaultPrng.init(0xc1d7);
    const random = prng.random();
    const alphabet = "{}[]\":,0123456789-=AZaz.";

    var accepted: usize = 0;
    for (0..cases) |_| {
        var json: [base.len]u8 = base.*;
        for (0..random.intRangeAtMost(usize, 1, 4)) |_| json[random.uintLessThan(usize, json.len)] = alphabet[random.uintLessThan(usize, alphabet.len)];
        const parsed = std.json.parseFromSlice(std.json.Value, testing.allocator, &json, .{}) catch continue;
        defer parsed.deinit();
        if (bedwire.auth.client_data.validate(parsed.value, support.limits)) |_| {
            accepted += 1;
        } else |err| try testing.expectEqual(error.InvalidClientData, err);
    }
    try testing.expect(accepted > 0);
}
