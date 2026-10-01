# Bedwire

Minecraft Bedrock session networking for Zig 0.16.0. Bedwire sits between a transport such as RakNet or NetherNet and the `bedrock_protocol` packet codec. It handles batch framing, compression, login authentication, encryption, and session state. Your application owns network I/O and trust-key fetching.

## Add Bedwire to a project

In `build.zig.zon`, pin a commit and use the hash Zig reports for that archive:

```zig
.dependencies = .{
    .bedwire = .{
        .url = "https://github.com/Bedrock-Phanatics/bedwire/archive/<commit>.tar.gz",
        .hash = "<hash>",
    },
},
```

In `build.zig`:

```zig
const bedwire = b.dependency("bedwire", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("bedwire", bedwire.module("bedwire"));
```

## Use a session

Create a shared pool, then a session for each connection. `Session` uses the current `bedrock_protocol` profile:

```zig
const std = @import("std");
const bedwire = @import("bedwire");

var pool = try bedwire.BufferPool.init(
    allocator,
    .{},
    bedwire.PoolConfig.conservative(),
);
defer pool.deinit();

var session = try bedwire.Session.init(.server, .{ .pool = &pool });
defer session.deinit();

var packets = try session.ingest(incoming_frame);
defer packets.deinit();

while (packets.next()) |packet| {
    std.log.info("packet {d}: {d} bytes", .{ packet.id, packet.bytes.len });
}

const frame = try session.encodeOne(outgoing_packet);
defer frame.release();
carrier.send(frame.bytes) catch |err| {
    session.close();
    return err;
};
```

`incoming_frame` is a complete Bedrock batch from the transport; `outgoing_packet` is an encoded packet from your selected profile. Send frames in encode order. The transport must consume or copy `frame.bytes` before `send` returns.

Packet bytes are borrowed until `packets.deinit()`; frame bytes are borrowed until `frame.release()`. A session allows one outstanding packet iterator and one outgoing frame. Keep the session and pool at stable addresses, serialize calls on each session, and destroy the pool last.

## Observe a proxied connection

A `Tap` reads both directions without changing the bytes you forward. Call it for each cleartext batch with its actual direction:

```zig
var pool = try bedwire.BufferPool.init(
    allocator,
    .{},
    bedwire.PoolConfig.observer(),
);
defer pool.deinit();

var tap = try bedwire.Tap.init(.{ .pool = &pool });
defer tap.deinit();

if (tap.phase() != .encrypted) {
    var packets = try tap.observe(direction, original_payload);
    defer packets.deinit();

    while (packets.next()) |packet| {
        std.log.info("observed packet {d}", .{packet.id});
    }
}
try carrier.forward(original_payload);
```

Release the iterator before the next `observe`. After the server handshake, `tap.phase()` becomes `.encrypted`; pass later ciphertext through without observing it. To verify an observed Login, call `tap.authenticateLoginPacket(allocator, packet, trust_policy)` while that packet's iterator is active.

## Authenticate a Login

The host fetches and caches Microsoft's JWKS. For an OIDC profile, parse the keys and verify the Login packet while its iterator is active:

```zig
var keys = try bedwire.auth.KeySet.parse(allocator, jwks_json, .{});
defer keys.deinit();

const trust: bedwire.TrustPolicy = .{
    .oidc = .{ .now = now_unix_seconds, .keys = &keys },
};

var packets = try session.ingest(login_frame);
defer packets.deinit();
while (packets.next()) |packet| {
    if (packet.kind != .login) continue;
    var identity = try session.authenticateLoginPacket(allocator, packet, trust);
    defer identity.deinit();
    std.log.info("authenticated {s}", .{identity.display_name});
}
```

For a legacy profile, use `.{ .certificate_chain = .{ .now = now_unix_seconds } }` and set `options.policy.connection_request_format = .legacy_chain`. Use `SessionWithProfile(Profile)` or `TapWithProfile(Profile)` for another `bedrock_protocol` profile; the selected profile defines packet layouts and login flow. The host sends the cleartext server handshake before calling `session.installServerCrypto(...)`.

For a terminating proxy, `bedwire.auth.login.buildProxyConnectionRequest(Profile, allocator, proxy_key, &authenticated_identity, client_data_json, expires_at, .envelope, limits)` returns an owned connection request; free it with the same allocator. `bedwire.auth.login.encodeLoginPacket(Profile, &packet_storage, request, limits)` writes the typed Login packet into caller-owned storage. Use `.legacy_chain` for a backend configured for legacy framing. This builder supports certificate-chain profiles and signs both the identity link and caller-provided JSON client data with the proxy key. The backend must explicitly set `certificate_chain.trusted_issuer_key` to that public key and keep `allow_offline` disabled. The resulting identity is proxy-issued, with `online == false` and no Microsoft XUID; it does not claim Microsoft authentication.

## Limits and checks

`bedwire.Limits` bounds frames, decompressed batches, packets, authentication data, and JSON nesting. Set limits before creating the pool; pool allocation scales with them. Sessions and taps may use lower limits than their pool.

```sh
zig build test
zig build test -Doptimize=ReleaseSafe
python tools/interop/check.py
```

The interoperability check requires Python 3 and Go 1.25+.
