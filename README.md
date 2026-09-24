# bedwire

Minecraft: Bedrock Edition session networking for Zig 0.16.0.
<p align="center">
    Join our <a href="https://discord.gg/Yv9qPRQNc3">Discord</a>!
</p>

`bedwire` bridges transport carriers (such as RakNet or NetherNet) and packet codecs (`bedrock_protocol`). It handles batch framing, compression, ECDH key exchange, continuous AES-256-CTR session encryption, modern OpenID Connect (OIDC / RS256 / JWKS) and legacy Mojang certificate chain (ES384) authentication, and protocol-gated session state enforcement.

## Features

- **Bounded Batch Framing**: `0xFE` prefix with VarInt packet length delimiters and exact consumption validation.
- **Compression**: Raw DEFLATE and Snappy (S2 compatible) compression engines with reuse workspaces.
- **Session Cryptography**: P-384 ECDH key exchange and continuous AES-256-CTR session encryption with native Zig standard library primitives.
- **Modern Bedrock Authentication (Protocols $\ge$ 898 / Minecraft $\ge$ 1.21.130)**:
  - RFC 7517 JWKS catalog parser (`bedwire.auth.KeySet`) for Microsoft's authentication keys.
  - Strict RS256 verification of OpenID Connect ID tokens against trusted RSA-2048 public keys.
  - Ephemeral client public key (`cpk`) claim binding to ES384 `ClientData` tokens.
  - Canonical player `Identity` resolution: `displayName`, `XUID`, and UUIDv3 derivation (`pocket-auth-1-xuid:<xuid>`).
- **Legacy Authentication (Protocols $<$ 898 / Minecraft $<$ 1.21.130)**:
  - 3-link Mojang certificate chain verification against pinned Mojang root public key (`moj_root`).
- **Strict Protocol Gating & Anti-Downgrade**:
  - Wire framing (`legacy_chain` vs `envelope`) is explicit session policy; login flow is supplied by the selected protocol profile.
  - Atomic failure rollback: any verification or decoding error zeroes cryptographic state and resets session to `.disconnected`.
- **Zero-Allocation Steady State**:
  - Fixed-capacity shared `BufferPool` with generational slot recycling and zero heap allocations during steady-state packet I/O.
- **Zero Network I/O**: Pure in-memory cryptographic and protocol engine. The host application retains full ownership over HTTP fetching, caching, and network carriers.

## Requirements

- Zig 0.16.0
- `bedrock_protocol`

## Installation

Add `bedwire` to `build.zig.zon`:

```zig
.dependencies = .{
    .bedwire = .{
        .url = "https://github.com/Bedrock-Phanatics/bedwire/archive/<commit>.tar.gz",
        .hash = "...",
    },
},
```

Add the module dependency in `build.zig`:

```zig
const bedwire = b.dependency("bedwire", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("bedwire", bedwire.module("bedwire"));
```

## Quick Start

### 1. Initialize Buffer Pool and Session

```zig
const std = @import("std");
const bedwire = @import("bedwire");

// Define session limits
const limits = bedwire.Limits{};
try limits.validate();

// Initialize shared buffer pool across sessions
var pool = try bedwire.BufferPool.init(allocator, limits, bedwire.PoolConfig.conservative());
defer pool.deinit();

// Create a session using protocol-zig's current profile
var session = try bedwire.Session.init(
    allocator,
    .server,
    .{ .pool = &pool, .limits = limits },
);
defer session.deinit();
```

For a third-party multiversion profile, use
`bedwire.SessionWithProfile(MyProfile).init(allocator, .server, options)`.
The profile must implement `bedrock_protocol.validateProfile`'s compile-time
contract. Profiles are selected per session type; there is no global registry.
Set `options.policy.connection_request_format = .legacy_chain` for a profile
whose login uses that Bedwire authentication envelope.
For profile-specific adapters, use `bedwire.transport.RakNetWithProfile` or
`bedwire.transport.NetherNetWithProfile` with the same profile type.

### 2. Ingest and Process Packets

```zig
// Ingest incoming raw batch frame (0xfe prefixed wire buffer)
var packets = try session.ingest(batch_bytes);
defer packets.deinit();

while (packets.next()) |packet| {
    // packet.kind: ?bedrock_protocol.PacketKind
    // packet.id: PacketId
    // packet.bytes: []const u8 (borrows from internal pool buffer)
    // session.decodePacket(packet) uses the selected profile's borrowed codec
}
```

### 3. Send Framed Packets

```zig
// Encode packets into an outbound wire frame (compressed and encrypted if enabled)
var frame = try session.encode(&.{ packet_one_bytes, packet_two_bytes });
defer frame.release();

// Send frame.bytes over carrier (e.g. RakNet or NetherNet)
try carrier.send(frame.bytes);
```

Each session permits one outstanding `Frame` and one `Packets` iterator.
Release the frame before another encode (`PoolExhausted`) and deinit the iterator
before another ingest (`InvalidState`). Shared pool exhaustion also returns
`PoolExhausted`; there is no fallback allocation or queue.

Frame and packet bytes survive `Session.close()`. Release/deinit ends the borrow
for all copies; `Session.deinit()` ends any remaining borrows. Keep sessions and
pools at stable addresses, and serialize access to each session.

Send frames in encode order. If sending fails or a frame is abandoned, close the
session. Transport send hooks must consume or copy bytes before returning.
NetherNet `pump` closes after a consumed message fails admission; push-style
callers may retry backpressure if they retain the input.

## Authentication

Bedwire provides `session.authenticateLoginPacket(...)` for a profile-decoded Login packet, or `session.authenticateLogin(...)` for an already extracted connection request. Both enforce the selected login flow, wire format policy, and failure atomicity.

### Modern OIDC Authentication (Protocols $\ge$ 898, e.g. 944)

The host application fetches Microsoft's JWKS catalog (e.g., from `https://authorization.franchise.minecraft-services.net/.well-known/keys`), parses it once into a `KeySet`, and supplies an `OidcPolicy`:

```zig
// 1. Host application parses cached JWKS keys
var key_set = try bedwire.auth.jwks.KeySet.parse(allocator, jwks_json, limits);
defer key_set.deinit();

// 2. Configure OIDC trust policy
const now_unix_seconds: i64 = /* supplied by host */;
const oidc_policy = bedwire.auth.OidcPolicy{
    .now = now_unix_seconds,
    .clock_skew = 60,
    .keys = &key_set,
    // .issuer defaults to "https://authorization.franchise.minecraft-services.net/"
    // .audience defaults to "api://auth-minecraft-services/multiplayer"
};

// 3. Authenticate Login packet connection_request payload
var identity = try session.authenticateLogin(
    allocator,
    connection_request_bytes,
    .{ .oidc = oidc_policy },
);
defer identity.deinit();

std.debug.print("Authenticated player: {s} (UUID: {s}, XUID: {s})\n", .{
    identity.display_name,
    identity.uuid,
    identity.xuid,
});
```

### Legacy Certificate Chain (Protocols $<$ 898)

For older Bedrock versions, configure a `ChainPolicy` to verify Mojang's 3-link certificate chain:

```zig
const now_unix_seconds: i64 = /* supplied by host */;
const chain_policy = bedwire.auth.ChainPolicy{
    .now = now_unix_seconds,
};

var identity = try session.authenticateLogin(
    allocator,
    connection_request_bytes,
    .{ .certificate_chain = chain_policy },
);
defer identity.deinit();
```

### Enabling Session Encryption

Once identity is verified, the server sends the `ServerToClientHandshake` packet in the clear, and then derives the continuous AES-256-CTR encryption keys using the client's public key (stored in `session.peer_key`):

```zig
// 1. Send ServerToClientHandshake packet to client (sent in the clear)
// var frame = try session.encodeOne(server_handshake_packet);
// defer frame.release();
// try carrier.send(frame.bytes);

// 2. Derive shared secrets from session.peer_key.? and enable encryption
try session.installServerCrypto(server_ecdh_key.secret_key, salt);

// On client side:
// try session.acceptServerHandshake(allocator, handshake_jwt, client_ecdh_key.secret_key);
```

## Memory and Limits

Session limits and memory bounds are configured via `bedwire.Limits`:

```zig
var limits: bedwire.Limits = .{};
limits.max_frame_bytes = 4 * 1024 * 1024;
limits.max_batch_bytes = 16 * 1024 * 1024;
limits.max_packet_bytes = 4 * 1024 * 1024;
limits.max_packets_per_batch = 1024;

limits.max_jwt_header_bytes = 8 * 1024;
limits.max_jwt_payload_bytes = 1024 * 1024;
limits.max_jwks_bytes = 64 * 1024;
limits.max_jwks_keys = 16;
limits.max_connection_request_bytes = 2 * 1024 * 1024;
limits.max_identity_bytes = 1024;

try limits.validate();
```

## Testing and Validation

Run the test suite across optimization modes:

```sh
# Debug mode
zig build test

# ReleaseSafe mode
zig build test -Doptimize=ReleaseSafe

# ReleaseFast mode
zig build test -Doptimize=ReleaseFast
```

Verify formatting across sources and tests:

```sh
zig fmt --check build.zig build.zig.zon src tests tools/interop/export.zig
```

### Cross-Language Interoperability

The `tools/interop` suite provides standalone bidirectional verification against Go S2 (pinned via `tools/interop/go.mod`):

1. Cross-decodes Zig Snappy frames using Go S2.
2. Refreshes deterministic test fixtures (`tests/compression/interop.json`) for raw DEFLATE, Snappy, continuous AES-256-CTR, and P-384 ECDH.

Running the interoperability check requires Python 3 and Go 1.25+:

```sh
python tools/interop/check.py
```
