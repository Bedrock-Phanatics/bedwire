# bedwire

Minecraft: Bedrock Edition session networking for Zig 0.16.0.
<p align="center">
    Join our <a href="https://discord.gg/Yv9qPRQNc3">Discord</a>!
</p>

`bedwire` bridges transport carriers (such as RakNet or NetherNet) and packet codecs (`bedrock_protocol`). It handles batch framing, compression, ECDH key exchange, AES-256-CTR session encryption, Mojang/OIDC authentication, and session state enforcement.

## Features

- Bounded batch framing (`0xFE` prefix with VarInt packet lengths)
- Raw DEFLATE and Snappy compression
- P-384 ECDH key exchange and continuous AES-256-CTR session encryption
- Mojang certificate chain (ES384 JWT) and Xbox Live / OIDC identity validation
- State machine gating packet types from handshake to in-game
- Resource pack manifest negotiation and chunk transfer verification
- Zero heap allocations during steady-state packet I/O

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

```zig
const std = @import("std");
const bedwire = @import("bedwire");

// 1. Define or adapt a carrier providing receive, send, and close
const Carrier = struct {
    pub fn receive(self: *@This()) ![]const u8 { ... }
    pub fn send(self: *@This(), bytes: []const u8) !void { ... }
    pub fn close(self: *@This()) void { ... }
};

// 2. Initialize a Connection (allocates internal buffers once)
var conn = try bedwire.Connection(Carrier).init(
    allocator,
    &carrier,
    .server,
    .{},
);
defer conn.deinit();

// 3. Receive packets from a batch frame
var batch = try conn.receive();
while (try batch.next()) |packet_bytes| {
    // packet_bytes borrows memory from conn.ingress until the next receive()
    _ = packet_bytes;
}

// 4. Send packets (framed, compressed, and encrypted as state requires)
try conn.send(&.{ packet_one, packet_two });
```

For NetherNet connections, a built-in carrier adapter is provided:

```zig
var carrier = bedwire.carrier.NetherNet(nethernet.Connection){
    .connection = &nethernet_connection,
};
```

## Authentication and Encryption

Once the client sends its settings request and the server replies with `NetworkSettings`, negotiate compression and verify identity:

```zig
// Enable negotiated compression
try conn.enableCompression(.snappy, 512);

// Verify Mojang identity chain
var auth_data = try conn.authenticateLegacy(allocator, chain_json, client_data, policy);
defer auth_data.deinit();

// Derive session keys and enable encryption
try conn.send(&.{server_handshake_packet});
try conn.installServerCrypto(server_key.secret_key, salt);

// Transition state as handshake steps complete
try conn.advance(.resource_packs);
try conn.advance(.waiting_for_start_game);
try conn.advance(.spawn_ready);
try conn.advance(.in_game);
```

For clients connecting to a server:

```zig
try conn.acceptServerHandshake(allocator, handshake_jwt, client_key.secret_key);
```

## Memory and Limits

All core buffers (ingress, outgoing, batch scratch, and compression workspaces) are allocated once in `Connection.init`. Steady-state `send` and `receive` perform no heap allocations. Packet slices returned by `receive` borrow memory from the internal ingress buffer and expire upon the next `receive` call.

Decode bounds are enforced by `DecodeLimits`:

```zig
var limits: bedwire.DecodeLimits = .{};
limits.protocol.max_batch_bytes = 4 * 1024 * 1024;
limits.protocol.max_decompressed_batch_bytes = 16 * 1024 * 1024;
limits.max_jwt_header_bytes = 8 * 1024;
limits.max_jwt_payload_bytes = 1024 * 1024;
limits.max_chain_length = 8;
limits.max_resource_pack_bytes = 512 * 1024 * 1024;
limits.max_resource_packs = 128;
```

## Testing and Validation

Run the test suite in Debug and ReleaseSafe modes:

```sh
zig build test
zig build test -Doptimize=ReleaseSafe
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

