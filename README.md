# network-zig

Bedrock networking for Zig 0.16.0.

It handles the layer between packet serialization (`zig-protocol`) and underlying transports (`raknet-zig` or `nethernet-zig`): batch framing, compression, session encryption, authentication, and state tracking.

## Features

- Bounded batch framing (`0xFE` prefix and VarInt lengths)
- Raw DEFLATE and Snappy compression
- P-384 ECDH key exchange and continuous AES-256-CTR session crypto
- Mojang chain and OIDC JWT authentication
- Connection state enforcement from handshake to in-game
- Resource pack negotiation and streaming chunk verification
- Zero heap allocations during steady-state packet processing

## Requirements

- Zig 0.16.0
- `bedrock_protocol`

## Usage

`Connection` wraps any reliable, ordered carrier:

```zig
const std = @import("std");
const network = @import("network");

// carrier requires receive() ![]const u8, send([]const u8) !void, close() void
var carrier: MyCarrier = ...;

var conn = try network.Connection(MyCarrier).init(
    allocator,
    &carrier,
    .server,
    .{},
);
defer conn.deinit();

// receive packets from a batch
var packets = try conn.receive();
while (try packets.next()) |packet| {
    // packet slices are borrowed from internal buffers
    _ = packet;
}

// Send packets batched and framed
try conn.send(&.{packet_one, packet_two});
```

For NetherNet connections, an adapter is included:

```zig
var carrier = network.carrier.NetherNet(nethernet.Connection){
    .connection = &nethernet_conn,
};
var conn = try network.Connection(@TypeOf(carrier)).init(allocator, &carrier, .server, .{});
```

## Session lifecycle

`Connection` tracks protocol progression and rejects out-of-order packets:

1. **Handshake**: client requests network settings, server responds. Call `enableCompression(algorithm, threshold)` once negotiated.
2. **Authentication**: receive login packet and verify identity with `authenticateLegacy` (Mojang chain) or `authenticateOidc`.
3. **Crypto**: server generates handshake JWT and derives session key with `installServerCrypto`. Client verifies with `acceptServerHandshake`.
4. **Resource packs**: call `advance(.resource_packs)` to negotiate packs and stream chunks.
5. **In-game**: advance through `.waiting_for_start_game`, `.spawn_ready`, and `.in_game`.

## Memory and limits

All core buffers (ingress, outgoing, batch scratch, and compression workspaces) are allocated once during `Connection.init`. Steady-state send and receive operations make no allocator calls.

Packet slices returned by `receive()` borrow memory from the internal ingress buffer and expire on the next `receive()` call.

Limits can be configured with `DecodeLimits`:

```zig
var limits: network.DecodeLimits = .{};
limits.protocol.max_batch_bytes = 1024 * 1024;
limits.protocol.max_decompressed_batch_bytes = 4 * 1024 * 1024;
limits.max_chain_length = 4;
```

## Commands

```sh
zig build test
zig build test -Doptimize=ReleaseSafe
```
