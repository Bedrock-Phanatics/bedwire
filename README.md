# Bedwire

Minecraft Bedrock session networking for Zig 0.17.0.

Bedwire sits between a transport such as RakNet or NetherNet and [protocol-zig](https://github.com/Bedrock-Phanatics/protocol-zig). It handles Bedrock batch framing, compression, encryption, login authentication and session state. The application owns network I/O, transport reliability and backpressure, and trusted-key retrieval.

- Client and server sessions with configurable protocol profiles and resource limits
- Snappy and DEFLATE compression, with optional libdeflate
- AES session encryption and JWT-based login verification
- Reusable buffer pools and borrowed packet data
- RakNet and NetherNet transport adapters
- Proxy observation, session relay and resource-pack utilities

## Installation

Pin a commit in `build.zig.zon` and use the hash reported by Zig:

```zig
.dependencies = .{
    .bedwire = .{
        .url = "https://github.com/Bedrock-Phanatics/bedwire/archive/<commit>.tar.gz",
        .hash = "<hash>",
    },
},
```

Add the module in `build.zig`:

```zig
const bedwire = b.dependency("bedwire", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("bedwire", bedwire.module("bedwire"));
```

Bedwire uses pure Zig compression by default. Pass `.libdeflate = true` in the dependency options to enable the statically linked libdeflate backend, which requires libc.

## Sessions

Create a shared pool and one session per connection:

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
```

For each complete Bedrock frame received from the transport:

```zig
var packets = try session.ingest(incoming_frame);
defer packets.deinit();

while (packets.next()) |packet| {
    std.log.info("packet {d}: {d} bytes", .{ packet.id, packet.bytes.len });
    // Call session.decodePacket(packet) when typed fields are needed.
}
```

If the frame stays alive and unchanged until the iterator is released, `session.ingestBorrowed(frame)` reads uncompressed plaintext batches in place instead of copying them into the pool. The RakNet and NetherNet adapters use it.

To send an already encoded Bedrock packet:

```zig
const frame = try session.encodeOne(encoded_packet);
defer frame.release();

carrier.send(frame.bytes) catch |err| {
    session.close();
    return err;
};
```

A group that may not fit one batch can be split across frames in order. Every packet is checked before the first frame, and each frame is sized to fit even if it doesn't compress:

```zig
var batches = try session.encodeBatches(encoded_packets);
while (try batches.next()) |frame| {
    defer frame.release();
    carrier.send(frame.bytes) catch |err| {
        session.close();
        return err;
    };
}
```

The RakNet and NetherNet adapters' `send` split this way on their own and close the session if a group fails after its first frame.

`Limits.max_outgoing_batch_bytes` and `Limits.max_outgoing_packets_per_batch` cap what this side sends without loosening what it accepts. Batches that compression would not shrink go out uncompressed.

Sessions enforce their protocol's handshake and packet-state transitions. One-time steps such as Login, either handshake packet and StartGame are refused if repeated, pack downloads must follow the offer, and a client key can be authenticated once and never replaced. Install server encryption only after the cleartext ServerToClientHandshake frame is sent and released. Errors from `ingest` other than `PoolExhausted` close the session, while a failed `encode` leaves it unchanged. Keep each session at a stable address and serialize operations on it. Pools can be shared across workers, but release every packet iterator and outgoing frame before destroying its session; destroy the pool after all sessions are gone. Borrowed packet bytes expire when the iterator is released, and outgoing bytes expire when the frame is released. Size `Limits` and pool slot counts for your workload.

## Startup

`session.startup` records what the startup packets established, whichever side sent them:

- the client's acknowledgment of the final resource pack stack
- StartGame's runtime ID
- PlayStatus PlayerSpawn, which may arrive before StartGame
- the first SetLocalPlayerAsInitialised, which must name that runtime ID and follow the spawn

`advance()` refuses `.waiting_for_start_game` while an offered stack is unacknowledged, `.spawn_ready` before StartGame, and `.in_game` before the initialization ack. Call `session.settle()` after each batch to take every transition already allowed, or keep calling `advance()` yourself. A server that never offers packs, such as a packless relay, can advance straight to `.waiting_for_start_game`. Bedwire checks protocol readiness only. Loading the world and attaching the player stay with the application.

## Proxy support

`Tap` observes the unencrypted handshake without modifying forwarded frames. Use `PoolConfig.observer()` for an observation-only pool. Once the handshake establishes encryption, the tap becomes opaque; forwarding encrypted traffic remains the application's responsibility. On transports without Bedrock encryption, such as NetherNet, it moves to `established` after the login and keeps reading the traffic.

For terminating proxies, `Session.relayTo()` can relay between compatible in-game sessions. Bedwire also supports authenticated connection-request generation and backend login forwarding. Proxy-issued identities must be trusted explicitly by the backend; they are not Microsoft-authenticated identities.

## Resource packs

`resource_packs.Transfer` downloads a pack into caller-owned storage. Keep up to `window` chunk requests in flight with `nextRequest()` and pass each ResourcePackChunkData to `accept()`:

```zig
var transfer = try bedwire.resource_packs.Transfer.init(allocator, .fromDataInfo(info), limits, .{ .window = 8 });
defer transfer.deinit();
while (transfer.nextRequest()) |request| try sendChunkRequest(request);
// for each chunk that arrives:
_ = try transfer.accept(.fromPacket(chunk_data), storage);
```

Chunks may arrive in any order inside the window. Repeats are reported and ignored, and anything unsolicited or malformed fails the transfer. The archive is hashed as its prefix fills in and checked against the ResourcePackDataInfo SHA-256 when it completes. `Delivery` serves a pack from a caller source and sends each chunk at most once. Storage and sources are any type with `writeAt` and `readAt`, and `Memory` and `Archive` cover buffers already in memory, so Bedwire itself does no file or network I/O. `Negotiation` tracks the offer, cached packs, required packs and completion.

## Authentication

Login verification supports Microsoft OIDC/JWKS or legacy certificate chains, according to the selected protocol profile. For OIDC, parse a trusted JWKS with `bedwire.auth.KeySet.parse()` and supply it through `bedwire.TrustPolicy` to `session.authenticateLoginPacket()` or `tap.authenticateLoginPacket()` while the login packet's iterator is alive.

ClientData is verified with the identity key and its client-controlled claims are checked before an identity is returned. Absent claims are allowed, but present ones must have the right type and size, and every skin, cape and animation frame must decode to exactly width × height × 4 bytes. Proxies can run the same check on relayed metadata with `bedwire.auth.client_data.validate()`.

The application fetches and refreshes trusted keys. Authentication returns an owned `Identity` that must be released with `identity.deinit()`. Do not treat offline or proxy-issued identities as Microsoft-authenticated.

## Compression

Sessions support Snappy and raw DEFLATE. The default pure Zig DEFLATE encoder uses level 1; set `PoolConfig.deflate_level` to a value from 1 to 9 to configure it. At level 1, batches up to 512 bytes are written as one fixed-Huffman block instead of going through std's encoder, which is 20 to 50 times cheaper for them but can be up to a third larger. Levels 2 to 9 always use std's encoder. The optional libdeflate backend uses reusable level-3 contexts allocated with the pool. It can improve compression throughput at the cost of additional memory per slot, and is not necessarily faster for every workload.

## Testing and benchmarks

```sh
zig build test
zig build test -Doptimize=ReleaseSafe
python tools/interop/check.py
zig build bench-baseline
zig build bench-scale
```

The interoperability checker requires Python 3 and Go 1.25+. Besides the Snappy fixtures, an independent Go reader decrypts, decompresses and splits a stream of Bedwire's frames and compares every packet. `bench-scale` measures split packet groups, thousands of sessions on one pool, and resource pack transfers. To build the benchmark without running it, use `zig build bench-baseline-build`; the executable is `zig-out/bin/bedwire-baseline` (or `.exe` on Windows). Add `-Dlibdeflate=true` to test the optional backend.

Recorded measurements, methodology, workload limits and raw results are in:

- [Session benchmarks](tests/bench/README.md)
- [libdeflate comparison](tests/bench/LIBDEFLATE.md)
- [Snappy optimization](tests/bench/SNAPPY.md)

Benchmarks measure isolated synthetic session workloads, not network I/O or production latency. Allocation figures refer to the benchmark's tracked steady-state pool allocations, not all operating-system allocations.

## License

See [LICENSE](LICENSE).
