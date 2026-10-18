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

To send an already encoded Bedrock packet:

```zig
const frame = try session.encodeOne(encoded_packet);
defer frame.release();

carrier.send(frame.bytes) catch |err| {
    session.close();
    return err;
};
```

Sessions enforce their protocol's handshake and packet-state transitions. Keep each session at a stable address and serialize operations on it. Pools can be shared across workers, but release every packet iterator and outgoing frame before destroying its session; destroy the pool after all sessions are gone. Borrowed packet bytes expire when the iterator is released, and outgoing bytes expire when the frame is released. Size `Limits` and pool slot counts for your workload.

## Proxy support

`Tap` observes the unencrypted handshake without modifying forwarded frames. Use `PoolConfig.observer()` for an observation-only pool. Once the handshake establishes encryption, the tap becomes opaque; forwarding encrypted traffic remains the application's responsibility.

For terminating proxies, `Session.relayTo()` can relay between compatible in-game sessions. Bedwire also supports authenticated connection-request generation and backend login forwarding. Proxy-issued identities must be trusted explicitly by the backend; they are not Microsoft-authenticated identities.

## Authentication

Login verification supports Microsoft OIDC/JWKS or legacy certificate chains, according to the selected protocol profile. For OIDC, parse a trusted JWKS with `bedwire.auth.KeySet.parse()` and supply it through `bedwire.TrustPolicy` to `session.authenticateLoginPacket()` or `tap.authenticateLoginPacket()` while the login packet's iterator is alive.

The application fetches and refreshes trusted keys. Authentication returns an owned `Identity` that must be released with `identity.deinit()`. Do not treat offline or proxy-issued identities as Microsoft-authenticated.

## Compression

Sessions support Snappy and raw DEFLATE. The default pure Zig DEFLATE encoder uses level 1; set `PoolConfig.deflate_level` to a value from 1 to 9 to configure it. The optional libdeflate backend uses reusable level-3 contexts allocated with the pool. It can improve compression throughput at the cost of additional memory per slot, and is not necessarily faster for every workload.

## Testing and benchmarks

```sh
zig build test
zig build test -Doptimize=ReleaseSafe
python tools/interop/check.py
zig build bench-baseline
```

The interoperability checker requires Python 3 and Go 1.25+. To build the benchmark without running it, use `zig build bench-baseline-build`; the executable is `zig-out/bin/bedwire-baseline` (or `.exe` on Windows). Add `-Dlibdeflate=true` to test the optional backend.

Recorded measurements, methodology, workload limits and raw results are in:

- [Session benchmarks](tests/bench/README.md)
- [libdeflate comparison](tests/bench/LIBDEFLATE.md)
- [Snappy optimization](tests/bench/SNAPPY.md)

Benchmarks measure isolated synthetic session workloads, not network I/O or production latency. Allocation figures refer to the benchmark's tracked steady-state pool allocations, not all operating-system allocations.

## License

See [LICENSE](LICENSE).
