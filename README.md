# Bedwire

A high-performance Minecraft Bedrock session networking library for Zig 0.17.0.

Bedwire provides batch framing, compression, encryption, login authentication and session management. It works independently of the underlying transport, including RakNet and NetherNet, and integrates with [protocol-zig](https://github.com/Bedrock-Phanatics/protocol-zig).

- Transport-independent session handling
- Snappy and DEFLATE compression
- AES encryption and JWT authentication
- Pooled buffers with allocation-free steady-state processing
- Thread-safe buffer pooling and worker-owned sessions
- Configurable resource limits and protocol profiles
- Proxy support through passive packet observation and authenticated login forwarding

## Installation

Add Bedwire to `build.zig.zon` using a pinned commit:

```zig
.dependencies = .{
    .bedwire = .{
        .url = "https://github.com/Bedrock-Phanatics/bedwire/archive/<commit>.tar.gz",
        .hash = "<hash>",
    },
},
```

Import the module in `build.zig`:

```zig
const bedwire = b.dependency("bedwire", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("bedwire", bedwire.module("bedwire"));
```

Bedwire uses pure Zig compression by default. To enable the optional libdeflate backend, add `.libdeflate = true` to the dependency arguments.

## Usage

Create a shared buffer pool and a session for each connection.

```zig
const std = @import("std");
const bedwire = @import("bedwire");

var pool = try bedwire.BufferPool.init(
    allocator,
    .{},
    bedwire.PoolConfig.conservative(),
);
defer pool.deinit();

var session = try bedwire.Session.init(.server, .{
    .pool = &pool,
});
defer session.deinit();

// Receive a complete Bedrock batch
var packets = try session.ingest(incoming_frame);
defer packets.deinit();

while (packets.next()) |packet| {
    std.log.info("packet {d}: {d} bytes", .{
        packet.id,
        packet.bytes.len,
    });
}

// Encode and send a packet
const frame = try session.encodeOne(outgoing_packet);
defer frame.release();

carrier.send(frame.bytes) catch |err| {
    session.close();
    return err;
};
```

The application handles network I/O, transport ordering and backpressure. Bedwire manages framing, compression, encryption and session state.

Sessions are owned by a single thread but may share a buffer pool across workers. Packet data remains valid until `packets.deinit()`, and encoded frames remain valid until `frame.release()`.

A session permits one outstanding packet iterator and one outgoing frame. Release both before destroying the session, and destroy the pool after all sessions.

## Proxy support

`Tap` allows a proxy to inspect cleartext Bedrock traffic without changing the forwarded data.

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
        std.log.info("packet {d}", .{packet.id});
    }
}

try carrier.forward(original_payload);
```

Once encryption is established, the tap stops decoding traffic. Encrypted packets continue through the proxy unchanged.

For terminating proxies, Bedwire also supports authenticated connection request generation and backend login forwarding. Proxy-issued identities require an explicitly trusted backend key and are not represented as Microsoft-authenticated identities.

## Authentication

Bedwire supports Microsoft OIDC/JWKS verification and legacy certificate-chain authentication, depending on the selected protocol profile.

```zig
var keys = try bedwire.auth.KeySet.parse(
    allocator,
    jwks_json,
    .{},
);
defer keys.deinit();

const trust: bedwire.TrustPolicy = .{
    .oidc = .{
        .now = now_unix_seconds,
        .keys = &keys,
    },
};
```

Verify Login packets using `session.authenticateLoginPacket()` or `tap.authenticateLoginPacket()` while their packet iterator is active.

The application is responsible for fetching and caching Microsoft's trusted keys. Authentication results own their allocated data and must be released with `identity.deinit()`.

## Compression

Bedwire supports Snappy and raw DEFLATE, including an optional [libdeflate](https://github.com/ebiggers/libdeflate) 1.26 backend.

| Backend | Default level | Dependencies |
|---|---:|---|
| Pure Zig DEFLATE | 1 | None |
| libdeflate | 3 | Bundled C sources |
| Snappy | — | None |

Compression levels can be configured through `PoolConfig.deflate_level` (1–9).

The libdeflate backend is compiled statically and does not require a system installation. It requires libc support and allocates approximately 668 KB per transmit slot and 12 KB per receive slot for reusable compression state.

The pure Zig backend remains the default for lower memory overhead.

## Benchmarks

Performance measurements were recorded using Zig 0.17.0 in ReleaseFast mode on an AMD Ryzen 5 5500, running Windows x86_64.

### Session performance

The following results compare the implementation before and after the 0.3.0 optimization pass.

Median round-trip execution time, including session processing, compression, encryption where applicable, and packet iteration. Lower is better.

| Workload | Before | Bedwire 0.3.0 | Speedup |
|---|---:|---:|---:|
| Small Snappy + AES | 1.85 µs | **1.44 µs** | **1.29x** |
| Medium Snappy + AES | 99.66 µs | **74.13 µs** | **1.34x** |
| Large Snappy + AES | 346.38 µs | **176.14 µs** | **1.97x** |
| Large noise Snappy + AES | 990.24 µs | **401.57 µs** | **2.47x** |
| Medium DEFLATE | 977.36 µs | **262.27 µs** | **3.73x** |
| Medium DEFLATE + AES | 888.08 µs | **256.38 µs** | **3.46x** |

These gains come from improvements to AES processing, compression defaults, buffer handling and session structures.

In particular, AES processing uses pipelined CTR operations with a shared key schedule. A 1,392-byte encryption operation improved from approximately 2.54 µs to 1.07 µs.

### libdeflate comparison

A separate benchmark compares the default pure Zig DEFLATE backend with optional libdeflate using reusable compression contexts.

Median round-trip time. Lower is better.

| Workload | Pure Zig | libdeflate | Speedup |
|---|---:|---:|---:|
| Small DEFLATE | 15.64 µs | **7.42 µs** | **2.11x** |
| Medium DEFLATE | 886.91 µs | **128.92 µs** | **6.88x** |
| Medium DEFLATE + AES | 908.61 µs | **147.37 µs** | **6.17x** |
| Large DEFLATE | 2.04 ms | **0.86 ms** | **2.36x** |
| Large DEFLATE + AES | 2.21 ms | **1.12 ms** | **1.97x** |

These results are from the earlier backend comparison, not the final 0.3.0 benchmark, and should not be compared directly with the preceding table.

libdeflate offers faster compression on the tested realistic batches, at the cost of additional pool memory. Some highly compressible decode-only workloads perform better with pure Zig.

### Buffer pool

The 0.3.0 changes also reduce contention between receive and transmit workers sharing a buffer pool.

| Workers | Before | After | Speedup |
|---|---:|---:|---:|
| 4 threads | 41.6 ns | **4.9 ns** | **8.5x** |
| 8 threads | 56.1 ns | **6.4 ns** | **8.8x** |

These measurements cover split-direction acquisition and release with a single slot per direction. Same-direction contention is unchanged.

Recorded session benchmarks reported **zero steady-state pool allocator calls** after initialization.

The benchmark suite covers small (256 B), medium (16 KiB) and large (256 KiB) batches, with compressible, incompressible and generated Minecraft packet data. Results exclude network I/O and typed packet serialization.

Full methodology, results and reproduction instructions are available in [bench/README.md](bench/README.md), [bench/LIBDEFLATE.md](bench/LIBDEFLATE.md) and [bench/SNAPPY.md](bench/SNAPPY.md).

## Testing

Run the test suite:

```sh
zig build test
zig build test -Doptimize=ReleaseSafe
```

Check interoperability with the reference implementations:

```sh
python tools/interop/check.py
```

The interoperability checker requires Python 3 and Go 1.25+.

To run the session benchmarks:

```sh
zig build bench-baseline-build
./zig-out/bin/bedwire-baseline
```

Use `zig build bench-baseline-build -Dlibdeflate=true` to benchmark the optional backend.

Tests cover session state, encryption, authentication, compression, buffer ownership, resource limits, malformed packets and interoperability.

## License

See [LICENSE](LICENSE).
