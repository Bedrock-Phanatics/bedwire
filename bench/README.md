# Session baseline

For optional codec comparisons, pool contention and Tracy evaluation, see
[CANDIDATES.md](CANDIDATES.md).

Build with Zig 0.17.0, then run the executable separately from the compiler:

```sh
zig build bench-baseline-build
./zig-out/bin/bedwire-baseline > baseline.csv
```

On Windows, use `zig-out/bin/bedwire-baseline.exe`. `zig build bench-baseline`
also runs the matrix. Both always use ReleaseFast for Bedwire and protocol-zig.
The older `bench` and `bench-build` steps remain available.

The matrix has 135 cases: three sizes, three contents, five compression/crypto
settings, and encode, decode, or round trip. An operation processes one complete
Bedrock batch. Decode includes frame admission and packet iteration; round trip
includes both encode and that decode path. Typed packet decoding is outside the
timed path. All cases use the same bounded session API and pool, without network
I/O. Compression is negotiated with threshold zero to isolate each codec.

Sizes target 256 B, 16 KiB, and 256 KiB of packet bytes. Contents are:

- Compressible: zero-filled opaque packets with valid packet headers.
- Noise: seeded pseudorandom opaque packets with valid packet headers.
- Realistic: generated typed MovePlayer packets for small/medium batches,
  and a typed LevelChunk containing modeled palette/run data with 25% random
  bytes for large batches. These are reproducible models, not captured traffic;
  the chunk body is an entropy model, not a validated serialized world chunk.

Medium synthetic batches contain 16 packets. Actual packet/frame lengths and
packet counts are recorded, since typed packets can exceed the target slightly.
Every case verifies a byte-for-byte session round trip before measurement.
The existing counting allocator tracks allocation, resize and remap calls; the
runner fails on steady-state allocator calls or unreleased leases.
CSV `allocations_per_op=0` represents that checked pool allocator contract,
not OS-level allocation profiling. Harness allocations are outside timing.

Each case records 1,024 individual-operation wall-clock latency samples, then
seven groups targeting roughly 20 ms each for throughput. Individual samples
include timer overhead and have the platform clock's resolution; submicrosecond
percentiles should be interpreted accordingly. Throughput timing amortizes that
overhead. Percentiles use nearest rank. CPU time is thread CPU time summed over
the throughput groups; Windows accounting is coarse, so CPU ns/op is approximate.
CPU time, ns/op and throughput exclude setup, validation, allocation, frame
preparation, sorting, and reporting. Decode replays sequential prebuilt frames,
with directional AES state restored once per group traversal; that restoration
is included in throughput timing and excluded from individual latency timing.
Prepared frame storage is capped at 16 MiB and freed after each case.

`MB_per_s` uses decimal MB and counts original packet bytes once per operation,
including round trips. `compressed_over_raw` divides codec output bytes by raw
batch bytes (including packet length prefixes), excluding the frame header,
compression marker and eight-byte encryption trailer. Smaller ratios are better.
No compression therefore reports 1.0. The CSV records throughput operation counts.

Pool rows exercise acquisition and release of all configured RX/TX slots for
1, 2, 4, 16 and 64 slots per direction. The time is per RX+TX acquire/release
pair. Allocated bytes include slot descriptors and scratch; backing bytes do not.
This measures single-thread slot scanning and memory sizing, not contention,
false sharing or resident memory. The main matrix uses two RX and one TX slot,
1 MiB frame limits and 4 MiB batch limits. Pool storage is not zeroed per operation.
The 64-slot sizing case reserves approximately 640 MiB of backing storage;
it is released before the process exits.

## Recorded baseline

Results under `results/` are from the unmodified production implementation at
`5ab4918`, using Zig 0.17.0, ReleaseFast, Windows x86_64, AMD Ryzen 5 5500.
Windows reports version 10.0.26200.0. The recorded executable SHA-256 is
`3d4c9b76040a656ba662adeece574d8770d5c49ac2b5f7da1722f67c6066dd74`.
They contain three sequential process runs on this machine. They do not establish
Linux/ARM performance, production tail latency, or performance under contention.
Backend comparisons must reuse this workload, build mode, limits and host, and
include repeat runs and interoperability checks before a dependency is retained.

All three runs completed all 135 cases and five pool configurations. All 405
case rows reported zero steady-state allocator calls. Selected generated-packet
results follow; times are medians of three runs in ns/op, with the observed
round-trip range shown separately. Raw CSVs contain throughput, CPU time and
individual-operation p50/p95/p99 for every content, including noise and zeros.

| Size | Mode | Encode ns/op | Decode ns/op | Round trip ns/op | Round trip range | Compressed/raw |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Small | None | 145 | 241 | 366 | 360–488 | 1.000000 |
| Small | Snappy | 376 | 426 | 858 | 792–1,073 | 0.789286 |
| Small | DEFLATE | 12,434 | 3,904 | 15,593 | 15,591–18,517 | 0.500000 |
| Small | Snappy + AES | 920 | 938 | 1,861 | 1,814–2,186 | 0.789286 |
| Small | DEFLATE + AES | 11,986 | 4,255 | 17,301 | 15,896–20,814 | 0.500000 |
| Medium | None | 9,485 | 14,269 | 35,594 | 19,308–40,795 | 1.000000 |
| Medium | Snappy | 46,442 | 37,236 | 72,925 | 51,496–117,465 | 0.722822 |
| Medium | DEFLATE | 1,226,364 | 75,948 | 897,891 | 890,138–1,013,420 | 0.339775 |
| Medium | Snappy + AES | 46,704 | 52,964 | 108,759 | 93,575–160,872 | 0.722822 |
| Medium | DEFLATE + AES | 991,851 | 88,201 | 963,775 | 909,402–983,861 | 0.339775 |
| Large | None | 5,374 | 8,359 | 10,674 | 10,590–14,150 | 1.000000 |
| Large | Snappy | 350,830 | 40,558 | 340,087 | 340,025–610,138 | 0.286478 |
| Large | DEFLATE | 2,454,933 | 441,943 | 3,019,421 | 1,980,471–3,072,802 | 0.264274 |
| Large | Snappy + AES | 666,501 | 191,640 | 876,958 | 617,125–912,473 | 0.286478 |
| Large | DEFLATE + AES | 3,051,674 | 635,213 | 3,157,306 | 2,158,522–3,460,957 | 0.264274 |

Desktop scheduling/load produced substantial variation in some cases. Phase
medians are measured independently and should not be added together. These
results identify DEFLATE encoding as worth investigating, but do not justify
retaining a dependency. Subsequent comparisons should interleave backends under
the same host conditions and demonstrate repeatable improvements beyond noise.

Verification for this benchmark infrastructure: fresh execution of 30 Debug
unit tests and 209 ReleaseSafe integration/adversarial tests passed, including
allocator failure cleanup, steady-state allocation checks, concurrency, JWT,
session state, resource-pack state, decompression bounds and interoperability
fixtures. The pinned Go S2 interoperability checker also passed without fixture
changes. The benchmark itself verifies every case and pool lease completion.
No production implementation or backend has changed in this phase. Reference
codec comparisons, optional Tracy evaluation, contention profiling, and
Linux/ARM measurements remain for subsequent phases.
