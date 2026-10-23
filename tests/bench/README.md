# Session baseline

For optional codec comparisons, pool contention and Tracy evaluation, see
[CANDIDATES.md](CANDIDATES.md).
For the resulting backend and Snappy trials, see [LIBDEFLATE.md](LIBDEFLATE.md)
and [SNAPPY.md](SNAPPY.md).

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

## 0.3.0 optimization pass

Interleaved before/after runs of this matrix, three each, on the same Windows
x86_64 Ryzen 5 5500 host and ReleaseFast build. "Before" is `3df3883`. Times
are medians in ns/op; raw CSVs are the `windows-x86_64-v030-*` files under
`results/`. The desktop was not idle, so differences under about 10% are noise.

| Case | Before | After | Gain |
| --- | ---: | ---: | ---: |
| Small realistic Snappy + AES round trip | 1,854 | 1,435 | 1.29x |
| Medium realistic Snappy + AES round trip | 99,659 | 74,133 | 1.34x |
| Large realistic Snappy + AES round trip | 346,379 | 176,141 | 1.97x |
| Large noise Snappy + AES round trip | 990,236 | 401,571 | 2.47x |
| Medium realistic DEFLATE encode | 928,030 | 159,540 | 5.82x |
| Medium realistic DEFLATE round trip | 977,360 | 262,265 | 3.73x |
| Medium realistic DEFLATE + AES round trip | 888,081 | 256,384 | 3.46x |
| Large realistic DEFLATE + AES round trip | 2,268,336 | 2,020,349 | 1.12x |

- AES-CTR now uses std's pipelined `ctrSlice` instead of one block at a time,
  and both directions share one key schedule. A pinned digest test proves the
  keystream and MAC bytes are unchanged. `seal`/`open` of 1,392 bytes went from
  about 2,540 to 1,070 ns, managed relay is about 2x faster, and `Session`
  shrank from 1,120 to 848 bytes.
- Pure Zig session encoding defaults to DEFLATE level 1 (`PoolConfig.deflate_level`).
  Output is equal or smaller on every workload here. Level 1 streams decode
  about 18% slower with std's inflater on the medium realistic case, which the
  encode gain outweighs. libdeflate keeps level 3.
- Plaintext frames decompress straight from the caller's buffer. Large Snappy
  decodes are 1.1-1.7x faster; uncompressed frames still take one copy.
- `Packets` shrank from 192 to 80 bytes by keeping only framing bounds.
- Uncompressed and plain Snappy cases moved within noise. Best-of-15 and 25 micro
  benchmarks against `3df3883` showed small-batch plaintext encode/ingest
  within a few ns and medium Snappy encode unchanged.

The RX and TX availability masks now sit on separate cache lines. With
split-direction traffic on one shared pool, `bedwire-pool-bench` medians of two
runs went from 41.6 to 4.9 ns per pair at 4 threads and 56.1 to 6.4 at 8
threads (one slot). Same-direction contention is unchanged, since threads still
share one mask; give each worker its own pool when that matters. The pool grew
from 256 to 512 bytes.

## 0.5.0 pass

Interleaved before/after runs of the matrix, three each, on the same Windows
x86_64 Ryzen 5 5500 host and ReleaseFast build. "Before" is `a6678d0`. Times are
medians in ns/op; raw CSVs are the `windows-x86_64-v050-*` files under
`results/`. The desktop was not idle, so differences under about 10% are noise.

| Case | Before | After | Gain |
| --- | ---: | ---: | ---: |
| Medium noise DEFLATE decode | 89,188 | 871 | 102x |
| Medium noise DEFLATE round trip | 284,437 | 184,817 | 1.54x |
| Medium noise DEFLATE + AES round trip | 302,484 | 208,261 | 1.45x |
| Large noise DEFLATE decode | 1,388,960 | 7,469 | 186x |
| Large noise DEFLATE + AES round trip | 6,678,050 | 5,755,643 | 1.16x |
| Small noise DEFLATE decode | 103 | 55 | 1.87x |

- A marked batch that compression would not shrink now goes out with the `0xff`
  marker. Receivers skip decompression entirely, and noise frames stop growing
  (a large DEFLATE frame went from 262,583 to 262,149 bytes). The compressor is
  given one byte less than the raw batch, so it gives up early, and batches under
  65 bytes skip std's DEFLATE setup. An independent Go reader in
  `tools/interop` decodes these frames.
- Every realistic and compressible case stayed within noise (-7.5% to +6%, with
  one large Snappy round trip outlier whose encode and decode halves did not move).
- The new ordering and startup checks first cost 40-60% on small typed batches,
  because the 832-byte decoded envelope was passed by value for every packet.
  Control packets are now decoded out of line, the per-packet step is inline and
  the codecs sit in their own function. Snappy's compressor is aligned to 64
  bytes, since code placement alone moved small Snappy encodes by 25%.
  Best-of-15 micro benchmarks of four-packet frames against `a6678d0`:
  compressible Snappy encode 170 to 162 ns, typed uncompressed round trip 189
  to 183 ns, and noise uncompressed round trip 173 to 180 ns, the cost of the
  checks themselves.

`zig build bench-scale` covers what the matrix doesn't. Two runs are in
`results/windows-x86_64-v050-scale-run*.txt`; these figures are from the second.

| Group | Mode | Split ns/packet | 64 KiB split | One frame per packet |
| --- | --- | ---: | ---: | ---: |
| 1,024 x 48 B | none | 45 | 57 | 113 |
| 1,024 x 48 B | Snappy + AES | 300 | 273 | 496 |
| 1,024 x 48 B | DEFLATE + AES | 1,109 | 1,137 | 590 |
| 256 x 32 B-6 KiB | none | 190 | 165 | 167 |
| 256 x 32 B-6 KiB | Snappy + AES | 4,529 | 12,070 | 13,547 |
| 64 x 16 KiB | none | 990 | 640 | 608 |
| 64 x 16 KiB | DEFLATE | 420,604 | 365,780 | 301,734 |

- Each row includes server encode and client ingest. Splitting a group of small
  packets into one frame is 2.5x faster than a frame each uncompressed and 1.7x
  with Snappy + AES, and with DEFLATE it sends 32% fewer bytes. The per-packet frames there go uncompressed because they
  are under 65 bytes, which is cheaper but larger.
- Very large uncompressed or DEFLATE frames lose cache locality. Capping
  batches with `Limits.max_outgoing_batch_bytes` near 64 KiB keeps most of the
  split gain for uncompressed traffic. Snappy is the exception: Bedwire only
  skips ahead on misses for inputs of 64 KiB or more, so its large frames are
  about 3x cheaper per byte on this half-noise data.
- 100, 1,000 and 10,000 session pairs on one pool (two RX and two TX slots)
  exchanging one 96-byte Snappy + AES packet each way: 590, 585 and 607 ns per
  packet in the second run (678, 722 and 825 in the first). The pool holds
  1,573,060 bytes, and each `Session` is 912 bytes, 368 of them its cipher
  state. Steady state made no allocator calls.
- Resource pack transfer of a 32 MiB archive from `Delivery` into `Transfer`,
  including SHA-256 and the copy into storage, ran at 1.21-1.53 GB/s. Chunks
  arriving in reverse order inside the window cost 2-12%, since they are read back
  for hashing once the gap fills.

### Small DEFLATE batches

std's DEFLATE encoder costs about 7 µs before it reads a byte, since it clears a
64 KiB hash table and builds dynamic Huffman codes for every call. At level 1,
batches up to 512 bytes now go out as one fixed-Huffman block with greedy
matching instead. Two interleaved matrix runs against the build above, medians
in ns/op, raw CSVs in `results/windows-x86_64-v050-fixed-*`:

| Small batch | Encode before | Encode after | Round trip before | Round trip after | Frame bytes |
| --- | ---: | ---: | ---: | ---: | --- |
| Realistic | 10,393 | 558 | 14,518 | 2,236 | 143 to 170 |
| Realistic + AES | 11,507 | 785 | 15,400 | 2,731 | 151 to 178 |
| Compressible | 6,305 | 190 | 6,623 | 380 | 11, unchanged |
| Noise | 18,270 | 507 | 18,284 | 575 | 260, uncompressed |

Fixed blocks decode faster too (4,140 to 1,680 ns for the realistic batch).
The cost is ratio: the realistic batch grew 19%, and on generated MovePlayer
batches the gap is 6% at 105 bytes and 29% at 525. Medium and large batches
still use std's encoder and did not move. Levels 2 to 9 keep std's encoder for
every batch.

Two smaller changes measured with best-of-15 micro benchmarks:
`ingestBorrowed` reads a 16 KiB uncompressed plaintext batch in 396 ns instead
of 595 (116 instead of 122 for 262 bytes), and decrypting straight into the
pool cut a 16 KiB encrypted ingest from 11,790 to 11,590 ns.
