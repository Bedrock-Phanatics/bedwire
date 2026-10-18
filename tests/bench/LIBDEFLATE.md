# Optional libdeflate session backend

Retain libdeflate level 3 as an opt-in backend. Three interleaved Windows runs
show substantial, repeatable improvements on realistic session batches, with
equal or smaller compressed output. Keep pure Zig as the default: native state
costs memory, all-zero decoding is slower, and ARM performance is unmeasured.

## Results

Medians across the three final runs, ns/op. The gain range compares paired
backends within each run; phase medians are independent and should not be added.

| Size | Mode | Phase | Zig | Native | Gain | Paired gain range |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Small | DEFLATE | Encode | 11,494 | 5,220 | 2.20x | 2.19–2.84x |
| Small | DEFLATE | Decode | 3,840 | 1,911 | 2.01x | 1.93–2.44x |
| Small | DEFLATE | Round trip | 15,640 | 7,417 | 2.11x | 1.85–2.22x |
| Small | DEFLATE + AES | Encode | 11,870 | 5,752 | 2.06x | 1.92–2.09x |
| Small | DEFLATE + AES | Decode | 4,171 | 2,211 | 1.89x | 1.86–1.98x |
| Small | DEFLATE + AES | Round trip | 16,259 | 7,892 | 2.06x | 2.01–2.14x |
| Medium | DEFLATE | Encode | 812,219 | 93,230 | 8.71x | 8.06–8.71x |
| Medium | DEFLATE | Decode | 72,741 | 32,866 | 2.21x | 2.01–2.22x |
| Medium | DEFLATE | Round trip | 886,906 | 128,923 | 6.88x | 6.62–6.90x |
| Medium | DEFLATE + AES | Encode | 819,280 | 103,614 | 7.91x | 7.37–7.95x |
| Medium | DEFLATE + AES | Decode | 83,212 | 43,467 | 1.91x | 1.80–1.94x |
| Medium | DEFLATE + AES | Round trip | 908,606 | 147,367 | 6.17x | 6.09–6.18x |
| Large | DEFLATE | Encode | 1,593,544 | 753,708 | 2.11x | 2.10–2.23x |
| Large | DEFLATE | Decode | 364,999 | 123,277 | 2.96x | 2.93–2.98x |
| Large | DEFLATE | Round trip | 2,035,006 | 864,060 | 2.36x | 2.31–2.36x |
| Large | DEFLATE + AES | Encode | 1,802,065 | 869,276 | 2.07x | 1.53–2.15x |
| Large | DEFLATE + AES | Decode | 488,959 | 250,585 | 1.95x | 1.95–1.98x |
| Large | DEFLATE + AES | Round trip | 2,207,471 | 1,118,899 | 1.97x | 1.95–2.00x |

Realistic round-trip throughput, normalized thread CPU time and native latency
percentiles, each the median of its recorded values across three runs:

| Size | Mode | MB/s Zig / native | CPU ns/op Zig / native | Native p50 / p95 / p99 ns |
| --- | --- | ---: | ---: | ---: |
| Small | DEFLATE | 17.39 / 36.67 | 15,477 / 7,134 | 7,100 / 9,000 / 13,600 |
| Small | DEFLATE + AES | 16.73 / 34.47 | 16,071 / 7,736 | 7,700 / 8,200 / 12,800 |
| Medium | DEFLATE | 18.48 / 127.11 | 913,149 / 125,558 | 124,500 / 146,400 / 189,600 |
| Medium | DEFLATE + AES | 18.04 / 111.21 | 913,149 / 146,637 | 145,100 / 170,700 / 224,200 |
| Large | DEFLATE | 128.82 / 303.40 | 2,008,929 / 873,447 | 854,500 / 915,800 / 1,025,000 |
| Large | DEFLATE + AES | 118.76 / 234.30 | 2,232,143 / 1,050,420 | 1,111,200 / 1,223,100 / 1,366,600 |

All 810 Windows measurements report zero steady-state allocator calls. Realistic
compressed/raw ratios are 0.500000 / 0.500000 (Zig/native) for small batches,
0.339775 / 0.328156 for medium, and 0.264274 / 0.263141 for large. Highly
compressible ratios are equal; native incompressible output is equal or smaller.
Highly compressible round-trip medians improve 1.33–2.13x without AES;
incompressible medians improve 2.08–3.58x. All nine entropy/size combinations
improve round trips with and without AES in every paired run.

This is not a universal decompression win. Zero-payload decode-only medians are
177 / 448 ns (small), 4,238 / 14,140 ns (medium) and 29,025 / 55,150 ns (large):
native is 2.53x, 3.34x and 1.90x slower respectively. AES cases show the same
pattern. Faster encoding still improves their round trips. Receive-heavy
workloads dominated by such data should prefer pure Zig unless measured.

The median gain across the 81 non-DEFLATE cases is 0.993x; individual median
ratios range 0.856–1.296x. The largest slowdown is medium realistic Snappy + AES
decode (49,887 / 58,278 ns); its paired gains range 0.785–1.007x, so it is not
uniform across runs. Small incompressible uncompressed decode changes from
50 to 56 ns, below the individual timestamp quantum. Do not interpret this as
a claim of unchanged performance in every other mode. An initial inlined
native wrapper repeatedly regressed medium incompressible Snappy encode by
about 30%; keeping native codec bodies out of shared dispatch removed that
regression in the final runs without changing Snappy itself.

## Reproduce

Use the repository's Zig 0.17.0 compiler. The default build remains pure Zig.
`-Dlibdeflate=true` lazily fetches the pinned libdeflate 1.26 archive and builds
four C source files with Zig's bundled Clang (`-O2 -std=c11`). No separately
installed C compiler, CMake, shared library or system libdeflate is required.
The target must support libc. The source dependency includes its MIT license.

```sh
zig build bench-baseline-build --prefix zig-out/pure-zig
zig build bench-baseline-build -Dlibdeflate=true --prefix zig-out/libdeflate
python tests/bench/run_sessions.py
```

The runner alternates backend order across three complete runs and checks the
135-case matrix, identical input sizes/packet counts, zero steady-state
allocations and unchanged frame sizes for the other compression modes. Windows
native builds use ReleaseFast and the same CPU target. Compilations and tests
finish before comparative timing starts. Binary hashes are retained alongside
the CSV files in `results/`.

## Measurement scope

The inputs and measurement method are the [baseline](README.md): small, medium
and large batches; highly compressible, realistic and incompressible contents;
no compression, Snappy, DEFLATE, Snappy + AES and DEFLATE + AES; encode, decode
and round trip. Timings include session checks, compression, crypto, pool leases
and batch iteration. Packets are pre-encoded; this does not time full typed
packet serialization or decoding. Decode-only cases consume each backend's
prepared frames, so compression ratio can affect AES decoding cost. The
[raw codec comparisons](CANDIDATES.md) separately decode identical streams.

The realistic small/medium workloads contain typed MovePlayer packets. The
large workload contains a LevelChunk envelope with modeled run/palette bytes;
it is not captured network traffic or a validated serialized world chunk.
Results support these representative session workloads, not all servers.
CSV files retain ns/op, decimal MB/s, compressed/raw size, allocator calls,
thread CPU time and 1,024-sample p50/p95/p99. Windows timestamp granularity is
100 ns, and desktop scheduling still affects individual samples.

## Ownership and safety

Each exclusively leased TX slot owns one level-3 compressor; each RX slot owns
one decompressor. Allocation happens during `BufferPool.init`, with partial
initialization cleanup and destruction through that same pool allocator.
libdeflate's per-context allocator callbacks have no user-data argument, so a
temporary thread-local allocator covers synchronous construction; an aligned
header remembers the owner for later destruction on any thread. No global
libdeflate allocator is changed and no context allocation happens per batch.

Session encoding/ingest, Tap decode and relay recompression use those contexts.
Existing standalone DEFLATE and Compression APIs retain their pure-Zig path;
default builds compile out the native state. No C struct types are exposed.
Pool leases, scratch ownership, compression thresholds, marker negotiation,
AES sequencing and session/authentication/resource-pack transitions retain
their existing contracts. RX/TX scratch remains available for pure-Zig callers
and Snappy.

Both backends enforce the existing minimum compression destination, maximum
compressed frame and maximum decompressed batch. Native decoding bounds the
output before calling C and rejects trailing input using the consumed length.
Truncated input can report malformed data or an output-limit error; both reject
the frame without exceeding the caller's destination.

The static library excludes gzip/zlib/checksum sources and ARM runtime feature
probes, which use filesystem reads for checksums. Raw ARM match finding uses
compile-time NEON support; raw x86 decoding retains libdeflate's CPU dispatch.
No transport, polling, profiler runtime or host-I/O API is added to Bedwire.

## Memory and setup

Measured x86_64 level 3 requests are 668,295 bytes per compressor and 11,568 per decoder.
The allocator bridge adds a 32-byte header per allocation and the slot gains
an 8-byte opaque handle on the tested 64-bit targets. A conservative pool
(two RX, one TX) therefore requests an additional 691,551 bytes. Every pool in
an enabled build reserves contexts, including Snappy/uncompressed users; an
observer pool has decoder state only. These are requested bytes, not resident
memory measurements or allocator page rounding.

The earlier codec investigation measures constructor/destructor latency and
reused-context cost. This session comparison excludes pool initialization.
State remains independent of packet count and returns to its allocator on
pool destruction. Increasing lease slots also increases codec state: 64 RX
and 64 TX slots add 43,516,352 requested bytes. Tune byte limits and concurrent
lease counts before enabling the backend for a large pool.

## Verification and portability

The final Windows default and optional ReleaseSafe suites each pass 241 tests
(30 unit, 211 integration/adversarial), using the default 20,000 malformed
inputs per campaign. Optional Debug testing also passes 241 tests with one
malformed input per campaign. Tests cover all initialization allocation
failures, encrypted allocation-free steady state, context reuse after malformed
input, trailing/truncated input, empty input, destination sizes 0..511, bomb
limits, Go DEFLATE fixtures, bidirectional Zig/native decoding, shared-pool
encrypted DEFLATE contention and destruction on another thread. The pinned
Go S2 fixture checker passes without fixture changes.

The production session matrix cross-builds as static x86_64-linux-musl and
aarch64-linux-musl executables. ELF program headers contain neither an
interpreter nor a dynamic segment; artifact hashes are recorded. All 135
x86_64 Linux cases run under WSL2 and verify packet bytes, leases and zero
steady-state allocations. The final run uses the host CPU for hardware AES;
an earlier generic-CPU run also passed. The retained run is compatibility
validation, not repeatable Linux throughput evidence. ARM was cross-built
only; native ARM timing, native Linux build-toolchain validation, other targets,
hardware memory/coherence counters and production traffic captures remain
unmeasured.

```sh
zig build bench-baseline-build -Dlibdeflate=true -Dtarget=x86_64-linux-musl -Dcpu=native --prefix zig-out/session-linux-x86_64
zig build bench-baseline-build -Dlibdeflate=true -Dtarget=aarch64-linux-musl --prefix zig-out/session-linux-aarch64
```

Both ordinary and opt-in installed library builds pass. The optional build
requires libc; Windows PE imports include its CRT, while the tested musl ELF
executables are static. An application using a different libc/toolchain should
repeat its own integration checks. `BufferPool.storageBytes()` continues to
count backing frame/batch buffers; it excludes scratch and native state.
