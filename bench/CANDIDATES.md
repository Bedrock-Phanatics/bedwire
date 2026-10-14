# Codec and pool investigation

This records the raw-codec and pool investigation before production changes.
The subsequent [session backend trial](LIBDEFLATE.md) retains libdeflate as an
opt-in backend. Ordinary builds continue to use pure Zig without a C dependency.

## Reproduce

Use Zig 0.17.0 and Go 1.25.6. Extract the
[libdeflate 1.26 source archive](https://codeload.github.com/ebiggers/libdeflate/zip/refs/tags/v1.26)
into `zig-pkg/libdeflate-1.26`. The archive SHA-256 is
`cc64b9177e8c7eed2d3960a3dd9b0aa061ddc4c43c9067af1209e208e4a8144f`.
The benchmark rejects other libdeflate versions.

```sh
zig build bench-codecs-build bench-pool-build "-Dlibdeflate-path=zig-pkg/libdeflate-1.26"
zig-out/bin/bedwire-codecs.exe > zig-out/codec-prepare.csv
```

From `tools/interop`, build the reference executable:

```sh
go test -c -o ../../zig-out/bin/s2-reference.test.exe
```

Then, from the repository root:

```sh
python bench/run_candidates.py
```

Remove `.exe` from executable names on Linux. The runner selects the platform
suffix automatically. A first codec run exports the deterministic corpus;
the reference test checks those exports and produces Snappy streams that the
Zig runner then verifies and benchmarks. Generated corpus files and upstream
source trees remain under ignored directories. Results are saved in `results/`.

## Method

Inputs are the exact framed batch bytes produced by the baseline workload
generator: three sizes and three entropy models. No packet serialization,
encryption, session admission or pool acquisition is timed in the codec tests.
These tests isolate codec cost; session gains require a separate production
trial using the baseline matrix, including AES.

Both Zig and libdeflate compress into the same 1,048,566-byte output limit.
Both decoders receive the same compressed buffer for each comparison and the
same 4 MiB output limit. Each of the six DEFLATE encoders supplies a stream to
both decoders. Zig level 6 calls Bedwire's existing function. Zig levels 1 and 3
use the same fixed writer/history/init/finish sequence with different standard
options. Libdeflate levels 1, 3 and 6 are compared; level numbers do not imply
identical compression ratios. Ratios are recorded for every stream.

The Snappy reference is the existing pinned `klauspost/compress/s2` v1.18.1
`EncodeSnappy`/`Decode`, using Go's optimized native implementation. It uses
the same input buffers and output capacities. Both encoders' streams are
decoded by both implementations. Seven additional 1/3/4/16/32/64/128-byte
inputs examine short-input and literal paths. The existing interoperability
fixture is also checked. Go additionally decodes Zig and libdeflate level-6
raw DEFLATE output for every main workload.

Zig/C timing uses 32 warmups, 1,024 individual latency observations, then seven
throughput groups targeting 10 ms each. Go uses 32 warmups before `testing.B.Loop`
and a 100 ms benchmark duration. Three Windows process rounds alternate which
language runner goes first; codecs within the Zig runner alternate encoder and
decoder work on each producer's stream. Ratios, counts and buffer lengths must
agree between repeated runs. Throughput uses decimal MB of raw batch bytes.
Windows clock resolution can produce zero short-input latency observations;
these mean below the timer tick, not zero work. Thread CPU accounting is coarse.
The Go runtime and its table pool have different allocation semantics from
Bedwire; `benchmem` results are reference measurements, not a replacement
allocation guarantee. In particular, Go's `sync.Pool` can discard tables on GC.

All C allocator calls are counted, including failed calls. Compressors and
decompressors are allocated before timing and reused. Any allocator call during
measured operations fails the runner. Context teardown must return live C bytes
to zero. Setup measurements include allocation/free for a context pair; Zig's
separate initialization measurement excludes compression/finish. State byte
counts measure requested C memory, excluding malloc/header/page overhead.
The standard compressor's recorded 230,096 bytes is its type size, not a
complete stack high-water measurement; scratch is another 65,536 bytes.

## Safety and portability

The candidate wrapper enforces compressed-input limits, bounded output, and
full input consumption using `libdeflate_deflate_decompress_ex`. The checks cover
the existing Go fixture, short output, trailing data, truncated input, a
131,072-byte expansion capped at 128 bytes, 1,000 bounded malformed inputs,
both context allocation failure positions, repeated context create/free,
and byte-for-byte cross-decoding of all encoder outputs.

The complete updated ReleaseSafe integration/adversarial suite passed all 209
tests. The standard unit-test target was unchanged and cached successfully;
its fresh 30-test run is recorded in the baseline phase. Go interoperability
tests pass for the original fixture and exported corpus. Every pool benchmark
checks token validity, idle completion and zero pool allocator calls.

Static C linking passed on Windows x86_64 and cross-builds for
`x86_64-linux-musl` and `aarch64-linux-musl`. The final Linux x86_64 executable
also completed all 210 codec cases and safety checks on Ubuntu under WSL2,
kernel `6.6.87.2-microsoft-standard-WSL2`. Its CSV is a single compatibility run,
not repeatable Linux performance evidence. ARM64 runtime performance and
functional execution remain untested because no ARM host was available.

The build compiles the eleven upstream C files directly with Zig's C compiler,
C11 and `-O2`, following
[upstream integration guidance](https://github.com/ebiggers/libdeflate/blob/v1.26/README.md).
No CMake or separate C compiler is needed. Libdeflate is MIT licensed and uses
runtime CPU feature dispatch; successful ARM cross-compilation does not establish
ARM speedups. A production backend would need a pinned optional source dependency,
one compressor per exclusive TX slot and one decompressor per exclusive RX slot,
fallible pool initialization/cleanup, and the full session/AES safety matrix.

## Repeated Windows results

All three runs completed 210 codec cases, 48 Go reference benchmarks and 69
pool cases. All 630 codec measurements made zero C allocator calls during
timing. Every warmed Go reference measurement reported 0 B/op and 0 allocs/op;
this does not remove its `sync.Pool`/GC caveat. This is Windows x86_64 on the
same AMD Ryzen 5 5500 as the baseline. Times below are medians of three runs;
raw CSVs contain ns/op, MB/s, ratios, CPU time and latency percentiles.
Executable SHA-256 values and Linux ELF linkage checks are recorded in
[candidate-artifacts.json](results/candidate-artifacts.json).

| Generated packet batch | Encoder | ns/op | Compressed/raw |
| --- | --- | ---: | ---: |
| Small | Zig 1 | 10,182 | 0.503571 |
| Small | Zig 3 | 10,326 | 0.500000 |
| Small | Zig 6 (current) | 11,414 | 0.500000 |
| Small | libdeflate 1 | 3,944 | 0.496429 |
| Small | libdeflate 3 | 4,970 | 0.500000 |
| Small | libdeflate 6 | 5,172 | 0.500000 |
| Medium | Zig 1 | 143,389 | 0.334381 |
| Medium | Zig 3 | 218,759 | 0.333373 |
| Medium | Zig 6 (current) | 787,682 | 0.339775 |
| Medium | libdeflate 1 | 41,369 | 0.364078 |
| Medium | libdeflate 3 | 84,385 | 0.328156 |
| Medium | libdeflate 6 | 149,609 | 0.348903 |
| Large | Zig 1 | 1,516,283 | 0.263164 |
| Large | Zig 3 | 1,533,362 | 0.263538 |
| Large | Zig 6 (current) | 1,606,102 | 0.264274 |
| Large | libdeflate 1 | 401,160 | 0.262767 |
| Large | libdeflate 3 | 722,513 | 0.263141 |
| Large | libdeflate 6 | 785,243 | 0.258365 |

Libdeflate level 3 beats the current encoder by 2.28–2.32x for small,
9.20–9.36x for medium and 2.22x for large generated packet batches across the
three runs, with equal or smaller output. Simply reducing Zig to level 1 helps
medium data substantially, but libdeflate 3 remains about 1.70x faster there
and 2.10x faster on large data, with slightly smaller output. Level 6 is not
universally the best quality choice: its medium-model ratio is worse than
libdeflate 3 and Zig 1. The ratio measurements should drive level selection.

For the **identical current Zig-6 streams**, decoder medians are:

| Batch | Zig ns/op | libdeflate ns/op | Speedup |
| --- | ---: | ---: | ---: |
| Small | 3,581 | 1,625 | 2.20x |
| Medium | 61,298 | 16,370 | 3.74x |
| Large | 355,404 | 123,482 | 2.88x |

The same comparison on libdeflate-3 output gives 2.21x, 3.49x and 2.92x.
Reusable context-pair setup/free costs approximately 2.7–2.9 microseconds on
this Windows run; isolated Zig initialization costs about 3.0 microseconds.
Neither is a per-packet allocation cost in the candidate. State requests are
202,759 bytes for level-1 compressors, 668,295 bytes for level-3/6 compressors,
and 11,568 bytes per decompressor, with one allocation each. TX state thus has
a meaningful memory cost which must be included in any pool integration.

These gains justify an **optional production trial of libdeflate level 3**,
preserving a pure-Zig build and the existing standalone codec API. They do not
yet establish session/AES speedups or gains on captured production traffic.
Keep the backend only after that trial repeats the baseline matrix, passes the
full safety suite with both backends, and preserves allocator/lifetime behavior.

Snappy comparison on generated packet data:

| Batch | Zig encode ns/op | S2 encode ns/op | Zig decode ns/op | S2 decode ns/op |
| --- | ---: | ---: | ---: | ---: |
| Small | 224.52 | 318.50 | 212.21 | 128.90 |
| Medium | 14,549.71 | 20,019.00 | 16,902.94 | 7,543.00 |
| Large | 297,577.49 | 36,222.00 | 32,195.65 | 21,906.00 |

Decoder columns use the same Zig-produced stream. Zig/S2 output ratios are
0.789286/0.696429 for small, 0.722822/0.673563 for medium and
0.286478/0.300333 for large. S2's faster large-data encoding produces about
4.8% more compressed bytes on this model. On 256 KiB noise, encode is
373,905/8,086 ns (Zig/S2), while decode is 4,733/4,766 ns. On 256 KiB zeros,
encode is 67,513/10,450 ns and decode is 378,316/122,610 ns.

The existing Snappy encoder wins small/medium packet latency; replacing it
wholesale is not justified. Large input match finding and repetitive-data copy
paths merit a focused pure-Zig optimization trial. Source inspection supports
those hypotheses: the encoder probes each byte on a miss and extends matches
byte by byte; overlapping decode copies are byte loops. Table clearing is
already bounded by reachable hash bits. The short-input results are retained
to catch regressions. No instruction-sampling profile was captured, so these
are measured workload bottlenecks and source-guided hypotheses, not attributed
per-line CPU percentages. Introducing the Go runtime would also abandon the
strict allocation contract.

## Pool

Three repeated matrices cover 1/2/4/16/64 slots per direction and 1/2/4/8
threads, with RX-only, RX+TX and split-direction traffic. Private-pool cases
provide a control at 2/4/8 threads. Limits are 4 KiB to avoid inflating backing
storage during contention tests. Thread creation and pool allocation are outside
timing. Workers start at a shared gate; wall time includes wakeup and join.
Each worker completes 50,000 cycles. Exhausted acquisitions yield and retry.
Mixed-mode partial RX acquisitions are counted even when TX acquisition retries.
The denominator is all successful acquire/release pairs; aggregate ns/pair is
inverse throughput across workers, not an individual latency. A worker timeout
fails the run rather than producing a passing result.

The RX and TX availability masks are eight bytes apart. Depending on pool
alignment, they can share a cache line. Split-direction/private controls can
indicate cache-line traffic, but do not isolate false sharing from scheduling
and other shared metadata. Hardware coherence counters and a padding experiment
were not collected. Increasing slot counts removes exhaustion but does not
remove contention on the shared availability masks. No pool replacement or
padding change is justified by these isolated timings alone.

Pool storage scales with frame/batch caps, independently of actual traffic.
Every RX slot reserves 64 KiB of DEFLATE history, including uncompressed and
Snappy traffic; TX reserves one 64 KiB union shared by DEFLATE history and Snappy
table. Buffer allocation is upfront; acquire/release does not clear frame/batch
storage. The existing union avoids reserving two TX scratch areas. Configure
slot counts for simultaneously held leases and set realistic byte caps before
considering a different scratch layout or additional slots.

Selected aggregate inverse-throughput medians in ns per successful pair:

| Slots/direction | Threads | Pool | Work | ns/pair |
| ---: | ---: | --- | --- | ---: |
| 1 | 1 | Shared | RX | 7.93 |
| 1 | 2 | Shared | Split RX/TX | 29.05 |
| 1 | 2 | Private | Split RX/TX | 4.80 |
| 1 | 4 | Shared | RX+TX | 18.93 |
| 4 | 4 | Shared | RX+TX | 42.95 |
| 16 | 4 | Shared | RX+TX | 44.61 |
| 64 | 4 | Shared | RX+TX | 44.84 |
| 1 | 4 | Private | RX+TX | 2.08 |
| 1 | 8 | Shared | RX+TX | 36.94 |
| 1 | 8 | Private | RX+TX | 1.21 |

Four slots remove exhausted acquisitions in the four-thread case, but more
slots do not increase throughput. The one-slot/yield case has a different
contention policy and can show better throughput despite retries; it is not
a recommendation to shrink production pools. Private cases demonstrate the
cost of sharing, not a drop-in pool replacement. Slot tuning needs the host's
lease holding time and traffic distribution. The synthetic split/private gap
is consistent with shared-cache-line traffic; hardware profiling or an
isolated padding trial is required before changing layout.

## Optional Tracy

Evaluated [ztracy](https://github.com/zig-gamedev/ztracy) revision
`d95d2a193b9f97944a17026c9a42b5d0f9a88c94` (archive SHA-256
`af94fc224ca419ca5ff0b8c077c30dac3bb8e32cc6bafba8ddae2c26d0a13bac`).
Its unchanged build fails on Zig 0.17 because `std.meta.fields` is deprecated.
Its disabled Zig binding can be compiled directly: an isolated `ZoneN`/`End`
probe emitted the same `push/mov/lea/pop/ret` instructions as the plain function,
with no calls. This proves compile-out for that disabled marker probe, not a
fully integrated profiler or enabled-client compatibility.

The disabled probe used the pinned `src/ztracy.zig` as an imported module,
with a `ztracy_options` module containing `pub const enable_ztracy = false;`:

```zig
const tracy = @import("ztracy");
export fn hotPath(value: u64) u64 {
    const zone = tracy.ZoneN(@src(), "frame decode");
    defer zone.End();
    return value +% 1;
}
```

The plain control was the same exported function containing only the return.
Both were compiled with Zig 0.17 `build-obj -Ofast -femit-asm`; the disabled
probe imported the binding directly and did not run the incompatible package
build script or link a C/C++ client.

Suitable integration points are `Session.ingest` (frame decode),
`Compression.decode` (decompression), `Packets.next` (batch iteration),
`Session.decodePacket` (packet decoding), `Compression.encode` (compression),
`SessionCrypto.seal/open` (encryption/decryption), `Session.encode`, and
`BufferPool.acquireRx/acquireTx`. A future integration should import/link Tracy
only when explicitly enabled, retain its compile-time stubs when disabled, and
verify the disabled artifact has no Tracy symbols/runtime. Enabled Tracy has
threading/networking/runtime dependencies and should remain an opt-in host
diagnostic. No profiling dependency or production instrumentation is retained
in this phase; upstream Zig 0.17 compatibility and enabled-client validation
are still required.
