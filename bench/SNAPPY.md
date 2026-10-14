# Snappy batch optimization

Bedwire keeps its own pure-Zig Snappy implementation. The earlier
[reference comparison](CANDIDATES.md) identified large-input match finding and
overlapping decode copies as meaningful costs. The changes add no dependency,
allocator, scratch storage, public API or session state.

For inputs of at least 64 KiB, successive misses increase the match-finding
stride from one byte to at most 128 bytes; a match resets it. Matches extend
eight bytes at a time with bounded, unaligned little-endian reads. Smaller
inputs retain dense probing and scalar extension in a separate compile-time
specialization. Hash-table sizing/reset and literal encoding remain unchanged.
Overlap decoding fills single-byte runs directly and doubles initialized ranges
for other repeats. Decode stays out of line to contain the larger copy path.

This trades a small loss of compression quality on the large packet model for
substantial repeatable session gains. It does not establish gains for captured
traffic or every packet distribution. Several smaller cases regress below.

## Method

Before binaries use production commit `7316e47`; after binaries use the Snappy
changes accompanying this report. Both session builds use the default pure-Zig
DEFLATE backend. Zig 0.17.0 ReleaseFast, Windows x86_64, AMD Ryzen 5 5500, the
same batch generator, buffers, output limits, counting allocators and timing
harnesses are used throughout. Three process rounds alternate before/after
order. Recorded runs execute without concurrent builds or tests.

Each variant runs all 210 raw-codec cases and all 135 session cases, including
none, Snappy, DEFLATE, and both compressed AES modes, with encode, decode and
round trip at all three sizes and entropy models. The raw codec matrix includes
1/3/4/16/32/64/128-byte inputs. Each process validates byte-for-byte round trips
and bounds before timing. The pinned Go S2 test checks each variant's exported
streams against the existing fixture and generated corpus: six passing runs.
Snappy also decodes the same S2-produced streams in both variants.

Timing uses 32 warmups in the codec harness, 1,024 latency samples, then seven
throughput groups targeting 10 ms (codecs) or 20 ms (sessions). Values below
are medians of three process runs; speedup ranges are paired before/after
ns/op ratios. Phases are measured independently. Session MB/s counts packet
bytes once; raw MB/s counts framed batch bytes. Compression ratios exclude
frame/encryption trailers. Windows CPU accounting and submicrosecond latency
observations are coarse; percentiles describe this isolated harness.

Full ns/op, MB/s, ratios, allocation counts, CPU time and p50/p95/p99 are in
`results/windows-x86_64-snappy-{codecs,sessions}-{before,after}-run{1,2,3}.csv`.
[Executable hashes](results/windows-x86_64-snappy-artifacts.json) identify the
measured binaries. The reference timing/ratio comparison is retained in
`CANDIDATES.md`; this phase repeats interoperability, not Go throughput timing.

The packet models are generated MovePlayer batches and a large LevelChunk
envelope with 75% run/palette-like bytes and 25% noise. The chunk body is an
entropy model, not a validated serialized world chunk or captured traffic.

## Session results

Generated packet data, ns/op:

| Size | Mode | Encode before / after | Decode before / after | Round trip before / after | Paired round-trip speedup |
| --- | --- | ---: | ---: | ---: | ---: |
| Small | Snappy | 381 / 396 | 424 / 441 | 831 / 817 | 0.99–1.03x |
| Small | Snappy + AES | 876 / 884 | 896 / 966 | 1,801 / 1,980 | 0.86–0.95x |
| Medium | Snappy | 22,310 / 21,885 | 28,065 / 30,842 | 51,034 / 54,786 | 0.90–1.02x |
| Medium | Snappy + AES | 43,571 / 43,653 | 50,371 / 51,079 | 95,296 / 96,083 | 0.96–1.02x |
| Large | Snappy | 307,803 / 46,425 | 36,413 / 21,344 | 337,985 / 71,089 | 4.06–5.32x |
| Large | Snappy + AES | 437,625 / 180,720 | 170,867 / 157,768 | 605,824 / 337,671 | 1.78–1.97x |

Large packet encode improves 6.44–6.86x and decode 1.67–1.95x without AES.
Compressed/raw changes from 0.286478 to 0.287310: 218 additional compressed
bytes, or 0.29% of the old compressed size. Small/medium packet ratios remain
0.789286 and 0.722822. Those outputs and all non-Snappy frame sizes are unchanged.

Large compressible round trips improve 10.01–11.39x (5.95–6.31x with AES), with
the same 0.046913 ratio. Large noise improves 13.08–15.24x (1.36–1.43x with AES),
with ratio 1.000038 becoming 1.000027. AES dominates noise decoding, which is
essentially unchanged. These synthetic extremes should not stand in for packet
traffic. No steady-state allocator calls occurred in any of the 810 session
rows or 1,260 raw-codec rows. BufferPool storage and acquisition are unchanged.

Small packet Snappy + AES round trip is about 10% slower at the median;
medium packet Snappy decode is about 10% slower and round trip about 7% slower.
Medium packet + AES round trip differs by under 1% at the median. These are
retained limitations, not gains. Unchanged non-Snappy control medians have
before/after speedup 0.986 overall, with individual cases spanning 0.547–1.225;
desktop variation does not explain away repeatable regressions. Hosts dominated
by small/medium packets should evaluate their own mix before adopting this
revision. The large-batch gains justify retaining this small internal change.

Large generated-packet session CPU and throughput medians:

| Mode / phase | CPU ns/op before / after | MB/s before / after |
| --- | ---: | ---: |
| Snappy encode | 333,156 / 50,501 | 851.69 / 5,646.79 |
| Snappy decode | 40,038 / 20,109 | 7,199.52 / 12,282.08 |
| Snappy round trip | 340,496 / 66,083 | 775.64 / 3,687.66 |
| Snappy + AES round trip | 608,766 / 340,496 | 432.72 / 776.36 |

Generated-packet round-trip latency medians, ns (p50 / p95 / p99):

| Size / mode | Before | After |
| --- | ---: | ---: |
| Small Snappy | 900 / 1,500 / 1,700 | 900 / 900 / 900 |
| Medium Snappy | 49,100 / 58,200 / 82,700 | 49,000 / 64,400 / 86,800 |
| Large Snappy | 335,700 / 357,100 / 387,700 | 65,700 / 90,200 / 111,400 |
| Large Snappy + AES | 602,600 / 632,400 / 712,400 | 335,700 / 349,500 / 365,500 |

## Raw-codec results and investigation

| Workload | Encode ns/op before / after | Decode S2 stream ns/op before / after |
| --- | ---: | ---: |
| Small packet model | 245 / 259 | 205 / 195 |
| Medium packet model | 14,639 / 13,939 | 12,329 / 13,995 |
| Large packet model | 303,617 / 38,918 | 299,081 / 20,553 |
| Small zeros | 89 / 160 | 393 / 30 |
| Medium zeros | 4,893 / 9,786 | 2,434 / 1,206 |
| Large zeros | 68,622 / 19,321 | 385,399 / 16,616 |
| Small noise | 202 / 195 | 139 / 153 |
| Medium noise | 16,339 / 17,916 | 202 / 201 |
| Large noise | 383,629 / 11,744 | 4,663 / 4,712 |

The raw small/medium zero encoder regresses substantially (about 1.8x/2x);
session zero encode changes are much smaller: 133/140 ns and 5,340/5,477 ns.
The 3-byte micro encoder also regresses from 68 to 128 ns. Micro results have
timer/code-generation sensitivity and do not justify short-input speed claims.
Every raw result, including these regressions, is retained. Large S2 packet
streams contain many short-distance repeats; their identical-stream decode
speedup is 14.51–14.66x. Bedwire's own large packet stream decode improves
1.65–1.70x, but its stream changes, so that is not an identical-input comparison.

A replay of the original match-selection algorithm on the generated corpus
counted 65,616 misses and 136 matches on large packet data, 262,140 misses and
one match on large noise, and six misses followed by one long match on zeros.
Medium packet data instead contains 2,609 mostly 4–11-byte matches. This
motivates limiting sampling and wide extension to large inputs. Replay of the
old zero stream finds 4,096 single-byte-overlap copies. These are algorithm
counters and source inspection, not sampled CPU attribution. No hardware
instruction profile or cache/coherence counters were captured.

Unconditional wide extension and a shared runtime large-input branch hurt
medium latency in exploratory runs; compile-time specializations contain that
cost. The two specializations increase code size. There is no table-reset,
literal, BufferPool, encryption or DEFLATE optimization in this change.
Recorded Windows executable sizes grow by 1,024 bytes for the raw-codec runner
and 1,536 bytes for the session runner; these are whole-artifact sizes, not
isolated function sizes or resident memory measurements.

## Verification and remaining limits

Both pure-Zig and optional-libdeflate ReleaseSafe builds pass all 243 tests,
including the existing 20,000-input fuzz campaigns. Added checks exhaust 8,704
short copy/offset/form combinations against a scalar oracle with output guards;
they also cover unaligned matches, mismatches, large tails, sparse matches,
short destination buffers and allocator refusal after setup. Existing tests
cover malformed/truncated input, decompression bombs, thresholds, leases,
allocator failure cleanup, encryption, JWT/session and resource-pack behavior.
No limits, ownership rules or packet/session API changes are introduced.

The final pure-Zig Debug build also passes all 243 tests with fuzz iterations
reduced to one per campaign; ReleaseSafe uses the full configured campaigns.
The direct pinned Go interoperability checker confirms the original fixture
is current without rewriting it. Zig formatting and Git whitespace checks pass.

Static builds succeed for `x86_64-linux-musl` with the host CPU and
`aarch64-linux-musl` with the generic target CPU. ELF headers contain no dynamic
or interpreter segment. Linux x86_64 under Ubuntu/WSL2 completes all 135 session
cases, including AES, with zero steady-state allocator calls. Its
[CSV](results/linux-x86_64-snappy-sessions.csv) is a single functional
compatibility run, not repeatable Linux performance evidence.
[Portability artifact hashes](results/snappy-portability-artifacts.json)
identify both static builds. ARM runtime performance, captured traffic,
production tail latency, resident memory and hardware CPU profiling remain
unverified.

## Reproduce

Build the before binaries from `7316e47` in a separate checkout with the same
Zig version, target and options; copy `bedwire-codecs.exe` and
`bedwire-baseline.exe` into `zig-out/snappy-before`. Both variants need the
pinned libdeflate source for the comparison executable, as described in
`CANDIDATES.md`; this does not enable it for sessions.

```sh
zig build bench-codecs-build bench-baseline-build "-Dlibdeflate-path=zig-pkg/libdeflate-1.26" --prefix zig-out/snappy-after
```

Run either codec executable once to export the raw corpus. From `tools/interop`,
build the pinned Go test binary and generate the reference streams:

```sh
go test -c -o ../../zig-out/bin/s2-reference.test.exe
../../zig-out/bin/s2-reference.test.exe -test.run=TestSnappyInteroperability -test.count=1
```

Then run `python bench/run_snappy.py` from the repository root. It validates
row counts, allocation counts, percentiles, unchanged metadata/control output,
cross-decoding, and saves all three pairs and executable hashes. On Linux omit
`.exe` in manual commands; the Python runner chooses the suffix automatically.
