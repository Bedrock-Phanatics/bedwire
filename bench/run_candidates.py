import csv
import pathlib
import platform
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
suffix = ".exe" if sys.platform == "win32" else ""
codec = root / "zig-out/bin" / ("bedwire-codecs" + suffix)
pool = root / "zig-out/bin" / ("bedwire-pool-bench" + suffix)
reference = root / "zig-out/bin" / ("s2-reference.test" + suffix)
architecture = platform.machine().lower().replace("amd64", "x86_64")
tag = ("windows" if sys.platform == "win32" else sys.platform) + "-" + architecture
results = root / "bench/results"
reference_args = [
    str(reference), "-test.run=TestSnappyInteroperability", "-test.count=1",
    "-test.bench=BenchmarkSnappy", "-test.benchtime=100ms", "-test.cpu=1",
    "-test.benchmem", "-test.timeout=120s",
]


def run(command, output, cwd=root):
    print("Running " + output.name, flush=True)
    with output.open("wb") as stream:
        subprocess.run(command, cwd=cwd, stdout=stream, check=True, timeout=300)
    output.write_bytes(b"\n".join(line.rstrip() for line in output.read_bytes().splitlines()) + b"\n")


def rows(path):
    with path.open() as stream:
        return list(csv.DictReader(line for line in stream if not line.startswith("#")))


subprocess.run(
    [str(reference), "-test.run=TestSnappyInteroperability", "-test.count=1"],
    cwd=root / "tools/interop", check=True, timeout=120,
)
for iteration in range(1, 4):
    codec_result = results / f"{tag}-codecs-run{iteration}.csv"
    reference_result = results / f"{tag}-s2-run{iteration}.txt"
    jobs = [
        ([str(codec)], codec_result, root),
        (reference_args, reference_result, root / "tools/interop"),
    ]
    for command, output, cwd in jobs if iteration % 2 else reversed(jobs):
        run(command, output, cwd)
    measurements = rows(codec_result)
    assert len(measurements) == 210, "Incomplete codec matrix"
    assert all(int(row["allocations_per_op"]) == 0 for row in measurements)
    assert all(float(row["ns_per_op"]) > 0 for row in measurements)
    assert all(int(row["p50_ns"]) <= int(row["p95_ns"]) <= int(row["p99_ns"]) for row in measurements)
    pool_result = results / f"{tag}-pool-run{iteration}.csv"
    run([str(pool)], pool_result)
    assert len(rows(pool_result)) == 69, "Incomplete pool matrix"
print("Three codec, Snappy reference, and pool runs completed.")
