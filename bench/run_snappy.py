import csv
import hashlib
import json
import pathlib
import platform
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
suffix = ".exe" if sys.platform == "win32" else ""
tag = ("windows" if sys.platform == "win32" else sys.platform) + "-" + platform.machine().lower().replace("amd64", "x86_64")
results = root / "bench/results"
binaries = {
    "before": root / "zig-out/snappy-before",
    "after": root / "zig-out/snappy-after/bin",
}


def rows(path):
    with path.open() as stream:
        return list(csv.DictReader(line for line in stream if not line.startswith("#")))


for iteration in range(1, 4):
    comparisons = {}
    variants = list(binaries.items())
    for variant, directory in variants if iteration % 2 else reversed(variants):
        for kind, executable, count in (("codecs", "bedwire-codecs", 210), ("sessions", "bedwire-baseline", 135)):
            output = results / f"{tag}-snappy-{kind}-{variant}-run{iteration}.csv"
            print("Running " + output.name, flush=True)
            with output.open("wb") as stream:
                subprocess.run([str(directory / (executable + suffix))], cwd=root, stdout=stream, check=True, timeout=300)
            measured = rows(output)
            assert len(measured) == count
            for row in measured:
                assert int(row["allocations_per_op"]) == 0
                assert float(row["ns_per_op"]) > 0
                assert int(row["p50_ns"]) <= int(row["p95_ns"]) <= int(row["p99_ns"])
            comparisons[variant, kind] = measured
        subprocess.run(
            [str(root / "zig-out/bin" / ("s2-reference.test" + suffix)), "-test.run=TestSnappyInteroperability", "-test.count=1"],
            cwd=root / "tools/interop", check=True, timeout=120,
        )
    for before, after in zip(comparisons["before", "sessions"], comparisons["after", "sessions"]):
        for field in ("size", "content", "mode", "phase", "packets", "payload_bytes"):
            assert before[field] == after[field]
        if not before["mode"].startswith("snappy") or before["size"] != "large":
            assert before["frame_bytes"] == after["frame_bytes"]
    for before, after in zip(comparisons["before", "codecs"], comparisons["after", "codecs"]):
        for field in ("workload", "backend", "phase", "source", "raw_bytes"):
            assert before[field] == after[field]
        if before["source"] != "snappy" and (before["backend"] != "snappy" or before["phase"] != "encode"):
            assert before["compressed_bytes"] == after["compressed_bytes"]

artifacts = {
    variant: {name: hashlib.sha256((directory / (name + suffix)).read_bytes()).hexdigest() for name in ("bedwire-codecs", "bedwire-baseline")}
    for variant, directory in binaries.items()
}
(results / f"{tag}-snappy-artifacts.json").write_text(json.dumps(artifacts, indent=2) + "\n")
print("Three codec/session comparisons and cross-implementation checks completed.")
