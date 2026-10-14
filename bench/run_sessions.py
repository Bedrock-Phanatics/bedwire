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
    backend: root / "zig-out" / backend / "bin" / ("bedwire-baseline" + suffix)
    for backend in ("pure-zig", "libdeflate")
}


def rows(path):
    with path.open() as stream:
        return list(csv.DictReader(line for line in stream if not line.startswith("#")))


for iteration in range(1, 4):
    measurements = {}
    jobs = list(binaries.items())
    for backend, binary in jobs if iteration % 2 else reversed(jobs):
        output = results / f"{tag}-sessions-{backend}-run{iteration}.csv"
        print("Running " + output.name, flush=True)
        with output.open("wb") as stream:
            subprocess.run([str(binary)], cwd=root, stdout=stream, check=True, timeout=300)
        measurements[backend] = rows(output)
        assert len(measurements[backend]) == 135, "Incomplete session matrix"
        for row in measurements[backend]:
            assert int(row["allocations_per_op"]) == 0
            assert float(row["ns_per_op"]) > 0
            assert int(row["p50_ns"]) <= int(row["p95_ns"]) <= int(row["p99_ns"])
    for pure, native in zip(measurements["pure-zig"], measurements["libdeflate"]):
        for field in ("size", "content", "mode", "phase", "packets", "payload_bytes"):
            assert pure[field] == native[field], "Different input workloads"
        if not pure["mode"].startswith("deflate"):
            assert pure["frame_bytes"] == native["frame_bytes"], "Unrelated encoding changed"

artifacts = {backend: hashlib.sha256(binary.read_bytes()).hexdigest() for backend, binary in binaries.items()}
(results / f"{tag}-session-artifacts.json").write_text(json.dumps(artifacts, indent=2) + "\n")
print("Three interleaved full session comparisons completed.")
