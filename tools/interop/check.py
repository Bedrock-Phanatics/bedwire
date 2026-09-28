"""Cross-check Zig Snappy against pinned Go S2 and verify the Go fixtures.

Fails if tests/compression/interop.json is stale; pass --update to rewrite it.
"""
import json
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[2]
interop_dir = root / "tools/interop"
fixture = root / "tests/compression/interop.json"
update = "--update" in sys.argv[1:]

subprocess.run(["zig", "build", "interop"], cwd=root, check=True)
exporter = root / "zig-out/bin" / ("interop-export.exe" if sys.platform == "win32" else "interop-export")
encoded = subprocess.run([exporter], capture_output=True, check=True).stderr.decode()

with tempfile.TemporaryDirectory(prefix="bedwire-interop-") as temporary:
    packet = pathlib.Path(temporary) / "snappy.bin"
    packet.write_bytes(bytes.fromhex(encoded))
    result = subprocess.run(
        ["go", "run", ".", str(packet)],
        cwd=interop_dir, capture_output=True, check=True,
    )

expected = json.dumps(json.loads(result.stdout), indent=2) + "\n"
if update:
    fixture.write_text(expected, encoding="utf-8", newline="\n")
    print("Go S2 decoded Zig Snappy; fixture updated.")
elif fixture.read_text(encoding="utf-8").replace("\r\n", "\n") != expected:
    sys.exit("tests/compression/interop.json is stale; run tools/interop/check.py --update")
else:
    print("Go S2 decoded Zig Snappy; fixture is current.")
