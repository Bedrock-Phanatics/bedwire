"""Validate Zig Snappy with Gophertunnel's pinned Go S2 and refresh public fixtures."""
import json
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[2]
reference = root / "references/gophertunnel"
if not reference.is_dir():
    reference = root.parent / "docs/references/gophertunnel"
command = [
    "zig", "run", "-OReleaseSafe", "--dep", "bedwire",
    "-Mroot=tools/interop/export.zig", "-OReleaseSafe", "--dep", "bedrock_protocol",
    "-Mbedwire=src/root.zig", "-OReleaseSafe", "-Mbedrock_protocol=../zig-protocol/src/root.zig",
]
encoded = subprocess.run(command, cwd=root, capture_output=True, check=True).stderr
with tempfile.TemporaryDirectory(prefix="bedwire-interop-") as temporary:
    packet = pathlib.Path(temporary) / "snappy.bin"
    packet.write_bytes(bytes.fromhex(encoded.decode()))
    result = subprocess.run(
        ["go", "run", str(root / "tools/interop/main.go"), str(packet)],
        cwd=reference, capture_output=True, check=True,
    )
    data = json.loads(result.stdout)
    fixture = root / "tests/compression/interop.json"
    fixture.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
print("Go S2 decoded Zig Snappy; Go DEFLATE, Snappy, AES-CTR and P384 fixtures refreshed.")
