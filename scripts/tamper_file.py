"""Integrity demo (FR-21, success criterion "a modified file fails verification").

Flips one byte inside the stored encrypted blob of a shared file, simulating silent
modification in storage. The next download must fail with "Integrity verification failed".

    python scripts/tamper_file.py --list
    python scripts/tamper_file.py <filename or file_id>
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from app import config  # noqa: E402
from app.db import connect  # noqa: E402

conn = connect()
if len(sys.argv) < 2 or sys.argv[1] == "--list":
    for r in conn.execute("SELECT file_id, filename, owner, status, created_at FROM files ORDER BY created_at"):
        print(f"{r['file_id']}  {r['status']:16} {r['owner']:12} {r['filename']}")
    sys.exit(0)

key = sys.argv[1]
row = conn.execute("SELECT file_id, filename FROM files WHERE file_id = ? OR filename = ? "
                   "ORDER BY created_at DESC", (key, key)).fetchone()
if row is None:
    sys.exit(f"No file matching '{key}'. Use --list.")

blob = config.STORAGE_DIR / f"{row['file_id']}.bin"
data = bytearray(blob.read_bytes())
pos = len(data) // 2
data[pos] ^= 0x01
blob.write_bytes(bytes(data))
print(f"Flipped 1 bit at byte {pos} of {blob.name} ({row['filename']}). Now try downloading it.")
