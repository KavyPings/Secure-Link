"""Create a disguised file for the file-security demo (FR-17).

    python scripts/make_spoofed_file.py                 # writes demo_files/invoice.pdf
    python scripts/make_spoofed_file.py photo.png

The file starts with a Windows executable header ("MZ") but carries an allowed extension,
i.e. "malicious.exe renamed to document.pdf". SecureLink must reject it with
"File rejected: Signature does not match declared type".
It contains no executable code: just the 2-byte DOS signature, a stub message and padding.
"""
import sys
from pathlib import Path

name = sys.argv[1] if len(sys.argv) > 1 else "invoice.pdf"
out_dir = Path(__file__).resolve().parent.parent / "demo_files"
out_dir.mkdir(exist_ok=True)
path = out_dir / name
path.write_bytes(b"MZ" + b"\x90\x00" * 30 + b"This program cannot be run in DOS mode.\r\n" + b"\x00" * 256)
print(f"wrote {path} ({path.stat().st_size} bytes): executable signature with a .{name.rsplit('.', 1)[-1]} extension")
