"""Upload validation pipeline (FR-14 .. FR-19).

Order follows FR-19: format (extension) -> MIME -> magic bytes -> size -> compatibility.
Signatures are hand-written here (no libmagic), so an administrator can only enable or
disable types this module knows how to recognise.
"""
import io
import zipfile

from .. import config

GENERIC_MIMES = {"", "application/octet-stream"}

# extension -> the type its binary signature must reveal
EXT_TO_DETECTED = {
    "pdf": "pdf", "docx": "docx", "xlsx": "xlsx", "pptx": "pptx", "txt": "txt",
    "jpg": "jpeg", "jpeg": "jpeg", "png": "png", "webp": "webp",
}
DETECTED_TO_MIME = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "txt": "text/plain",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "webp": "image/webp",
}
SUPPORTED_EXTENSIONS = set(EXT_TO_DETECTED)


class FileRejected(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def extension_of(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def detect_type(data: bytes) -> str | None:
    """Identify the real format from the file's binary signature (magic bytes)."""
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"PK\x03\x04"):
        # DOCX/XLSX/PPTX all share the ZIP signature; the folder inside tells them apart.
        try:
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        except zipfile.BadZipFile:
            return None
        if "[Content_Types].xml" not in names:
            return None
        for prefix, kind in (("word/", "docx"), ("xl/", "xlsx"), ("ppt/", "pptx")):
            if any(n.startswith(prefix) for n in names):
                return kind
        return None
    if _is_text(data):
        return "txt"  # plain text has no signature: must be valid UTF-8 with no NUL bytes
    return None


def _is_text(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def validate(conn, filename: str, declared_mime: str, data: bytes) -> dict:
    """Return {ext, mime, detected_type} or raise FileRejected with the user-facing reason."""
    ext = extension_of(filename)
    row = conn.execute(
        "SELECT mime, enabled, browser_compatible FROM allowed_file_types WHERE ext = ?", (ext,)
    ).fetchone()

    # 1. Format / extension check
    if row is None or not row["enabled"] or ext not in SUPPORTED_EXTENSIONS:
        raise FileRejected(f"File type '.{ext}' is not allowed" if ext else "File has no extension")
    expected_mime = row["mime"]

    # 2. MIME check: declared Content-Type must match (some mobile browsers send none / generic)
    declared = (declared_mime or "").split(";")[0].strip().lower()
    if declared not in GENERIC_MIMES and declared != expected_mime:
        raise FileRejected(f"MIME type '{declared}' does not match expected '{expected_mime}'")

    # 3. Magic byte check: the real signature must match the extension
    detected = detect_type(data)
    if detected != EXT_TO_DETECTED[ext]:
        raise FileRejected("Signature does not match declared type")
    # ... and the MIME derived from the signature must equal the expected MIME
    if DETECTED_TO_MIME[detected] != expected_mime:
        raise FileRejected("Detected MIME type does not match declared type")

    # 4. Size check
    if len(data) == 0:
        raise FileRejected("File is empty")
    if len(data) > config.MAX_UPLOAD_MB * 1024 * 1024:
        raise FileRejected(f"File exceeds the {config.MAX_UPLOAD_MB} MB limit")

    # 5. Compatibility check (browser/device support flag per type)
    if not row["browser_compatible"]:
        raise FileRejected("File type is not supported on all company devices")

    return {"ext": ext, "mime": expected_mime, "detected_type": detected}
