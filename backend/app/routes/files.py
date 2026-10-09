"""Document/image sharing with validation, encryption and integrity verification (FR-13 .. FR-21)."""
import uuid
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

from .. import audit, config
from ..db import get_db, now_iso, transaction
from ..security import crypto, filecheck
from ..security.rbac import deny, require

router = APIRouter(prefix="/api/files", tags=["files"])

INTEGRITY_FAILED = "Integrity verification failed. File unavailable. Security event recorded"


def _blob_path(file_id):
    return config.STORAGE_DIR / f"{file_id}.bin"


@router.post("")
def upload_and_share(
    request: Request,
    file: UploadFile = File(...),
    client_sha256: str = Form(...),
    recipients: list[str] = Form(...),
    user=Depends(require("upload_file")),
    conn=Depends(get_db),
):
    # 1. Authorization: sharing permission + every recipient must be an active company user
    if "share_file" not in user["permissions"]:
        deny(conn, request, "missing permission share_file")
    recipients = sorted({r for item in recipients for r in item.split(",") if r.strip()} - {user["user_id"]})
    if not recipients:
        raise HTTPException(400, "Select at least one recipient")
    for rid in recipients:
        if not conn.execute("SELECT 1 FROM users WHERE user_id = ? AND status = 'active'", (rid,)).fetchone():
            audit.log_event(conn, "ACCESS_DENIED", "DENIED", request, details=f"invalid recipient {rid}")
            raise HTTPException(400, f"Recipient '{rid}' is not an active company user")

    filename = (file.filename or "").replace("\\", "/").split("/")[-1][:200]
    data = file.file.read(config.MAX_UPLOAD_MB * 1024 * 1024 + 1)

    # 2-6. Extension -> MIME -> magic bytes -> size -> compatibility
    try:
        info = filecheck.validate(conn, filename, file.content_type, data)
    except filecheck.FileRejected as exc:
        audit.log_event(conn, "INVALID_FILE_TYPE", "REJECTED", request, resource=filename, details=exc.reason)
        raise HTTPException(422, f"File rejected: {exc.reason}")

    # 7. Hash: the server's SHA-256 must equal the hash the browser computed before sending.
    #    Browsers only offer WebCrypto over HTTPS, so the check is skipped solely in lab plaintext mode.
    digest = crypto.sha256_hex(data)
    client_sha256 = client_sha256.strip().lower()
    if client_sha256 == "unavailable" and config.TLS_ENABLED:
        raise HTTPException(422, "File rejected: secure connection required for integrity check")
    if client_sha256 != "unavailable" and digest != client_sha256:
        audit.log_event(conn, "INTEGRITY_FAILURE", "FAILURE", request, resource=filename,
                        details="upload hash mismatch (corrupted in transit)")
        raise HTTPException(422, "File rejected: integrity check failed during upload. Please retry.")

    # 8. Encrypt (AAD = file_id) and store
    file_id = uuid.uuid4().hex
    _blob_path(file_id).write_bytes(crypto.encrypt(data, file_id.encode()))
    now = now_iso()
    with transaction(conn):
        conn.execute(
            """INSERT INTO files (file_id, filename, size, mime_type, detected_type, sha256, owner, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_id, filename, len(data), info["mime"], info["detected_type"], digest, user["user_id"], now),
        )
        conn.executemany(
            "INSERT INTO shares (file_id, sender_id, recipient_id, shared_at) VALUES (?, ?, ?, ?)",
            [(file_id, user["user_id"], rid, now) for rid in recipients],
        )

    # 9. Audit
    audit.log_event(conn, "FILE_UPLOAD", "SUCCESS", request, resource=filename,
                    details=f"file_id={file_id} size={len(data)} sha256={digest}")
    audit.log_event(conn, "FILE_SHARE", "SUCCESS", request, resource=filename,
                    details=f"file_id={file_id} recipients={','.join(recipients)}")
    return {"file_id": file_id, "sha256": digest, "recipients": recipients}


@router.get("")
def list_files(user=Depends(require("download_file")), conn=Depends(get_db)):
    me = user["user_id"]
    received = conn.execute(
        """SELECT f.file_id, f.filename, f.size, f.mime_type, f.sha256, f.status, f.version,
                  s.sender_id, s.shared_at, s.status AS share_status
           FROM shares s JOIN files f ON f.file_id = s.file_id
           WHERE s.recipient_id = ? ORDER BY s.shared_at DESC""",
        (me,),
    ).fetchall()
    sent = conn.execute(
        """SELECT f.file_id, f.filename, f.size, f.mime_type, f.sha256, f.status, f.version,
                  f.created_at, GROUP_CONCAT(s.recipient_id, ', ') AS recipients
           FROM files f LEFT JOIN shares s ON s.file_id = f.file_id
           WHERE f.owner = ? GROUP BY f.file_id ORDER BY f.created_at DESC""",
        (me,),
    ).fetchall()
    return {"received": [dict(r) for r in received], "sent": [dict(r) for r in sent]}


def _integrity_failure(conn, request, file_row, reason):
    conn.execute("UPDATE files SET status = 'integrity_failed' WHERE file_id = ?", (file_row["file_id"],))
    audit.log_event(conn, "INTEGRITY_FAILURE", "FAILURE", request, resource=file_row["filename"],
                    details=f"file_id={file_row['file_id']} {reason}")
    raise HTTPException(409, INTEGRITY_FAILED)


@router.get("/{file_id}")
def download(file_id: str, request: Request, user=Depends(require("download_file")), conn=Depends(get_db)):
    f = conn.execute("SELECT * FROM files WHERE file_id = ?", (file_id,)).fetchone()
    if f is None:
        raise HTTPException(404, "File not found")

    # Authorization: only the owner or a recipient of this file
    me = user["user_id"]
    is_recipient = conn.execute("SELECT 1 FROM shares WHERE file_id = ? AND recipient_id = ?",
                                (file_id, me)).fetchone()
    if f["owner"] != me and not is_recipient:
        deny(conn, request, f"file {f['filename']} not shared with user")

    if f["status"] == "integrity_failed":
        raise HTTPException(409, INTEGRITY_FAILED)

    # Decrypt (GCM tag = authentication) then compare SHA-256 with the original hash
    try:
        data = crypto.decrypt(_blob_path(file_id).read_bytes(), file_id.encode())
    except FileNotFoundError:
        _integrity_failure(conn, request, f, "stored blob missing")
    except crypto.InvalidTag:
        _integrity_failure(conn, request, f, "AES-GCM authentication tag mismatch (blob modified)")
    if crypto.sha256_hex(data) != f["sha256"]:
        _integrity_failure(conn, request, f, "SHA-256 mismatch after decryption")

    if is_recipient:
        conn.execute("UPDATE shares SET status = 'downloaded' WHERE file_id = ? AND recipient_id = ?",
                     (file_id, me))
    audit.log_event(conn, "FILE_DOWNLOAD", "SUCCESS", request, resource=f["filename"],
                    details=f"file_id={file_id}")
    return Response(
        content=data,
        media_type=f["mime_type"],
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(f['filename'])}",
            "X-File-SHA256": f["sha256"],
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


class IntegrityReport(BaseModel):
    client_sha256: str = Field(min_length=64, max_length=64)


@router.post("/{file_id}/integrity-report")
def integrity_report(file_id: str, body: IntegrityReport, request: Request,
                     user=Depends(require("download_file")), conn=Depends(get_db)):
    """Called by the browser when its post-download SHA-256 does not match the original hash."""
    f = conn.execute("SELECT filename, sha256 FROM files WHERE file_id = ?", (file_id,)).fetchone()
    if f is None:
        raise HTTPException(404, "File not found")
    ok = body.client_sha256.lower() == f["sha256"]
    audit.log_event(conn, "INTEGRITY_FAILURE" if not ok else "INTEGRITY_VERIFIED",
                    "FAILURE" if not ok else "SUCCESS", request, resource=f["filename"],
                    details=f"file_id={file_id} client-side post-transfer check")
    return {"verified": ok}
