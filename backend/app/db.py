"""SQLite access with the standard library (no ORM)."""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config

SCHEMA_FILE = Path(__file__).with_name("schema.sql")

# Type list from FR-14: (ext, MIME, category)
DEFAULT_FILE_TYPES = [
    ("pdf", "application/pdf", "document"),
    ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "document"),
    ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "document"),
    ("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "document"),
    ("txt", "text/plain", "document"),
    ("jpg", "image/jpeg", "image"),
    ("jpeg", "image/jpeg", "image"),
    ("png", "image/png", "image"),
    ("webp", "image/webp", "image"),
]


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    """Fixed-width UTC timestamps so string comparison == time comparison."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso(offset_minutes=0):
    return iso(utcnow() + timedelta(minutes=offset_minutes))


def connect(path=None):
    # Autocommit: every statement is durable before the response is sent (FastAPI runs yield-dependency
    # teardown after sending), and audit rows survive even when the request later fails.
    conn = sqlite3.connect(path or config.DB_PATH, timeout=15, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def transaction(conn):
    """Group several writes so they succeed or fail together."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def get_db():
    """FastAPI dependency: one connection per request."""
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    config.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
        with transaction(conn):
            _seed(conn)
    finally:
        conn.close()


def _seed(conn):
    if conn.execute("SELECT COUNT(*) FROM roles").fetchone()[0] == 0:
        for name in config.DEFAULT_ROLES:
            role_id = conn.execute("INSERT INTO roles (name) VALUES (?)", (name,)).lastrowid
            perms = config.ALL_PERMISSIONS if name == config.ADMIN_ROLE else config.EMPLOYEE_PERMISSIONS
            conn.executemany(
                "INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)",
                [(role_id, p) for p in perms],
            )
    if conn.execute("SELECT COUNT(*) FROM allowed_file_types").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO allowed_file_types (ext, mime, category) VALUES (?, ?, ?)",
            DEFAULT_FILE_TYPES,
        )
