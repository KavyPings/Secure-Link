"""Server-side sessions (FR-04 .. FR-07).

The browser holds a random token in an HttpOnly cookie; the database stores only SHA-256(token).
A "device" is the random device_id the browser keeps in localStorage.
"""
import hashlib
import secrets

from .. import audit, config
from ..db import now_iso


class SessionLimitReached(Exception):
    pass


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def expire_stale(conn, user_id=None):
    """Mark sessions past their absolute lifetime or inactivity window as expired."""
    idle_cutoff = now_iso(-config.INACTIVITY_TIMEOUT_MIN)
    sql = """UPDATE sessions SET status = 'expired'
             WHERE status = 'active' AND (expires_at <= ? OR last_activity <= ?)"""
    params = [now_iso(), idle_cutoff]
    if user_id:
        sql += " AND user_id = ?"
        params.append(user_id)
    conn.execute(sql, params)


def revoke(conn, session_id, request=None, reason="revoked"):
    updated = conn.execute(
        "UPDATE sessions SET status = 'revoked' WHERE session_id = ? AND status = 'active'",
        (session_id,),
    ).rowcount
    if updated:
        row = conn.execute("SELECT user_id, device_id FROM sessions WHERE session_id = ?",
                           (session_id,)).fetchone()
        audit.log_event(conn, "SESSION_TERMINATED", "SUCCESS", request,
                        user_id=row["user_id"], device_id=row["device_id"],
                        resource=f"session:{session_id[:12]}", details=reason)
    return bool(updated)


def revoke_all(conn, user_id, request=None, reason="revoked by administrator"):
    rows = conn.execute("SELECT session_id FROM sessions WHERE user_id = ? AND status = 'active'",
                        (user_id,)).fetchall()
    for r in rows:
        revoke(conn, r["session_id"], request, reason)
    return len(rows)


def create(conn, user_id, device_id, device_label, request=None) -> str:
    """Create a session and return the raw token. Enforces the per-user device limit."""
    expire_stale(conn, user_id)

    # Same device logging in again replaces its own session instead of using a new slot.
    same_device = conn.execute(
        "SELECT session_id FROM sessions WHERE user_id = ? AND device_id = ? AND status = 'active'",
        (user_id, device_id),
    ).fetchall()
    for r in same_device:
        revoke(conn, r["session_id"], request, "replaced by new login on same device")

    active = conn.execute(
        "SELECT session_id FROM sessions WHERE user_id = ? AND status = 'active' ORDER BY created_at, rowid",
        (user_id,),
    ).fetchall()
    if len(active) >= config.MAX_SESSIONS_PER_USER:
        if config.SESSION_LIMIT_POLICY == "revoke_oldest":
            for r in active[: len(active) - config.MAX_SESSIONS_PER_USER + 1]:
                revoke(conn, r["session_id"], request, "oldest session revoked by device limit")
        else:
            raise SessionLimitReached()

    token = secrets.token_urlsafe(32)
    now = now_iso()
    conn.execute(
        """INSERT INTO sessions (session_id, user_id, device_id, device_label,
                                 created_at, last_activity, expires_at, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'active')""",
        (_hash(token), user_id, device_id, device_label, now, now,
         now_iso(config.SESSION_LIFETIME_MIN)),
    )
    return token


def validate(conn, token: str | None, background: bool):
    """Return the active session row, or None if missing/expired/revoked.

    Background requests (message polling) do not count as user activity, otherwise the
    inactivity timeout could never fire while a tab is open.
    """
    if not token:
        return None
    session_id = _hash(token)
    row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    if row is None or row["status"] != "active":
        return None
    now = now_iso()
    if row["expires_at"] <= now or row["last_activity"] <= now_iso(-config.INACTIVITY_TIMEOUT_MIN):
        conn.execute("UPDATE sessions SET status = 'expired' WHERE session_id = ?", (session_id,))
        audit.log_event(conn, "SESSION_EXPIRED", "SUCCESS", user_id=row["user_id"],
                        device_id=row["device_id"], resource=f"session:{session_id[:12]}")
        return None
    if not background:
        conn.execute("UPDATE sessions SET last_activity = ? WHERE session_id = ?", (now, session_id))
    return row


def session_id_from_token(token: str) -> str:
    return _hash(token)
