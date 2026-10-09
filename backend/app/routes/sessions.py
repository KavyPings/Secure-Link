"""A user's own sessions (FR-07) and the company directory used to pick recipients."""
from fastapi import APIRouter, Depends, HTTPException, Request

from ..db import get_db
from ..security import sessions
from ..security.rbac import current_user, deny

router = APIRouter(prefix="/api", tags=["sessions"])


@router.get("/sessions")
def my_sessions(user=Depends(current_user), conn=Depends(get_db)):
    sessions.expire_stale(conn, user["user_id"])
    rows = conn.execute(
        """SELECT session_id, device_id, device_label, created_at, last_activity, expires_at
           FROM sessions WHERE user_id = ? AND status = 'active' ORDER BY created_at""",
        (user["user_id"],),
    ).fetchall()
    return [dict(r) | {"current": r["session_id"] == user["session_id"]} for r in rows]


@router.delete("/sessions/{session_id}")
def revoke_my_session(session_id: str, request: Request, user=Depends(current_user), conn=Depends(get_db)):
    row = conn.execute("SELECT user_id FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Session not found")
    if row["user_id"] != user["user_id"]:
        deny(conn, request, "revoke another user's session")
    sessions.revoke(conn, session_id, request, "revoked by user")
    return {"ok": True}


@router.get("/users")
def directory(user=Depends(current_user), conn=Depends(get_db)):
    """Active colleagues (no credentials or status details)."""
    rows = conn.execute(
        """SELECT u.user_id, u.name, u.department, r.name AS role
           FROM users u JOIN roles r ON r.role_id = u.role_id
           WHERE u.status = 'active' AND u.user_id != ? ORDER BY u.name""",
        (user["user_id"],),
    ).fetchall()
    return [dict(r) for r in rows]
