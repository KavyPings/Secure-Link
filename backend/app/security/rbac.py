"""Authentication + authorization dependencies (FR-08, FR-09).

Every protected route runs: authenticated? -> user active? -> permission? -> (route checks resource).
"""
from fastapi import Depends, HTTPException, Request

from .. import audit, config
from ..db import get_db
from . import sessions

SESSION_EXPIRED = "Session expired. Please log in again"
FORBIDDEN = "403 Forbidden"


def load_permissions(conn, role_id):
    return {r["permission"] for r in conn.execute(
        "SELECT permission FROM role_permissions WHERE role_id = ?", (role_id,))}


def current_user(request: Request, conn=Depends(get_db)):
    token = request.cookies.get(config.SESSION_COOKIE)
    background = request.headers.get("X-Background") == "1"
    session = sessions.validate(conn, token, background)
    if session is None:
        raise HTTPException(401, SESSION_EXPIRED)

    user = conn.execute(
        """SELECT u.user_id, u.name, u.department, u.company_profile, u.status, u.role_id,
                  r.name AS role
           FROM users u JOIN roles r ON r.role_id = u.role_id WHERE u.user_id = ?""",
        (session["user_id"],),
    ).fetchone()
    if user is None or user["status"] != "active":
        sessions.revoke(conn, session["session_id"], request, "account not active")
        raise HTTPException(401, SESSION_EXPIRED)

    principal = {
        "user_id": user["user_id"],
        "name": user["name"],
        "department": user["department"],
        "company_profile": user["company_profile"],
        "role": user["role"],
        "permissions": sorted(load_permissions(conn, user["role_id"])),
        "session_id": session["session_id"],
        "device_id": session["device_id"],
    }
    request.state.principal = principal  # lets audit.log_event attribute the request
    return principal


def deny(conn, request, details=None):
    audit.log_event(conn, "ACCESS_DENIED", "DENIED", request, details=details)
    raise HTTPException(403, FORBIDDEN)


def require(permission):
    def checker(request: Request, user=Depends(current_user), conn=Depends(get_db)):
        if permission not in user["permissions"]:
            deny(conn, request, f"missing permission {permission}")
        return user
    return checker
