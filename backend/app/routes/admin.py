"""Administrator functions (PRD 5.1): users, roles, file types, sessions, audit log, dashboard."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import audit, config
from ..db import get_db, now_iso, transaction
from ..security import filecheck, sessions
from ..security.passwords import hash_password
from ..security.rbac import require

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _admin_action(conn, request, resource, details):
    audit.log_event(conn, "ADMIN_ACTION", "SUCCESS", request, resource=resource, details=details)


def _role_id(conn, role_name):
    row = conn.execute("SELECT role_id FROM roles WHERE name = ?", (role_name,)).fetchone()
    if row is None:
        raise HTTPException(400, f"Unknown role '{role_name}'")
    return row["role_id"]


def _check_password(pw):
    if len(pw) < config.MIN_PASSWORD_LENGTH:
        raise HTTPException(400, f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters")


# ---------- Users (FR-01) ----------

class UserIn(BaseModel):
    user_id: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    name: str = Field(min_length=1, max_length=100)
    company_profile: str = Field(default=config.COMPANY_NAME, min_length=1, max_length=100)
    department: str = Field(min_length=1, max_length=100)
    role: str
    password: str
    status: Literal["active", "disabled"] = "active"


class UserPatch(BaseModel):
    name: str | None = None
    department: str | None = None
    role: str | None = None
    password: str | None = None
    status: Literal["active", "disabled"] | None = None   # "active" also unlocks a locked account


@router.get("/users")
def list_users(user=Depends(require("manage_users")), conn=Depends(get_db)):
    sessions.expire_stale(conn)
    rows = conn.execute(
        """SELECT u.user_id, u.name, u.company_profile, u.department, r.name AS role, u.status,
                  u.failed_logins, u.created_at,
                  (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.user_id AND s.status = 'active')
                      AS active_sessions
           FROM users u JOIN roles r ON r.role_id = u.role_id ORDER BY u.user_id"""
    ).fetchall()
    return [dict(r) for r in rows]


@router.post("/users")
def create_user(body: UserIn, request: Request, user=Depends(require("manage_users")), conn=Depends(get_db)):
    _check_password(body.password)
    if conn.execute("SELECT 1 FROM users WHERE user_id = ?", (body.user_id,)).fetchone():
        raise HTTPException(409, "User ID already exists")
    conn.execute(
        """INSERT INTO users (user_id, name, company_profile, department, role_id, password_hash, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (body.user_id, body.name, body.company_profile, body.department, _role_id(conn, body.role),
         hash_password(body.password), body.status, now_iso()),
    )
    _admin_action(conn, request, f"user:{body.user_id}", f"created user with role {body.role}")
    return {"ok": True}


@router.patch("/users/{user_id}")
def update_user(user_id: str, body: UserPatch, request: Request,
                user=Depends(require("manage_users")), conn=Depends(get_db)):
    target = conn.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if target is None:
        raise HTTPException(404, "User not found")
    if user_id == user["user_id"] and (body.status == "disabled" or body.role):
        raise HTTPException(400, "You cannot disable yourself or change your own role")
    changes = []
    if body.name:
        conn.execute("UPDATE users SET name = ? WHERE user_id = ?", (body.name, user_id))
        changes.append("name")
    if body.department:
        conn.execute("UPDATE users SET department = ? WHERE user_id = ?", (body.department, user_id))
        changes.append("department")
    if body.role:
        conn.execute("UPDATE users SET role_id = ? WHERE user_id = ?", (_role_id(conn, body.role), user_id))
        changes.append(f"role={body.role}")
    if body.password:
        _check_password(body.password)
        conn.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (hash_password(body.password), user_id))
        changes.append("password reset")
    if body.status:
        conn.execute("UPDATE users SET status = ?, failed_logins = 0 WHERE user_id = ?", (body.status, user_id))
        changes.append(f"status={body.status}")
        if body.status == "disabled":
            sessions.revoke_all(conn, user_id, request, "account disabled")
    _admin_action(conn, request, f"user:{user_id}", "updated " + ", ".join(changes or ["nothing"]))
    return {"ok": True}


# ---------- Roles & permissions (FR-08) ----------

class RoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    permissions: list[str] = []


def _check_permissions(perms):
    unknown = set(perms) - set(config.ALL_PERMISSIONS)
    if unknown:
        raise HTTPException(400, f"Unknown permissions: {', '.join(sorted(unknown))}")


@router.get("/roles")
def list_roles(user=Depends(require("manage_users")), conn=Depends(get_db)):
    roles = conn.execute("SELECT role_id, name FROM roles ORDER BY role_id").fetchall()
    return {
        "all_permissions": config.ALL_PERMISSIONS,
        "roles": [
            {"role_id": r["role_id"], "name": r["name"], "editable": r["name"] != config.ADMIN_ROLE,
             "permissions": sorted(p["permission"] for p in conn.execute(
                 "SELECT permission FROM role_permissions WHERE role_id = ?", (r["role_id"],)))}
            for r in roles
        ],
    }


@router.post("/roles")
def create_role(body: RoleIn, request: Request, user=Depends(require("manage_roles")), conn=Depends(get_db)):
    _check_permissions(body.permissions)
    if conn.execute("SELECT 1 FROM roles WHERE name = ?", (body.name,)).fetchone():
        raise HTTPException(409, "Role already exists")
    with transaction(conn):
        role_id = conn.execute("INSERT INTO roles (name) VALUES (?)", (body.name,)).lastrowid
        conn.executemany("INSERT INTO role_permissions VALUES (?, ?)", [(role_id, p) for p in set(body.permissions)])
    _admin_action(conn, request, f"role:{body.name}", f"created with {sorted(body.permissions)}")
    return {"ok": True}


@router.put("/roles/{role_id}")
def set_role_permissions(role_id: int, body: RoleIn, request: Request,
                         user=Depends(require("manage_roles")), conn=Depends(get_db)):
    _check_permissions(body.permissions)
    role = conn.execute("SELECT name FROM roles WHERE role_id = ?", (role_id,)).fetchone()
    if role is None:
        raise HTTPException(404, "Role not found")
    if role["name"] == config.ADMIN_ROLE:
        raise HTTPException(400, "The Administrator role always has every permission")
    with transaction(conn):
        conn.execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))
        conn.executemany("INSERT INTO role_permissions VALUES (?, ?)", [(role_id, p) for p in set(body.permissions)])
    _admin_action(conn, request, f"role:{role['name']}", f"permissions set to {sorted(body.permissions)}")
    return {"ok": True}


# ---------- Allowed file types (FR-14) ----------

class FileTypePatch(BaseModel):
    enabled: bool | None = None
    browser_compatible: bool | None = None


@router.get("/file-types")
def list_file_types(user=Depends(require("manage_file_types")), conn=Depends(get_db)):
    return [dict(r) for r in conn.execute("SELECT * FROM allowed_file_types ORDER BY category, ext")]


@router.patch("/file-types/{ext}")
def update_file_type(ext: str, body: FileTypePatch, request: Request,
                     user=Depends(require("manage_file_types")), conn=Depends(get_db)):
    if ext not in filecheck.SUPPORTED_EXTENSIONS:
        raise HTTPException(404, "Unsupported file type")
    if body.enabled is not None:
        conn.execute("UPDATE allowed_file_types SET enabled = ? WHERE ext = ?", (int(body.enabled), ext))
    if body.browser_compatible is not None:
        conn.execute("UPDATE allowed_file_types SET browser_compatible = ? WHERE ext = ?",
                     (int(body.browser_compatible), ext))
    _admin_action(conn, request, f"file-type:{ext}", body.model_dump_json(exclude_none=True))
    return {"ok": True}


# ---------- Sessions (FR-07) ----------

@router.get("/sessions")
def all_sessions(user=Depends(require("manage_sessions")), conn=Depends(get_db)):
    sessions.expire_stale(conn)
    rows = conn.execute(
        """SELECT session_id, user_id, device_id, device_label, created_at, last_activity, expires_at
           FROM sessions WHERE status = 'active' ORDER BY user_id, created_at"""
    ).fetchall()
    return [dict(r) for r in rows]


@router.delete("/sessions/{session_id}")
def admin_revoke_session(session_id: str, request: Request,
                         user=Depends(require("manage_sessions")), conn=Depends(get_db)):
    if not sessions.revoke(conn, session_id, request, "revoked by administrator"):
        raise HTTPException(404, "No active session with that ID")
    _admin_action(conn, request, f"session:{session_id[:12]}", "revoked session")
    return {"ok": True}


@router.delete("/users/{user_id}/sessions")
def admin_revoke_all(user_id: str, request: Request,
                     user=Depends(require("manage_sessions")), conn=Depends(get_db)):
    count = sessions.revoke_all(conn, user_id, request)
    _admin_action(conn, request, f"user:{user_id}", f"revoked all sessions ({count})")
    return {"revoked": count}


# ---------- Audit log (FR-22) ----------

@router.get("/audit")
def audit_log(user_id: str | None = None, event_type: str | None = None, since: str | None = None,
              limit: int = 200, user=Depends(require("view_audit")), conn=Depends(get_db)):
    sql, params = "SELECT * FROM audit_logs WHERE 1=1", []
    if user_id:
        sql += " AND user_id = ?"
        params.append(user_id)
    if event_type:
        sql += " AND event_type = ?"
        params.append(event_type)
    if since:
        sql += " AND timestamp >= ?"
        params.append(since)
    sql += " ORDER BY event_id DESC LIMIT ?"
    params.append(max(1, min(limit, 1000)))
    return [dict(r) for r in conn.execute(sql, params)]


# ---------- Security dashboard (PRD section 21) ----------

@router.get("/dashboard")
def dashboard(capture_id: int | None = None, user=Depends(require("view_dashboard")), conn=Depends(get_db)):
    sessions.expire_stale(conn)

    def one(sql, *params):
        return conn.execute(sql, params).fetchone()[0]

    def events(event_type, result=None):
        if result:
            return one("SELECT COUNT(*) FROM audit_logs WHERE event_type = ? AND result = ?", event_type, result)
        return one("SELECT COUNT(*) FROM audit_logs WHERE event_type = ?", event_type)

    captures = [dict(r) for r in conn.execute("SELECT * FROM captures ORDER BY capture_id DESC")]
    selected = next((c for c in captures if c["capture_id"] == capture_id), captures[0] if captures else None)
    sec_events = []
    if selected:
        sec_events = [dict(r) for r in conn.execute(
            """SELECT * FROM security_events WHERE capture_id = ?
               ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, count DESC""",
            (selected["capture_id"],))]

    return {
        "users": {
            "active_users": one("SELECT COUNT(*) FROM users WHERE status = 'active'"),
            "active_sessions": one("SELECT COUNT(*) FROM sessions WHERE status = 'active'"),
            "locked_accounts": one("SELECT COUNT(*) FROM users WHERE status = 'locked'"),
            "disabled_accounts": one("SELECT COUNT(*) FROM users WHERE status = 'disabled'"),
        },
        "sessions": {
            "current_sessions": one("SELECT COUNT(*) FROM sessions WHERE status = 'active'"),
            "device_count": one("SELECT COUNT(DISTINCT device_id) FROM sessions WHERE status = 'active'"),
            "expired_sessions": one("SELECT COUNT(*) FROM sessions WHERE status = 'expired'"),
        },
        "files": {
            "uploads": events("FILE_UPLOAD", "SUCCESS"),
            "downloads": events("FILE_DOWNLOAD", "SUCCESS"),
            "rejected_files": events("INVALID_FILE_TYPE"),
            "integrity_failures": events("INTEGRITY_FAILURE"),
        },
        "network": {
            "capture": selected,
            "packets_analyzed": selected["packet_count"] if selected else 0,
            "connections": selected["connections"] if selected else 0,
            "failed_connections": selected["failed_connections"] if selected else 0,
            "suspicious_events": len(sec_events),
        },
        "security": {
            "failed_logins": events("LOGIN_FAILED"),
            "unauthorized_requests": events("ACCESS_DENIED"),
            "external_access_attempts": events("EXTERNAL_ACCESS_ATTEMPT"),
            "rate_limited": events("RATE_LIMITED"),
            "security_alerts": sec_events,
        },
        "captures": captures,
    }
