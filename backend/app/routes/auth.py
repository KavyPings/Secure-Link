"""Login / logout / current user (FR-03, FR-07)."""
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import audit, config
from ..db import get_db
from ..security import sessions
from ..security.passwords import verify_password
from ..security.rbac import current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])

LOGIN_FAILED = "Login failed"


class LoginIn(BaseModel):
    user_id: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    device_id: str = Field(min_length=8, max_length=64)


def device_label(user_agent: str) -> str:
    ua = user_agent or ""
    os_name = next((n for k, n in [("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"),
                                   ("Windows", "Windows"), ("Mac OS", "macOS"), ("Linux", "Linux")]
                    if k in ua), "Unknown OS")
    browser = next((n for k, n in [("Edg/", "Edge"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
                                   ("Safari/", "Safari"), ("python-requests", "Script")]
                    if k in ua), "Browser")
    return f"{browser} on {os_name}"


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, conn=Depends(get_db)):
    t0 = time.perf_counter()
    user = conn.execute(
        "SELECT user_id, password_hash, status, failed_logins FROM users WHERE user_id = ?",
        (body.user_id,),
    ).fetchone()

    # 1. Password hash verification (also run for unknown users to avoid a timing oracle)
    if not verify_password(user["password_hash"] if user else None, body.password):
        details = "unknown user" if user is None else "wrong password"
        if user is not None and user["status"] == "active":
            failed = user["failed_logins"] + 1
            if failed >= config.LOCKOUT_THRESHOLD:
                conn.execute("UPDATE users SET failed_logins = ?, status = 'locked' WHERE user_id = ?",
                             (failed, user["user_id"]))
                details += f"; account locked after {failed} failures"
            else:
                conn.execute("UPDATE users SET failed_logins = ? WHERE user_id = ?", (failed, user["user_id"]))
        audit.log_event(conn, "LOGIN_FAILED", "FAILURE", request, user_id=body.user_id,
                        device_id=body.device_id, details=details)
        raise HTTPException(401, LOGIN_FAILED)

    # 2. User account check
    if user["status"] != "active":
        audit.log_event(conn, "LOGIN_FAILED", "FAILURE", request, user_id=user["user_id"],
                        device_id=body.device_id, details=f"account {user['status']}")
        raise HTTPException(401, LOGIN_FAILED)
    t_auth = time.perf_counter()

    # 3. Session creation (role/permissions are loaded per request by rbac.current_user)
    try:
        token = sessions.create(conn, user["user_id"], body.device_id,
                                device_label(request.headers.get("user-agent", "")), request)
    except sessions.SessionLimitReached:
        audit.log_event(conn, "LOGIN_FAILED", "DENIED", request, user_id=user["user_id"],
                        device_id=body.device_id, details="maximum active sessions reached")
        raise HTTPException(409, "Maximum active sessions reached")
    t_session = time.perf_counter()

    conn.execute("UPDATE users SET failed_logins = 0 WHERE user_id = ?", (user["user_id"],))
    audit.log_event(conn, "LOGIN", "SUCCESS", request, user_id=user["user_id"], device_id=body.device_id)
    audit.log_event(conn, "SESSION_CREATED", "SUCCESS", request, user_id=user["user_id"],
                    device_id=body.device_id)

    response.set_cookie(
        config.SESSION_COOKIE, token,
        max_age=config.SESSION_LIFETIME_MIN * 60,
        httponly=True, secure=config.TLS_ENABLED, samesite="strict", path="/",
    )
    # Standard Server-Timing header: lets the benchmark separate auth time from session creation time.
    response.headers["Server-Timing"] = (
        f"auth;dur={(t_auth - t0) * 1000:.2f}, session;dur={(t_session - t_auth) * 1000:.2f}"
    )
    return {"ok": True}


@router.post("/logout")
def logout(request: Request, response: Response, user=Depends(current_user), conn=Depends(get_db)):
    sessions.revoke(conn, user["session_id"], request, "logout")
    audit.log_event(conn, "LOGOUT", "SUCCESS", request)
    response.delete_cookie(config.SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(user=Depends(current_user)):
    return {k: v for k, v in user.items() if k != "session_id"} | {
        "inactivity_timeout_min": config.INACTIVITY_TIMEOUT_MIN,
    }
