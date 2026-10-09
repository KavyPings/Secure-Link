"""Company-only network restriction and request rate limiting (FR-10, FR-11, SR-05).

Network location never grants access by itself; it is an extra gate in front of login + RBAC.
"""
import ipaddress
import time
from collections import defaultdict, deque

from fastapi.responses import JSONResponse

from .. import audit, config
from ..db import connect

_trusted = [ipaddress.ip_network(n, strict=False) for n in config.TRUSTED_NETWORKS]
_hits = defaultdict(deque)          # (bucket, ip) -> request timestamps in the last 60 s
_last_logged = {}                   # (bucket, ip) -> last time a RATE_LIMITED event was written


def is_trusted(host: str | None) -> bool:
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in net for net in _trusted)


def _over_limit(bucket, ip, limit, now):
    q = _hits[(bucket, ip)]
    while q and q[0] <= now - 60:
        q.popleft()
    q.append(now)
    return len(q) > limit


def _log(request, event_type, result, details=None):
    conn = connect()
    try:
        audit.log_event(conn, event_type, result, request, details=details)
        conn.commit()
    finally:
        conn.close()


async def netguard_middleware(request, call_next):
    ip = request.client.host if request.client else None

    if not is_trusted(ip):
        _log(request, "EXTERNAL_ACCESS_ATTEMPT", "BLOCKED", "source outside trusted networks")
        return JSONResponse({"detail": "Access restricted to the company network"}, status_code=403)

    path = request.url.path
    if path.startswith("/api/"):
        now = time.monotonic()
        is_login = path == "/api/auth/login" and request.method == "POST"
        bucket, limit = ("login", config.LOGIN_RATE_LIMIT_PER_MIN) if is_login else ("api", config.RATE_LIMIT_PER_MIN)
        if _over_limit(bucket, ip, limit, now):
            if now - _last_logged.get((bucket, ip), -60) >= 60:   # one audit row per IP per minute
                _last_logged[(bucket, ip)] = now
                _log(request, "RATE_LIMITED", "BLOCKED", f"{bucket} limit {limit}/min exceeded")
            return JSONResponse({"detail": "Too many requests. Slow down and retry shortly."},
                                status_code=429)

    return await call_next(request)
