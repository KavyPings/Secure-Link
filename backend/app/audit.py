"""Audit trail for security-relevant actions (FR-22, SR-04). Never pass file or message content here."""
from .db import now_iso


def client_ip(request):
    return request.client.host if request and request.client else None


def log_event(conn, event_type, result, request=None, user_id=None, device_id=None,
              resource=None, details=None):
    principal = getattr(request.state, "principal", None) if request else None
    if principal is not None:
        user_id = user_id or principal["user_id"]
        device_id = device_id or principal["device_id"]
    conn.execute(
        """INSERT INTO audit_logs
           (user_id, device_id, event_type, resource, request_type, timestamp, source_ip, result, details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            user_id,
            device_id,
            event_type,
            resource if resource is not None else (request.url.path if request else None),
            request.method if request else None,
            now_iso(),
            client_ip(request),
            result,
            details,
        ),
    )
