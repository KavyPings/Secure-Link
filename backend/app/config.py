"""All tunable settings. Every value can be overridden with an environment variable (SL_<NAME>)."""
import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = BACKEND_DIR.parent


def _env(name, default):
    return os.getenv(f"SL_{name}", default)


def _int(name, default):
    return int(_env(name, default))


def _bool(name, default):
    return str(_env(name, default)).lower() in ("1", "true", "yes", "on")


def _list(name, default):
    return [item.strip() for item in _env(name, default).split(",") if item.strip()]


# --- Paths ---
DATA_DIR = Path(_env("DATA_DIR", BACKEND_DIR / "data"))
STORAGE_DIR = Path(_env("STORAGE_DIR", BACKEND_DIR / "storage"))
DB_PATH = Path(_env("DB_PATH", DATA_DIR / "securelink.db"))
KEY_FILE = Path(_env("KEY_FILE", DATA_DIR / "master.key"))
CERT_DIR = Path(_env("CERT_DIR", PROJECT_DIR / "certs"))
FRONTEND_DIST = Path(_env("FRONTEND_DIST", PROJECT_DIR / "frontend" / "dist"))

# --- Server / transport (section 17, FR-25) ---
TLS_ENABLED = _bool("TLS_ENABLED", "true")   # "false" ONLY for the lab "before security controls" capture
HOST = _env("HOST", "0.0.0.0")               # set to the server's LAN IP to bind one interface only
PORT = _int("PORT", 8443 if TLS_ENABLED else 8080)
COMPANY_NAME = _env("COMPANY_NAME", "SecureLink Corp")

# --- Sessions (FR-04 .. FR-07) ---
SESSION_LIFETIME_MIN = _int("SESSION_LIFETIME_MIN", 480)      # 8 hours
INACTIVITY_TIMEOUT_MIN = _int("INACTIVITY_TIMEOUT_MIN", 30)
MAX_SESSIONS_PER_USER = _int("MAX_SESSIONS_PER_USER", 2)
SESSION_LIMIT_POLICY = _env("SESSION_LIMIT_POLICY", "reject")  # "reject" | "revoke_oldest"
SESSION_COOKIE = "sl_session"

# --- Accounts ---
LOCKOUT_THRESHOLD = _int("LOCKOUT_THRESHOLD", 5)
MIN_PASSWORD_LENGTH = _int("MIN_PASSWORD_LENGTH", 8)

# --- Company-only access + availability (FR-10, FR-11, SR-05) ---
TRUSTED_NETWORKS = _list(
    "TRUSTED_NETWORKS",
    "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
)
RATE_LIMIT_PER_MIN = _int("RATE_LIMIT_PER_MIN", 120)
LOGIN_RATE_LIMIT_PER_MIN = _int("LOGIN_RATE_LIMIT_PER_MIN", 10)

# --- Files (FR-14 .. FR-19) ---
MAX_UPLOAD_MB = _int("MAX_UPLOAD_MB", 100)
MAX_MESSAGE_CHARS = _int("MAX_MESSAGE_CHARS", 5000)

# --- Permissions (FR-08 / FR-09) ---
ALL_PERMISSIONS = [
    "send_message",
    "upload_file",
    "share_file",
    "download_file",
    "manage_users",
    "manage_roles",
    "manage_file_types",
    "manage_sessions",
    "view_audit",
    "view_dashboard",
]
EMPLOYEE_PERMISSIONS = ["send_message", "upload_file", "share_file", "download_file"]
DEFAULT_ROLES = ["Administrator", "Developer", "HR", "Finance", "Manager", "IT"]
ADMIN_ROLE = "Administrator"
