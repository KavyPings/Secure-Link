"""Bootstrap the first administrator account (there is no public registration, FR-01).

    python scripts/init_admin.py --user-id admin --name "System Administrator" --department IT
"""
import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from app import config  # noqa: E402
from app.db import connect, init_db, now_iso  # noqa: E402
from app.security.passwords import hash_password  # noqa: E402

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--user-id", default="admin")
parser.add_argument("--name", default="System Administrator")
parser.add_argument("--department", default="IT")
parser.add_argument("--password", help="omit to be prompted (recommended)")
args = parser.parse_args()

init_db()
password = args.password or getpass.getpass("New admin password: ")
if len(password) < config.MIN_PASSWORD_LENGTH:
    sys.exit(f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters")

conn = connect()
role_id = conn.execute("SELECT role_id FROM roles WHERE name = ?", (config.ADMIN_ROLE,)).fetchone()[0]
if conn.execute("SELECT 1 FROM users WHERE user_id = ?", (args.user_id,)).fetchone():
    sys.exit(f"User '{args.user_id}' already exists")
conn.execute(
    """INSERT INTO users (user_id, name, company_profile, department, role_id, password_hash, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'active', ?)""",
    (args.user_id, args.name, config.COMPANY_NAME, args.department, role_id, hash_password(password), now_iso()),
)
conn.execute(
    """INSERT INTO audit_logs (user_id, event_type, resource, timestamp, result, details)
       VALUES (?, 'ADMIN_ACTION', ?, ?, 'SUCCESS', 'bootstrap administrator created from console')""",
    (args.user_id, f"user:{args.user_id}", now_iso()),
)
conn.commit()
conn.close()
print(f"Administrator '{args.user_id}' created.")
