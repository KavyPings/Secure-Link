"""Generate controlled abnormal traffic while Wireshark is capturing (FR-23, FR-26).

    python scripts/attack_sim.py --server https://192.168.1.20:8443 --ca certs/ca.crt

Steps (each produces audit events and packet patterns that analysis/detect.py looks for):
  1. failed-logins    repeated wrong passwords          -> LOGIN_FAILED, HTTP 401 burst, lockout
  2. unauthorized     admin API without a session        -> 401 responses
  3. request-burst    many new connections in seconds    -> high request rate / rate limiting (429)
  4. unexpected-port  TCP connection attempts to closed ports -> failed connections, unexpected port
Run it only against your own lab server.
"""
import argparse
import socket
import time
from urllib.parse import urlparse

import requests

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--server", required=True)
parser.add_argument("--ca", default=None, help="path to certs/ca.crt (TLS mode)")
parser.add_argument("--user", default="victim_user", help="account to target with wrong passwords")
parser.add_argument("--attempts", type=int, default=8)
parser.add_argument("--burst", type=int, default=150, help="> RATE_LIMIT_PER_MIN triggers 429")
args = parser.parse_args()

verify = args.ca if args.ca else True
base = args.server.rstrip("/")
host = urlparse(base).hostname


def fresh_get(path):
    """New TCP connection per request (no keep-alive) so connection-rate rules can see it."""
    try:
        return requests.get(base + path, verify=verify, timeout=5, headers={"Connection": "close"}).status_code
    except requests.RequestException as exc:
        return type(exc).__name__


print("1. failed logins")
for i in range(args.attempts):
    r = requests.post(base + "/api/auth/login", verify=verify, timeout=5, headers={"Connection": "close"},
                      json={"user_id": args.user, "password": f"wrong-{i}", "device_id": "attack-sim-0001"})
    print(f"   attempt {i + 1}: {r.status_code}")

print("2. unauthorized API access")
for path in ("/api/admin/users", "/api/admin/audit", "/api/files"):
    print(f"   GET {path}: {fresh_get(path)}")

print(f"3. request burst ({args.burst} new connections)")
codes = [fresh_get("/api/auth/me") for _ in range(args.burst)]
print("   status codes:", {c: codes.count(c) for c in set(codes)})

print("4. connection attempts to unexpected ports")
for port in (21, 22, 23, 3389, 5432):
    s = socket.socket()
    s.settimeout(1)
    result = s.connect_ex((host, port))
    s.close()
    print(f"   port {port}: {'open' if result == 0 else 'closed/filtered'}")
    time.sleep(0.1)

print("done - stop the capture and run analysis/pcap_to_sqlite.py")
