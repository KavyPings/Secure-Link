"""Rule-based traffic analysis over imported packets (FR-26). Writes security_events + risk_score.

    python analysis/detect.py <capture_id> [--server-ip IP] [--port 8443]

Rules (thresholds are command-line options):
  repeated_failed_connections  >= N failed TCP connections from one source in 60 s
  high_request_rate            >= N new connections or HTTP requests from one source in 10 s
  unexpected_protocol          non-TCP traffic sent to the server (the intranet only uses TCP)
  unexpected_port              traffic sent to a server port other than the app port
  large_traffic_burst          >= N bytes from one source in 1 s
  repeated_auth_failures       >= N HTTP 401 responses to one client in 60 s
                               (needs a plaintext capture or a TLS key log; HTTPS hides status codes)
"""
import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from app.db import connect, transaction  # noqa: E402

SYN, RST, ACK = 0x02, 0x04, 0x10
WEIGHT = {"low": 10, "medium": 25, "high": 40}

DEFAULTS = {
    "failed_conn": 5,
    "conn_rate": 20,
    "burst_bytes": 5_000_000,
    "auth_failures": 5,
}


def flag_bits(flags):
    try:
        return int(flags, 16) if flags else 0
    except ValueError:
        return 0


def streams(conn, capture_id):
    """Per-connection summary: who opened it, when, and whether it succeeded."""
    out = {}
    for p in conn.execute(
        """SELECT stream_id, timestamp, source_ip, destination_ip, destination_port, flags, payload_size
           FROM network_packets WHERE capture_id = ? AND transport = 'TCP' ORDER BY timestamp""",
        (capture_id,),
    ):
        s = out.setdefault(p["stream_id"], {"client": None, "start": p["timestamp"], "syn": False,
                                            "synack": False, "rst": False, "payload": 0, "dport": None})
        bits = flag_bits(p["flags"])
        if bits & SYN and not bits & ACK:
            s.update(syn=True, client=p["source_ip"], start=p["timestamp"], dport=p["destination_port"])
        if bits & SYN and bits & ACK:
            s["synack"] = True
        if bits & RST:
            s["rst"] = True
        s["payload"] += p["payload_size"] or 0
    for s in out.values():
        s["failed"] = (s["syn"] and not s["synack"]) or (s["rst"] and s["payload"] == 0)
    return out


def capture_stats(conn, capture_id):
    row = conn.execute(
        """SELECT COUNT(*) AS packets, COALESCE(SUM(packet_size), 0) AS wire, COALESCE(SUM(payload_size), 0) AS payload,
                  COALESCE(SUM(sensitive), 0) AS exposures
           FROM network_packets WHERE capture_id = ?""",
        (capture_id,),
    ).fetchone()
    st = streams(conn, capture_id)
    return {
        "packets": row["packets"],
        "connections": len(st),
        "failed_connections": sum(1 for s in st.values() if s["failed"]),
        "wire_bytes": row["wire"],
        "payload_bytes": row["payload"],
        "plaintext_exposures": row["exposures"],
    }


def _windows(items, size):
    """Group (source, timestamp, amount) by source and fixed time window."""
    buckets = defaultdict(int)
    for src, ts, amount in items:
        buckets[(src, int(ts // size) * size)] += amount
    return buckets


def run(conn, capture_id, server_ip, port, thresholds=None):
    t = {**DEFAULTS, **(thresholds or {})}
    events = []  # (rule, source_ip, window_start, window_len, count, severity, details, packet_filter)

    st = streams(conn, capture_id)

    # 1. Repeated failed connections
    failed = [(s["client"], s["start"], 1) for s in st.values() if s["failed"] and s["client"]]
    for (src, win), n in _windows(failed, 60).items():
        if n >= t["failed_conn"]:
            events.append(("repeated_failed_connections", src, win, 60, n, "medium",
                           f"{n} failed TCP connections in 60 s", None))

    # 2. Abnormally high request rate (new connections, plus HTTP requests when visible)
    new_conns = [(s["client"], s["start"], 1) for s in st.values() if s["syn"] and s["client"]]
    requests = [(r["source_ip"], r["timestamp"], 1) for r in conn.execute(
        "SELECT source_ip, timestamp FROM network_packets WHERE capture_id = ? AND http_request IS NOT NULL",
        (capture_id,))]
    for label, items in (("connections", new_conns), ("HTTP requests", requests)):
        for (src, win), n in _windows(items, 10).items():
            if n >= t["conn_rate"]:
                events.append(("high_request_rate", src, win, 10, n, "medium", f"{n} {label} in 10 s", None))

    # 3. Unexpected protocol (anything but TCP addressed to the server)
    for r in conn.execute(
        """SELECT source_ip, protocol, transport, COUNT(*) AS n, MIN(timestamp) AS first FROM network_packets
           WHERE capture_id = ? AND destination_ip = ? AND transport != 'TCP'
           GROUP BY source_ip, protocol, transport""",
        (capture_id, server_ip),
    ):
        events.append(("unexpected_protocol", r["source_ip"], r["first"], None, r["n"], "low",
                       f"{r['protocol']} over {r['transport']} sent to server",
                       ("protocol = ?", r["protocol"])))

    # 4. Unexpected port (one event per source, listing the ports it tried)
    for r in conn.execute(
        """SELECT source_ip, GROUP_CONCAT(DISTINCT destination_port) AS ports, COUNT(*) AS n,
                  MIN(timestamp) AS first FROM network_packets
           WHERE capture_id = ? AND destination_ip = ? AND destination_port IS NOT NULL AND destination_port != ?
           GROUP BY source_ip""",
        (capture_id, server_ip, port),
    ):
        ports = sorted(int(p) for p in r["ports"].split(","))
        sev = "high" if set(ports) & {21, 22, 23, 445, 3389} or len(ports) >= 5 else "medium"
        events.append(("unexpected_port", r["source_ip"], r["first"], None, r["n"], sev,
                       f"{r['n']} packets to ports {', '.join(map(str, ports))} (app port is {port})",
                       ("destination_port != ?", port)))

    # 5. Large traffic burst
    sizes = [(r["source_ip"], r["timestamp"], r["packet_size"]) for r in conn.execute(
        "SELECT source_ip, timestamp, packet_size FROM network_packets WHERE capture_id = ?", (capture_id,))]
    for (src, win), n in _windows(sizes, 1).items():
        if n >= t["burst_bytes"]:
            events.append(("large_traffic_burst", src, win, 1, n, "low", f"{n / 1e6:.1f} MB in 1 s", None))

    # 6. Repeated authentication failures (HTTP 401 responses, grouped by the client receiving them)
    fails = [(r["destination_ip"], r["timestamp"], 1) for r in conn.execute(
        "SELECT destination_ip, timestamp FROM network_packets WHERE capture_id = ? AND http_status = 401",
        (capture_id,))]
    for (client, win), n in _windows(fails, 60).items():
        if n >= t["auth_failures"]:
            events.append(("repeated_auth_failures", client, win, 60, n, "high",
                           f"{n} HTTP 401 responses in 60 s", None))

    with transaction(conn):
        conn.execute("DELETE FROM security_events WHERE capture_id = ?", (capture_id,))
        conn.execute("UPDATE network_packets SET risk_score = 0 WHERE capture_id = ?", (capture_id,))
        for rule, src, win, length, count, sev, details, extra in events:
            conn.execute(
                """INSERT INTO security_events (capture_id, rule, source_ip, window_start, count, severity, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (capture_id, rule, src, win, count, sev, details),
            )
            sql = ("UPDATE network_packets SET risk_score = MIN(100, risk_score + ?) "
                   "WHERE capture_id = ? AND (source_ip = ? OR destination_ip = ?)")
            params = [WEIGHT[sev], capture_id, src, src]
            if length:
                sql += " AND timestamp >= ? AND timestamp < ?"
                params += [win, win + length]
            if extra:
                sql += f" AND {extra[0]}"
                params.append(extra[1])
            conn.execute(sql, params)

    print(f"Detection: {len(events)} security event(s) for capture #{capture_id}")
    for rule, src, _, _, count, sev, details, _ in events:
        print(f"  [{sev:6}] {rule:28} {src:16} {details}")
    return events


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("capture_id", type=int)
    parser.add_argument("--server-ip", help="default: the server IP stored with the capture")
    parser.add_argument("--port", type=int, help="default: the port stored with the capture")
    for name, value in DEFAULTS.items():
        parser.add_argument(f"--{name.replace('_', '-')}", type=int, default=value, dest=name)
    args = parser.parse_args()
    db = connect()
    cap = db.execute("SELECT server_ip, server_port FROM captures WHERE capture_id = ?", (args.capture_id,)).fetchone()
    if cap is None:
        sys.exit(f"No capture #{args.capture_id}")
    run(db, args.capture_id, args.server_ip or cap["server_ip"], args.port or cap["server_port"],
        {k: getattr(args, k) for k in DEFAULTS})
