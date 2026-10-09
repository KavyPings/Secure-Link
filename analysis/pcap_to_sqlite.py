"""PCAP/PCAPNG -> PyShark -> packet extraction -> filtering -> feature extraction -> SQLite (FR-24).

    python analysis/pcap_to_sqlite.py capture.pcapng --label after-tls
    python analysis/pcap_to_sqlite.py before.pcapng --label before-http --mode http --port 8080
    python analysis/pcap_to_sqlite.py after.pcapng --label after-keylog --keylog sslkeys.log

Requires Wireshark/tshark installed (PyShark drives tshark).
Results go into the same SQLite database the intranet uses, so the admin dashboard shows them.
After import, the detection rules in detect.py run automatically (disable with --no-detect).
"""
import argparse
import socket
import sys
from pathlib import Path

import pyshark

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from app import config  # noqa: E402
from app.db import connect, init_db, now_iso, transaction  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detect  # noqa: E402

# Byte patterns that mean application secrets/content are readable on the wire (FR-25 before/after).
SENSITIVE_MARKERS = [b'"password"', b"password=", b'name="file"', b'"content"', b"sl_session="]


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def field(layer, name):
    try:
        value = layer.get_field_value(name)
    except AttributeError:
        return None
    return None if value is None else str(value)


def hex_bytes(value):
    if not value:
        return b""
    try:
        return bytes.fromhex(value.replace(":", ""))
    except ValueError:
        return b""


def extract(pkt):
    """One packet -> one network_packets row (feature extraction)."""
    ip = getattr(pkt, "ip", None) or getattr(pkt, "ipv6", None)
    if ip is None:
        return None
    transport = pkt.transport_layer  # 'TCP', 'UDP' or None (e.g. ICMP)
    row = {
        "timestamp": float(pkt.sniff_timestamp),
        "source_ip": ip.src,
        "destination_ip": ip.dst,
        "protocol": pkt.highest_layer,
        "transport": transport or ip.get_field_value("proto") or "OTHER",
        "source_port": None,
        "destination_port": None,
        "packet_size": int(pkt.length),
        "payload_size": 0,
        "flags": None,
        "stream_id": None,
        "http_request": None,
        "http_status": None,
        "sensitive": 0,
    }
    raw = b""
    if transport == "TCP":
        tcp = pkt.tcp
        row["source_port"], row["destination_port"] = int(tcp.srcport), int(tcp.dstport)
        row["flags"] = field(tcp, "flags")
        row["stream_id"] = int(tcp.stream)
        row["payload_size"] = int(field(tcp, "len") or 0)
        raw = hex_bytes(field(tcp, "payload"))
    elif transport == "UDP":
        udp = pkt.udp
        row["source_port"], row["destination_port"] = int(udp.srcport), int(udp.dstport)
        row["payload_size"] = max(int(udp.length) - 8, 0)

    http = getattr(pkt, "http", None)
    if http is not None:
        method, uri = field(http, "request_method"), field(http, "request_uri")
        if method:
            row["http_request"] = f"{method} {uri or ''}".strip()
        code = field(http, "response_code")
        row["http_status"] = int(code) if code and code.isdigit() else None
        raw += (field(http, "file_data") or "").encode(errors="ignore")
    row["sensitive"] = int(any(m in raw for m in SENSITIVE_MARKERS))
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pcap", help="Wireshark .pcap or .pcapng file")
    parser.add_argument("--label", help="name shown on the dashboard (default: file name)")
    parser.add_argument("--server-ip", default=None, help="intranet server IP (default: this machine's LAN IP)")
    parser.add_argument("--port", type=int, default=None, help="app port (default 8443 for tls, 8080 for http)")
    parser.add_argument("--mode", choices=["tls", "http"], default="tls", help="how the server was running")
    parser.add_argument("--keylog", help="TLS key log file (SSLKEYLOGFILE) to decrypt HTTPS for analysis")
    parser.add_argument("--db", default=str(config.DB_PATH))
    parser.add_argument("--no-detect", action="store_true")
    args = parser.parse_args()

    server_ip = args.server_ip or lan_ip()
    port = args.port or (8443 if args.mode == "tls" else 8080)
    ip_field = "ipv6.addr" if ":" in server_ip else "ip.addr"

    # Filtering: only traffic to/from the intranet server
    capture = pyshark.FileCapture(
        args.pcap,
        display_filter=f"{ip_field} == {server_ip}",
        decode_as={f"tcp.port=={port}": "tls" if args.mode == "tls" else "http"},
        override_prefs={"tls.keylog_file": str(Path(args.keylog).resolve())} if args.keylog else None,
        keep_packets=False,
    )

    if args.db != str(config.DB_PATH):
        config.DB_PATH = Path(args.db)
    init_db()
    conn = connect()
    capture_id = conn.execute(
        "INSERT INTO captures (label, filename, imported_at, mode, server_ip, server_port) VALUES (?, ?, ?, ?, ?, ?)",
        (args.label or Path(args.pcap).name, Path(args.pcap).name, now_iso(), args.mode, server_ip, port),
    ).lastrowid

    columns = ["capture_id", "timestamp", "source_ip", "destination_ip", "protocol", "transport", "source_port",
               "destination_port", "packet_size", "payload_size", "flags", "stream_id", "http_request",
               "http_status", "sensitive"]
    sql = f"INSERT INTO network_packets ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))})"
    batch, total = [], 0
    try:
        for pkt in capture:
            row = extract(pkt)
            if row is None:
                continue
            batch.append([capture_id] + [row[c] for c in columns[1:]])
            if len(batch) >= 1000:
                with transaction(conn):
                    conn.executemany(sql, batch)
                total += len(batch)
                batch.clear()
                print(f"\r{total} packets...", end="", flush=True)
        if batch:
            with transaction(conn):
                conn.executemany(sql, batch)
            total += len(batch)
    finally:
        capture.close()

    stats = detect.capture_stats(conn, capture_id)
    conn.execute(
        """UPDATE captures SET packet_count = ?, connections = ?, failed_connections = ?, wire_bytes = ?,
                               payload_bytes = ?, plaintext_exposures = ? WHERE capture_id = ?""",
        (stats["packets"], stats["connections"], stats["failed_connections"], stats["wire_bytes"],
         stats["payload_bytes"], stats["plaintext_exposures"], capture_id),
    )
    print(f"\rImported capture #{capture_id}: {total} packets for server {server_ip}:{port} ({args.mode})")
    overhead = (stats["wire_bytes"] / stats["payload_bytes"] - 1) * 100 if stats["payload_bytes"] else 0
    print(f"  connections={stats['connections']} failed={stats['failed_connections']} "
          f"wire={stats['wire_bytes']}B payload={stats['payload_bytes']}B overhead={overhead:.1f}% "
          f"plaintext_exposures={stats['plaintext_exposures']}")

    if not args.no_detect:
        detect.run(conn, capture_id, server_ip, port)
    conn.close()


if __name__ == "__main__":
    main()
