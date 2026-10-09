"""Performance / security-overhead measurements (PRD sections 29-30).

    python evaluation/benchmark.py --server https://192.168.1.20:8443 --ca certs/ca.crt \
        --user bench_user --password '...' [--recipient hr_bob] [--reps 3]
    python evaluation/benchmark.py --local-only            # crypto timings only, no server needed

Measures, for 10 KB / 100 KB / 1 MB / 10 MB / 50 MB / 100 MB files:
  hashing, encryption, decryption, verification time   (SecureLink's crypto module, in-process)
  upload time, download time, throughput               (real HTTPS requests to the server)
  server CPU % and memory                               (psutil on the server process; run on the server PC)
plus login response time, session creation time (Server-Timing header) and message latency.
Packet overhead comes from capturing this run in Wireshark and importing it with analysis/pcap_to_sqlite.py.

Each upload stores a new encrypted copy (about 3 x 161 MB with the defaults), so use a test account.
"""
import argparse
import csv
import hashlib
import os
import statistics
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import psutil
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from app.security import crypto  # noqa: E402

DEFAULT_SIZES_KB = [10, 100, 1024, 10240, 51200, 102400]
KEY = os.urandom(32)


def synthetic_pdf(size):
    head, tail = b"%PDF-1.4\n", b"\n%%EOF\n"
    return head + os.urandom(max(size - len(head) - len(tail), 0)) + tail


def timed(fn, *args):
    t0 = time.perf_counter()
    out = fn(*args)
    return out, (time.perf_counter() - t0) * 1000


def median_ms(fn, reps):
    return statistics.median(timed(fn)[1] for _ in range(reps))


class ResourceSampler:
    """Samples CPU % and RSS of the server process in the background during a transfer."""

    def __init__(self, proc):
        self.proc, self.cpu, self.rss, self._stop = proc, [], [], threading.Event()

    def __enter__(self):
        if self.proc:
            self.proc.cpu_percent(None)
            self._t = threading.Thread(target=self._run, daemon=True)
            self._t.start()
        return self

    def _run(self):
        while not self._stop.wait(0.1):
            try:
                self.cpu.append(self.proc.cpu_percent(None))
                self.rss.append(self.proc.memory_info().rss)
            except psutil.Error:
                return

    def __exit__(self, *exc):
        self._stop.set()


def find_server_process(port):
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.laddr and c.laddr.port == port and c.status == psutil.CONN_LISTEN and c.pid:
                return psutil.Process(c.pid)
    except (psutil.Error, PermissionError):
        pass
    return None


def local_crypto(size, reps):
    data = synthetic_pdf(size)
    aad = b"benchmark"
    blob = crypto.encrypt(data, aad, KEY)
    digest = crypto.sha256_hex(data)
    return {
        "hash_ms": median_ms(lambda: crypto.sha256_hex(data), reps),
        "encrypt_ms": median_ms(lambda: crypto.encrypt(data, aad, KEY), reps),
        "decrypt_ms": median_ms(lambda: crypto.decrypt(blob, aad, KEY), reps),
        "verify_ms": median_ms(lambda: crypto.sha256_hex(crypto.decrypt(blob, aad, KEY)) == digest, reps),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--server")
    p.add_argument("--ca", help="certs/ca.crt for HTTPS verification")
    p.add_argument("--user")
    p.add_argument("--password")
    p.add_argument("--recipient", help="default: first colleague in the directory")
    p.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES_KB)), help="comma-separated sizes in KB")
    p.add_argument("--reps", type=int, default=3)
    p.add_argument("--server-pid", type=int, help="server process id (auto-detected when on the same PC)")
    p.add_argument("--out", default=str(Path(__file__).resolve().parent / "results"))
    p.add_argument("--local-only", action="store_true")
    args = p.parse_args()

    sizes = [int(s) * 1024 for s in args.sizes.split(",")]
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows, summary = [], {}

    s = None
    if not args.local_only:
        if not (args.server and args.user and args.password):
            p.error("--server, --user and --password are required unless --local-only")
        base = args.server.rstrip("/")
        s = requests.Session()
        s.verify = args.ca or True
        proc = psutil.Process(args.server_pid) if args.server_pid else find_server_process(urlparse(base).port or 443)
        print("server process:", proc.pid if proc else "not found (CPU/memory columns left empty)")

        r, login_ms = timed(lambda: s.post(base + "/api/auth/login", json={
            "user_id": args.user, "password": args.password, "device_id": "benchmark-device-01"}))
        r.raise_for_status()
        timing = dict(part.strip().split(";dur=") for part in r.headers.get("Server-Timing", "").split(",") if ";dur=" in part)
        summary.update(login_response_ms=round(login_ms, 2), password_verify_ms=float(timing.get("auth", 0)),
                       session_creation_ms=float(timing.get("session", 0)))

        recipient = args.recipient or s.get(base + "/api/users").json()[0]["user_id"]
        msg_times = [timed(lambda: s.post(base + "/api/messages", json={
            "recipient_id": recipient, "content": "benchmark latency probe"}).raise_for_status())[1] for _ in range(5)]
        summary["message_latency_ms"] = round(statistics.median(msg_times), 2)

    for size in sizes:
        print(f"{size // 1024} KB …", flush=True)
        row = {"size_kb": size // 1024, **{k: round(v, 3) for k, v in local_crypto(size, args.reps).items()}}
        if s is not None:
            data = synthetic_pdf(size)
            digest = hashlib.sha256(data).hexdigest()
            up, down = [], []
            with ResourceSampler(proc) as sampler:
                for i in range(args.reps):
                    r, ms = timed(lambda: s.post(base + "/api/files", files={"file": (f"bench_{size}_{i}.pdf", data, "application/pdf")},
                                                 data={"client_sha256": digest, "recipients": recipient}))
                    r.raise_for_status()
                    up.append(ms)
                    file_id = r.json()["file_id"]
                    r, ms = timed(lambda: s.get(base + f"/api/files/{file_id}"))
                    r.raise_for_status()
                    assert hashlib.sha256(r.content).hexdigest() == digest, "post-transfer integrity check failed"
                    down.append(ms)
            u, d = statistics.median(up), statistics.median(down)
            row.update(upload_ms=round(u, 2), download_ms=round(d, 2),
                       upload_MBps=round(size / 1e6 / (u / 1000), 2), download_MBps=round(size / 1e6 / (d / 1000), 2),
                       server_cpu_avg=round(statistics.mean(sampler.cpu), 1) if sampler.cpu else "",
                       server_cpu_max=round(max(sampler.cpu), 1) if sampler.cpu else "",
                       server_rss_max_mb=round(max(sampler.rss) / 1e6, 1) if sampler.rss else "")
        rows.append(row)
        print("   ", row)

    if s is not None:
        s.post(base + "/api/auth/logout")

    with open(out_dir / "benchmark.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    if summary:
        with open(out_dir / "benchmark_summary.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["metric", "value"])
            w.writerows(summary.items())
        print("summary:", summary)
    print(f"results written to {out_dir}")


if __name__ == "__main__":
    main()
