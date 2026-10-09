# SecureLink: Secure Company Intranet

A private, role-based company intranet where authenticated employees exchange **text, documents and images**. It enforces company-only access, a two-device session limit, file-type validation, SHA-256 integrity verification, AES-GCM encryption at rest, TLS transport and full audit logging. A **network security layer** captures intranet traffic with Wireshark, analyses it with PyShark and converts the PCAP into SQLite for the admin security dashboard.

Information Security Lab project, Manipal Institute of Technology (B.Tech IT, Semester V).
Kavy Khilrani (240911170), Ruchi Pawar (240911152). Guides: Dr. Akshay KC, Dr. Snehal Samanth.

| Document | Purpose |
|---|---|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | How employees, administrators and security analysts use the system |
| [docs/DEMO_STEPS.txt](docs/DEMO_STEPS.txt) | Simple step-by-step demo instructions (full demo) |
| [docs/PROGRESS_DEMO.txt](docs/PROGRESS_DEMO.txt) | Progress demo: what can be shown and verified today, and what is left |
| [docs/COMMANDS.txt](docs/COMMANDS.txt) | Copy-paste cheat sheet of every command (setup, server modes, demos, analysis, measurements, reset) |
| [PLAN.md](PLAN.md) | Design plan, requirement traceability and **issues found in the PRD/synopsis** |
| `prd.txt`, `SecureLink_Synopsis.pdf` | Source requirements |

---

## Features → requirements

| Feature | How | Requirement |
|---|---|---|
| Admin-created accounts only | No sign-up route; `scripts/init_admin.py` + Admin › Users | FR-01 |
| Password hashing | Argon2id (`argon2-cffi`); only the encoded hash is stored | FR-02 |
| Login | hash verify → account check → role/permissions → session | FR-03 |
| Two-device limit | `device_id` per browser; 3rd device rejected (or oldest revoked, configurable) | FR-04 |
| Session expiry / inactivity | 8 h lifetime, 30 min idle; background polling doesn't count as activity | FR-05, FR-06 |
| Session revocation | Users revoke their own devices; admins revoke one or all | FR-07 |
| Roles & permissions | Configurable roles, 10 permissions, owner/recipient file access | FR-08, FR-09 |
| Company-only network | Trusted-CIDR allowlist middleware; blocked requests audited | FR-10, FR-11 |
| Text messaging | Sender, recipient, time, content (AES-GCM at rest), sent/delivered/read | FR-12 |
| Document/image sharing | PDF, DOCX, XLSX, PPTX, TXT, JPG, PNG, WEBP | FR-13, FR-14 |
| File validation | extension → MIME → magic bytes → size → compatibility | FR-15 to FR-19 |
| Integrity | SHA-256 in browser before upload, on server, after decryption, and in browser after download | FR-20, FR-21 |
| Encryption | AES-256-GCM at rest (AAD binds blob to record) + HTTPS/TLS in transit | §17, SR-01, SR-02 |
| Audit trail | 16 event types with user, device, IP, method, resource, result | FR-22, SR-04 |
| Responsive UI | One React app for PC and phone | FR-18 |
| Availability | Rate limiting, upload size limit, keep-alive timeout, `/health` | SR-05 |
| PCAP → SQLite | `analysis/pcap_to_sqlite.py` (PyShark) | FR-23, FR-24 |
| Traffic analysis | `analysis/detect.py`: 6 rules → security events + risk score | FR-25, FR-26 |
| Security dashboard | Users, sessions, files, network, security, alerts, captures | §21 |
| Evaluation | Entropy, MSE, PSNR, correlation, NPCR, UACI, latency, throughput, CPU, memory | §23 to §30 |

---

## Architecture

```text
 PC browser ─┐                              ┌──────────── FastAPI (backend/app) ─────────────┐
 Phone ──────┼── HTTPS/TLS :8443 ──────────▶│ netguard: trusted networks + rate limit        │
 Laptop ─────┘   (React app + JSON API)     │ auth/sessions → rbac → routes                  │
                                            │ filecheck → SHA-256 → AES-GCM → storage/*.bin  │
                                            │ audit_logs                                     │
                                            └──────────────┬─────────────────────────────────┘
                                                           │ SQLite (backend/data/securelink.db)
 Wireshark capture ─▶ .pcapng ─▶ analysis/pcap_to_sqlite.py (PyShark) ─▶ network_packets
                                 analysis/detect.py ─▶ security_events ─▶ Admin › Dashboard
```

One SQLite database holds the application data, the audit log and the imported packet data, so the dashboard can show all three.

---

## Project layout

```text
backend/
  run.py                    start the server (HTTPS)
  requirements.txt
  app/
    main.py                 FastAPI app, middleware, static frontend, /health
    config.py               every setting (override with SL_* environment variables)
    db.py, schema.sql       SQLite access + schema + seed roles/file types
    audit.py                audit logging
    security/               passwords, sessions, rbac, netguard, crypto, filecheck
    routes/                 auth, sessions (+ directory), messages, files, admin (+ dashboard)
frontend/                   React + Vite (no other libraries); `npm run build` → dist/
analysis/                   pcap_to_sqlite.py, detect.py
evaluation/                 image_metrics.py, benchmark.py
scripts/                    gen_cert.py, init_admin.py, make_spoofed_file.py, tamper_file.py, attack_sim.py
docs/USER_GUIDE.md
```

---

## Setup

### Prerequisites

| Tool | Version used | Needed for |
|---|---|---|
| Python | 3.12 | backend, analysis, evaluation |
| Node.js | 20+ (tested 24 LTS) | building the frontend (not needed at runtime) |
| Wireshark | 4.x (tested 4.6) | PyShark uses its `tshark`; capturing on Windows also needs **Npcap** (installed by the Wireshark installer, or from npcap.com) |

### 1. Install

```bash
python -m venv .venv
```
```bash
.venv/Scripts/python -m pip install -r backend/requirements.txt -r analysis/requirements.txt -r evaluation/requirements.txt
```
(on Linux/macOS use `.venv/bin/python`)
```bash
cd frontend && npm install && npm run build
```

### 2. TLS certificate

```bash
.venv/Scripts/python scripts/gen_cert.py
```
This creates `certs/ca.crt` (a local certificate authority) and `certs/server.crt`/`server.key`, valid for `localhost`, `127.0.0.1` and the machine's LAN IP. You can pass extra IPs or hostnames: `gen_cert.py 192.168.1.20 intranet.local`. **Install `certs/ca.crt` as a trusted CA on every client device** (steps in the [user guide](docs/USER_GUIDE.md#1-connecting-a-device)). Keep `certs/ca.key` private.

### 3. First administrator

```bash
.venv/Scripts/python scripts/init_admin.py --user-id admin --name "System Administrator"
```
You are prompted for the password (minimum 8 characters). All other users are created by an administrator in the web UI.

### 4. Run

```bash
.venv/Scripts/python backend/run.py
```
The server prints the addresses to open, for example `https://localhost:8443` on the server PC and `https://<server-LAN-IP>:8443` on other company devices. **Don't open `https://0.0.0.0:8443`** from Uvicorn's log line: `0.0.0.0` means "listening on all interfaces" and browsers reject it with `ERR_ADDRESS_INVALID`. Allow TCP 8443 in the server's firewall for the LAN only.

> On Windows, use the IP address rather than `localhost` in scripts. `localhost` tries IPv6 first and adds about 2 s per new connection, because the server listens on IPv4.

---

## Configuration

All settings live in [backend/app/config.py](backend/app/config.py) and can be overridden with environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `SL_TRUSTED_NETWORKS` | loopback + `10/8`, `172.16/12`, `192.168/16` | Comma-separated CIDRs allowed to reach the server. **Narrow this to your LAN**, e.g. `192.168.1.0/24,127.0.0.1/32` |
| `SL_HOST` / `SL_PORT` | `0.0.0.0` / `8443` | Bind address (set to the LAN IP to listen on one interface) and port |
| `SL_TLS_ENABLED` | `true` | `false` only for the lab "before security controls" capture (port defaults to 8080) |
| `SL_SESSION_LIFETIME_MIN` | `480` | Absolute session lifetime (8 h) |
| `SL_INACTIVITY_TIMEOUT_MIN` | `30` | Idle timeout |
| `SL_MAX_SESSIONS_PER_USER` | `2` | Device limit |
| `SL_SESSION_LIMIT_POLICY` | `reject` | `reject` or `revoke_oldest` when a 3rd device logs in |
| `SL_LOCKOUT_THRESHOLD` | `5` | Failed logins before an account is locked |
| `SL_RATE_LIMIT_PER_MIN` | `120` | API requests per IP per minute |
| `SL_LOGIN_RATE_LIMIT_PER_MIN` | `10` | Login attempts per IP per minute |
| `SL_MAX_UPLOAD_MB` | `100` | Largest accepted file |
| `SL_COMPANY_NAME` | `SecureLink Corp` | Default company profile for new users |
| `SL_DATA_DIR`, `SL_STORAGE_DIR`, `SL_CERT_DIR` | `backend/data`, `backend/storage`, `certs` | Locations |

Example (PowerShell): `$env:SL_TRUSTED_NETWORKS="192.168.1.0/24,127.0.0.1/32"; .venv\Scripts\python backend\run.py`

---

## Security design

- **Passwords:** Argon2id with a per-hash random salt. Unknown users still go through a dummy verification so response timing doesn't reveal which accounts exist. Generic "Login failed" message. Lockout after 5 failures.
- **Sessions:** 256-bit random token in an `HttpOnly; Secure; SameSite=Strict` cookie. The database stores only SHA-256(token). Absolute and idle expiry. At most 2 devices per user.
- **Authorization:** every route checks authenticated → active → permission → resource ownership/recipient. Failures return `403 Forbidden` and write an `ACCESS_DENIED` audit row.
- **Network:** requests from outside `SL_TRUSTED_NETWORKS` are refused before any application logic runs and logged as `EXTERNAL_ACCESS_ATTEMPT` with source IP, time, path, method and result. The network check never replaces login.
- **Files:**
  1. The extension must be allowed.
  2. The declared MIME type must match.
  3. The real magic bytes must match. DOCX/XLSX/PPTX are told apart by their ZIP contents, and TXT must be valid UTF-8 with no NUL bytes.
  4. The size limit applies.
  5. The type must be flagged browser-compatible.
  6. The browser's SHA-256 is compared with the server's, so corruption in transit is caught.
  7. The file is encrypted with AES-256-GCM using a fresh nonce and AAD = file_id. The key lives in `backend/data/master.key`, outside the database.
- **Download:** the server decrypts (GCM tag check), recomputes SHA-256 and compares it with the original before sending. The browser then hashes the received bytes and compares again (WebCrypto). Any mismatch marks the file `integrity_failed`, logs `INTEGRITY_FAILURE`, and the user sees "Integrity verification failed. File unavailable. Security event recorded".
- **Messages:** AES-256-GCM at rest, AAD = sender|recipient|timestamp.
- **Audit:** never stores passwords, message text or file contents.

**Known limitations** (details in PLAN.md section 9):
- Encryption at rest uses a server-held key, so this is not end-to-end encryption.
- PyShark cannot see HTTP status codes inside TLS without a key log.
- NPCR/UACI/correlation are image-cipher metrics and say little about AES-GCM.
- The rate limiter keeps its counters in memory and resets when the server restarts.

---

## Network security analysis

1. Capture with Wireshark on the server's network interface while employees use the app. Run `scripts/attack_sim.py` during the capture to generate abnormal traffic.
2. Import the capture:
   ```bash
   .venv/Scripts/python analysis/pcap_to_sqlite.py capture.pcapng --label after-tls
   ```
   Options: `--server-ip` (default: this PC's LAN IP), `--port`, `--mode tls|http`, `--keylog sslkeys.log` (decrypts HTTPS for analysis), `--db`.
3. Detection runs automatically. To rerun it with other thresholds: `analysis/detect.py <capture_id> --failed-conn 5 --conn-rate 20 --burst-bytes 5000000 --auth-failures 5`.
4. Open **Dashboard** in the web UI to see packets, connections, failed connections, plaintext exposures, packet overhead and the security alerts.

| Rule | Triggers when |
|---|---|
| `repeated_failed_connections` | ≥ 5 failed TCP connections (SYN unanswered or RST without data) from one source in 60 s |
| `high_request_rate` | ≥ 20 new connections or HTTP requests from one source in 10 s |
| `unexpected_protocol` | non-TCP traffic sent to the server |
| `unexpected_port` | traffic to any server port other than the app port |
| `large_traffic_burst` | ≥ 5 MB from one source in 1 s |
| `repeated_auth_failures` | ≥ 5 HTTP 401 responses to one client in 60 s (plaintext or key-logged capture) |

The **before/after TLS** demonstration (FR-25) is walked through step by step in the [user guide, section 7](docs/USER_GUIDE.md#7-security-analyst-traffic-capture-and-analysis).

---

## Evaluation

```bash
.venv/Scripts/python evaluation/image_metrics.py photo.png --save-dir evaluation/results --csv evaluation/results/image_metrics.csv
```
This computes entropy, MSE, PSNR, adjacent-pixel correlation, NPCR and UACI using the system's own AES-GCM. It saves the cipher image and the decrypted image for the report. Sample run on a 384×256 gradient image:

| Metric | Original | Encrypted / recovered |
|---|---|---|
| Pixel entropy (bits/byte) | 7.83 | 7.9994 |
| Horizontal / vertical / diagonal correlation | 0.992 / 0.992 / 0.984 | −0.015 / −0.002 / 0.008 |
| MSE / PSNR (original vs decrypted) | | 0 / ∞ (lossless) |
| NPCR / UACI (one-pixel change) | | 99.62 % / 33.41 % |

```bash
.venv/Scripts/python evaluation/benchmark.py --server https://<server-ip>:8443 --ca certs/ca.crt --user bench_user --password "<password>"
```
This measures login and session-creation time, message latency, and hashing, encryption, decryption and verification time. It also records upload/download time, throughput, and server CPU and memory for 10 KB to 100 MB files, writing the results to `evaluation/results/*.csv`. Run it on the server PC so it can find the server process. `--local-only` runs only the cryptographic timings. To measure packet overhead, capture the benchmark run and import it with `pcap_to_sqlite.py`.

---

## Demo and verification scripts

| Script | Demonstrates |
|---|---|
| `scripts/make_sample_pcap.py` | Writes a SAMPLE capture (login, message, attacker) so the PCAP → SQLite pipeline can be shown before live capture is available. Import with `--mode http --port 8080 --server-ip 192.168.1.10` |
| `scripts/make_spoofed_file.py` | Builds `demo_files/invoice.pdf` with an executable (MZ) signature. Upload it and it is rejected: "Signature does not match declared type" |
| `scripts/tamper_file.py <name>` | Flips one bit of a stored encrypted file. The next download fails the integrity check and is logged |
| `scripts/attack_sim.py --server … --ca certs/ca.crt` | Failed-login burst, unauthorized API calls, connection burst (rate limiting), port probes, for the capture |

The success-criteria checklist (PRD §38) is in [PLAN.md section 8](PLAN.md). Each criterion has been exercised against a running server: login and lockout, the two-device limit, same-device re-login, session revocation, 30-minute inactivity (tested at 1 min), RBAC 403, untrusted-IP block, disguised `.exe` rejection, wrong-MIME rejection, upload hash mismatch, tampered-blob rejection, message encryption round-trip, PCAP import and detection, dashboard, and the evaluation scripts.
