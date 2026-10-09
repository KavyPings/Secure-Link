# SecureLink User Guide

SecureLink is your company's private intranet for messages, documents and images. It works in any modern browser on a PC, Android phone or iPhone, so there is nothing to install apart from a one-time certificate.

**Contents**
1. [Connecting a device](#1-connecting-a-device)
2. [Logging in and out](#2-logging-in-and-out)
3. [Messages](#3-messages)
4. [Files](#4-files)
5. [Your devices (sessions)](#5-your-devices-sessions)
6. [Administrators](#6-administrators)
7. [Security analyst: traffic capture and analysis](#7-security-analyst-traffic-capture-and-analysis)
8. [Messages you may see](#8-messages-you-may-see)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Connecting a device

SecureLink can only be reached from inside the company network (office Wi-Fi or LAN). From anywhere else you'll see *"Access restricted to the company network"*.

**Address:** `https://<server-IP>:8443` (your administrator will give you the exact address, for example `https://192.168.1.20:8443`).

### One-time: trust the company certificate

The server's HTTPS certificate is issued by the company's own certificate authority, `ca.crt`, which your administrator provides. Install it once per device. Until you do, browsers show a security warning and file integrity checking can't run.

| Device | Steps |
|---|---|
| **Windows** (Chrome, Edge) | Double-click `ca.crt` → **Install Certificate** → *Current User* → **Place all certificates in the following store** → *Trusted Root Certification Authorities* → Finish → Yes. Or in a terminal: `certutil -addstore -user Root ca.crt`. Restart the browser. |
| **Windows / Linux / macOS, Firefox** | Settings → Privacy & Security → Certificates → **View Certificates** → *Authorities* → **Import** → select `ca.crt` → tick *Trust this CA to identify websites*. |
| **macOS** (Safari, Chrome) | Double-click `ca.crt` → Keychain Access opens → double-click *SecureLink Local CA* → Trust → *When using this certificate*: **Always Trust**. |
| **Android** | Copy `ca.crt` to the phone → Settings → Security (or *Security & privacy*) → *More security settings* → *Encryption & credentials* → **Install a certificate** → **CA certificate** → Install anyway → choose `ca.crt`. Menu names differ slightly between manufacturers. |
| **iPhone / iPad** | Send `ca.crt` to the device (AirDrop, Mail or Files) and open it → Settings → **Profile Downloaded** → Install. Then Settings → General → About → **Certificate Trust Settings** → turn on *SecureLink Local CA*. |

---

## 2. Logging in and out

1. Open the SecureLink address and enter the **User ID** and **password** your administrator gave you. There is no self-registration.
2. Use **Log out** at the top right when you finish, especially on shared devices.

Rules you should know:
- **Two devices at most.** You can be signed in on two devices at once (for example laptop + phone). Logging in on a third shows *"Maximum active sessions reached"*. To fix it, sign out on one device or revoke it from **Sessions** (section 5). Logging in again on the same browser just replaces that browser's old session.
- **Sessions expire** after **8 hours**, or after **30 minutes without activity**. Leaving the Messages page open doesn't count as activity. You'll see *"Session expired. Please log in again"*.
- **One account per browser.** All tabs of a browser share one sign-in and count as one device. If you log in as someone else in one tab, every other tab switches to that account; logging out in one tab logs out all of them. To use two accounts at once (for example when testing), use two different browsers or a private/incognito window.
- **Five wrong passwords lock your account.** An administrator has to unlock it. For security, the message is always just *"Login failed"*, whatever the reason.

---

## 3. Messages

1. Open **Messages**. The left list shows your colleagues; a blue number means unread messages.
2. Select a colleague, type in the box at the bottom and press **Send** (or Enter).
3. Ticks under your messages show delivery status: **✓** sent, **✓✓** delivered (their app fetched it), **✓✓ read** (they opened the conversation).

New messages appear automatically every few seconds. On a phone the list and the conversation are separate screens; use **← Back** to return to the list.
Messages are stored encrypted on the server and travel over HTTPS.

---

## 4. Files

### Sharing a file
1. Open **Files** → *Share a document or image*.
2. **Choose a file.** Allowed types: **PDF, DOCX, XLSX, PPTX, TXT, JPG/JPEG, PNG, WEBP**, up to **100 MB**. Your administrator may have disabled some of them.
3. Tick one or more **Recipients**.
4. Click **Upload & share**. The app:
   1. computes the file's SHA-256 fingerprint in your browser
   2. uploads it over HTTPS
   3. on the server: checks the extension, MIME type, real file signature, size and compatibility, then compares fingerprints
   4. stores it encrypted.

   On success you see *"Shared with … SHA-256 …"*.

Uploads are rejected when:
- **the file isn't really what its name says**, for example a program renamed to `invoice.pdf`: *"File rejected: Signature does not match declared type"*
- the type isn't allowed, or the file is too large or empty
- the file was corrupted on the way: *"integrity check failed during upload. Please retry."*

### Receiving a file
1. **Files** → *Received files* lists everything shared with you: sender, time, size, type and fingerprint.
2. Click **Download**. Your browser downloads the file and recalculates its SHA-256. If it matches the original you see **"Integrity Verified ✓"**. Then click **Save file**.
3. **Images** (JPG, PNG, WEBP) also show a preview.
4. If the file was modified in storage or in transit you see **"Integrity verification failed. File unavailable. Security event recorded."** Don't use that file. The security team has already been notified through the audit log.
5. If the network drops you see *"Transfer interrupted. Retry available."*. Click **Retry**.

You can open only files you sent or that were shared with you. Anything else returns *403 Forbidden* and is logged.

---

## 5. Your devices (sessions)

**Sessions** lists every device you're signed in on, with browser/OS, sign-in time, last activity and expiry.
- **Revoke** signs that other device out immediately, for example if you left a PC signed in or lost a phone.
- On the row marked *this device*, **Log out** signs you out here.

---

## 6. Administrators

Administrators see **Admin** and **Dashboard** tabs. Every administrative action is written to the audit log.

### Users
- **Create a user:** fill in User ID (also their login name), name, department, role and an initial password (minimum 8 characters), then click **Create user**. Give the password to the employee through a safe channel.
- **Change role:** use the role drop-down in the user's row. It takes effect on their next request.
- **Disable:** blocks the account and signs out all its sessions. **Enable** reactivates it.
- **Unlock:** a *locked* account (5 failed logins) shows **Unlock**, which also resets the counter.
- **Reset password** and **Revoke sessions** are available on every row.

The first administrator is created on the server console with `scripts/init_admin.py`.

### Roles
Roles are configurable. Each role is a set of permissions:

| Permission | Allows |
|---|---|
| send_message | Messages tab |
| upload_file / share_file | Uploading and sharing files (both needed) |
| download_file | Files tab, downloading files shared with you |
| manage_users | Users and Roles sections |
| manage_roles | Editing role permissions, adding roles |
| manage_file_types | File types section |
| manage_sessions | Sessions section (revoke anyone's sessions) |
| view_audit | Audit log |
| view_dashboard | Security dashboard |

Tick or untick permissions and click **Save** on that row. **Add role** creates a new role (for example *Legal*) with messaging and download rights, which you can then extend. The *Administrator* role always has every permission so that you can't lock yourself out.

### File types
Turn **Allowed** off to block a type for everyone. **Browser compatible** off also blocks it, because it fails the compatibility check. Only types SecureLink can verify by file signature appear in this list.

### Sessions
Shows every active session in the company. **Revoke** ends one session; **Revoke all for user** signs a user out everywhere.

### Audit log
Filter by user, event type and start time. Each row shows time, user, device, event, resource, HTTP method, source IP, result and details. File and message contents are never logged. Important events:

| Event | Meaning |
|---|---|
| LOGIN / LOGIN_FAILED / LOGOUT | Authentication. LOGIN_FAILED details include *wrong password*, *unknown user*, *account locked*, *maximum active sessions reached* |
| SESSION_CREATED / SESSION_TERMINATED / SESSION_EXPIRED | Session lifecycle (logout, revoke, replaced, timeout) |
| FILE_UPLOAD / FILE_SHARE / FILE_DOWNLOAD | File activity; details include the file id and SHA-256 |
| INVALID_FILE_TYPE | Upload rejected by validation, with the reason |
| INTEGRITY_FAILURE | Hash or encryption tag mismatch (upload, storage or client download) |
| ACCESS_DENIED | 403: missing permission or someone else's file |
| EXTERNAL_ACCESS_ATTEMPT | Request from outside the trusted company network (blocked) |
| RATE_LIMITED | Too many requests from one IP (blocked for a minute) |
| ADMIN_ACTION | Any administrative change |

### Dashboard
- **Users:** active, active sessions, locked and disabled accounts.
- **Sessions:** current, devices, expired.
- **Files:** uploads, downloads, rejected, integrity failures.
- **Security:** failed logins, unauthorized requests, external access attempts, rate-limited clients.
- **Network:** results of the selected PCAP import (packets, connections, failed connections, suspicious events, plaintext exposures).
- **Security alerts** and the **Imported captures** table.

Orange tiles are non-zero security counters worth a look. Use the capture selector to compare captures, for example *before-http* vs *after-tls*.

---

## 7. Security analyst: traffic capture and analysis

This section is for the project's security experiments (PRD FR-23 to FR-26). Run all commands from the project folder on the server PC.

### Setup
- Install **Wireshark**. On Windows, make sure **Npcap** is installed (the Wireshark installer offers it, or get it from npcap.com), otherwise Wireshark can't capture.
- Capture on the server's **Wi-Fi/Ethernet adapter** and use **other devices** (a phone and a second laptop) as clients. Traffic between a PC and itself never reaches the network adapter. If you must use the same PC, capture on Npcap's *Adapter for loopback traffic capture*, browse to `https://127.0.0.1:8443`, and pass `--server-ip 127.0.0.1` when importing.

### Experiment A: before security controls (plaintext HTTP)
Use an isolated lab network only. This mode deliberately exposes credentials.
1. Start the server without TLS:
   ```powershell
   $env:SL_TLS_ENABLED="false"; .venv\Scripts\python backend\run.py
   ```
   It listens on `http://<server-IP>:8080`.
2. In Wireshark, start capturing with capture filter `host <server-IP>`.
3. From a client device:
   - log in
   - send a message
   - upload and download a file
   - try a wrong password
   - open a file that wasn't shared with you (403).

   Optionally, from another PC: `python scripts/attack_sim.py --server http://<server-IP>:8080 --user <some user>`.
4. Stop and save the capture as `before.pcapng`. In Wireshark, filter with `http` and use *Follow → HTTP Stream* on the login request. The **password, message text and file bytes are readable**.
5. Import it:
   ```bash
   .venv/Scripts/python analysis/pcap_to_sqlite.py before.pcapng --label before-http --mode http --port 8080
   ```

### Experiment B: after security controls (HTTPS)
1. Restart the server normally (`$env:SL_TLS_ENABLED="true"` or a new terminal): `.venv\Scripts\python backend\run.py`.
2. Capture again while repeating the same actions plus `scripts/attack_sim.py --server https://<server-IP>:8443 --ca certs/ca.crt --user <some user>`. Save as `after.pcapng`.
3. In Wireshark, filter with `tls`. Only handshakes and encrypted *Application Data* records are visible: no passwords, URLs, message text or file bytes.
4. Import it:
   ```bash
   .venv/Scripts/python analysis/pcap_to_sqlite.py after.pcapng --label after-tls
   ```
5. Compare the two captures on the **Dashboard** (*Plaintext exposures* should drop to 0) and in the *Imported captures* table (packet overhead).

### Optional: analysing inside TLS with a key log
HTTP status codes (needed for the *repeated_auth_failures* rule) are hidden by TLS. For analysis you can let your own browser export its session keys:
```powershell
$env:SSLKEYLOGFILE="$PWD\sslkeys.log"; & "C:\Program Files\Google\Chrome\Application\chrome.exe"
```
Close all Chrome windows first. Python scripts such as `attack_sim.py` also honour `SSLKEYLOGFILE`. Then import with `--keylog sslkeys.log`. Delete the key log afterwards, because anyone who has it can decrypt that capture.

### What the analyzer stores
Each packet becomes one row in `network_packets` with these fields:
- timestamp
- source/destination IP and port
- protocol and transport
- size and payload size
- TCP flags
- connection (stream) id
- HTTP request/status when visible
- a *sensitive* flag (password, message content, file upload or session cookie readable on the wire)
- a risk score

Detection rules then write `security_events`; the rules are listed in the README. To rerun them with your own thresholds:
```bash
.venv/Scripts/python analysis/detect.py 2 --failed-conn 3 --auth-failures 3
```

### Evaluation scripts
- `evaluation/image_metrics.py <image>`: entropy, MSE/PSNR, correlation, NPCR/UACI.
- `evaluation/benchmark.py`: timings, throughput, CPU and memory.

The README explains both and how to read the results.

---

## 8. Messages you may see

| Message | Meaning / what to do |
|---|---|
| Login failed | Wrong user ID or password, or the account is disabled or locked. Contact your administrator after repeated failures. |
| Maximum active sessions reached | You're already signed in on two devices. Revoke one (Sessions) or log out there. |
| Session expired. Please log in again | 8-hour limit or 30 minutes idle, or your session was revoked. |
| 403 Forbidden | You don't have permission for that action or file. The attempt is logged. |
| Access restricted to the company network | You're outside the trusted network. Connect to the office network. |
| Too many requests. Slow down and retry shortly. | Rate limit reached; wait a minute. |
| File rejected: Signature does not match declared type | The file's content doesn't match its extension (possibly disguised). |
| File rejected: MIME type … does not match … | The browser reported a different type than the extension implies. |
| File rejected: File type '.x' is not allowed | Type not permitted by the administrator. |
| File rejected: File exceeds the 100 MB limit | File too large. |
| File rejected: integrity check failed during upload | The file changed in transit. Retry. |
| Integrity verification failed. File unavailable. Security event recorded | Stored or received file doesn't match its original fingerprint. Don't use it. |
| Transfer interrupted. Retry available. | Network problem. Click Retry. |

---

## 9. Troubleshooting

| Problem | Fix |
|---|---|
| `ERR_ADDRESS_INVALID` at `https://0.0.0.0:8443` | `0.0.0.0` is the server's "all interfaces" bind address, not a web address. Open one of the URLs the server prints at startup: `https://localhost:8443` on the server PC, `https://<server-IP>:8443` elsewhere. |
| Browser says the connection is not private | Install `ca.crt` on this device (section 1). The address must match the certificate: use the IP your admin gave you. If the server's IP changed, the admin reruns `scripts/gen_cert.py`. |
| Downloads never show "Integrity Verified" | The page isn't in a secure context (certificate not trusted). Install `ca.crt`. |
| Phone can't reach the server | Same Wi-Fi as the server? Server firewall allows TCP 8443? Is the phone's IP inside `SL_TRUSTED_NETWORKS`? |
| Wireshark shows no traffic | Capture on the adapter that carries the clients' traffic. Install Npcap. Clients must be other devices (or use the loopback adapter). |
| `pcap_to_sqlite.py` reports 0 packets | Check `--server-ip` (default is this PC's LAN IP) and `--port`/`--mode`. |
| `TShark not found` | Install Wireshark, or add `C:\Program Files\Wireshark` to PATH. |
