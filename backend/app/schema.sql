-- SecureLink database schema (SQLite).
-- Tables from PRD section 35 plus the ones marked (+) that the functional requirements need.

CREATE TABLE IF NOT EXISTS roles (                       -- (+) FR-08 configurable roles
    role_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS role_permissions (            -- (+) FR-09
    role_id    INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE IF NOT EXISTS users (
    user_id         TEXT PRIMARY KEY,                    -- also the login username
    name            TEXT NOT NULL,
    company_profile TEXT NOT NULL,
    department      TEXT NOT NULL,
    role_id         INTEGER NOT NULL REFERENCES roles(role_id),
    password_hash   TEXT NOT NULL,                       -- Argon2id encoded hash (salt + params inside)
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'locked')),
    failed_logins   INTEGER NOT NULL DEFAULT 0,          -- (+) lockout counter
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,                      -- SHA-256 of the cookie token, never the token
    user_id       TEXT NOT NULL REFERENCES users(user_id),
    device_id     TEXT NOT NULL,
    device_label  TEXT,                                  -- (+) human-readable browser/OS
    created_at    TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, status);

CREATE TABLE IF NOT EXISTS messages (                    -- (+) FR-12
    message_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id       TEXT NOT NULL REFERENCES users(user_id),
    recipient_id    TEXT NOT NULL REFERENCES users(user_id),
    ciphertext      BLOB NOT NULL,                       -- AES-GCM: nonce || ciphertext || tag
    sent_at         TEXT NOT NULL,
    delivery_status TEXT NOT NULL DEFAULT 'sent' CHECK (delivery_status IN ('sent', 'delivered', 'read'))
);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, recipient_id);

CREATE TABLE IF NOT EXISTS allowed_file_types (          -- (+) FR-14 / FR-19
    ext                TEXT PRIMARY KEY,
    mime               TEXT NOT NULL,
    category           TEXT NOT NULL CHECK (category IN ('document', 'image')),
    enabled            INTEGER NOT NULL DEFAULT 1,
    browser_compatible INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS files (
    file_id       TEXT PRIMARY KEY,
    filename      TEXT NOT NULL,
    size          INTEGER NOT NULL,
    mime_type     TEXT NOT NULL,
    detected_type TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    owner         TEXT NOT NULL REFERENCES users(user_id),
    created_at    TEXT NOT NULL,
    version       INTEGER NOT NULL DEFAULT 1,            -- (+) FR-13 (versioning itself is Phase 2)
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'integrity_failed'))
);

CREATE TABLE IF NOT EXISTS shares (
    share_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id      TEXT NOT NULL REFERENCES files(file_id),
    sender_id    TEXT NOT NULL REFERENCES users(user_id),
    recipient_id TEXT NOT NULL REFERENCES users(user_id),
    shared_at    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'shared' CHECK (status IN ('shared', 'downloaded'))
);
CREATE INDEX IF NOT EXISTS idx_shares_recipient ON shares(recipient_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      TEXT,
    device_id    TEXT,
    event_type   TEXT NOT NULL,
    resource     TEXT,
    request_type TEXT,                                   -- (+) FR-11 "request type" (HTTP method)
    timestamp    TEXT NOT NULL,
    source_ip    TEXT,
    result       TEXT NOT NULL,
    details      TEXT                                    -- (+) never contains file/message content
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_logs(event_type);

CREATE TABLE IF NOT EXISTS captures (                    -- (+) one row per imported PCAP
    capture_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label               TEXT NOT NULL,
    filename            TEXT NOT NULL,
    imported_at         TEXT NOT NULL,
    mode                TEXT NOT NULL,                   -- 'tls' or 'http'
    server_ip           TEXT,
    server_port         INTEGER,
    packet_count        INTEGER NOT NULL DEFAULT 0,
    connections         INTEGER NOT NULL DEFAULT 0,
    failed_connections  INTEGER NOT NULL DEFAULT 0,
    wire_bytes          INTEGER NOT NULL DEFAULT 0,
    payload_bytes       INTEGER NOT NULL DEFAULT 0,
    plaintext_exposures INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS network_packets (
    packet_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id       INTEGER NOT NULL REFERENCES captures(capture_id),  -- (+)
    timestamp        REAL NOT NULL,
    source_ip        TEXT,
    destination_ip   TEXT,
    protocol         TEXT,                               -- highest dissected layer
    transport        TEXT,                               -- (+) TCP / UDP / other
    source_port      INTEGER,
    destination_port INTEGER,
    packet_size      INTEGER NOT NULL,
    payload_size     INTEGER NOT NULL DEFAULT 0,         -- (+) for packet-overhead metric
    flags            TEXT,                               -- TCP flags as hex, e.g. 0x0012
    stream_id        INTEGER,                            -- (+) "connection information" (tcp.stream)
    http_request     TEXT,                               -- (+) only visible in plaintext / keylog captures
    http_status      INTEGER,                            -- (+)
    sensitive        INTEGER NOT NULL DEFAULT 0,         -- (+) plaintext secret/content visible
    risk_score       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_packets_capture ON network_packets(capture_id);

CREATE TABLE IF NOT EXISTS security_events (             -- (+) FR-26
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id   INTEGER NOT NULL REFERENCES captures(capture_id),
    rule         TEXT NOT NULL,
    source_ip    TEXT,
    window_start REAL,
    count        INTEGER NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    details      TEXT
);
