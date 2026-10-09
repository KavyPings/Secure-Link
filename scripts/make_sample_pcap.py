"""Write a SAMPLE (synthetic) packet capture so the PCAP -> SQLite pipeline can be shown
before live Wireshark capture is available (Npcap not installed yet).

    python scripts/make_sample_pcap.py                    # writes sample_capture.pcap
    python analysis/pcap_to_sqlite.py sample_capture.pcap --label sample --mode http --port 8080 --server-ip 192.168.1.10

Contents (server 192.168.1.10:8080, plaintext HTTP as in the "before TLS" experiment):
  employee 192.168.1.50  logs in and sends a message (password + message readable on the wire)
  attacker 192.168.1.66  6 failed logins, a port scan, a burst of 25 unanswered connections, a UDP probe
  employee 192.168.1.50  a ~6 MB upload burst
This is generated data for demonstration only; real results come from Wireshark captures.
"""
import struct
import sys

SERVER, CLIENT, ATTACKER = "192.168.1.10", "192.168.1.50", "192.168.1.66"
frames = []
clock = [1_760_000_000.0]


def ip_bytes(ip):
    return bytes(int(x) for x in ip.split("."))


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ipv4_frame(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, ip_bytes(src), ip_bytes(dst))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + hdr + payload


def tcp(src, dst, sport, dport, seq, ack, flags, data=b""):
    return ipv4_frame(src, dst, 6, struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + data)


def emit(frame, dt=0.001):
    clock[0] += dt
    frames.append((clock[0], frame))


def http_exchange(client, sport, request, response, dt=0.01):
    c, s = 1000, 5000
    emit(tcp(client, SERVER, sport, 8080, c, 0, 0x02), dt)                          # SYN
    emit(tcp(SERVER, client, 8080, sport, s, c + 1, 0x12))                           # SYN-ACK
    emit(tcp(client, SERVER, sport, 8080, c + 1, s + 1, 0x10))                       # ACK
    emit(tcp(client, SERVER, sport, 8080, c + 1, s + 1, 0x18, request))              # request
    emit(tcp(SERVER, client, 8080, sport, s + 1, c + 1 + len(request), 0x18, response))
    emit(tcp(client, SERVER, sport, 8080, c + 1 + len(request), s + 1 + len(response), 0x11))  # FIN
    emit(tcp(SERVER, client, 8080, sport, s + 1 + len(response), c + 2 + len(request), 0x11))


def request(method, path, body):
    return (f"{method} {path} HTTP/1.1\r\nHost: {SERVER}:8080\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode() + body


def response(code, text, body=b'{"ok":true}'):
    return (f"HTTP/1.1 {code} {text}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode() + body


# Normal employee activity (readable because TLS is off)
http_exchange(CLIENT, 50001, request("POST", "/api/auth/login",
              b'{"user_id":"hr_anna","password":"Demo#2026pass","device_id":"a1b2c3d4"}'), response(200, "OK"))
http_exchange(CLIENT, 50002, request("POST", "/api/messages",
              b'{"recipient_id":"hr_bob","content":"salary list attached"}'), response(200, "OK"))
# Attacker: repeated failed logins
for i in range(6):
    http_exchange(ATTACKER, 51000 + i, request("POST", "/api/auth/login",
                  b'{"user_id":"hr_anna","password":"guess%d","device_id":"x"}' % i),
                  response(401, "Unauthorized", b'{"detail":"Login failed"}'), dt=0.2)
# Attacker: port scan (server answers with RST)
for i, port in enumerate((21, 22, 23, 445, 3389, 5432)):
    emit(tcp(ATTACKER, SERVER, 52000 + i, port, 1, 0, 0x02), 0.05)
    emit(tcp(SERVER, ATTACKER, port, 52000 + i, 0, 2, 0x14))
# Attacker: burst of connection attempts that are never answered
for i in range(25):
    emit(tcp(ATTACKER, SERVER, 53000 + i, 8080, 1, 0, 0x02), 0.05)
# Attacker: UDP probe (the intranet only uses TCP)
emit(ipv4_frame(ATTACKER, SERVER, 17, struct.pack("!HHHH", 40000, 9999, 12, 0) + b"ping"), 0.5)
# Employee: large upload burst (~6 MB in under a second)
for i in range(4500):
    emit(tcp(CLIENT, SERVER, 50003, 8080, 1 + i * 1400, 1, 0x10, b"A" * 1400), 0.0001)

out = sys.argv[1] if len(sys.argv) > 1 else "sample_capture.pcap"
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # classic pcap, Ethernet
    for ts, frame in frames:
        f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame)
print(f"wrote {out}: {len(frames)} packets of SAMPLE traffic (server {SERVER}:8080)")
