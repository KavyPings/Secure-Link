"""Create a local certificate authority and a server certificate for HTTPS.

    python scripts/gen_cert.py                 # auto-detects this machine's LAN IP
    python scripts/gen_cert.py 192.168.1.20    # or list the server IPs / hostnames explicitly

Outputs (in certs/):
    ca.crt      install + trust this on every test device (PC, Android, iPhone)
    ca.key      keep private; only needed to issue new server certificates
    server.crt  server.key   used by backend/run.py
"""
import ipaddress
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT_DIR = Path(__file__).resolve().parent.parent / "certs"


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent; just picks the outbound interface
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def write(path, data):
    path.write_bytes(data)
    print("wrote", path)


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


def main(names):
    CERT_DIR.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc)

    ca_key_path, ca_crt_path = CERT_DIR / "ca.key", CERT_DIR / "ca.crt"
    if ca_key_path.exists() and ca_crt_path.exists():
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), None)
        ca_cert = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())
        print("reusing existing CA", ca_crt_path)
    else:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureLink Local CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        write(ca_key_path, key_pem(ca_key))
        write(ca_crt_path, ca_cert.public_bytes(serialization.Encoding.PEM))

    sans = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    for n in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0] if names else "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=397))   # within Apple/Chrome server-cert lifetime limits
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    write(CERT_DIR / "server.key", key_pem(server_key))
    write(CERT_DIR / "server.crt", server_cert.public_bytes(serialization.Encoding.PEM))
    print("server certificate valid for:", ", ".join(str(s.value) for s in sans))
    print("Install certs/ca.crt as a trusted CA on each client device (see docs/USER_GUIDE.md).")


if __name__ == "__main__":
    args = sys.argv[1:] or [ip for ip in [lan_ip()] if ip]
    main(args)
