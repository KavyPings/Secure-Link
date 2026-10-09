"""Start the SecureLink server.  Usage:  python backend/run.py"""
import socket
import sys
from pathlib import Path

import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parent))
from app import config  # noqa: E402

if __name__ == "__main__":
    ssl = {}
    if config.TLS_ENABLED:
        cert, key = config.CERT_DIR / "server.crt", config.CERT_DIR / "server.key"
        if not cert.exists() or not key.exists():
            sys.exit("TLS certificate missing. Run:  python scripts/gen_cert.py")
        ssl = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
    else:
        print("WARNING: TLS disabled. Use only on an isolated lab network for the 'before' capture.")

    # Uvicorn reports the bind address (0.0.0.0 = all interfaces), which browsers cannot open.
    scheme = "https" if config.TLS_ENABLED else "http"
    hosts = ["localhost"]
    if config.HOST in ("0.0.0.0", "::"):
        try:
            hosts += sorted({ip for *_, (ip, *_) in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
                             if not ip.startswith(("127.", "169.254."))})
        except OSError:
            pass
    else:
        hosts = [config.HOST]
    print("\nSecureLink is starting. Open in a browser:")
    for h in hosts:
        print(f"  {scheme}://{h}:{config.PORT}")
    print("(ignore Uvicorn's 0.0.0.0 address below: it only means 'listening on all interfaces')\n", flush=True)

    uvicorn.run(
        "app.main:app",
        host=config.HOST,
        port=config.PORT,
        timeout_keep_alive=10,   # connection timeout (SR-05)
        # Windows: the default Proactor loop logs a harmless but noisy ConnectionResetError traceback
        # whenever a browser resets an idle keep-alive connection (unguarded socket.shutdown() in
        # asyncio). The selector loop has no such code path.
        loop="asyncio:SelectorEventLoop" if sys.platform == "win32" else "auto",
        app_dir=str(Path(__file__).resolve().parent),
        **ssl,
    )
