"""Production entry point: `python serve.py`.

Reads PORT (set by the host), serves the Gateway behind the host's TLS-terminating proxy, and does not
advertise the server software. FORWARDED_ALLOW_IPS lists the proxy addresses whose X-Forwarded-* headers
are trusted (the client IP in audit logs depends on it). It defaults to loopback only, so a container that
is reachable directly cannot have its client address spoofed; set it to the host proxy (or "*" when the
container is only reachable through that proxy, as on Railway).
"""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "gateway:app",
        host="0.0.0.0",  # nosec B104 - a container must bind all interfaces; the host decides what reaches it
        port=int(os.environ.get("PORT", "8000")),
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"),
        server_header=False,
        log_level=os.environ.get("LOG_LEVEL", "info"),
    )
