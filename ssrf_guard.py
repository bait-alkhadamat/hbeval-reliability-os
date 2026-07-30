"""
ssrf_guard.py — SSRF Protection for the Verified Evaluation Path
================================================================

The verified path (A) has the platform call a user-supplied agent endpoint.
That is powerful and dangerous: without protection, a malicious user could
point the platform at internal services (cloud metadata, databases, admin
panels) and exfiltrate secrets — a Server-Side Request Forgery (SSRF) attack.

This module is the gate. Every user-supplied agent URL passes through
`validate_agent_url` BEFORE any request is made, and every connection is
additionally pinned to the validated public IP to defeat DNS rebinding.

Design: deny by default (fail-closed). If anything is uncertain — unresolvable
host, private IP, non-HTTPS, redirect to a private target — we REFUSE.

This module performs DNS resolution (read-only) but makes no outbound HTTP
requests itself; it only judges whether a URL is safe to call.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# ── Policy constants ─────────────────────────────────────────────────────────
ALLOWED_SCHEMES = {"https"}          # HTTPS only — no plaintext, no file://, etc.
ALLOWED_PORTS = {443}                # standard HTTPS only
MAX_URL_LENGTH = 2048
# Hostnames that must never be reached, regardless of IP resolution.
BLOCKED_HOSTNAMES = {
    "localhost", "metadata", "metadata.google.internal",
    "instance-data", "169.254.169.254",
}


class SSRFValidationError(Exception):
    """Raised when a user-supplied URL fails SSRF validation."""


def _is_public_ip(ip_str: str) -> bool:
    """True only if the IP is a normal, routable, public address."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # Reject every category that could reach internal/infra resources.
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        return False
    # Link-local 169.254.0.0/16 (cloud metadata) is is_link_local → already
    # rejected above. Carve-out guard kept explicit for clarity:
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in ipaddress.ip_network("169.254.0.0/16"):
            return False
        if ip in ipaddress.ip_network("100.64.0.0/10"):  # carrier-grade NAT
            return False
    return ip.is_global


def resolve_public_ips(hostname: str) -> list[str]:
    """Resolve a hostname to its IPs and require ALL of them to be public.

    Returning every resolved IP lets the caller pin the connection to a
    validated address, defeating DNS rebinding (where DNS later flips to a
    private IP). If ANY resolved IP is non-public, we refuse the whole host.
    """
    try:
        infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, socket.herror, UnicodeError) as exc:
        raise SSRFValidationError(f"Hostname does not resolve: {hostname}") from exc

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise SSRFValidationError(f"No addresses for hostname: {hostname}")

    for ip in ips:
        if not _is_public_ip(ip):
            raise SSRFValidationError(
                f"Hostname {hostname} resolves to a non-public address ({ip}); refused."
            )
    return ips


def validate_agent_url(url: str) -> dict:
    """Validate a user-supplied agent endpoint URL. Fail-closed.

    Returns a dict {"url", "hostname", "public_ips"} when safe.
    Raises SSRFValidationError otherwise. Call this BEFORE any request.
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("Agent URL is required and must be a string.")
    if len(url) > MAX_URL_LENGTH:
        raise SSRFValidationError("Agent URL is too long.")

    parsed = urlparse(url.strip())

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFValidationError(
            f"Only HTTPS is allowed (got scheme '{parsed.scheme or 'none'}')."
        )
    if not parsed.hostname:
        raise SSRFValidationError("Agent URL has no hostname.")

    hostname = parsed.hostname.lower()
    if hostname in BLOCKED_HOSTNAMES:
        raise SSRFValidationError(f"Hostname '{hostname}' is blocked.")

    # If the host is a literal IP, validate it directly.
    try:
        literal = ipaddress.ip_address(hostname)
        if not _is_public_ip(str(literal)):
            raise SSRFValidationError(f"IP {hostname} is not a public address.")
        public_ips = [str(literal)]
    except ValueError:
        # Not a literal IP → resolve and validate every resolved address.
        public_ips = resolve_public_ips(hostname)

    port = parsed.port or 443
    if port not in ALLOWED_PORTS:
        raise SSRFValidationError(f"Port {port} is not allowed (HTTPS/443 only).")

    return {"url": url.strip(), "hostname": hostname, "public_ips": public_ips}


def validate_redirect_target(location: str, original_host: str) -> str:
    """Validate a redirect Location header before following it.

    Redirects are a classic SSRF bypass: a public URL 302-redirects to an
    internal one. This re-validates the target under the same fail-closed
    policy.

    CURRENTLY UNCALLED, AND THAT IS INTENTIONAL.
    verified_runner sets follow_redirects=False and rejects any 3xx outright,
    so there is no redirect to validate — refusing is strictly safer than
    following a re-validated one, because re-validation reopens the same TOCTOU
    window the refusal closes.

    It is kept rather than deleted because a future caller that must follow
    redirects (a user-configured webhook, say) needs exactly this check, and
    rewriting it later invites getting it wrong. The note exists so nobody
    reads the function's presence as evidence that redirects are being
    validated somewhere — they are not; they are refused.
    """
    if not location:
        raise SSRFValidationError("Empty redirect target.")
    # Re-run the full validation on the redirect destination.
    validate_agent_url(location)
    return location
