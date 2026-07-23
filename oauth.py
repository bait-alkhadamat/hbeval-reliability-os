"""
oauth.py — OAuth 2.1 authorization server for HB-Eval's remote MCP endpoint
============================================================================
Implements what the MCP specification requires of any server reachable over
the internet: OAuth 2.1 with PKCE (S256), Protected Resource Metadata
(RFC 9728), Authorization Server Metadata (RFC 8414), and Dynamic Client
Registration (RFC 7591).

WHY THIS EXISTS AT ALL
----------------------
The local (stdio) MCP server requires the user to install a package and edit
a config file. That excludes everyone using Claude in a browser, which is
most people. A remote server turns setup into: paste a URL, sign in once.
The spec's price for that reach is this file.

WHAT THE FLOW LOOKS LIKE
------------------------
  1. Client calls /mcp with no token.
  2. Gateway answers 401 with WWW-Authenticate pointing at the PRM document.
  3. Client reads PRM, learns which authorization server to use.
  4. Client reads AS metadata, self-registers via DCR.
  5. Client sends the user to /oauth/authorize with a PKCE challenge.
  6. User signs in on hbeval.com and approves.
  7. Gateway issues a one-time code bound to that challenge.
  8. Client exchanges code + verifier at /oauth/token.
  9. Client retries /mcp with the bearer token.

SECURITY DECISIONS, AND WHY
---------------------------
  • Tokens are stored hashed. A database dump must not yield usable
    credentials — the same standard already applied to agent API keys.

  • Redirect URIs are compared by exact string equality. Prefix or wildcard
    matching is the classic way authorization codes get delivered to an
    attacker, and no convenience justifies it.

  • Authorization codes are consumed, not deleted. A replayed code is then
    distinguishable from an unknown one, and replay revokes the whole token
    chain rather than silently failing.

  • Refresh tokens rotate, and reuse of a rotated token revokes everything
    descended from it. Reuse is the signature of a stolen refresh token; the
    only safe response is to invalidate the chain and make the user
    reconnect.

  • PKCE is mandatory even though the spec technically allows S256 only for
    public clients — every client here is treated as public, because DCR and
    CIMD register Claude as one.

WHAT IS DELIBERATELY NOT HERE
-----------------------------
Client credentials (machine-to-machine) grant. Claude connectors do not
support it, and offering a user-less path into an account's evaluation data
would weaken the model for no gain.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlencode

logger = logging.getLogger("hb-eval-gateway.oauth")

# ── Lifetimes ───────────────────────────────────────────────────────────────
# Codes live briefly: they cross the browser's address bar, which is the most
# exposed part of the flow.
CODE_TTL_SECONDS = 300              # 5 minutes
ACCESS_TOKEN_TTL_SECONDS = 3600     # 1 hour
REFRESH_TOKEN_TTL_DAYS = 30

SUPPORTED_SCOPES = ["hbeval:read", "hbeval:evaluate"]

# The canonical public URL of this Gateway. It MUST match the URL the user
# types into their client, character for character including any path: Claude
# verifies that the PRM `resource` equals the origin it derived, and rejects
# the connection otherwise. Misconfiguring this is the single most likely
# cause of a connection that fails with no useful error.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")

# Where the user is sent to sign in and approve. Lives on the website, not
# here, because it needs the existing session cookie.
CONSENT_URL = os.environ.get("CONSENT_URL", "https://hbeval.com/oauth/consent")


def _hash(value: str) -> str:
    """Tokens and codes are stored as SHA-256 digests, never in the clear."""
    return hashlib.sha256(value.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    """Check a PKCE verifier against the stored challenge.

    Only S256 is accepted. The `plain` method offers no protection against an
    attacker who can read the authorization request, and OAuth 2.1 removes it;
    accepting it here would advertise a security property the server does not
    actually provide.
    """
    if method != "S256":
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return secrets.compare_digest(expected, challenge)


# ── Metadata documents ──────────────────────────────────────────────────────
def protected_resource_metadata(mcp_path: str = "/mcp") -> dict:
    """RFC 9728 Protected Resource Metadata.

    Mandatory for remote MCP servers since the June 2025 spec revision. The
    client fetches this to learn which authorization server governs this
    resource.

    `resource` must equal the MCP URL exactly as the user enters it. If a user
    types a URL with a trailing path and this value omits it, the client
    treats the mismatch as possible impersonation and refuses.
    """
    return {
        "resource": f"{PUBLIC_BASE_URL}{mcp_path}",
        "authorization_servers": [PUBLIC_BASE_URL],
        "scopes_supported": SUPPORTED_SCOPES,
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://hbeval.com/docs/mcp",
    }


def authorization_server_metadata() -> dict:
    """RFC 8414 Authorization Server Metadata.

    Every capability advertised here must match actual behaviour. Claiming
    S256 support while accepting `plain`, or advertising registration at an
    endpoint that does not provision usable clients, produces clients that
    fail in confusing ways well after the connection appeared to succeed.
    """
    return {
        "issuer": PUBLIC_BASE_URL,
        "authorization_endpoint": f"{PUBLIC_BASE_URL}/oauth/authorize",
        "token_endpoint": f"{PUBLIC_BASE_URL}/oauth/token",
        "registration_endpoint": f"{PUBLIC_BASE_URL}/oauth/register",
        "revocation_endpoint": f"{PUBLIC_BASE_URL}/oauth/revoke",
        "scopes_supported": SUPPORTED_SCOPES,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


# ── Dynamic Client Registration ─────────────────────────────────────────────
async def register_client(supabase: Any, to_thread: Any, body: dict) -> dict:
    """RFC 7591 registration for a public client.

    Open registration is required for clients like Claude that cannot be
    pre-provisioned. It is bounded by validating redirect URIs strictly and by
    the periodic cleanup of registrations that never complete a flow.
    """
    redirect_uris = body.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise ValueError("redirect_uris is required and must be a non-empty list.")

    cleaned: list[str] = []
    for uri in redirect_uris[:10]:
        uri = str(uri)
        # HTTPS everywhere, with localhost exempted so a developer can test a
        # client locally. An http:// redirect to any other host would expose
        # the authorization code on the wire.
        if not (uri.startswith("https://")
                or uri.startswith("http://localhost")
                or uri.startswith("http://127.0.0.1")):
            raise ValueError(f"redirect_uri must use https (or localhost): {uri}")
        cleaned.append(uri)

    requested = body.get("scope", "")
    scopes = [s for s in str(requested).split() if s in SUPPORTED_SCOPES] or SUPPORTED_SCOPES

    client_id = f"hbeval-{secrets.token_urlsafe(24)}"
    row = {
        "client_id": client_id,
        "client_name": str(body.get("client_name", "MCP Client"))[:200],
        "redirect_uris": cleaned,
        "is_public": True,
        "scopes": scopes,
    }

    def _insert():
        supabase.table("oauth_clients").insert(row).execute()

    await to_thread(_insert)

    # No client_secret: this is a public client. Returning one would imply a
    # confidentiality guarantee a browser-based client cannot keep.
    return {
        "client_id": client_id,
        "client_name": row["client_name"],
        "redirect_uris": cleaned,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": " ".join(scopes),
    }


# ── Authorization ───────────────────────────────────────────────────────────
async def load_client(supabase: Any, to_thread: Any, client_id: str) -> Optional[dict]:
    def _q():
        return (supabase.table("oauth_clients").select("*")
                .eq("client_id", client_id).execute())
    res = await to_thread(_q)
    rows = res.data or []
    return rows[0] if rows else None


def validate_authorization_request(client: dict, redirect_uri: str,
                                   response_type: str, code_challenge: str,
                                   code_challenge_method: str) -> None:
    """Validate before showing any consent screen.

    Order matters: the redirect URI is checked first, because every later
    error is reported by redirecting to it. Reporting an error to an
    unvalidated URI would leak the failure — and any state with it — to
    whoever supplied that URI.
    """
    if redirect_uri not in (client.get("redirect_uris") or []):
        raise ValueError("redirect_uri does not match a registered URI for this client.")
    if response_type != "code":
        raise ValueError("Only response_type=code is supported.")
    if not code_challenge:
        raise ValueError("PKCE is required: code_challenge is missing.")
    if code_challenge_method != "S256":
        raise ValueError("Only code_challenge_method=S256 is supported.")


async def issue_code(supabase: Any, to_thread: Any, *, client_id: str,
                     user_id: str, redirect_uri: str, scopes: list[str],
                     code_challenge: str, code_challenge_method: str,
                     resource: Optional[str]) -> str:
    """Mint a one-time authorization code bound to the PKCE challenge."""
    code = secrets.token_urlsafe(32)
    row = {
        "code_hash": _hash(code),
        "client_id": client_id,
        "user_id": user_id,
        "redirect_uri": redirect_uri,
        "scopes": scopes,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "resource": resource,
        "expires_at": _iso(_now() + timedelta(seconds=CODE_TTL_SECONDS)),
    }

    def _insert():
        supabase.table("oauth_codes").insert(row).execute()

    await to_thread(_insert)
    return code


def build_redirect(redirect_uri: str, params: dict) -> str:
    sep = "&" if "?" in redirect_uri else "?"
    return f"{redirect_uri}{sep}{urlencode(params)}"


# ── Token issuance ──────────────────────────────────────────────────────────
async def _mint_tokens(supabase: Any, to_thread: Any, *, client_id: str,
                       user_id: str, scopes: list[str],
                       resource: Optional[str]) -> tuple[dict, str]:
    """Create an access/refresh pair. Returns (response_body, token_row_id)."""
    access = secrets.token_urlsafe(32)
    refresh = secrets.token_urlsafe(32)
    now = _now()

    row = {
        "access_token_hash": _hash(access),
        "refresh_token_hash": _hash(refresh),
        "client_id": client_id,
        "user_id": user_id,
        "scopes": scopes,
        "resource": resource,
        "access_expires_at": _iso(now + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS)),
        "refresh_expires_at": _iso(now + timedelta(days=REFRESH_TOKEN_TTL_DAYS)),
    }

    def _insert():
        return supabase.table("oauth_tokens").insert(row).execute()

    res = await to_thread(_insert)
    token_id = (res.data or [{}])[0].get("id")

    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "refresh_token": refresh,
        "scope": " ".join(scopes),
    }, token_id


class OAuthError(Exception):
    """Carries an RFC 6749 error code.

    The code matters: Claude relies on `invalid_grant` specifically to know a
    refresh token is dead and a reconnect is needed. Returning a generic or
    custom code instead leaves the client retrying a token that will never
    work again.
    """
    def __init__(self, code: str, description: str = "", status: int = 400):
        super().__init__(description or code)
        self.code = code
        self.description = description
        self.status = status


async def exchange_code(supabase: Any, to_thread: Any, *, code: str,
                        client_id: str, redirect_uri: str,
                        code_verifier: str) -> dict:
    """Redeem an authorization code. Single use, PKCE enforced."""
    code_hash = _hash(code)

    def _q():
        return (supabase.table("oauth_codes").select("*")
                .eq("code_hash", code_hash).execute())
    res = await to_thread(_q)
    rows = res.data or []
    if not rows:
        raise OAuthError("invalid_grant", "Unknown or expired authorization code.")

    rec = rows[0]

    # Replay: this code was already redeemed. Revoke everything issued from it
    # — a code presented twice means either the client is broken or someone
    # else has a copy, and the second possibility is the one to plan for.
    if rec.get("consumed_at"):
        logger.warning("Authorization code replay detected for client %s", client_id)
        await revoke_tokens_for_user(supabase, to_thread, rec["user_id"], rec["client_id"])
        raise OAuthError("invalid_grant", "Authorization code has already been used.")

    try:
        expires = datetime.fromisoformat(str(rec["expires_at"]).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise OAuthError("invalid_grant", "Malformed code expiry.")
    if expires < _now():
        raise OAuthError("invalid_grant", "Authorization code has expired.")

    if rec["client_id"] != client_id:
        raise OAuthError("invalid_grant", "Code was not issued to this client.")
    if rec["redirect_uri"] != redirect_uri:
        raise OAuthError("invalid_grant", "redirect_uri does not match the authorization request.")

    if not verify_pkce(code_verifier, rec["code_challenge"], rec.get("code_challenge_method", "S256")):
        raise OAuthError("invalid_grant", "PKCE verification failed.")

    def _consume():
        (supabase.table("oauth_codes")
         .update({"consumed_at": _iso(_now())})
         .eq("code_hash", code_hash).execute())

    await to_thread(_consume)

    body, _ = await _mint_tokens(
        supabase, to_thread,
        client_id=client_id, user_id=rec["user_id"],
        scopes=rec.get("scopes") or SUPPORTED_SCOPES,
        resource=rec.get("resource"),
    )
    return body


async def refresh_tokens(supabase: Any, to_thread: Any, *, refresh_token: str,
                         client_id: str) -> dict:
    """Rotate a refresh token.

    Rotation is required for public clients. Detecting reuse of an already
    rotated token is the part that actually protects the user: it is the one
    observable signal that a refresh token has been copied.
    """
    token_hash = _hash(refresh_token)

    def _q():
        return (supabase.table("oauth_tokens").select("*")
                .eq("refresh_token_hash", token_hash).execute())
    res = await to_thread(_q)
    rows = res.data or []
    if not rows:
        raise OAuthError("invalid_grant", "Unknown refresh token.")

    rec = rows[0]

    if rec.get("replaced_by"):
        # Reuse of a rotated token. Revoke the whole chain: the legitimate
        # holder can reconnect, and whoever else has a copy is locked out.
        logger.warning("Refresh token reuse detected for user %s", rec["user_id"])
        await revoke_tokens_for_user(supabase, to_thread, rec["user_id"], rec["client_id"])
        raise OAuthError("invalid_grant", "Refresh token has already been used.")

    if rec.get("revoked_at"):
        raise OAuthError("invalid_grant", "Refresh token has been revoked.")

    if rec["client_id"] != client_id:
        raise OAuthError("invalid_grant", "Refresh token was not issued to this client.")

    exp = rec.get("refresh_expires_at")
    if exp:
        try:
            if datetime.fromisoformat(str(exp).replace("Z", "+00:00")) < _now():
                raise OAuthError("invalid_grant", "Refresh token has expired.")
        except (ValueError, TypeError):
            raise OAuthError("invalid_grant", "Malformed refresh expiry.")

    body, new_id = await _mint_tokens(
        supabase, to_thread,
        client_id=client_id, user_id=rec["user_id"],
        scopes=rec.get("scopes") or SUPPORTED_SCOPES,
        resource=rec.get("resource"),
    )

    def _mark():
        (supabase.table("oauth_tokens")
         .update({"replaced_by": new_id, "revoked_at": _iso(_now())})
         .eq("id", rec["id"]).execute())

    await to_thread(_mark)
    return body


async def revoke_tokens_for_user(supabase: Any, to_thread: Any,
                                 user_id: str, client_id: Optional[str] = None) -> None:
    """Revoke a user's tokens, optionally scoped to one client."""
    def _revoke():
        q = (supabase.table("oauth_tokens")
             .update({"revoked_at": _iso(_now())})
             .eq("user_id", user_id))
        if client_id:
            q = q.eq("client_id", client_id)
        q.execute()

    try:
        await to_thread(_revoke)
    except Exception as exc:
        logger.error("Token revocation failed for user %s: %s", user_id, exc)


# ── Bearer validation ───────────────────────────────────────────────────────
async def resolve_bearer(supabase: Any, to_thread: Any,
                         authorization_header: str) -> Optional[dict]:
    """Resolve a bearer token to its account, or None.

    Returns None for every failure mode rather than distinguishing them: the
    caller answers 401 identically in all cases, and telling an unauthenticated
    caller *why* a token failed helps only an attacker probing for valid ones.
    """
    if not authorization_header or not authorization_header.lower().startswith("bearer "):
        return None
    token = authorization_header[7:].strip()
    if not token:
        return None

    def _q():
        return (supabase.table("oauth_tokens").select("*")
                .eq("access_token_hash", _hash(token)).execute())
    try:
        res = await to_thread(_q)
    except Exception as exc:
        logger.error("Bearer lookup failed: %s", exc)
        return None

    rows = res.data or []
    if not rows:
        return None

    rec = rows[0]
    if rec.get("revoked_at"):
        return None

    try:
        if datetime.fromisoformat(str(rec["access_expires_at"]).replace("Z", "+00:00")) < _now():
            return None
    except (ValueError, TypeError):
        return None

    return {
        "user_id": rec["user_id"],
        "client_id": rec["client_id"],
        "scopes": rec.get("scopes") or [],
        "token_id": rec.get("id"),
    }


def www_authenticate_header(mcp_path: str = "/mcp") -> str:
    """The 401 challenge that starts discovery.

    Without this pointer a client has no way to find the metadata, and the
    connection simply fails as unauthorized instead of beginning the OAuth
    flow. It is the hinge the whole remote experience turns on.
    """
    prm = f"{PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"
    return f'Bearer resource_metadata="{prm}"'
