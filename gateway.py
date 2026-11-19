"""
HB-Eval — Reliability Gateway v2.2.0
========================================
Production FastAPI application deployed on Railway (private repo).

This version implements docs/PROTOCOL.md exactly, in lockstep with the SDK.
The four silent contract bugs found in the v2.0.0 review are all fixed here:

  1. HMAC signature (Protocol §4): the Gateway now verifies a signature over
     nonce_hex + "." + timestamp + "." + ciphertext_hex, keyed with the
     project's SEPARATE signing secret (from projects.hmac_secret_encrypted),
     NOT the api_key. This matches the SDK byte-for-byte.

  2. Nonce (Protocol §2): the nonce is 12 bytes, transmitted as 24 hex chars.
     The Gateway decodes the full 24 hex chars to 12 bytes for AES-GCM — the
     same 12 bytes the SDK used to encrypt. Decryption now succeeds.

  3. Recovery data (Protocol §6): the engine reads recovery_episodes (a list).
     The plain-request model and validation use that exact field name. The old
     recovery_attempts integer is gone.

  4. Identity (the fourth bug): the Gateway reads agent/account identity from
     the `agents` table, which is the live, current identity table (it holds
     the real rows: api_key, per-agent encrypted secrets, plan_type, and the
     owning user_id). The field name `project_id` is kept in the returned
     auth context purely for downstream key-name compatibility with the SDK
     and frontend, which still expect that key — it is populated from the
     agent row's own id, not from a separate `projects` table.

Server-side validation (Protocol §5) now rejects malformed payloads BEFORE
the engine runs, mirroring the SDK's client-side validation: defense in depth.

Required environment variables (Railway dashboard):
    AES_KEY        — base64 32-byte AES-256 key (project-level in this build)
    SUPABASE_URL   — Supabase project URL
    SUPABASE_KEY   — Supabase service_role key
    REDIS_URL      — Redis connection string (for rate limiting)
Optional:
    DEV_MODE       — "true" to expose Swagger UI and the /evaluate_plain route
    DEV_API_KEY    — fallback key when Supabase is unreachable in dev
    DEV_SIGNING_SECRET — base64 signing secret used in dev fallback
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac as hmac_module
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

import redis.asyncio as aioredis
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from pydantic import BaseModel, Field
from supabase import Client, create_client

from engines import HBEvalEngines
from validation import validate_payload, ValidationError
from scenario_orchestrator import aggregate_battery_results
# Remote MCP is an OPTIONAL access layer. Its absence must never take down
# evaluation, monitoring or memory — the core of the service. A hard import
# here would do exactly that: if hbeval_oauth.py is missing from a deployment,
# the whole Gateway fails to start and every endpoint dies with it.
#
# The module is also named hbeval_oauth rather than oauth to avoid colliding
# with the `oauth` package on PyPI, which a transitive dependency could pull
# in and shadow.
# Alerting is optional in the same sense OAuth is: its absence disables
# notifications and touches nothing else. A missing module must never stop the
# Gateway from evaluating and monitoring, which is the core of the service.
# Optional in the same sense as alerting: without it, passports are
# unavailable and nothing else changes. Evaluation and monitoring are the core
# of the service and must not depend on a reporting feature.
try:
    import passport as passport_lib
    _HAS_PASSPORT = True
except ImportError:
    passport_lib = None
    _HAS_PASSPORT = False

try:
    import alerts as alerts_lib
    _HAS_ALERTS = True
except ImportError:
    alerts_lib = None
    _HAS_ALERTS = False

try:
    import hbeval_oauth as oauth_lib
    import mcp_tools
    _HAS_OAUTH = True
except ImportError:
    oauth_lib = None
    mcp_tools = None
    _HAS_OAUTH = False

import edm_guard  # Layer 1: EDM selective-storage guard (persistence governance)
import hci_edm    # Layer 2: HCI-EDM performance-grounded interpretability

# ── 1. Logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("hb-eval-gateway")

# Fire-and-forget work (usage metering, audit log, evaluation storage) must not be fire-and-FORGET.
# asyncio keeps only a weak reference to a task, so an unreferenced one can be garbage-collected
# mid-flight, and an exception inside it is reported nowhere. Billing and audit records were being
# written that way. _spawn() holds a strong reference until the task finishes and logs any failure.
_BACKGROUND_TASKS: set = set()


def _spawn(coro, *, name: str | None = None):
    task = asyncio.create_task(coro, name=name)
    _BACKGROUND_TASKS.add(task)

    def _finished(t) -> None:
        _BACKGROUND_TASKS.discard(t)
        if not t.cancelled() and t.exception() is not None:
            logger.error("Background task %s failed: %r", t.get_name(), t.exception())

    task.add_done_callback(_finished)
    return task

# Two protocol numbers, deliberately separate (see hb-eval-sdk docs/PROTOCOL.md §1):
#
#   PROTOCOL_VERSION              the WIRE protocol: which requests exist and how they are signed
#                                 and shaped. Advertised on every response (X-HBEval-Protocol).
#                                 2.8.0 = 2.7.0 plus the additive, opt-in enforcement surface.
#   MEASUREMENT_PROTOCOL_VERSION  the protocol the SCORES were produced under. It is stamped into
#                                 the measurement fingerprint of every passport, and results under
#                                 different values are not comparable. It moves ONLY when how a
#                                 metric is computed moves. Raising it because an endpoint was
#                                 added would claim a measurement change that never happened, and
#                                 would break baseline continuity for every existing agent.
PROTOCOL_VERSION = "2.8.0"
MEASUREMENT_PROTOCOL_VERSION = "2.7.0"


# ── 2. Environment ──────────────────────────────────────────────────────────
def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        msg = f"Required environment variable '{name}' is missing or empty."
        logger.critical(msg)
        raise RuntimeError(msg)
    return value


_AES_KEY_B64 = _require_env("AES_KEY")
_SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
_SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
_DEV_MODE = os.environ.get("DEV_MODE", "false").lower() == "true"

# Until migration 15 has populated agents.api_key_hash for every agent, a key that is not found by its
# hash is looked up by its plaintext. That keeps existing agents working, at the price of keeping
# plaintext API keys in the database and querying them on every miss. Set to "false" as soon as every
# agent has a hash. Default stays "true" only so this change cannot lock out existing agents; the
# database review (R11-B) decides when it flips.
_ALLOW_PLAINTEXT_KEY_LOOKUP = os.environ.get("ALLOW_PLAINTEXT_API_KEY_LOOKUP", "true").strip().lower() == "true"

try:
    _AES_KEY = base64.b64decode(_AES_KEY_B64)
    if len(_AES_KEY) != 32:
        raise ValueError(f"AES key is {len(_AES_KEY)} bytes — must be exactly 32.")
except Exception as exc:
    logger.critical("Invalid AES_KEY: %s", exc)
    raise RuntimeError(f"Invalid AES_KEY: {exc}") from exc


# ── 3. Supabase ─────────────────────────────────────────────────────────────
_supabase: Client | None = None
if _SUPABASE_URL and _SUPABASE_KEY:
    _supabase = create_client(_SUPABASE_URL, _SUPABASE_KEY)
    logger.info("Supabase client initialised.")
else:
    logger.warning("Supabase not configured — storage, auditing, usage tracking disabled.")


# ── 4. Lifespan ─────────────────────────────────────────────────────────────
# Module-level Redis handle, shared by the rate limiter, the nonce-replay guard,
# and the daily-cap counter. Set during lifespan startup. If Redis is
# unavailable, _redis stays None and the guards fail SAFE (see helpers below).
_redis = None


async def _nonce_already_used(nonce: str) -> bool:
    """
    Replay protection. Record each nonce in Redis with a TTL slightly longer
    than the signature freshness window (5 min). If the same nonce arrives
    twice, the second time is a replay and is rejected.

    Fail-closed choice: if Redis is down we REJECT (return True) for the
    /evaluate path rather than allow a possible replay. Availability of Redis
    is already required for rate limiting, so this does not add a new
    dependency — it hardens an existing one.
    """
    if _redis is None:
        # Redis unavailable: be conservative. Reject to prevent replay.
        return True
    try:
        # SET key value NX EX 360 → returns True only if the key did NOT exist.
        was_set = await _redis.set(f"nonce:{nonce}", "1", nx=True, ex=360)
        return not was_set        # if it was already set, this is a replay
    except Exception as exc:
        logger.error("Nonce check failed: %s. Rejecting to be safe.", exc)
        return True


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _redis
    try:
        redis_conn = await aioredis.from_url(_REDIS_URL, decode_responses=True)
        await FastAPILimiter.init(redis_conn)

        # Retention runs in-process; see the note above the loop.
        retention_task = _spawn(_retention_loop(), name="retention-loop")
        _redis = redis_conn
        logger.info("Rate limiter + nonce guard initialised.")
    except Exception as exc:
        retention_task = None
        logger.error("Redis unavailable: %s. Proceeding without.", exc)
    yield
    logger.info("Gateway shutting down.")
    # A redeploy must not lose the usage increments and audit rows still in flight.
    if retention_task is not None:
        retention_task.cancel()
    pending = [t for t in _BACKGROUND_TASKS if t is not retention_task]
    if pending:
        _done, still = await asyncio.wait(pending, timeout=10)
        if still:
            logger.warning("Shutdown: %d background task(s) did not finish within 10 s.", len(still))


app = FastAPI(
    title="HB-Eval Gateway",
    version=PROTOCOL_VERSION,
    description="Reliability evaluation gateway for agentic AI systems.",
    docs_url="/docs" if _DEV_MODE else None,
    redoc_url=None,
    lifespan=lifespan,
)


# ── 4b. CORS ─────────────────────────────────────────────────────────────────
# Allowed browser origins are read from the ALLOWED_ORIGINS environment
# variable (set in Railway), a comma-separated list, e.g.:
#   https://hbeval.com,https://www.hbeval.com
# If the variable is unset we fall back to "*" ONLY in dev mode; in
# production an unset variable yields an empty allow-list (fail-closed),
# so a misconfiguration cannot silently open the gateway to every origin.
_origins_raw = os.getenv("ALLOWED_ORIGINS", "").strip()
if _origins_raw == "*" and not _DEV_MODE:
    # A wildcard with credentials makes Starlette REFLECT whatever Origin the caller sends, so any
    # website could make credentialed requests. It is honoured only in DEV_MODE; in production it is
    # a misconfiguration and is treated as an empty allow-list (fail-closed).
    logger.error("ALLOWED_ORIGINS='*' is refused outside DEV_MODE; no cross-origin access is allowed. "
                 "List the origins explicitly.")
    _allowed_origins = []
elif _origins_raw == "*":
    _allowed_origins = ["*"]
elif _origins_raw:
    _allowed_origins = [o.strip() for o in _origins_raw.split(",") if o.strip()]
else:
    _allowed_origins = ["*"] if _DEV_MODE else []

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-HBEval-Protocol", "X-HBEval-Protocol-Warning"],
)
logger.info("CORS allowed origins: %s", _allowed_origins or "(none — fail-closed)")

# Largest request body accepted, in bytes. An evaluation payload is a few hundred KB at the very most; an
# unbounded body is a memory-exhaustion request that costs the caller nothing.
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", "5000000"))


class _BodyTooLarge(Exception):
    pass


class _BodyLimitMiddleware:
    """Refuse oversized bodies: by Content-Length up front, and by counting bytes for chunked uploads."""

    def __init__(self, app, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            return await self._refuse(send)
        received = 0
        started = False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if not started:
                await self._refuse(send)

    async def _refuse(self, send):
        body = b'{"detail":"Request body too large."}'
        await send({"type": "http.response.start", "status": 413, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"x-hbeval-protocol", PROTOCOL_VERSION.encode())]})
        await send({"type": "http.response.body", "body": body})


class _SecurityHeadersMiddleware:
    """Defence-in-depth headers on every response. This is an API: nothing it returns should be framed,
    sniffed, cached by an intermediary, or sent onward in a Referer header."""

    BASE = ((b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"),
            (b"cache-control", b"no-store"), (b"x-frame-options", b"DENY"),
            (b"strict-transport-security", b"max-age=31536000; includeSubDomains"))

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                is_json = any(k.lower() == b"content-type" and v.startswith(b"application/json") for k, v in headers)
                for k, v in self.BASE:
                    if k not in present:
                        headers.append((k, v))
                if is_json and b"content-security-policy" not in present:
                    headers.append((b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


app.add_middleware(_SecurityHeadersMiddleware)
app.add_middleware(_BodyLimitMiddleware, max_bytes=MAX_BODY_BYTES)


def _protocol_parts(version):
    """'2.8.0' -> (2, 8, 0); anything that is not exactly three integers -> None."""
    if not isinstance(version, str):
        return None
    parts = version.strip().split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return int(parts[0]), int(parts[1]), int(parts[2])


@app.middleware("http")
async def _negotiate_protocol(request: Request, call_next):
    """Advertise this Gateway's wire protocol on every response, and check the caller's.

    major differs  -> 400. The two sides do not share a protocol, and answering would be guessing.
    minor differs  -> served, with X-HBEval-Protocol-Warning, because endpoints may be missing on one side.
    absent / unreadable -> served. Older SDKs, curl and browsers do not send it; refusing them would
                           break every existing client for no safety gain.
    """
    declared = request.headers.get("X-HBEval-Protocol")
    ours = _protocol_parts(PROTOCOL_VERSION)
    theirs = _protocol_parts(declared) if declared is not None else None
    advertise = {"X-HBEval-Protocol": PROTOCOL_VERSION}
    if theirs is not None and theirs[0] != ours[0]:
        return JSONResponse(
            status_code=400, headers=advertise,
            content={"detail": f"Unsupported protocol major version: client {declared}, gateway {PROTOCOL_VERSION}."})
    response = await call_next(request)
    response.headers["X-HBEval-Protocol"] = PROTOCOL_VERSION
    if theirs is not None and theirs[1] != ours[1]:
        response.headers["X-HBEval-Protocol-Warning"] = (
            f"minor version differs: client {declared}, gateway {PROTOCOL_VERSION}")
    return response

if not _HAS_OAUTH:
    logger.warning(
        "hbeval_oauth.py not found — remote MCP and OAuth endpoints are "
        "disabled. Every other capability is unaffected. Add the file to the "
        "repository root to enable remote MCP."
    )


# ── 5. Models ────────────────────────────────────────────────────────────────
class BatteryPreviewRequest(BaseModel):
    """A studio selection. Every field is optional — the default is the full
    taxonomy, because full coverage is what the battery is for."""
    n_scenarios: int = Field(default=18, ge=6, le=60)
    seed: int | None = Field(default=None)
    fault_types: list | None = Field(default=None)
    domains: list | None = Field(default=None)
    question: str | None = Field(default=None, max_length=500)


class EncryptedEvaluationRequest(BaseModel):
    ciphertext: str = Field(..., description="AES-256-GCM encrypted payload, hex-encoded.")


class PlainEvaluationRequest(BaseModel):
    # Field names match Protocol §5 exactly. Note recovery_episodes (a list),
    # never a recovery_attempts integer.
    trajectory: list[dict] = Field(default_factory=list)
    sub_tasks: int = Field(default=1, ge=1)
    constraint_violations: int = Field(default=0, ge=0)
    recovery_episodes: list[dict] = Field(default_factory=list)
    ti_score: float | None = Field(default=None)
    context: str = Field(default="")
    agent_id: str = Field(default="unknown-agent")
    project_id: str = Field(default="00000000-0000-0000-0000-000000000001")


# ── 6. Vault: decrypt project secrets at rest ────────────────────────────────
def _decrypt_secret(encrypted_b64: str) -> bytes:
    """
    Decrypt a project secret (AES key or signing secret) stored encrypted at
    rest in the projects table. The storage format is AES-256-GCM with the
    Gateway's master AES_KEY, encoded as base64(nonce[12] || ciphertext).

    This keeps per-project secrets encrypted in the database; they are only
    ever in plaintext in Gateway memory, for the duration of a single request.
    The database-side migration that provisions these secrets uses the same
    format (see database/migration_signing_secret.sql).
    """
    raw = base64.b64decode(encrypted_b64)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(_AES_KEY)
    return aesgcm.decrypt(nonce, ct, None)


# ── 7. Authentication ────────────────────────────────────────────────────────
async def _extract_api_key(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    token = authorization[len("Bearer "):].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    return token


async def verify_api_key(api_key: str = Depends(_extract_api_key)) -> dict[str, Any]:
    """
    Validate the API key against the `agents` table — the current, live
    identity table for both agents and their owning accounts — and return a
    context dict.

    This is the two-layer security model. For each agent we recover TWO
    secrets here, both stored encrypted at rest under the master key:

      • signing_secret  — verifies the request signature (Protocol §4)
      • agent_aes_key   — decrypts THIS agent's payload, and only this agent's

    The master key (AES_KEY env) decrypts each agent's per-agent AES key; the
    per-agent AES key then decrypts that agent's payloads. No two agents share
    an encryption key, so no agent can ever decrypt another's data — even in
    principle. This is why the identity lookup must recover the per-agent key
    here, rather than the Gateway decrypting payloads with the master key
    directly (the old single-layer model, now removed).
    """
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    if _supabase:
        # Look the key up by its SHA-256 digest, not by the key itself.
        #
        # api_key_hash was already being computed here, but only for log lines —
        # the lookup used the raw value, which requires the plaintext key to sit
        # in a queryable column. Matching on the digest is the standard practice
        # (Stripe, GitHub) for one reason: a leaked database then yields nothing
        # directly usable.
        #
        # Migration 15 adds and backfills api_key_hash. During rollout the
        # plaintext path is retained as a fallback so a Gateway deployed before
        # the migration lands does not reject every request. Once backfill is
        # confirmed complete, the fallback below should be deleted — leaving it
        # forever would preserve exactly the property this change removes.
        _COLS = ("id, user_id, plan_type, evaluation_limit, evaluations_this_month, "
                 "last_reset_date, evaluations_today, last_eval_date, "
                 "aes_key_encrypted, hmac_secret_encrypted, is_active")

        def _query_by_hash():
            return (
                _supabase.table("agents").select(_COLS)
                .eq("api_key_hash", api_key_hash).execute()
            )

        def _query_by_plaintext():
            return (
                _supabase.table("agents").select(_COLS)
                .eq("api_key", api_key).execute()
            )

        try:
            result = await asyncio.to_thread(_query_by_hash)
        except Exception:
            if not _ALLOW_PLAINTEXT_KEY_LOOKUP:
                logger.error("api_key_hash lookup failed and the plaintext fallback is disabled.")
                raise HTTPException(status_code=503, detail="Authentication backend unavailable.")
            # The column does not exist yet (migration 15 not applied). Fall
            # back rather than fail closed on every request during rollout.
            logger.warning(
                "api_key_hash lookup failed; falling back to plaintext match. "
                "Apply migration 15 to remove this path."
            )
            result = await asyncio.to_thread(_query_by_plaintext)

        if not result.data and _ALLOW_PLAINTEXT_KEY_LOOKUP:
            # Also try plaintext for rows the backfill has not reached.
            try:
                result = await asyncio.to_thread(_query_by_plaintext)
            except Exception:
                pass
        if not result.data:
            logger.warning("Rejected unknown API key (hash %s...).", api_key_hash[:8])
            raise HTTPException(status_code=401, detail="Invalid API key.")

        row = result.data[0]

        # An explicitly deactivated agent is refused, fail-closed.
        if row.get("is_active") is False:
            raise HTTPException(status_code=401, detail="This agent is inactive.")

        # Recover the signing secret (encrypted at rest with the master key).
        enc_sign = row.get("hmac_secret_encrypted")
        if not enc_sign:
            logger.error("Agent %s has no signing secret provisioned.", row["id"])
            raise HTTPException(status_code=401, detail="Agent credentials incomplete.")

        # Recover the per-agent AES key (encrypted at rest with the master key).
        enc_aes = row.get("aes_key_encrypted")
        if not enc_aes:
            logger.error("Agent %s has no AES key provisioned.", row["id"])
            raise HTTPException(status_code=401, detail="Agent credentials incomplete.")

        try:
            signing_secret = _decrypt_secret(enc_sign)
            agent_aes_key = _decrypt_secret(enc_aes)
        except Exception as exc:
            logger.error("Failed to decrypt credentials for agent %s: %s", row["id"], exc)
            raise HTTPException(status_code=401, detail="Agent credentials invalid.")

        if len(agent_aes_key) != 32:
            logger.error("Agent %s AES key is not 32 bytes after decryption.", row["id"])
            raise HTTPException(status_code=401, detail="Agent credentials invalid.")

        return {
            "project_id": row["id"],           # kept key name for downstream compatibility
            "agent_id_pk": row["id"],
            "user_id": row.get("user_id"),     # account owner — for account-level usage
            "api_key_hash": api_key_hash,
            "signing_secret": signing_secret,
            "agent_aes_key": agent_aes_key,    # per-agent key for payload decryption
            "plan_type": row.get("plan_type", "free"),
            "evaluation_limit": row.get("evaluation_limit", 500),
            "evaluations_this_month": row.get("evaluations_this_month", 0),
            "last_reset_date": row.get("last_reset_date", "2000-01-01"),
            "evaluations_today": row.get("evaluations_today", 0),
            "last_eval_date": row.get("last_eval_date", "2000-01-01"),
        }
    else:
        # Development fallback ONLY. This branch is reached when Supabase is not configured. In
        # production that is a misconfiguration, and it must fail CLOSED: the fallback below uses an
        # empty default API key and constant default secrets that anyone can read in this file, so
        # letting it run outside DEV_MODE would let any caller authenticate (an empty bearer token
        # matches an empty key, and the default signing and AES secrets are public).
        if not _DEV_MODE:
            logger.critical("Authentication backend (Supabase) is not configured and DEV_MODE is off. "
                            "Refusing every request.")
            raise HTTPException(status_code=503, detail="Authentication backend is not configured.")
        dev_key = os.environ.get("DEV_API_KEY", "")
        if not dev_key or not hmac_module.compare_digest(api_key, dev_key):
            raise HTTPException(status_code=401, detail="Invalid API key.")
        dev_secret_b64 = os.environ.get("DEV_SIGNING_SECRET", base64.b64encode(b"d" * 32).decode())
        dev_aes_b64 = os.environ.get("DEV_AGENT_AES_KEY", base64.b64encode(b"a" * 32).decode())
        return {
            "project_id": "00000000-0000-0000-0000-000000000001",
            "agent_id_pk": "00000000-0000-0000-0000-000000000001",
            "api_key_hash": api_key_hash,
            "signing_secret": base64.b64decode(dev_secret_b64),
            "agent_aes_key": base64.b64decode(dev_aes_b64),
            "plan_type": "pro",
            "evaluation_limit": 999999,
            "evaluations_this_month": 0,
            "last_reset_date": "2000-01-01",
        }


# ── 8. Usage gate ────────────────────────────────────────────────────────────
# Account-level limits. The monthly allowance belongs to the ACCOUNT, not to
# each agent — so a user with several agents still shares ONE pool of 500
# (free) or 5,000 (pro). The authoritative counter lives in the account_usage
# table (migration 08); usage_gate reads it via the get_account_quota RPC
# rather than summing per-agent counters, so there is a single source of
# truth for the whole account regardless of how many agents it owns. The
# daily cap is likewise account-wide (allowance / 28).
ACCOUNT_LIMITS = {"free": 500, "pro": 5_000, "enterprise": 2_147_483_647}

# Free monthly runs of the VERIFIED path, per account.
#
# The verified path is the one capability the free plan cannot otherwise reach:
# the platform calls the agent's endpoint itself, so the result cannot be
# shaped by the agent. That is the difference between evidence an agent
# reported about itself and evidence HB-Eval observed — the strongest thing the
# paid tier offers, and the hardest to convey in a sentence.
#
# Five is enough to run it, read the passport, and compare it against a
# self-reported one. It is also small enough that the outbound calls it spends
# on somebody else's infrastructure stay bounded.
#
# Per ACCOUNT, not per agent: per agent would mean three agents buys fifteen.
# Counted separately from the monthly allowance, because spending an ordinary
# quota to discover a paid feature exists is the opposite of the intent.
VERIFIED_TRIAL_LIMIT = 5

# The daily cap spreads a monthly allowance across the month so a single
# afternoon cannot exhaust it. That is right for ordinary use and wrong for
# testing the platform itself, where the whole point is to finish a run today.
#
# WHY AN ENVIRONMENT VARIABLE AND NOT A CODE CHANGE
# Turning a limit off by editing a constant means turning it back on requires a
# deploy — and a protection that is inconvenient to restore tends not to be
# restored. This can be flipped from Railway in seconds, in both directions.
#
# DEFAULTS TO ON. A deployment that forgets to set it gets the safe behaviour,
# which is the only sensible direction for a default to fail in.
DAILY_CAP_ENABLED = os.environ.get(
    "DAILY_CAP_ENABLED", "true").strip().lower() not in ("false", "0", "no")

if not DAILY_CAP_ENABLED:
    # Logged at WARNING on every start, so a change made for an afternoon of
    # testing cannot quietly become permanent. A rate limit nobody remembers
    # disabling is how a month's allowance disappears in an hour.
    logger.warning(
        "DAILY_CAP_ENABLED=false - the per-day evaluation cap is OFF. An "
        "account can spend its entire monthly allowance in a single day. "
        "Set DAILY_CAP_ENABLED=true to restore it.")


async def _read_account_quota(user_id: str | None, plan: str,
                              fallback: dict | None = None) -> dict:
    """Read the account's shared usage counters and its limits.

    Extracted so REST and MCP consult the SAME numbers by the same route. They
    previously did not: the whole quota system lived on usage_gate, which the
    MCP endpoint never touches, so a paid account could run verified
    evaluations through MCP with no ceiling and no counter. A second door to a
    metered capability that carries a different lock is a door with no lock.

    Duplicating the logic instead of sharing it would recreate exactly the
    drift hazard fixed elsewhere in this release.
    """
    import math
    now = datetime.now(timezone.utc)
    account_limit = ACCOUNT_LIMITS.get(plan, 500)
    month_used = 0
    today_used = 0

    if _supabase and user_id:
        def _q():
            return (_supabase.rpc("get_account_quota", {"p_user_id": user_id})
                    .execute())
        try:
            res = await asyncio.to_thread(_q)
            rows = res.data or []
            if rows:
                row = rows[0]
                account_limit = row.get("evaluation_limit") or account_limit
                month_used = row.get("evaluations_this_month", 0) or 0

            def _qd():
                return (_supabase.table("account_usage")
                        .select("evaluations_today, last_eval_date")
                        .eq("user_id", user_id).execute())
            resd = await asyncio.to_thread(_qd)
            for a in (resd.data or []):
                try:
                    d2 = datetime.fromisoformat(str(a.get("last_eval_date", "2000-01-01")))
                    if d2.date() == now.date():
                        today_used = a.get("evaluations_today", 0) or 0
                except (ValueError, TypeError):
                    pass
        except Exception as exc:
            logger.error("Account quota read failed for %s: %s", user_id, exc)
            # A transient database error must not lock out legitimate users, so
            # fall back to the per-agent counter, which can never exceed the
            # account pool and is therefore the conservative choice.
            if fallback:
                month_used = fallback.get("evaluations_this_month", 0) or 0
                today_used = fallback.get("evaluations_today", 0) or 0

    return {
        "account_limit": account_limit,
        "month_used": month_used,
        "today_used": today_used,
        # Monthly allowance spread across 28 days, so a single day cannot burn
        # the month.
        "daily_cap": max(1, math.ceil(account_limit / 28)),
        "plan": plan,
    }


def _quota_violation(q: dict, units: int = 1) -> str | None:
    """Reason the request exceeds quota, or None when it is within limits."""
    if q["month_used"] + max(0, units - 1) >= q["account_limit"]:
        if q["plan"] == "free":
            return (f"Monthly account limit reached ({q['account_limit']}). "
                    "Upgrade at https://hbeval.com/pricing for 5,000 "
                    "evaluations/month.")
        return (f"Monthly account limit of {q['account_limit']} reached. "
                "Contact support.")
    if DAILY_CAP_ENABLED and \
            q["today_used"] + max(0, units - 1) >= q["daily_cap"]:
        return (f"Daily account limit reached ({q['daily_cap']}/day). Your "
                "monthly allowance is spread across the month; please continue "
                "tomorrow.")
    return None


async def usage_gate(auth: dict = Depends(verify_api_key)) -> dict:
    """Enforce the account's monthly and daily ceilings on a REST call.

    Thin wrapper over the shared helpers so this path and the MCP path can
    never diverge on what the limits are or how they are read.
    """
    if not _supabase:
        return auth

    quota = await _read_account_quota(
        auth.get("user_id"), auth.get("plan_type", "free"), fallback=auth
    )
    violation = _quota_violation(quota, units=1)
    if violation:
        raise HTTPException(status_code=429, detail=violation)

    auth["account_month_used"] = quota["month_used"]
    auth["account_limit"] = quota["account_limit"]
    return auth


async def _increment_usage(user_id: str | None, count: int = 1) -> None:
    """Increment the ACCOUNT's shared usage by `count` evaluation units.

    The monthly pool belongs to the account (user), shared by all its agents
    (migration 08). A battery of N scenarios costs N units. We call the
    account-level RPCs, which atomically add N to the shared counter and handle
    month/day rollover server-side. count is clamped (DoS guard).

    If user_id is missing (e.g. dev key), we no-op rather than miscount.
    """
    if not _supabase or not user_id:
        return
    count = max(1, min(int(count), 100))   # never < 1, never absurd
    now = datetime.now(timezone.utc)

    def _rpc_month():
        _supabase.rpc("increment_account_usage", {
            "p_user_id": user_id,
            "p_count": count,
            "p_current_year": now.year,
            "p_current_month": now.month,
        }).execute()

    try:
        await asyncio.to_thread(_rpc_month)
    except Exception as exc:
        logger.error("Account usage increment failed for %s: %s", user_id, exc)

    def _rpc_daily():
        _supabase.rpc("increment_account_daily", {
            "p_user_id": user_id,
            "p_count": count,
            "p_today": now.date().isoformat(),
        }).execute()

    try:
        await asyncio.to_thread(_rpc_daily)
    except Exception as exc:
        logger.error("Account daily increment failed for %s: %s", user_id, exc)


# ── 9. Rate-limit identifier ─────────────────────────────────────────────────
async def _api_key_identifier(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return hashlib.sha256(auth_header[len("Bearer "):].encode()).hexdigest()
    return request.client.host if request.client else "anonymous"


# ── 10. Audit log ────────────────────────────────────────────────────────────
async def _audit_log(*, project_id, api_key_hash, endpoint, method, status_code,
                     request_id=None, error_code=None, latency_ms=0, ip_raw=None) -> None:
    if not _supabase:
        return
    ip_hashed = hashlib.sha256(ip_raw.encode()).hexdigest() if ip_raw else None

    def _write():
        _supabase.table("audit_logs").insert({
            "project_id": project_id, "api_key_hash": api_key_hash,
            "endpoint": endpoint, "method": method, "status_code": status_code,
            "request_id": request_id, "error_code": error_code,
            "latency_ms": latency_ms, "ip_address": ip_hashed,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()

    try:
        await asyncio.to_thread(_write)
    except Exception as exc:
        logger.error("Audit log write failed: %s", exc)


# ── 11. History + persistence ────────────────────────────────────────────────
async def _fetch_history(project_id: str, agent_id: str) -> dict[str, list]:
    if not _supabase:
        return {"pei_scores": [], "irs_scores": [], "outcomes": []}

    def _query():
        result = (
            _supabase.table("evaluations")
            .select("pei_score, irs_score, verdict")
            .eq("project_id", project_id).eq("agent_id", agent_id)
            .order("created_at", desc=True).limit(100).execute()
        )
        rows = result.data or []
        return {
            "pei_scores": [r["pei_score"] for r in rows if r.get("pei_score") is not None],
            "irs_scores": [r["irs_score"] for r in rows if r.get("irs_score") is not None],
            "outcomes": [r["verdict"] == "SAFE" for r in rows],
        }

    try:
        return await asyncio.to_thread(_query)
    except Exception as exc:
        logger.error("History fetch failed: %s", exc)
        return {"pei_scores": [], "irs_scores": [], "outcomes": []}


async def _store_evaluation(run_id, project_id, agent_id, payload, result) -> None:
    if not _supabase:
        return
    metrics = result.get("metrics") or result.get("aggregate_metrics", {})
    hash_source = payload.get("trajectory") or payload.get("scenario_results") \
        or payload.get("base_task", {})
    traj_hash = hashlib.sha256(
        json.dumps(hash_source, sort_keys=True).encode()
    ).hexdigest()

    def _write():
        _supabase.table("evaluations").insert({
            "id": run_id, "project_id": project_id, "agent_id": agent_id,
            "trajectory_hash": traj_hash,
            "verdict": result["verdict"],
            "pei_score": metrics.get("pei"), "irs_score": metrics.get("irs"),
            "frr_score": metrics.get("frr"), "ti_score": metrics.get("ti"),
            "csi_score": metrics.get("csi"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()

    try:
        await asyncio.to_thread(_write)
    except Exception as exc:
        logger.error("Evaluation persist failed: %s", exc)


# ── 12. Signature verification (Protocol §4) ─────────────────────────────────
def _verify_signature(signing_secret: bytes, nonce_hex: str, timestamp: str,
                      ciphertext_hex: str, received_sig: str) -> None:
    """
    Verify the canonical signature. Keyed with the SEPARATE signing secret,
    over nonce_hex + "." + timestamp + "." + ciphertext_hex. This is the exact
    string and key the SDK uses (Protocol §4).
    """
    try:
        request_time = int(timestamp)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid timestamp.")

    if abs(int(time.time()) - request_time) > 300:
        raise HTTPException(status_code=403, detail="Request expired (clock skew > 5 min).")

    message = f"{nonce_hex}.{timestamp}.{ciphertext_hex}".encode("utf-8")
    expected = hmac_module.new(signing_secret, message, hashlib.sha256).hexdigest()

    # Constant-time comparison prevents timing side-channels.
    if not hmac_module.compare_digest(expected, received_sig):
        raise HTTPException(status_code=403, detail="Invalid signature.")


async def _claim_verified_trial(user_id: str | None) -> tuple:
    """Claim one free verified run. Returns (granted, remaining).

    Atomic in the database rather than read-then-write here: two requests
    starting at once would otherwise both read four-used and both proceed,
    which is not an exotic race — it is what a script does.
    """
    if not _supabase or not user_id:
        return False, 0

    def _q():
        return _supabase.rpc("claim_verified_trial", {
            "p_user_id": user_id,
            "p_limit": VERIFIED_TRIAL_LIMIT,
        }).execute()

    try:
        res = await asyncio.to_thread(_q)
        rows = res.data or []
        if not rows:
            return False, 0
        row = rows[0]
        return bool(row.get("granted")), int(row.get("remaining") or 0)
    except Exception:
        # Fail CLOSED. A database problem must not silently hand out unlimited
        # runs of the one metered capability the free plan is gated from.
        return False, 0


async def _refund_verified_trial(user_id: str | None) -> None:
    """Give a claimed trial back when the run failed for our reasons.

    Without this, a Gateway timeout or an internal error costs somebody an
    allowance they never got any value from.
    """
    if not _supabase or not user_id:
        return

    def _q():
        return _supabase.rpc("refund_verified_trial",
                             {"p_user_id": user_id}).execute()
    try:
        await asyncio.to_thread(_q)
    except Exception:
        # Nothing to do. Losing a refund is a minor unfairness; raising here
        # would replace the user's real error with a bookkeeping one.
        pass


# ── 13. Plan gating ──────────────────────────────────────────────────────────
def _is_paid(plan_type: str) -> bool:
    return plan_type in ("pro", "enterprise")


def _apply_plan_gates(result: dict, plan_type: str) -> dict:
    """
    Gate ONLY the formal tier-qualification credential, never the diagnostic
    value.

    Free-tier users receive the full metrics AND the full diagnostic guidance —
    they learn exactly where their agent stands and how to improve it. What
    requires a paid plan is the *formal* credential: the official, displayable
    Tier-qualification stamp. This split is deliberate: knowledge and
    mentorship are free (which is what earns trust and drives word-of-mouth
    adoption), while the official, showable credential is the paid product. A
    free user is never left with a bare "fail" — they always receive the
    guidance that tells them why and what to do next.
    """
    if _is_paid(plan_type):
        return result
    gated = dict(result)
    gated["tier"] = None
    gated["qualified"] = False
    gated["certified"] = False
    gated["note"] = (
        "Your full metrics and improvement guidance are included. The formal "
        "Tier-qualification credential requires a Pro plan. "
        "See https://hbeval.com/pricing"
    )
    return gated


# ── 14. Endpoints ────────────────────────────────────────────────────────────
# How long a dependency probe may take before it counts as unavailable. Short,
# because a health check that hangs is itself an outage: whatever polls this is
# waiting on it.
HEALTH_PROBE_TIMEOUT_S = 3.0

# Last successful retention sweep, exposed on /health. A retention policy is a
# promise, and a promise nobody can verify is only a claim. This makes it
# checkable.
_last_retention_run: str | None = None
_last_retention_result: dict | None = None


async def _probe_supabase() -> tuple:
    """Is the database actually reachable? Returns (state, detail)."""
    if not _supabase:
        return "not_configured", "Storage and auditing are disabled."

    def _q():
        # The cheapest query that proves a round trip completed.
        return _supabase.table("agents").select("id").limit(1).execute()

    try:
        await asyncio.wait_for(asyncio.to_thread(_q),
                               timeout=HEALTH_PROBE_TIMEOUT_S)
        return "ok", None
    except asyncio.TimeoutError:
        return "degraded", f"No response within {HEALTH_PROBE_TIMEOUT_S}s."
    except Exception as exc:
        # The exception TYPE only. This endpoint is public, and a database
        # error string can name schemas, hosts and columns.
        return "down", type(exc).__name__


async def _probe_redis() -> tuple:
    """Redis backs replay protection and rate limiting.

    Its absence is reported as degraded rather than down: evaluation still
    works, but the nonce guard fails closed, so requests get rejected. That is
    a real service impact, and reporting "ok" would hide it.
    """
    if _redis is None:
        return "degraded", "Replay protection and rate limiting are unavailable."
    try:
        await asyncio.wait_for(_redis.ping(), timeout=HEALTH_PROBE_TIMEOUT_S)
        return "ok", None
    except asyncio.TimeoutError:
        return "degraded", f"No response within {HEALTH_PROBE_TIMEOUT_S}s."
    except Exception as exc:
        return "degraded", type(exc).__name__


# ── R11-C: enforcement surface (OFF unless HBEVAL_ENFORCE_API_KEY is set) ──
try:
    from enforcement_mount import mount as _mount_enforcement
    ENFORCEMENT_STATUS = _mount_enforcement(app)
except Exception as _exc:          # never take the Gateway down for this
    ENFORCEMENT_STATUS = {"enforcement_api": "disabled", "reason": "mount error"}
    logger.error("enforcement mount failed: %s", _exc)


@app.get("/health", tags=["Infrastructure"])
async def health() -> dict:
    """Service health, checked rather than asserted.

    This previously returned {"status": "ok"} unconditionally, which meant it
    reported healthy with the database down. A health check that cannot detect
    ill health is worse than none: it turns an outage into a silent one, and
    anything monitoring it learns nothing.

    Public and unauthenticated, so it names no hostname, schema or error text —
    only which component is affected, and how.
    """
    started = time.monotonic()
    db_probe, redis_probe = await asyncio.gather(
        _probe_supabase(), _probe_redis(),
    )
    db_state, db_detail = db_probe
    redis_state, redis_detail = redis_probe

    # The worst component decides. A service whose database is dead is not "ok"
    # merely because the web process is still answering.
    if db_state == "down":
        overall = "down"
    elif "degraded" in (db_state, redis_state) or db_state == "not_configured":
        overall = "degraded"
    else:
        overall = "ok"

    return {
        "status": overall,
        "version": PROTOCOL_VERSION,                      # kept for existing consumers: the wire protocol
        "protocol_version": PROTOCOL_VERSION,
        "measurement_protocol_version": MEASUREMENT_PROTOCOL_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "database": {"status": db_state, "detail": db_detail},
            "cache": {"status": redis_state, "detail": redis_detail},
            "api": {"status": "ok", "detail": None},
            "enforcement": {"status": ENFORCEMENT_STATUS["enforcement_api"],
                            "detail": ENFORCEMENT_STATUS["reason"]},
        },
        # Published so the retention policy can be verified rather than taken
        # on trust.
        "retention": {
            "last_run": _last_retention_run,
            "last_result": _last_retention_result,
        },
        "probe_ms": int((time.monotonic() - started) * 1000),
    }


@app.post("/evaluate", tags=["Evaluation"])
async def evaluate(
    http_request: Request,
    body: EncryptedEvaluationRequest,
    auth: dict = Depends(usage_gate),
    _rate: bool = Depends(RateLimiter(times=100, seconds=60, identifier=_api_key_identifier)),
) -> dict:
    run_id = str(uuid.uuid4())
    project_id = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    plan_type = auth["plan_type"]
    start_time = time.monotonic()
    status_code, error_code, success = 500, "UNKNOWN_ERROR", False

    try:
        nonce = http_request.headers.get("X-HBEval-Nonce", "")
        timestamp = http_request.headers.get("X-HBEval-Timestamp", "")
        signature = http_request.headers.get("X-HBEval-Signature", "")

        if not all([nonce, timestamp, signature]):
            status_code, error_code = 400, "MISSING_SECURITY_HEADERS"
            raise HTTPException(status_code=400, detail="Missing security headers.")

        # Verify signature against the separate signing secret (Protocol §4).
        try:
            _verify_signature(auth["signing_secret"], nonce, timestamp, body.ciphertext, signature)
        except HTTPException as exc:
            status_code = exc.status_code
            error_code = "INVALID_SIGNATURE" if exc.status_code == 403 else "INVALID_TIMESTAMP"
            raise

        # Replay protection: a valid signature + fresh timestamp is not enough —
        # an attacker could capture and resend an authentic request within the
        # 5-minute window. Each nonce may be used only once.
        if await _nonce_already_used(nonce):
            status_code, error_code = 409, "REPLAY_DETECTED"
            raise HTTPException(status_code=409, detail="This request has already been processed (replay detected).")

        # Decrypt with the PER-AGENT AES key (two-layer model). The master key
        # already decrypted this agent's key in verify_api_key; here we use that
        # key to decrypt the payload. nonce is 24 hex chars → 12 bytes (Protocol §2).
        try:
            aesgcm = AESGCM(auth["agent_aes_key"])
            gcm_nonce = bytes.fromhex(nonce)        # full 24 hex chars → 12 bytes
            raw_bytes = bytes.fromhex(body.ciphertext)
            decrypted = aesgcm.decrypt(gcm_nonce, raw_bytes, None)
            payload = json.loads(decrypted.decode())
        except Exception as exc:
            status_code, error_code = 400, "DECRYPTION_FAILED"
            logger.warning("Decryption failed (run %s): %s", run_id, exc)
            raise HTTPException(status_code=400, detail="Payload decryption failed.")

        # Server-side validation BEFORE computation (Protocol §5, defense in depth).
        try:
            validate_payload(payload)
        except ValidationError as exc:
            status_code, error_code = 400, "VALIDATION_FAILED"
            raise HTTPException(status_code=400, detail=str(exc))

        agent_id = payload.get("agent_id", "unknown-agent")
        history = await _fetch_history(project_id, agent_id)
        result = HBEvalEngines.evaluate(payload, history)

        gated = _apply_plan_gates(result, plan_type)
        _spawn(_store_evaluation(run_id, project_id, agent_id, payload, result))
        # Layer 1 — EDM selective storage: consolidate only if PEI>=0.8 AND TI>=4.0
        _spawn(edm_guard.consolidate(_supabase, run_id, project_id, payload, result))

        success, status_code, error_code = True, 200, None
        return {**gated, "run_id": run_id}

    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in /evaluate (run %s).", run_id)
        status_code, error_code = 500, "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw = http_request.client.host if http_request.client else None
        _spawn(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/evaluate", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))
        if success:
            _spawn(_increment_usage(auth.get("user_id")))


@app.post("/evaluate_battery", tags=["Evaluation"])
async def evaluate_battery(
    http_request: Request,
    body: EncryptedEvaluationRequest,
    auth: dict = Depends(usage_gate),
    _rate: bool = Depends(RateLimiter(times=100, seconds=60, identifier=_api_key_identifier)),
) -> dict:
    """Active evaluation: score an SDK-collected fault-injection battery.

    The SDK runs the agent across the injected scenario battery and sends the
    raw per-scenario responses here (encrypted + signed, exactly like
    /evaluate). The SERVER scores all five metrics and decides the verdict —
    the client never scores itself, which keeps strictness authoritative and
    tamper-resistant. Returns a comprehensive report (verdict + summary +
    per-scenario detail), not a single number.
    """
    run_id = str(uuid.uuid4())
    project_id = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    plan_type = auth["plan_type"]
    start_time = time.monotonic()
    status_code, error_code, success = 500, "UNKNOWN_ERROR", False

    try:
        nonce = http_request.headers.get("X-HBEval-Nonce", "")
        timestamp = http_request.headers.get("X-HBEval-Timestamp", "")
        signature = http_request.headers.get("X-HBEval-Signature", "")

        if not all([nonce, timestamp, signature]):
            status_code, error_code = 400, "MISSING_SECURITY_HEADERS"
            raise HTTPException(status_code=400, detail="Missing security headers.")

        # Same signature verification as /evaluate (Protocol §4).
        try:
            _verify_signature(auth["signing_secret"], nonce, timestamp, body.ciphertext, signature)
        except HTTPException as exc:
            status_code = exc.status_code
            error_code = "INVALID_SIGNATURE" if exc.status_code == 403 else "INVALID_TIMESTAMP"
            raise

        # Same replay protection.
        if await _nonce_already_used(nonce):
            status_code, error_code = 409, "REPLAY_DETECTED"
            raise HTTPException(status_code=409, detail="This request has already been processed (replay detected).")

        # Same per-agent AES decryption.
        try:
            aesgcm = AESGCM(auth["agent_aes_key"])
            gcm_nonce = bytes.fromhex(nonce)
            raw_bytes = bytes.fromhex(body.ciphertext)
            decrypted = aesgcm.decrypt(gcm_nonce, raw_bytes, None)
            payload = json.loads(decrypted.decode())
        except Exception as exc:
            status_code, error_code = 400, "DECRYPTION_FAILED"
            logger.warning("Battery decryption failed (run %s): %s", run_id, exc)
            raise HTTPException(status_code=400, detail="Payload decryption failed.")

        # Validate the battery payload shape (defense in depth).
        scenario_results = payload.get("scenario_results")
        if not isinstance(scenario_results, list) or not scenario_results:
            status_code, error_code = 400, "VALIDATION_FAILED"
            raise HTTPException(status_code=400, detail="Field 'scenario_results' must be a non-empty list.")

        # Hard ceiling on battery size (DoS protection, mirrors MAX_SCENARIOS).
        if len(scenario_results) > 60:
            status_code, error_code = 400, "BATTERY_TOO_LARGE"
            raise HTTPException(status_code=400, detail="Battery exceeds the maximum of 60 scenarios.")

        # Fair billing: a battery runs the agent once PER scenario, so it costs
        # one evaluation unit per scenario (not one for the whole battery).
        billable_units = len(scenario_results)

        agent_id = payload.get("agent_id", "unknown-agent")
        required = payload.get("required_in_response", [])

        # Server-authoritative scoring — the client cannot tamper with this.
        report = aggregate_battery_results(scenario_results, required)

        # Battery-spec drift check. The SDK mirrors this server's fault
        # specification so the local and verified paths stress agents
        # identically. If the two have diverged, the numbers are no longer
        # comparable — and that must appear on the report rather than being
        # left for someone to discover by contradiction later.
        client_spec = payload.get("battery_spec")
        try:
            from fault_injection import battery_spec_fingerprint
            server_spec = battery_spec_fingerprint()
        except Exception:
            server_spec = None

        if client_spec and server_spec and client_spec != server_spec:
            report["battery_spec_mismatch"] = {
                "client": str(client_spec)[:32],
                "server": server_spec,
                "note": ("This SDK ran a different fault specification from "
                         "the one this server scores against. Local and "
                         "verified results are not directly comparable until "
                         "the SDK is upgraded."),
            }
            logger.warning(
                "Battery spec drift: client=%s server=%s (agent %s)",
                client_spec, server_spec, agent_id,
            )
        elif client_spec is None:
            # Older SDKs do not send it. Recorded, not warned: their absence is
            # expected, not an anomaly.
            report["battery_spec_mismatch"] = None

        gated = _apply_plan_gates(report, plan_type)
        _spawn(_store_evaluation(run_id, project_id, agent_id, payload, report))
        # EDM consolidation uses the aggregate report (high-quality episodes).
        _spawn(edm_guard.consolidate(_supabase, run_id, project_id, payload, report))

        success, status_code, error_code = True, 200, None
        return {**gated, "run_id": run_id}

    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in /evaluate_battery (run %s).", run_id)
        status_code, error_code = 500, "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw = http_request.client.host if http_request.client else None
        _spawn(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/evaluate_battery", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))
        if success:
            _spawn(_increment_usage(auth.get("user_id"), billable_units))



@app.post("/evaluate_verified", tags=["Evaluation"])
async def evaluate_verified(
    http_request: Request,
    body: EncryptedEvaluationRequest,
    auth: dict = Depends(usage_gate),
    _rate: bool = Depends(RateLimiter(times=20, seconds=60, identifier=_api_key_identifier)),
) -> dict:
    """Verified active evaluation (paid path A).

    The PLATFORM calls the user's agent endpoint across the fault-injection
    battery — the user never touches the middle, so the result cannot be
    tampered with and earns a `verified` mark. Because this consumes platform
    resources (outbound calls, up to 100 scenarios), it is restricted to paid
    plans and carries tighter rate limits.

    Security: the agent URL is SSRF-validated before any call; outbound calls
    are IP-pinned, timeout-bounded, redirect-refused, and size-capped
    (see verified_runner + ssrf_guard). Encrypted + signed like /evaluate.
    """
    run_id = str(uuid.uuid4())
    project_id = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    plan_type = auth["plan_type"]
    start_time = time.monotonic()
    status_code, error_code, success = 500, "UNKNOWN_ERROR", False
    billable_units = 1   # fair billing: verified battery costs N units (set below)

    try:
        # ── Plan gate, with a monthly allowance on the free plan ─────────
        #
        # The verified path used to be closed to free accounts entirely. That
        # made the most important difference between the plans invisible: on
        # every other path the behavioural evidence comes from the agent's own
        # runner, and here it comes from HB-Eval calling the agent itself.
        #
        # Somebody who has never seen both cannot evaluate the claim, and no
        # amount of prose substitutes for running it and reading the two
        # passports side by side. Five runs a month is enough to do that.
        #
        # The trial is claimed BEFORE the outbound call and refunded if the
        # run fails for our reasons. Claiming afterwards would let a caller
        # start many runs at once and have them all pass the check.
        trial_claimed = False
        trials_left = None
        if plan_type in (None, "free", "trial"):
            granted, remaining = await _claim_verified_trial(
                auth.get("user_id"))
            if not granted:
                status_code, error_code = 402, "UPGRADE_REQUIRED"
                raise HTTPException(
                    status_code=402,
                    detail=(
                        f"You have used all {VERIFIED_TRIAL_LIMIT} free "
                        "verified evaluations this month. The allowance "
                        "resets at the start of next month, or a paid plan "
                        "removes the limit. Meanwhile /evaluate_battery runs "
                        "locally with no cap — the difference is that it "
                        "scores evidence your agent reports about itself, "
                        "while this path scores what HB-Eval observed."
                    ),
                )
            trial_claimed = True
            trials_left = remaining

        # ── Same security envelope as /evaluate (signature + nonce + decrypt) ──
        nonce = http_request.headers.get("X-HBEval-Nonce", "")
        timestamp = http_request.headers.get("X-HBEval-Timestamp", "")
        signature = http_request.headers.get("X-HBEval-Signature", "")
        if not all([nonce, timestamp, signature]):
            status_code, error_code = 400, "MISSING_SECURITY_HEADERS"
            raise HTTPException(status_code=400, detail="Missing security headers.")

        try:
            _verify_signature(auth["signing_secret"], nonce, timestamp, body.ciphertext, signature)
        except HTTPException as exc:
            status_code = exc.status_code
            error_code = "INVALID_SIGNATURE" if exc.status_code == 403 else "INVALID_TIMESTAMP"
            raise

        if await _nonce_already_used(nonce):
            status_code, error_code = 409, "REPLAY_DETECTED"
            raise HTTPException(status_code=409, detail="This request has already been processed (replay detected).")

        try:
            aesgcm = AESGCM(auth["agent_aes_key"])
            gcm_nonce = bytes.fromhex(nonce)
            raw_bytes = bytes.fromhex(body.ciphertext)
            decrypted = aesgcm.decrypt(gcm_nonce, raw_bytes, None)
            payload = json.loads(decrypted.decode())
        except Exception as exc:
            status_code, error_code = 400, "DECRYPTION_FAILED"
            logger.warning("Decryption failed (verified run %s): %s", run_id, exc)
            raise HTTPException(status_code=400, detail="Payload decryption failed.")

        # ── Verified-path inputs ──
        agent_url = payload.get("agent_url", "")
        base_task = payload.get("base_task", {})
        n_scenarios = int(payload.get("n_scenarios", 30))
        consent = payload.get("consent", False)
        agent_headers = payload.get("agent_headers", {}) or {}
        required = payload.get("required_in_response", []) or base_task.get("required_in_response", [])

        # ── Explicit consent is mandatory before we call an external agent ──
        if not consent:
            status_code, error_code = 400, "CONSENT_REQUIRED"
            raise HTTPException(
                status_code=400,
                detail=("Explicit consent is required: the platform will call "
                        "your agent endpoint across multiple scenarios. Set "
                        "consent=true to proceed."),
            )

        # ── SSRF validation happens inside run_verified_battery (fail-closed) ──
        try:
            from verified_runner import run_verified_battery, VerifiedRunError
            from ssrf_guard import SSRFValidationError
            records = await run_verified_battery(
                agent_url=agent_url, base_task=base_task,
                n_scenarios=n_scenarios, headers=agent_headers,
            )
            # Fair billing: one unit per scenario actually run.
            billable_units = len(records) if records else 1
        except SSRFValidationError as exc:
            status_code, error_code = 400, "UNSAFE_AGENT_URL"
            raise HTTPException(status_code=400, detail=f"Agent URL rejected: {exc}")
        except VerifiedRunError as exc:
            status_code, error_code = 400, "VERIFIED_RUN_ERROR"
            raise HTTPException(status_code=400, detail=str(exc))

        # ── Server-side scoring (authoritative, tamper-proof) ──
        report = aggregate_battery_results(records, required)
        report["verification"] = "verified"   # the platform ran it end-to-end

        agent_id = payload.get("agent_id", "verified-agent")
        gated = _apply_plan_gates(report, plan_type)
        _spawn(_store_evaluation(run_id, project_id, agent_id, payload, report))
        _spawn(edm_guard.consolidate(_supabase, run_id, project_id, payload, report))

        success, status_code, error_code = True, 200, None

        # Reported in the response rather than left to be discovered by a 402
        # on the sixth attempt. A limit somebody cannot see is a limit that
        # arrives as a surprise, usually mid-script.
        out = {**gated, "run_id": run_id}
        if trials_left is not None:
            out["verified_trial"] = {
                "used_this_month": VERIFIED_TRIAL_LIMIT - trials_left,
                "remaining_this_month": trials_left,
                "limit": VERIFIED_TRIAL_LIMIT,
                "note": (
                    f"{trials_left} of {VERIFIED_TRIAL_LIMIT} free verified "
                    "evaluations left this month. This path scores what "
                    "HB-Eval observed by calling your agent; "
                    "/evaluate_battery scores what your agent reported about "
                    "itself, and has no cap."
                ),
            }
        return out

    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in /evaluate_verified (run %s).", run_id)
        status_code, error_code = 500, "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        # A claimed trial is returned unless the run actually completed.
        #
        # The failures here are timeouts, unreachable endpoints, and our own
        # internal errors — none gave the user the thing the trial was for.
        # Charging for them would let somebody exhaust a month's allowance
        # without once seeing the feature work.
        if trial_claimed and not success:
            try:
                await _refund_verified_trial(auth.get("user_id"))
            except Exception:
                # A lost refund is a minor unfairness; raising here would
                # replace the user's real error with a bookkeeping one.
                pass
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw = http_request.client.host if http_request.client else None
        _spawn(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/evaluate_verified", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))
        if success:
            _spawn(_increment_usage(auth.get("user_id"), billable_units))


@app.post("/evaluate_plain", tags=["Evaluation"])
async def evaluate_plain(
    http_request: Request,
    body: PlainEvaluationRequest,
    auth: dict = Depends(usage_gate),
    _rate: bool = Depends(RateLimiter(times=100, seconds=60, identifier=_api_key_identifier)),
) -> dict:
    # Plaintext route is for development only — refuse it in production.
    if not _DEV_MODE:
        raise HTTPException(
            status_code=403,
            detail="The plaintext endpoint is disabled in production. Use /evaluate with the SDK.",
        )

    run_id = str(uuid.uuid4())
    project_id = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    plan_type = auth["plan_type"]
    start_time = time.monotonic()
    status_code, error_code, success = 500, "UNKNOWN_ERROR", False

    try:
        payload = body.model_dump()
        try:
            validate_payload(payload)
        except ValidationError as exc:
            status_code, error_code = 400, "VALIDATION_FAILED"
            raise HTTPException(status_code=400, detail=str(exc))

        agent_id = payload.get("agent_id", "unknown-agent")
        history = await _fetch_history(project_id, agent_id)
        result = HBEvalEngines.evaluate(payload, history)
        gated = _apply_plan_gates(result, plan_type)
        _spawn(_store_evaluation(run_id, project_id, agent_id, payload, result))
        _spawn(edm_guard.consolidate(_supabase, run_id, project_id, payload, result))
        success, status_code, error_code = True, 200, None
        return {**gated, "run_id": run_id}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in /evaluate_plain (run %s).", run_id)
        status_code, error_code = 500, "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw = http_request.client.host if http_request.client else None
        _spawn(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/evaluate_plain", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))
        if success:
            _spawn(_increment_usage(auth.get("user_id")))


@app.post("/api/v1/memory/retrieve", tags=["Memory"])
async def memory_retrieve(
    http_request: Request,
    body: EncryptedEvaluationRequest,
    auth: dict = Depends(verify_api_key),
    _rate: bool = Depends(RateLimiter(times=100, seconds=60, identifier=_api_key_identifier)),
) -> dict:
    run_id = str(uuid.uuid4())
    project_id = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    start_time = time.monotonic()
    status_code, error_code = 500, "UNKNOWN_ERROR"

    try:
        nonce = http_request.headers.get("X-HBEval-Nonce", "")
        timestamp = http_request.headers.get("X-HBEval-Timestamp", "")
        signature = http_request.headers.get("X-HBEval-Signature", "")
        if not all([nonce, timestamp, signature]):
            status_code, error_code = 400, "MISSING_SECURITY_HEADERS"
            raise HTTPException(status_code=400, detail="Missing security headers.")

        _verify_signature(auth["signing_secret"], nonce, timestamp, body.ciphertext, signature)

        aesgcm = AESGCM(auth["agent_aes_key"])   # per-agent key (two-layer model)
        gcm_nonce = bytes.fromhex(nonce)
        decrypted = aesgcm.decrypt(gcm_nonce, bytes.fromhex(body.ciphertext), None)
        payload = json.loads(decrypted.decode())

        requested_top_k = int(payload.get("top_k", 5))
        effective_top_k = requested_top_k if _is_paid(auth["plan_type"]) else min(requested_top_k, 3)

        if not _supabase:
            raise HTTPException(status_code=503, detail="Memory service unavailable.")

        def _query():
            return (
                _supabase.table("edm_memory").select("*")
                .eq("project_id", payload.get("project_id", project_id))
                .order("created_at", desc=True).limit(effective_top_k).execute()
            ).data or []

        memories = await asyncio.to_thread(_query)
        status_code, error_code = 200, None
        response = {"memories": memories, "total_retrieved": len(memories)}
        if not _is_paid(auth["plan_type"]) and requested_top_k > 3:
            response["note"] = "Free plan returns up to 3 memories. Upgrade to Pro for more."
        return response
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in memory retrieve.")
        status_code, error_code = 500, "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw = http_request.client.host if http_request.client else None
        _spawn(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/api/v1/memory/retrieve", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))


@app.post("/api/v1/explain", tags=["Interpretability"])
async def explain(
    http_request: Request,
    body: EncryptedEvaluationRequest,
    auth: dict = Depends(verify_api_key),
    _rate: bool = Depends(RateLimiter(times=100, seconds=60, identifier=_api_key_identifier)),
) -> dict:
    """
    Layer 2 — HCI-EDM performance-grounded interpretability.
    Returns an explanation grounded in a certified stored episode, or the
    mandatory uncertainty response when no qualified precedent exists.
    Payload (decrypted) must contain a "plan_summary" string.
    """
    run_id = str(uuid.uuid4())
    project_id = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    start_time = time.monotonic()
    status_code, error_code = 500, "UNKNOWN_ERROR"

    try:
        nonce = http_request.headers.get("X-HBEval-Nonce", "")
        timestamp = http_request.headers.get("X-HBEval-Timestamp", "")
        signature = http_request.headers.get("X-HBEval-Signature", "")
        if not all([nonce, timestamp, signature]):
            status_code, error_code = 400, "MISSING_SECURITY_HEADERS"
            raise HTTPException(status_code=400, detail="Missing security headers.")

        _verify_signature(auth["signing_secret"], nonce, timestamp, body.ciphertext, signature)

        aesgcm = AESGCM(auth["agent_aes_key"])
        gcm_nonce = bytes.fromhex(nonce)
        decrypted = aesgcm.decrypt(gcm_nonce, bytes.fromhex(body.ciphertext), None)
        payload = json.loads(decrypted.decode())

        plan_summary = str(payload.get("plan_summary", "")).strip()
        if not plan_summary:
            status_code, error_code = 400, "MISSING_PLAN_SUMMARY"
            raise HTTPException(status_code=400, detail="plan_summary is required.")

        result = await asyncio.to_thread(
            hci_edm.explain, _supabase, project_id, plan_summary
        )
        status_code, error_code = 200, None
        return {**result, "run_id": run_id}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in explain.")
        status_code, error_code = 500, "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw = http_request.client.host if http_request.client else None
        _spawn(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/api/v1/explain", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))


# ── 15. Runtime monitoring ───────────────────────────────────────────────────
# Stores closed monitoring sessions produced by the SDK's monitor() context
# manager. Requires migration 09 (monitoring_sessions, monitoring_events).
#
# NOT metered against the evaluation quota, deliberately: the monitoring work
# itself runs in the user's own process on their machine and costs the platform
# nothing but a single small write per session. This matches the project-wide
# rule that what runs on the user's machine is free, and what runs on our
# infrastructure is paid. Managed monitoring (live dashboard, webhook dispatch)
# is the paid tier, and it is gated where that work actually happens, not here.

# Hard caps: a session summary is user-supplied data, so it is bounded before
# it ever reaches the database.
MAX_MONITORING_EVENTS = 500      # breaches stored per session
MAX_MONITORING_STEPS = 100_000   # sanity ceiling on reported step count


def _coerce_metric(value: Any) -> float | None:
    """Accept a numeric metric or None.

    None is preserved rather than coerced to 0.0. This matters: an undefined
    metric (IRS with no faults injected, CSI within a single session) is not
    the same as a metric that scored zero, and storing 0.0 would render an
    agent as failing on a dimension that was never measured.
    """
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


async def _write_halt_audit(user_id: str | None, summary: dict) -> None:
    """Record why a session halted, as a structured, queryable row.

    Safe Halt stops an agent on the operator's behalf. Without this record the
    operator sees only that something stopped — not which metric breached,
    against which policy, at which step. In any deployment where halting
    matters, that is the first question asked, and a system that cannot answer
    it will simply have the feature switched off.

    Written only when a halt actually occurred. Idempotent by the unique index
    on session_id, so a retried summary cannot duplicate the entry.
    """
    if not _supabase or not summary.get("halted"):
        return

    record = summary.get("halt_record") or {}

    def _to_iso(ts: Any) -> str | None:
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            return None

    def _num(v):
        try:
            return float(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    def _int(v):
        try:
            return int(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    row = {
        "session_id": str(summary.get("session_id", ""))[:200],
        "user_id": user_id,
        "agent_id": str(summary.get("agent_id", "unknown-agent"))[:200],
        "metric": (str(record.get("metric"))[:32] if record.get("metric") else None),
        "metric_value": _num(record.get("metric_value")),
        "threshold": _num(record.get("threshold")),
        "consecutive_steps": _int(record.get("consecutive_steps")),
        "step_index": _int(record.get("step_index")),
        # The policy verbatim: a halt must remain reproducible against the rule
        # that produced it, even after the user changes their configuration.
        "policy": record.get("policy") or summary.get("halt_policy") or {},
        "reason": (str(record.get("reason") or summary.get("halt_reason") or "")[:500] or None),
        "trigger_source": (str(record.get("trigger_source", "policy"))[:32]),
        "occurred_at": _to_iso(record.get("occurred_at")) or datetime.now(timezone.utc).isoformat(),
    }

    def _write():
        _supabase.table("halt_audit_log").upsert(row, on_conflict="session_id").execute()

    try:
        await asyncio.to_thread(_write)
    except Exception as exc:
        # An audit failure must not fail the session write that already
        # succeeded; it is logged loudly instead, because a silently missing
        # audit row is worse than a noisy one.
        logger.error("Halt audit write failed (%s): %s", row["session_id"], exc)


async def _store_monitoring_session(user_id: str | None, project_id: str,
                                    summary: dict) -> None:
    """Persist a monitoring session and its breach events."""
    if not _supabase:
        return

    metrics = summary.get("live_metrics") or {}
    breaches = summary.get("breaches") or []
    if len(breaches) > MAX_MONITORING_EVENTS:
        breaches = breaches[:MAX_MONITORING_EVENTS]

    session_id = str(summary.get("session_id", ""))[:200]
    agent_id = str(summary.get("agent_id", "unknown-agent"))[:200]

    def _to_iso(ts: Any) -> str | None:
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            return None

    def _write_session():
        # UPSERT, not insert: with live streaming the session row already
        # exists by the time the closing summary arrives, having been created
        # by the first progress batch. An insert would collide on session_id
        # and the final, authoritative numbers would be lost.
        _supabase.table("monitoring_sessions").upsert({
            "session_id": session_id,
            "status": "completed",
            "last_event_at": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "agent_id": agent_id,
            "started_at": _to_iso(summary.get("started_at")),
            "ended_at": _to_iso(summary.get("ended_at")),
            "duration_seconds": summary.get("duration_seconds"),
            "step_count": min(int(summary.get("step_count", 0) or 0), MAX_MONITORING_STEPS),
            "breach_count": len(breaches),
            "halted": bool(summary.get("halted", False)),
            "halt_reason": (str(summary["halt_reason"])[:500]
                            if summary.get("halt_reason") else None),
            # Cost of monitoring, measured on the client. NULL rather than 0
            # when no steps were recorded: zero would report a measured cost
            # of nothing, when in fact nothing was measured.
            "overhead_p50_ms": _coerce_metric((summary.get("overhead") or {}).get("p50_ms")),
            "overhead_p95_ms": _coerce_metric((summary.get("overhead") or {}).get("p95_ms")),
            "overhead_p99_ms": _coerce_metric((summary.get("overhead") or {}).get("p99_ms")),
            "overhead_samples": int((summary.get("overhead") or {}).get("samples", 0) or 0) or None,
            "pei_live": _coerce_metric(metrics.get("pei")),
            "frr_live": _coerce_metric(metrics.get("frr")),
            "irs_live": _coerce_metric(metrics.get("irs")),
            "ti_live": _coerce_metric(metrics.get("ti")),
            "csi_live": _coerce_metric(metrics.get("csi")),
            "thresholds": summary.get("thresholds") or {},
            "metadata": summary.get("metadata") or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }, on_conflict="session_id").execute()

    try:
        await asyncio.to_thread(_write_session)
    except Exception as exc:
        logger.error("Monitoring session persist failed (%s): %s", session_id, exc)
        return   # without the parent row, the events have nothing to attach to

    if not breaches:
        return

    rows = []
    for b in breaches:
        try:
            rows.append({
                "session_id": session_id,
                "user_id": user_id,
                "metric": str(b.get("metric", ""))[:32],
                "value": float(b.get("value")),
                "threshold": float(b.get("threshold")),
                "step_index": int(b.get("step_index", 0)),
                "occurred_at": _to_iso(b.get("timestamp")) or datetime.now(timezone.utc).isoformat(),
            })
        except (TypeError, ValueError):
            continue   # skip a malformed breach rather than losing the whole batch

    if not rows:
        return

    def _write_events():
        # Idempotent by the (session_id, step_index, metric) constraint added
        # in migration 10: a retried or overlapping batch cannot duplicate a
        # breach that is already recorded.
        _supabase.table("monitoring_events").upsert(
            rows, on_conflict="session_id,step_index,metric"
        ).execute()

    try:
        await asyncio.to_thread(_write_events)
    except Exception as exc:
        logger.error("Monitoring events persist failed (%s): %s", session_id, exc)


@app.post("/api/v1/monitoring/session", tags=["Monitoring"])
async def monitoring_session(
    http_request: Request,
    body: EncryptedEvaluationRequest,
    auth: dict = Depends(verify_api_key),
    _rate: bool = Depends(RateLimiter(times=120, seconds=60, identifier=_api_key_identifier)),
) -> dict:
    """Record a closed runtime-monitoring session.

    The SDK sends this once, when a monitor() context exits — never per step,
    so real-time monitoring adds no per-step network latency to the agent's
    execution path.

    Same security envelope as every other endpoint: signed, nonce-protected
    against replay, and decrypted with the per-agent AES key.
    """
    run_id = str(uuid.uuid4())
    project_id = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    start_time = time.monotonic()
    status_code, error_code = 500, "UNKNOWN_ERROR"

    try:
        nonce = http_request.headers.get("X-HBEval-Nonce", "")
        timestamp = http_request.headers.get("X-HBEval-Timestamp", "")
        signature = http_request.headers.get("X-HBEval-Signature", "")
        if not all([nonce, timestamp, signature]):
            status_code, error_code = 400, "MISSING_SECURITY_HEADERS"
            raise HTTPException(status_code=400, detail="Missing security headers.")

        try:
            _verify_signature(auth["signing_secret"], nonce, timestamp, body.ciphertext, signature)
        except HTTPException as exc:
            status_code = exc.status_code
            error_code = "INVALID_SIGNATURE" if exc.status_code == 403 else "INVALID_TIMESTAMP"
            raise

        if await _nonce_already_used(nonce):
            status_code, error_code = 409, "REPLAY_DETECTED"
            raise HTTPException(status_code=409, detail="This request has already been processed (replay detected).")

        try:
            aesgcm = AESGCM(auth["agent_aes_key"])
            gcm_nonce = bytes.fromhex(nonce)
            decrypted = aesgcm.decrypt(gcm_nonce, bytes.fromhex(body.ciphertext), None)
            summary = json.loads(decrypted.decode())
        except Exception as exc:
            status_code, error_code = 400, "DECRYPTION_FAILED"
            logger.warning("Monitoring decryption failed (run %s): %s", run_id, exc)
            raise HTTPException(status_code=400, detail="Payload decryption failed.")

        if not isinstance(summary, dict) or not summary.get("session_id"):
            status_code, error_code = 400, "VALIDATION_FAILED"
            raise HTTPException(status_code=400, detail="A monitoring summary with 'session_id' is required.")

        await _store_monitoring_session(auth.get("user_id"), project_id, summary)

        # Audit the halt decision, if there was one. Awaited rather than fired
        # as a background task: an audit trail that races the response and may
        # lose is not an audit trail.
        await _write_halt_audit(auth.get("user_id"), summary)

        # Alert on the halt itself. Always sent, never deduplicated against the
        # breaches that led to it: a breach is a warning, a halt is an action
        # already taken on the operator's behalf, and collapsing the two would
        # hide the more important one.
        if _HAS_ALERTS and summary.get("halted"):
            record = summary.get("halt_record") or {}
            _spawn(alerts_lib.dispatch(
                _supabase, asyncio.to_thread, ssrf_guard,
                user_id=auth.get("user_id"),
                event={
                    "event_type": "halt",
                    "session_id": str(summary.get("session_id", "")),
                    "agent_id": str(summary.get("agent_id", "unknown-agent")),
                    "metric": record.get("metric"),
                    "metric_value": record.get("metric_value"),
                    "threshold": record.get("threshold"),
                    "step_index": record.get("step_index"),
                    "reason": summary.get("halt_reason"),
                },
            ))

        # Anonymous aggregate contribution, only if this account opted in.
        # Fired as a background task: the user's own session is already
        # stored, and a slow or failing contribution must not delay their
        # response.
        _spawn(_contribute_to_observatory(auth.get("user_id"), summary))

        status_code, error_code = 200, None
        return {"stored": True, "session_id": summary.get("session_id"), "run_id": run_id}

    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in monitoring session (run %s).", run_id)
        status_code, error_code = 500, "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw = http_request.client.host if http_request.client else None
        _spawn(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/api/v1/monitoring/session", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))


# Live streaming ceiling. The SDK flushes at most every ~2s per session plus
# an immediate send on each breach, so this allows roughly ten concurrent
# monitored agents per key before throttling — generous for real use, bounded
# enough that a runaway loop cannot flood the database.
MAX_STREAM_EVENTS = 50          # breach events accepted in one batch


async def _apply_monitoring_batch(user_id: str | None, batch: dict) -> None:
    """Upsert an in-flight session and append any breaches it carries.

    Called on every progress batch, so it must stay cheap and idempotent:
    the same session is written many times over a run, and a retried batch
    must not duplicate events.
    """
    if not _supabase:
        return

    metrics = batch.get("live_metrics") or {}
    session_id = str(batch.get("session_id", ""))[:200]
    agent_id = str(batch.get("agent_id", "unknown-agent"))[:200]
    status = "active" if batch.get("status") == "active" else "completed"
    now_iso = datetime.now(timezone.utc).isoformat()

    def _to_iso(ts: Any) -> str | None:
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            return None

    row = {
        "session_id": session_id,
        "user_id": user_id,
        "agent_id": agent_id,
        "status": status,
        "started_at": _to_iso(batch.get("started_at")),
        "step_count": min(int(batch.get("step_count", 0) or 0), MAX_MONITORING_STEPS),
        "breach_count": int(batch.get("breach_count", 0) or 0),
        "halted": bool(batch.get("halted", False)),
        # Safe Halt cause, when the SDK stopped the run. Truncated because it
        # is caller-influenced text reaching the database.
        "halt_reason": (str(batch["halt_reason"])[:500]
                        if batch.get("halt_reason") else None),
        # NULL is preserved: an undefined metric (IRS with no faults yet, CSI
        # within a single session) must not be stored as 0.0, which would read
        # as a failing score on a dimension that was never measured.
        "pei_live": _coerce_metric(metrics.get("pei")),
        "frr_live": _coerce_metric(metrics.get("frr")),
        "irs_live": _coerce_metric(metrics.get("irs")),
        "ti_live": _coerce_metric(metrics.get("ti")),
        "csi_live": _coerce_metric(metrics.get("csi")),
        "thresholds": batch.get("thresholds") or {},
        "metadata": batch.get("metadata") or {},
        "last_event_at": now_iso,
    }
    if status == "completed":
        row["ended_at"] = _to_iso(batch.get("ended_at")) or now_iso

    def _upsert_session():
        _supabase.table("monitoring_sessions").upsert(
            row, on_conflict="session_id"
        ).execute()

    try:
        await asyncio.to_thread(_upsert_session)
    except Exception as exc:
        logger.error("Monitoring stream upsert failed (%s): %s", session_id, exc)
        return   # without the parent row the events have nothing to attach to

    # ── Keep the snapshot instead of discarding it ──
    #
    # Every batch carries the full metric set, and until now each one
    # overwrote the last on the session row. That left the platform able to
    # report what an agent's metrics ARE and never what they DID — and
    # reliability is a trajectory. An agent that ended at FRR 0.6 having fallen
    # from 0.9 is a different problem from one that climbed there from 0.3.
    #
    # Upsert rather than insert: the unique (session_id, step_count) index in
    # migration 16 means a batch reporting no new steps collides with what is
    # already stored and changes nothing. Rows are bounded by steps taken, not
    # by how long the agent ran, and a retried batch is idempotent.
    snapshot = {
        "session_id": session_id,
        "user_id": user_id,
        "agent_id": agent_id,
        "step_count": row["step_count"],
        # NULL preserved. A chart must show an undefined metric as a gap, never
        # as a fall to zero.
        "pei": row["pei_live"],
        "frr": row["frr_live"],
        "irs": row["irs_live"],
        "ti": row["ti_live"],
        "csi": row["csi_live"],
        "breach_count": row["breach_count"],
        "halted": row["halted"],
        "recorded_at": now_iso,
    }

    def _upsert_snapshot():
        _supabase.table("monitoring_snapshots").upsert(
            snapshot, on_conflict="session_id,step_count"
        ).execute()

    try:
        await asyncio.to_thread(_upsert_snapshot)
    except Exception as exc:
        # A lost snapshot costs one point on a chart. It must never cost the
        # session write that already succeeded, so this is logged and dropped.
        logger.debug("Snapshot write failed (%s): %s", session_id, exc)

    events = batch.get("events") or []
    if not isinstance(events, list) or not events:
        return
    events = events[:MAX_STREAM_EVENTS]

    rows = []
    for e in events:
        try:
            rows.append({
                "session_id": session_id,
                "user_id": user_id,
                "metric": str(e.get("metric", ""))[:32],
                "value": float(e.get("value")),
                "threshold": float(e.get("threshold")),
                "step_index": int(e.get("step_index", 0)),
                "occurred_at": _to_iso(e.get("timestamp")) or now_iso,
            })
        except (TypeError, ValueError):
            continue   # skip a malformed breach rather than losing the batch

    if not rows:
        return

    # Alert on breaches. Fired as a background task and never awaited: a slow
    # Slack endpoint must not add latency to a monitoring call an agent is
    # waiting on. Deduplication happens in the database, so the same metric
    # breaching on twenty consecutive steps produces one notification.
    if _HAS_ALERTS and user_id:
        for e in rows:
            _spawn(alerts_lib.dispatch(
                _supabase, asyncio.to_thread, ssrf_guard,
                user_id=user_id,
                event={
                    "event_type": "breach",
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "metric": e.get("metric"),
                    "metric_value": e.get("value"),
                    "threshold": e.get("threshold"),
                    "step_index": e.get("step_index"),
                },
            ))

    def _upsert_events():
        _supabase.table("monitoring_events").upsert(
            rows, on_conflict="session_id,step_index,metric"
        ).execute()

    try:
        await asyncio.to_thread(_upsert_events)
    except Exception as exc:
        logger.error("Monitoring stream events failed (%s): %s", session_id, exc)


# ── 16. Observatory ─────────────────────────────────────────────────────────
# Publishes AGGREGATE reliability statistics so the field can see what
# operational reliability looks like in deployment, not only in controlled
# studies. See migration 11 for the full privacy model.
#
# The salt below turns an account id into a stable but non-reversible
# contributor token, used only so k-anonymity can count distinct
# contributors. It lives in the environment, never in the database, so a
# database dump on its own cannot be correlated back to accounts.
#
# If unset, contribution is DISABLED entirely rather than falling back to an
# unsalted hash. An unsalted hash of a UUID is trivially reversible by anyone
# holding the user list, which would defeat the whole anonymisation.
_OBSERVATORY_SALT = os.environ.get("OBSERVATORY_SALT", "")
if not _OBSERVATORY_SALT:
    logger.warning(
        "OBSERVATORY_SALT is not set — Observatory contribution is disabled. "
        "Set it to enable anonymous aggregate publishing."
    )


def _contributor_hash(user_id: str) -> str:
    """Stable, non-reversible token for one account."""
    return hashlib.sha256(f"{_OBSERVATORY_SALT}:{user_id}".encode()).hexdigest()


def _step_bucket(step_count: int) -> str:
    """Coarse run size. Bucketed so an unusually long run cannot single
    itself out by its exact step count."""
    if step_count <= 5:
        return "1-5"
    if step_count <= 20:
        return "6-20"
    if step_count <= 100:
        return "21-100"
    return "100+"


async def _has_observatory_consent(user_id: str | None) -> bool:
    """Whether this account has explicitly opted in.

    Fail-closed everywhere: no user, no row, an error, or an explicit false
    all mean NO. Consent is the one place where a transient failure must not
    be resolved in favour of publishing.
    """
    if not _supabase or not user_id or not _OBSERVATORY_SALT:
        return False

    def _q():
        return (_supabase.table("observatory_consent")
                .select("enabled").eq("user_id", user_id).execute())
    try:
        res = await asyncio.to_thread(_q)
        rows = res.data or []
        return bool(rows and rows[0].get("enabled"))
    except Exception as exc:
        logger.error("Observatory consent check failed for %s: %s", user_id, exc)
        return False


async def _contribute_to_observatory(user_id: str | None, summary: dict) -> None:
    """Write one anonymised contribution from a completed session.

    Identifiers are dropped HERE, at write time, so the public table never
    holds them at all. agent_id, metadata and step labels are deliberately
    absent: the first two identify, and step labels leak business logic.
    """
    if not await _has_observatory_consent(user_id):
        return

    metrics = summary.get("live_metrics") or {}
    breaches = summary.get("breaches") or []

    # Distinct metric names only — never step labels.
    breached = sorted({str(b.get("metric", ""))[:16]
                       for b in breaches if b.get("metric")})

    row = {
        "contributor_hash": _contributor_hash(str(user_id)),
        "pei": _coerce_metric(metrics.get("pei")),
        "frr": _coerce_metric(metrics.get("frr")),
        "irs": _coerce_metric(metrics.get("irs")),
        "ti": _coerce_metric(metrics.get("ti")),
        "csi": _coerce_metric(metrics.get("csi")),
        "step_bucket": _step_bucket(int(summary.get("step_count", 0) or 0)),
        "breach_count": min(int(summary.get("breach_count", 0) or 0), 10_000),
        "halted": bool(summary.get("halted", False)),
        "breached_metrics": breached,
        "source": "live",
    }

    def _write():
        _supabase.table("observatory_contributions").insert(row).execute()

    try:
        await asyncio.to_thread(_write)
    except Exception as exc:
        # Never let a contribution failure affect the user's own session,
        # which has already been stored by this point.
        logger.error("Observatory contribution failed: %s", exc)


# -- Fault Injection Studio -------------------------------------------------
@app.post("/api/v1/battery/preview", tags=["Evaluation"])
async def battery_preview(
    request: BatteryPreviewRequest,
    _rl=Depends(RateLimiter(times=30, seconds=60)),
) -> dict:
    """Show the battery a selection WOULD run, without running anything.

    No agent is called, no quota is consumed, no result is stored.

    This exists because "context_corruption" is a label until you see what it
    actually does to a prompt. A team choosing which faults to gate their
    pipeline on should be choosing from what the injection really says, not
    from its name.

    Unauthenticated on purpose: it returns the platform's own fault taxonomy,
    which is published in the paper and the open-source repository, and nothing
    about any account. Requiring a key to read public methodology would be
    friction with no secret behind it. Rate limited because it is cheap for us
    and cheap to abuse.
    """
    started = time.monotonic()
    try:
        from fault_injection import (
            build_scenario_battery, inject_fault, normalise_selection,
            FAULT_TYPES, DOMAINS,
        )
    except ImportError:
        raise HTTPException(status_code=503,
                            detail="Battery preview is unavailable.")

    n = max(6, min(int(request.n_scenarios or 18), 60))
    active_faults, active_domains = normalise_selection(
        request.fault_types, request.domains)

    # Reported so a caller sees their typo, rather than silently getting the
    # full set back and believing they had narrowed the run.
    unknown = (sorted(set(request.fault_types or []) - set(FAULT_TYPES))
               + sorted(set(request.domains or []) - set(DOMAINS)))

    battery = build_scenario_battery(
        n, seed=request.seed,
        fault_types=request.fault_types, domains=request.domains,
    )

    question = (request.question or "").strip()[:500] or (
        "A shipment is three days late. Respond appropriately.")

    scenarios = []
    for i, s in enumerate(battery):
        scenarios.append({
            "index": i,
            "domain": s["domain"],
            "fault_type": s["fault_type"],
            "is_nominal": s["is_nominal"],
            # The actual text the agent would receive. This is the whole point
            # of a preview: the injection itself, not a description of it.
            "prompt": (question if s["is_nominal"]
                       else inject_fault(question, s["fault_type"])),
        })

    counts: dict = {}
    for s in battery:
        counts[s["fault_type"]] = counts.get(s["fault_type"], 0) + 1

    narrowed = (len(active_faults) < len(FAULT_TYPES)
                or len(active_domains) < len(DOMAINS))

    return {
        "ok": True,
        "n_scenarios": len(battery),
        "seed": request.seed,
        "scenarios": scenarios,
        "counts": counts,
        "available": {"fault_types": list(FAULT_TYPES), "domains": list(DOMAINS)},
        "unknown_selections": unknown,
        # Stated rather than left to be inferred. A narrowed battery no longer
        # covers the full taxonomy, so its numbers are not comparable with a
        # full run's, and whoever reads the result needs telling.
        "narrowed": narrowed,
        "coverage_note": (
            f"This selection covers {len(active_faults)} of {len(FAULT_TYPES)} "
            f"fault types and {len(active_domains)} of {len(DOMAINS)} domains. "
            "Results from a narrowed battery are not comparable with a full run."
            if narrowed else
            "Full taxonomy: every fault type and domain is represented."
        ),
        "latency_ms": int((time.monotonic() - started) * 1000),
    }


# -- Retention ---------------------------------------------------------------
# HOW OFTEN, AND WHY IT RUNS THIS WAY
# Every 24 hours, plus once shortly after startup.
#
# The database functions to do this were written alongside the migrations that
# created the tables, and nothing ever called them. A retention policy that is
# documented but never executed is not a policy — it is a claim, and publishing
# it would have made it a false one.
#
# An in-process task rather than an external scheduler, because this deployment
# is a single instance: adding a cron service to run three SQL functions would
# be more infrastructure than the job deserves. The trade is that a process
# restarting constantly might never reach the 24-hour mark, which is exactly
# why the last successful run is published on /health — so a gap is visible
# rather than silent.
RETENTION_INTERVAL_S = 24 * 60 * 60
RETENTION_STARTUP_DELAY_S = 120       # let the service finish coming up first
RETENTION_DAYS = 90


async def _run_retention_once() -> dict:
    """Call each cleanup function. Failures are recorded, never raised."""
    global _last_retention_run, _last_retention_result
    if not _supabase:
        return {"skipped": "no database configured"}

    jobs = [
        ("monitoring_snapshots", "prune_monitoring_snapshots",
         {"retain_days": RETENTION_DAYS}),
        ("webhook_deliveries", "prune_webhook_deliveries",
         {"retain_days": RETENTION_DAYS}),
        # A year after they lapse, not ninety days: a compliance response
        # citing a passport link should stay resolvable for a reasonable period
        # after the passport itself has expired.
        ("published_passports", "prune_published_passports",
         {"grace_days": 365}),
        ("oauth_tokens", "oauth_cleanup", {}),
    ]

    # EVERY prune_* function in the schema must appear above. This one was
    # written with migration 19 and left uncalled for four items — the exact
    # failure this loop was built to fix, repeated. It surfaced only because
    # last_result is published on /health and named three tables where the
    # schema defines four. A retention policy that is documented and never
    # executed is not a policy, and the way to catch that is to make the gap
    # visible rather than to remember harder.
    result = {}

    for label, fn, params in jobs:
        def _call(fn=fn, params=params):
            return _supabase.rpc(fn, params).execute()
        try:
            res = await asyncio.to_thread(_call)
            result[label] = (res.data
                             if getattr(res, "data", None) is not None else "ok")
        except Exception as exc:
            # One failing function must not stop the others: a missing
            # migration should not leave the other two tables growing forever.
            result[label] = f"failed: {type(exc).__name__}"
            logger.error("Retention job %s failed: %s", fn, exc)

    _last_retention_run = datetime.now(timezone.utc).isoformat()
    _last_retention_result = result
    logger.info("Retention sweep complete: %s", result)
    return result


async def _retention_loop() -> None:
    await asyncio.sleep(RETENTION_STARTUP_DELAY_S)
    while True:
        try:
            await _run_retention_once()
        except Exception:
            logger.exception("Retention loop error")
        await asyncio.sleep(RETENTION_INTERVAL_S)


# -- Agent Passport ----------------------------------------------------------
@app.get("/api/v1/passport/key", tags=["Passport"])
async def passport_public_key(
    _rl=Depends(RateLimiter(times=60, seconds=60)),
) -> dict:
    """The public key that verifies passports.

    Unauthenticated, and that is the whole point. A passport is only worth
    issuing if a third party — an auditor, a regulator, a customer — can check
    it without asking us and without our permission. A public key behind a
    login is not published.
    """
    if not _HAS_PASSPORT:
        raise HTTPException(status_code=503, detail="Passports are unavailable.")
    return passport_lib.public_key_info()


@app.get("/api/v1/passport/{agent_id}", tags=["Passport"])
async def get_passport(
    agent_id: str,
    days: int = 90,
    auth: dict = Depends(verify_api_key),
    _rl=Depends(RateLimiter(times=20, seconds=60, identifier=_api_key_identifier)),
) -> dict:
    """Issue a signed record of how this agent has behaved.

    Free on every plan. A record of an agent's own behaviour is not a premium
    feature — charging for the evidence would make the evidence look
    negotiable.
    """
    if not _HAS_PASSPORT:
        raise HTTPException(status_code=503, detail="Passports are unavailable.")

    window = max(1, min(int(days or 90), 365))

    fingerprint = None
    try:
        from fault_injection import battery_spec_fingerprint
        fingerprint = battery_spec_fingerprint()
    except Exception:
        # Reported as null rather than omitted: the reader needs to know the
        # run cannot be tied to a specification, not be left to notice that a
        # field is absent.
        pass

    try:
        return await passport_lib.build_passport(
            _supabase, asyncio.to_thread,
            agent_id=agent_id,
            user_id=auth.get("user_id"),
            window_days=window,
            battery_fingerprint=fingerprint,
            protocol_version=MEASUREMENT_PROTOCOL_VERSION,
        )
    except PermissionError:
        # Same response whether the agent belongs to someone else or does not
        # exist. Distinguishing them confirms which agent ids are real.
        raise HTTPException(status_code=404, detail="Agent not found.")
    except Exception:
        logger.exception("Passport generation failed for %s", agent_id)
        raise HTTPException(status_code=500,
                            detail="Could not generate the passport.")


@app.post("/api/v1/passport/demo", tags=["Passport"])
async def demo_passport(
    body: dict,
    _rl=Depends(RateLimiter(times=20, seconds=60)),
) -> dict:
    """Sign a passport for the public demo run.

    WHY THIS EXISTS SEPARATELY
    The demo's whole argument is that measurement produces a document somebody
    else can verify. Showing the metrics and then stopping short of the signed
    artefact leaves the most important claim untested by the visitor.

    But a demo passport must never be mistakable for a real one. Three things
    keep them apart, and all three are inside the signed bytes so none can be
    stripped without breaking the signature:

      * demo: true, at the top level
      * an agent id that says so
      * a statement in the issuer block naming it a demonstration

    WHY IT IS SIGNED WITH THE PRODUCTION KEY
    Because a demo passport signed with a throwaway key would verify against
    nothing, and the visitor would learn that verification "works" without
    being able to check it. The signature is a true statement either way:
    HB-Eval did issue this document, and it does say demo: true.

    Unauthenticated and rate limited. It reads no account data and writes
    nothing; the metrics arrive in the request because the demo computed them
    with the published SDK.
    """
    if not _HAS_PASSPORT:
        raise HTTPException(status_code=503, detail="Passports are unavailable.")

    metrics_in = body.get("metrics") or {}
    # Only the five known keys, only numbers or None. The payload comes from a
    # public endpoint, and echoing arbitrary caller-supplied fields into a
    # signed document would let anyone have us sign text of their choosing.
    metrics = {}
    for key in passport_lib.METRICS:
        value = metrics_in.get(key)
        metrics[key] = (float(value)
                        if isinstance(value, (int, float))
                        and not isinstance(value, bool) else None)

    steps = max(0, min(int(body.get("steps") or 0), 10_000))
    halted = bool(body.get("halted"))
    halt_reason = str(body.get("halt_reason") or "")[:200] or None
    breaches = max(0, min(int(body.get("breaches") or 0), 10_000))

    now = datetime.now(timezone.utc)
    issued_at = now.isoformat()
    key_id = os.environ.get(passport_lib.ENV_KEY_ID, "default")
    agent_id = "demo-support-agent"

    fingerprint = None
    try:
        from fault_injection import battery_spec_fingerprint
        fingerprint = battery_spec_fingerprint()
    except Exception:
        pass

    passport = {
        "schema_version": passport_lib.PASSPORT_SCHEMA_VERSION,
        # Inside the signed bytes, so it cannot be removed without the
        # signature failing.
        "demo": True,
        "passport_id": passport_lib.passport_id(agent_id, issued_at, key_id),
        "issued_at": issued_at,
        # Short-lived. A demo document circulating for ninety days would
        # eventually be presented as evidence of something.
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "validity_days": 1,
        "window": {"days": 1, "since": issued_at},

        "issuer": {
            "name": "HB-Eval",
            "url": "https://hbeval.com",
            "protocol_version": MEASUREMENT_PROTOCOL_VERSION,
            "issued_by": "HB-Eval",
            "statement": (
                "DEMONSTRATION PASSPORT. This records a scripted demo run on "
                "hbeval.com, not the behaviour of any deployed agent. The "
                "signature is genuine and verifies against HB-Eval's published "
                "key; what it attests is that HB-Eval issued this demo "
                "document. It is not a certification, and it describes no real "
                "system."
            ),
        },

        "identity": {
            "agent_id": agent_id,
            "name": "Demo support agent (scripted)",
            "created_at": issued_at,
            "plan": "demo",
            "active": False,
        },

        "reliability": {
            "metrics": metrics,
            "metric_names": passport_lib.METRIC_NAMES,
            "undefined": [m for m in passport_lib.METRICS if metrics[m] is None],
            "weakest": passport_lib._weakest(metrics),
            "evidence": passport_lib.evidence_depth(1, steps),
            "timeline": [],
            "note": (
                "A single scripted run. Averages across many sessions, and the "
                "30/60/90-day trajectory, are what a real passport reports; one "
                "run cannot supply either, so the timeline is empty rather than "
                "filled with a repeated figure."
            ),
        },

        "operational_record": {
            "sessions": 1,
            "steps_executed": steps,
            "runtime_seconds": 0,
            "runtime_hours": 0,
            "sessions_halted": 1 if halted else 0,
            "total_breaches": breaches,
        },

        "safety_record": {
            "halt_decisions": 1 if halted else 0,
            "halts": ([{"reason": halt_reason, "triggered_by": "policy",
                        "at": issued_at}] if halted else []),
            "alerts_raised": 0,
            "alerts_delivered": 0,
            "alerts_failed": 0,
        },

        "measurement": {
            "fingerprint": passport_lib.measurement_fingerprint(
                protocol_version=MEASUREMENT_PROTOCOL_VERSION, battery_spec=fingerprint),
            "battery_spec_fingerprint": fingerprint,
            "monitoring_overhead_p50_ms": None,
            "monitoring_overhead_p99_ms": None,
            "note": (
                "Metrics computed by hb-eval-sdk-js, the published package, "
                "during a scripted demo run."
            ),
        },
    }

    return passport_lib.sign_passport(passport)


@app.post("/api/v1/passport/verify", tags=["Passport"])
async def verify_passport_endpoint(
    body: dict,
    _rl=Depends(RateLimiter(times=60, seconds=60)),
) -> dict:
    """Check a passport against this deployment's key.

    A convenience, never a requirement. Anyone can verify offline with the
    published key, and a verifier that must be called would defeat the purpose:
    this exists so a quick check does not require writing Ed25519 code, not so
    that verification runs through us.
    """
    if not _HAS_PASSPORT:
        raise HTTPException(status_code=503, detail="Passports are unavailable.")

    info = passport_lib.public_key_info()
    if not info.get("available"):
        return {"valid": False, "reason": info.get("reason", "No key configured.")}

    valid, reason = passport_lib.verify_passport(
        body if isinstance(body, dict) else {}, info["public_key_b64"])
    return {"valid": valid, "reason": reason, "key_id": info.get("key_id")}


@app.get("/api/v1/observatory", tags=["Observatory"])
async def observatory_summary(
    _rate: bool = Depends(RateLimiter(times=60, seconds=60)),
) -> dict:
    """Public reliability statistics across contributing deployments.

    Intentionally UNAUTHENTICATED: the Observatory is public, and requiring a
    key would defeat its purpose as a citable reference.

    Safety rests on the database function rather than on this handler: it
    returns aggregates only and refuses to return anything until enough
    distinct accounts are represented. This endpoint cannot read the
    underlying table even if it tried — direct access is revoked for all
    client roles in migration 11.
    """
    if not _supabase:
        raise HTTPException(status_code=503, detail="Observatory unavailable.")

    def _q():
        return _supabase.rpc("observatory_summary", {}).execute()

    try:
        res = await asyncio.to_thread(_q)
        data = res.data
        if isinstance(data, list):
            data = data[0] if data else None
        if not data:
            return {"available": False, "reason": "no_data"}
        return data
    except Exception:
        logger.exception("Observatory summary failed.")
        raise HTTPException(status_code=500, detail="Could not load statistics.")


@app.post("/api/v1/observatory/consent", tags=["Observatory"])
async def observatory_consent(
    http_request: Request,
    body: EncryptedEvaluationRequest,
    auth: dict = Depends(verify_api_key),
    _rate: bool = Depends(RateLimiter(times=30, seconds=60, identifier=_api_key_identifier)),
) -> dict:
    """Set this account's Observatory contribution preference.

    Signed and encrypted like every other authenticated call, so consent
    cannot be flipped on by a forged request.
    """
    run_id = str(uuid.uuid4())
    user_id = auth.get("user_id")
    project_id = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    start_time = time.monotonic()
    status_code, error_code = 500, "UNKNOWN_ERROR"

    try:
        nonce = http_request.headers.get("X-HBEval-Nonce", "")
        timestamp = http_request.headers.get("X-HBEval-Timestamp", "")
        signature = http_request.headers.get("X-HBEval-Signature", "")
        if not all([nonce, timestamp, signature]):
            status_code, error_code = 400, "MISSING_SECURITY_HEADERS"
            raise HTTPException(status_code=400, detail="Missing security headers.")

        _verify_signature(auth["signing_secret"], nonce, timestamp, body.ciphertext, signature)

        if await _nonce_already_used(nonce):
            status_code, error_code = 409, "REPLAY_DETECTED"
            raise HTTPException(status_code=409, detail="This request has already been processed (replay detected).")

        try:
            aesgcm = AESGCM(auth["agent_aes_key"])
            decrypted = aesgcm.decrypt(bytes.fromhex(nonce), bytes.fromhex(body.ciphertext), None)
            payload = json.loads(decrypted.decode())
        except Exception:
            status_code, error_code = 400, "DECRYPTION_FAILED"
            raise HTTPException(status_code=400, detail="Payload decryption failed.")

        if not user_id:
            status_code, error_code = 400, "NO_ACCOUNT"
            raise HTTPException(status_code=400, detail="No account is associated with this key.")

        enabled = bool(payload.get("enabled", False))

        def _upsert():
            _supabase.table("observatory_consent").upsert({
                "user_id": user_id,
                "enabled": enabled,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }, on_conflict="user_id").execute()

        await asyncio.to_thread(_upsert)

        status_code, error_code = 200, None
        return {"enabled": enabled, "run_id": run_id}

    except HTTPException:
        raise
    except Exception:
        logger.exception("Observatory consent failed (run %s).", run_id)
        status_code, error_code = 500, "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw = http_request.client.host if http_request.client else None
        _spawn(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/api/v1/observatory/consent", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))


@app.post("/api/v1/monitoring/stream", tags=["Monitoring"])
async def monitoring_stream(
    http_request: Request,
    body: EncryptedEvaluationRequest,
    auth: dict = Depends(verify_api_key),
    _rate: bool = Depends(RateLimiter(times=300, seconds=60, identifier=_api_key_identifier)),
) -> dict:
    """Receive a live progress batch from an in-flight monitoring session.

    This is what makes the dashboard live rather than retrospective: the SDK
    pushes progress DURING the run, so an agent working for twenty minutes is
    visible from its first step instead of only after it stops.

    Not metered against the evaluation quota. The monitored work runs in the
    user's own process; the platform only stores a small row per batch, which
    is the same reason basic monitoring is free.
    """
    run_id = str(uuid.uuid4())
    project_id = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    start_time = time.monotonic()
    status_code, error_code = 500, "UNKNOWN_ERROR"

    try:
        nonce = http_request.headers.get("X-HBEval-Nonce", "")
        timestamp = http_request.headers.get("X-HBEval-Timestamp", "")
        signature = http_request.headers.get("X-HBEval-Signature", "")
        if not all([nonce, timestamp, signature]):
            status_code, error_code = 400, "MISSING_SECURITY_HEADERS"
            raise HTTPException(status_code=400, detail="Missing security headers.")

        try:
            _verify_signature(auth["signing_secret"], nonce, timestamp, body.ciphertext, signature)
        except HTTPException as exc:
            status_code = exc.status_code
            error_code = "INVALID_SIGNATURE" if exc.status_code == 403 else "INVALID_TIMESTAMP"
            raise

        # Replay protection applies here too: every batch carries its own
        # nonce, so a captured batch cannot be resent to corrupt live state.
        if await _nonce_already_used(nonce):
            status_code, error_code = 409, "REPLAY_DETECTED"
            raise HTTPException(status_code=409, detail="This request has already been processed (replay detected).")

        try:
            aesgcm = AESGCM(auth["agent_aes_key"])
            decrypted = aesgcm.decrypt(bytes.fromhex(nonce), bytes.fromhex(body.ciphertext), None)
            batch = json.loads(decrypted.decode())
        except Exception as exc:
            status_code, error_code = 400, "DECRYPTION_FAILED"
            logger.warning("Stream decryption failed (run %s): %s", run_id, exc)
            raise HTTPException(status_code=400, detail="Payload decryption failed.")

        if not isinstance(batch, dict) or not batch.get("session_id"):
            status_code, error_code = 400, "VALIDATION_FAILED"
            raise HTTPException(status_code=400, detail="A batch with 'session_id' is required.")

        await _apply_monitoring_batch(auth.get("user_id"), batch)

        status_code, error_code = 200, None
        return {"accepted": True, "session_id": batch.get("session_id")}

    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in monitoring stream (run %s).", run_id)
        status_code, error_code = 500, "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw = http_request.client.host if http_request.client else None
        _spawn(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/api/v1/monitoring/stream", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))


@app.post("/api/v1/monitoring/trend", tags=["Monitoring"])
async def monitoring_trend(
    http_request: Request,
    body: EncryptedEvaluationRequest,
    auth: dict = Depends(verify_api_key),
    _rate: bool = Depends(RateLimiter(times=60, seconds=60, identifier=_api_key_identifier)),
) -> dict:
    """Return an agent's reliability trend from its recorded monitoring history.

    SECURITY NOTE: the Gateway holds the service-role key, so row level
    security does NOT constrain these reads. The owning user_id is therefore
    filtered explicitly below. Omitting that filter would expose other
    accounts' trend data — the same class of mistake that made the
    agent_reliability_trend view unsafe before security_invoker was set on it.
    """
    run_id = str(uuid.uuid4())
    project_id = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    user_id = auth.get("user_id")
    start_time = time.monotonic()
    status_code, error_code = 500, "UNKNOWN_ERROR"

    try:
        nonce = http_request.headers.get("X-HBEval-Nonce", "")
        timestamp = http_request.headers.get("X-HBEval-Timestamp", "")
        signature = http_request.headers.get("X-HBEval-Signature", "")
        if not all([nonce, timestamp, signature]):
            status_code, error_code = 400, "MISSING_SECURITY_HEADERS"
            raise HTTPException(status_code=400, detail="Missing security headers.")

        try:
            _verify_signature(auth["signing_secret"], nonce, timestamp, body.ciphertext, signature)
        except HTTPException as exc:
            status_code = exc.status_code
            error_code = "INVALID_SIGNATURE" if exc.status_code == 403 else "INVALID_TIMESTAMP"
            raise

        if await _nonce_already_used(nonce):
            status_code, error_code = 409, "REPLAY_DETECTED"
            raise HTTPException(status_code=409, detail="This request has already been processed (replay detected).")

        try:
            aesgcm = AESGCM(auth["agent_aes_key"])
            decrypted = aesgcm.decrypt(bytes.fromhex(nonce), bytes.fromhex(body.ciphertext), None)
            payload = json.loads(decrypted.decode())
        except Exception as exc:
            status_code, error_code = 400, "DECRYPTION_FAILED"
            logger.warning("Trend decryption failed (run %s): %s", run_id, exc)
            raise HTTPException(status_code=400, detail="Payload decryption failed.")

        agent_id = str(payload.get("agent_id", "")).strip()
        if not agent_id:
            status_code, error_code = 400, "VALIDATION_FAILED"
            raise HTTPException(status_code=400, detail="Field 'agent_id' is required.")

        window = max(1, min(int(payload.get("window", 20) or 20), 200))

        if not _supabase:
            raise HTTPException(status_code=503, detail="Monitoring service unavailable.")

        def _query():
            q = (_supabase.table("monitoring_sessions")
                 .select("created_at, step_count, breach_count, halted, "
                         "pei_live, frr_live, irs_live, ti_live, csi_live")
                 .eq("agent_id", agent_id))
            # Explicit owner scoping - see SECURITY NOTE above.
            if user_id:
                q = q.eq("user_id", user_id)
            return q.order("created_at", desc=True).limit(window).execute()

        result = await asyncio.to_thread(_query)
        rows = result.data or []

        if not rows:
            status_code, error_code = 200, None
            return {
                "agent_id": agent_id,
                "session_count": 0,
                "direction": "insufficient_data",
                "note": ("No monitoring sessions recorded for this agent yet. "
                         "Run the agent inside client.monitor(...) to build history."),
                "run_id": run_id,
            }

        series = list(reversed(rows))

        def _avg(key: str):
            vals = [r[key] for r in series if r.get(key) is not None]
            return round(sum(vals) / len(vals), 4) if vals else None

        # Direction compares the first half of the window with the second, and
        # ONLY where the metric is defined in both halves. An undefined metric
        # (IRS with no faults, CSI within one session) yields no direction
        # rather than a fabricated one.
        half = max(1, len(series) // 2)
        early, late = series[:half], series[half:]

        def _half_avg(rows_, key):
            vals = [r[key] for r in rows_ if r.get(key) is not None]
            return sum(vals) / len(vals) if vals else None

        per_metric = {}
        improving = declining = 0
        for key, label in (("pei_live", "pei"), ("frr_live", "frr"),
                           ("irs_live", "irs"), ("ti_live", "ti"), ("csi_live", "csi")):
            a, b = _half_avg(early, key), _half_avg(late, key)
            if a is None or b is None:
                per_metric[label] = {"direction": "undefined", "early": None, "late": None}
                continue
            delta = round(b - a, 4)
            if delta > 0.01:
                d = "improving"; improving += 1
            elif delta < -0.01:
                d = "declining"; declining += 1
            else:
                d = "stable"
            per_metric[label] = {"direction": d, "early": round(a, 4),
                                 "late": round(b, 4), "delta": delta}

        # A direction requires a comparison. If NO metric was defined in both
        # halves of the window — the case with a single session, or when every
        # metric is undefined — there is nothing to compare, and reporting
        # "stable" would assert a stability the data cannot support. Say so
        # instead.
        comparable = sum(1 for v in per_metric.values() if v["direction"] != "undefined")
        if comparable == 0:
            overall = "insufficient_data"
        elif improving and not declining:
            overall = "improving"
        elif declining and not improving:
            overall = "declining"
        elif improving or declining:
            overall = "mixed"
        else:
            overall = "stable"

        status_code, error_code = 200, None
        return {
            "agent_id": agent_id,
            "session_count": len(series),
            "window": window,
            "averages": {
                "pei": _avg("pei_live"), "frr": _avg("frr_live"),
                "irs": _avg("irs_live"), "ti": _avg("ti_live"), "csi": _avg("csi_live"),
            },
            "total_breaches": sum(r.get("breach_count", 0) or 0 for r in series),
            "halted_sessions": sum(1 for r in series if r.get("halted")),
            "per_metric": per_metric,
            "direction": overall,
            "run_id": run_id,
        }

    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in monitoring trend (run %s).", run_id)
        status_code, error_code = 500, "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw = http_request.client.host if http_request.client else None
        _spawn(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/api/v1/monitoring/trend", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))


# ── 17. OAuth 2.1 + Remote MCP ──────────────────────────────────────────────
# The local MCP server needs an install and a config file, which excludes
# everyone using an assistant in a browser. These endpoints make HB-Eval
# reachable with a URL and a sign-in. The specification's price for that is
# OAuth 2.1 with PKCE, which oauth.py implements; this section wires it in.

from fastapi.responses import RedirectResponse
from fastapi import Form


def _require_oauth() -> None:
    """Refuse OAuth/MCP routes cleanly when the module is absent.

    503 rather than 500: the capability is unavailable by deployment, not
    broken by a fault, and the distinction tells an operator to add the file
    rather than hunt a bug.
    """
    if not _HAS_OAUTH:
        raise HTTPException(
            status_code=503,
            detail="Remote MCP is not enabled on this deployment.",
        )


def _oauth_error(exc) -> JSONResponse:
    """RFC 6749 error body.

    The code is load-bearing: clients rely on invalid_grant specifically to
    learn that a token is permanently dead and a reconnect is required. A
    generic code leaves them retrying forever.
    """
    return JSONResponse(
        status_code=exc.status,
        content={"error": exc.code, "error_description": exc.description},
    )


@app.get("/.well-known/oauth-protected-resource", tags=["OAuth"])
async def prm_metadata() -> dict:
    """RFC 9728. Mandatory for remote MCP servers.

    The `resource` value must equal the URL the user types, exactly. Clients
    compare it against the origin they derived and refuse on mismatch, which
    is a deliberate anti-impersonation check — and the most common cause of a
    connection that fails without a useful message.
    """
    _require_oauth()
    return oauth_lib.protected_resource_metadata("/mcp")


@app.get("/.well-known/oauth-authorization-server", tags=["OAuth"])
async def as_metadata() -> dict:
    """RFC 8414. Everything advertised here is enforced below."""
    _require_oauth()
    return oauth_lib.authorization_server_metadata()


@app.post("/oauth/register", tags=["OAuth"])
async def oauth_register(
    body: dict,
    _rate: bool = Depends(RateLimiter(times=20, seconds=60)),
) -> JSONResponse:
    """RFC 7591 Dynamic Client Registration.

    Open by necessity: clients like Claude cannot be pre-provisioned. Bounded
    by strict redirect-URI validation and by oauth_cleanup(), which removes
    registrations that never complete a flow.
    """
    if not _supabase:
        raise HTTPException(status_code=503, detail="Registration unavailable.")
    _require_oauth()
    try:
        result = await oauth_lib.register_client(_supabase, asyncio.to_thread, body)
        return JSONResponse(status_code=201, content=result)
    except ValueError as exc:
        return JSONResponse(status_code=400,
                            content={"error": "invalid_client_metadata",
                                     "error_description": str(exc)})
    except Exception:
        logger.exception("Client registration failed.")
        raise HTTPException(status_code=500, detail="Registration failed.")


@app.get("/oauth/authorize", tags=["OAuth"])
async def oauth_authorize(
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    scope: str = "",
    state: str = "",
    resource: str = "",
    _rate: bool = Depends(RateLimiter(times=30, seconds=60)),
):
    """Start the authorization flow.

    This endpoint does NOT authenticate the user — it validates the request,
    then hands off to the consent page on the website, which already holds the
    session cookie. Trying to authenticate here would mean duplicating the
    sign-in stack inside the Gateway.

    Validation happens BEFORE any redirect, and the redirect URI is checked
    first: every later error is reported by redirecting, and redirecting an
    error to an unvalidated URI would hand the failure, and the state with it,
    to whoever supplied that URI.
    """
    if not _supabase:
        raise HTTPException(status_code=503, detail="Authorization unavailable.")
    _require_oauth()

    client = await oauth_lib.load_client(_supabase, asyncio.to_thread, client_id)
    if not client:
        return JSONResponse(status_code=400,
                            content={"error": "invalid_client",
                                     "error_description": "Unknown client_id."})

    try:
        oauth_lib.validate_authorization_request(
            client, redirect_uri, response_type, code_challenge, code_challenge_method
        )
    except ValueError as exc:
        # Safe to render directly: the redirect URI is not yet trusted.
        return JSONResponse(status_code=400,
                            content={"error": "invalid_request",
                                     "error_description": str(exc)})

    # Hand off to the website's consent screen, carrying the validated request.
    params = {
        "client_id": client_id,
        "client_name": client.get("client_name") or "MCP Client",
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope or " ".join(oauth_lib.SUPPORTED_SCOPES),
        "state": state,
        "resource": resource,
    }
    return RedirectResponse(
        url=oauth_lib.build_redirect(oauth_lib.CONSENT_URL, params),
        status_code=302,
    )


@app.post("/oauth/approve", tags=["OAuth"])
async def oauth_approve(
    body: dict,
    _rate: bool = Depends(RateLimiter(times=30, seconds=60)),
) -> dict:
    """Called by the consent page once the signed-in user approves.

    The page proves who the user is by sending their Supabase access token;
    the Gateway verifies it rather than trusting a user_id in the body. Taking
    an unverified user_id here would let anyone mint a code for any account —
    the single most dangerous shortcut available in this whole flow.
    """
    if not _supabase:
        raise HTTPException(status_code=503, detail="Authorization unavailable.")
    _require_oauth()

    supabase_token = str(body.get("supabase_access_token", ""))
    if not supabase_token:
        raise HTTPException(status_code=401, detail="Sign-in required.")

    def _who():
        return _supabase.auth.get_user(supabase_token)

    try:
        user_res = await asyncio.to_thread(_who)
        user = getattr(user_res, "user", None)
        user_id = getattr(user, "id", None)
    except Exception:
        user_id = None

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")

    client_id = str(body.get("client_id", ""))
    redirect_uri = str(body.get("redirect_uri", ""))
    code_challenge = str(body.get("code_challenge", ""))
    method = str(body.get("code_challenge_method", "S256"))
    state = str(body.get("state", ""))
    resource = str(body.get("resource", "")) or None
    scopes = [s for s in str(body.get("scope", "")).split()
              if s in oauth_lib.SUPPORTED_SCOPES] or oauth_lib.SUPPORTED_SCOPES

    client = await oauth_lib.load_client(_supabase, asyncio.to_thread, client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Unknown client.")

    # Re-validate: the consent page is a browser and its inputs are not
    # trusted, however they were populated.
    try:
        oauth_lib.validate_authorization_request(
            client, redirect_uri, "code", code_challenge, method
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    code = await oauth_lib.issue_code(
        _supabase, asyncio.to_thread,
        client_id=client_id, user_id=str(user_id), redirect_uri=redirect_uri,
        scopes=scopes, code_challenge=code_challenge,
        code_challenge_method=method, resource=resource,
    )

    params = {"code": code}
    if state:
        params["state"] = state
    return {"redirect_to": oauth_lib.build_redirect(redirect_uri, params)}


@app.post("/oauth/token", tags=["OAuth"])
async def oauth_token(
    grant_type: str = Form(...),
    code: str = Form(default=""),
    redirect_uri: str = Form(default=""),
    client_id: str = Form(default=""),
    code_verifier: str = Form(default=""),
    refresh_token: str = Form(default=""),
    _rate: bool = Depends(RateLimiter(times=60, seconds=60)),
):
    """Exchange a code, or rotate a refresh token.

    Form-encoded because RFC 6749 requires it; JSON here would fail against
    spec-compliant clients.
    """
    if not _supabase:
        raise HTTPException(status_code=503, detail="Token service unavailable.")
    _require_oauth()

    try:
        if grant_type == "authorization_code":
            return await oauth_lib.exchange_code(
                _supabase, asyncio.to_thread,
                code=code, client_id=client_id,
                redirect_uri=redirect_uri, code_verifier=code_verifier,
            )
        if grant_type == "refresh_token":
            return await oauth_lib.refresh_tokens(
                _supabase, asyncio.to_thread,
                refresh_token=refresh_token, client_id=client_id,
            )
        return JSONResponse(status_code=400,
                            content={"error": "unsupported_grant_type",
                                     "error_description": f"Unsupported grant_type: {grant_type}"})
    except oauth_lib.OAuthError as exc:
        return _oauth_error(exc)
    except Exception:
        logger.exception("Token endpoint failed.")
        return JSONResponse(status_code=500,
                            content={"error": "server_error",
                                     "error_description": "Token issuance failed."})


@app.post("/oauth/revoke", tags=["OAuth"])
async def oauth_revoke(
    token: str = Form(...),
    client_id: str = Form(default=""),
    _rate: bool = Depends(RateLimiter(times=30, seconds=60)),
) -> dict:
    """RFC 7009 revocation.

    Always returns success, even for an unknown token. Distinguishing a valid
    token from an invalid one here would turn this into an oracle for probing
    which tokens exist.
    """
    if not _HAS_OAUTH or not _supabase:
        return {"revoked": True}

    ctx = await oauth_lib.resolve_bearer(_supabase, asyncio.to_thread, f"Bearer {token}")
    if ctx:
        await oauth_lib.revoke_tokens_for_user(
            _supabase, asyncio.to_thread, ctx["user_id"], ctx["client_id"]
        )
    return {"revoked": True}


# ── 18. Remote MCP endpoint ─────────────────────────────────────────────────
# The tools are defined in mcp_tools.py and call Gateway internals directly.
# They are deliberately NOT imported from the client SDK: the Gateway does not
# install that package, and the SDK's tools reach the Gateway over HTTP, which
# in remote mode would mean the Gateway calling itself.
#
# IMPORTANT ARCHITECTURAL NOTE
# In remote mode the MCP server IS the Gateway. It therefore resolves the
# bearer token to an account and calls internal logic directly, rather than
# making HTTP calls back to itself. Looping through HTTP would add latency,
# a second authentication hop, and a failure mode where the Gateway cannot
# reach its own public URL.

MCP_PATH = "/mcp"


# Inner rate limit for the expensive tool, on top of the endpoint-wide one.
#
# The endpoint limit (120/min) is applied by a FastAPI dependency, which runs
# before the body is parsed and therefore cannot tell `initialize` — free — from
# a verified evaluation that fires up to 60 outbound requests. At 120/min that
# is 7,200 external HTTP calls per minute aimed at an address the caller
# chooses, which makes this infrastructure a usable relay rather than a
# monitoring service.
#
# Quota now bounds the total, but not the burst, so the burst is bounded here.
MCP_EVAL_LIMIT_PER_MIN = 6


async def _mcp_eval_rate_ok(user_id: str) -> bool:
    """Whether this account may start another verified evaluation this minute.

    Fails OPEN when Redis is unavailable, unlike the nonce guard which fails
    closed. The distinction is deliberate: rejecting a replay protects against
    an attack, whereas rejecting here would deny a paying user a legitimate
    evaluation because of an infrastructure outage. Quota still bounds the
    total in that window, so the exposure is a burst, not unlimited use.
    """
    if _redis is None:
        return True
    key = f"mcp_eval:{user_id}:{int(time.time() // 60)}"
    try:
        count = await _redis.incr(key)
        if count == 1:
            await _redis.expire(key, 120)
        return count <= MCP_EVAL_LIMIT_PER_MIN
    except Exception as exc:
        logger.error("MCP eval rate check failed: %s", exc)
        return True


async def _mcp_auth(http_request: Request) -> dict:
    """Resolve the bearer token, or raise the 401 that begins OAuth discovery.

    The WWW-Authenticate header is what makes the flow start at all: without
    that pointer to the metadata document, a client simply sees an
    unauthorized error and stops, instead of discovering the authorization
    server and walking the user through sign-in.
    """
    _require_oauth()
    if not _supabase:
        raise HTTPException(status_code=503, detail="MCP service unavailable.")

    ctx = await oauth_lib.resolve_bearer(
        _supabase, asyncio.to_thread, http_request.headers.get("Authorization", "")
    )
    if not ctx:
        raise HTTPException(
            status_code=401,
            detail="Authorization required.",
            headers={"WWW-Authenticate": oauth_lib.www_authenticate_header(MCP_PATH)},
        )
    return ctx


async def _agent_for_user(user_id: str) -> dict | None:
    """Pick the agent whose credentials this session will act with.

    An account may own several agents. The most recently created is used, and
    the choice is surfaced to the model in the tool result rather than hidden,
    so a user with several agents can see which one answered instead of
    silently getting the wrong one.
    """
    def _q():
        # is_active is filtered here for the same reason verify_api_key checks
        # it on the REST path: a deactivated agent must not be usable. Without
        # this predicate, deactivation was enforced on one door and ignored on
        # the other.
        return (_supabase.table("agents")
                .select("id, name, agent_id, plan_type, is_active")
                .eq("user_id", user_id)
                .eq("is_active", True)
                .order("created_at", desc=True).limit(1).execute())
    try:
        res = await asyncio.to_thread(_q)
        rows = res.data or []
        return rows[0] if rows else None
    except Exception as exc:
        logger.error("Agent lookup failed for %s: %s", user_id, exc)
        return None


@app.get(MCP_PATH, tags=["MCP"])
async def mcp_discovery(http_request: Request):
    """Unauthenticated probe of the MCP endpoint.

    Answers 401 with the discovery hint when no valid token is presented,
    which is precisely what a client needs in order to begin the OAuth flow.
    """
    await _mcp_auth(http_request)
    return {
        "protocol": "mcp",
        "transport": "streamable-http",
        "server": "hb-eval",
        "version": PROTOCOL_VERSION,
    }


@app.post(MCP_PATH, tags=["MCP"])
async def mcp_endpoint(
    http_request: Request,
    body: dict,
    _rate: bool = Depends(RateLimiter(times=120, seconds=60)),
):
    """Handle a JSON-RPC MCP request over Streamable HTTP.

    Implements the subset of the protocol an assistant actually exercises:
    initialize, tools/list, and tools/call. Notifications are acknowledged
    without a body, as the JSON-RPC spec requires.

    HONEST LIMITATION
    Server-initiated streaming (SSE push from server to client) is not
    implemented. Every tool here is request/response, so nothing is lost
    today; a future tool that streams partial results would need it, and this
    is the place that would change.
    """
    ctx = await _mcp_auth(http_request)

    method = str(body.get("method", ""))
    req_id = body.get("id")

    def ok(result: dict):
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def err(code: int, message: str):
        return {"jsonrpc": "2.0", "id": req_id,
                "error": {"code": code, "message": message}}

    # Notifications carry no id and expect no response body.
    if req_id is None and method.startswith("notifications/"):
        return JSONResponse(status_code=202, content=None)

    if method == "initialize":
        return ok({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "hb-eval", "version": PROTOCOL_VERSION},
        })

    if method == "tools/list":
        # Defined natively in mcp_tools.py, NOT imported from the client SDK.
        # The Gateway does not install that package, and even if it did, those
        # tools call the Gateway over HTTP - which here would mean calling
        # ourselves.
        return ok({"tools": mcp_tools.TOOL_DEFINITIONS})

    if method == "tools/call":
        params = body.get("params") or {}
        tool_name = str(params.get("name", ""))
        args = params.get("arguments") or {}

        # Fetched, but not required: get_reliability_metrics and list_my_agents
        # are useful to an account with no agents yet, and refusing them would
        # make the connector look broken on first use.
        agent = await _agent_for_user(ctx["user_id"])

        # Gateway internals are passed in rather than imported by mcp_tools,
        # which keeps that module free of a circular import back into this one.
        deps = {
            "hci_explain": getattr(hci_edm, "explain", None),
            "aggregate_battery_results": aggregate_battery_results,
        }
        try:
            from verified_runner import run_verified_battery
            deps["run_verified_battery"] = run_verified_battery
        except ImportError:
            deps["run_verified_battery"] = None

        # ── Quota, rate and metering for tools that actually spend money ──
        #
        # Everything below existed on the REST path via usage_gate and
        # _increment_usage, and none of it was reachable from here. The same
        # capability was metered through one door and free through the other.
        units = mcp_tools.billable_units(tool_name, args)

        if units > 0:
            plan = (agent or {}).get("plan_type", "free")

            if not await _mcp_eval_rate_ok(ctx["user_id"]):
                return ok({
                    "content": [{"type": "text", "text": json.dumps({
                        "ok": False,
                        "error": (f"Too many evaluations started in the last "
                                  f"minute (limit {MCP_EVAL_LIMIT_PER_MIN}). "
                                  f"Each one makes up to 60 outbound calls to "
                                  f"your endpoint; please pace them."),
                    }, indent=2)}],
                    "isError": True,
                })

            quota = await _read_account_quota(ctx["user_id"], plan)
            violation = _quota_violation(quota, units=units)
            if violation:
                return ok({
                    "content": [{"type": "text", "text": json.dumps({
                        "ok": False, "error": violation,
                        "usage": {
                            "used_this_month": quota["month_used"],
                            "monthly_limit": quota["account_limit"],
                            "used_today": quota["today_used"],
                            "daily_limit": quota["daily_cap"],
                        },
                    }, indent=2)}],
                    "isError": True,
                })

        result = await mcp_tools.call_tool(
            tool_name, args,
            supabase=_supabase, to_thread=asyncio.to_thread,
            user_id=ctx["user_id"], agent=agent, deps=deps,
            # Enforced inside call_tool. Passed explicitly rather than read
            # from a global so the dependency is visible at the call site.
            scopes=ctx.get("scopes") or [],
        )
        # isError is derived from the payload the tool itself returned, so a
        # refusal (wrong plan, missing consent) reads as a failed call to the
        # model rather than a successful one with an error inside it.
        is_error = '"ok": false' in result

        # Meter only on success. Charging for a refused or failed call would
        # bill a user for work that never happened; not charging for a
        # successful one leaves a real cost invisible to every quota and
        # billing system on the platform, which is what happened before.
        if units > 0 and not is_error:
            _spawn(_increment_usage(ctx["user_id"], units))

        return ok({"content": [{"type": "text", "text": result}],
                   "isError": is_error})

    return err(-32601, f"Unsupported method: {method}")


@app.exception_handler(Exception)
async def _global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception at %s %s.", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "INTERNAL_SERVER_ERROR",
                           "message": "An unexpected error occurred."}},
    )
