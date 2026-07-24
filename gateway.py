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
from datetime import datetime, timezone
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

# NOTE: tracks the wire protocol AND package version together (they are
# intentionally kept in lockstep in this build). If you ever need the
# protocol version to diverge from the SDK package version, split this
# into PROTOCOL_VERSION and SOFTWARE_VERSION explicitly.
PROTOCOL_VERSION = "2.4.0"


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
        _redis = redis_conn
        logger.info("Rate limiter + nonce guard initialised.")
    except Exception as exc:
        logger.error("Redis unavailable: %s. Proceeding without.", exc)
    yield
    logger.info("Gateway shutting down.")


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
if _origins_raw == "*":
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
)
logger.info("CORS allowed origins: %s", _allowed_origins or "(none — fail-closed)")

if not _HAS_OAUTH:
    logger.warning(
        "hbeval_oauth.py not found — remote MCP and OAuth endpoints are "
        "disabled. Every other capability is unaffected. Add the file to the "
        "repository root to enable remote MCP."
    )


# ── 5. Models ────────────────────────────────────────────────────────────────
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
    return authorization[len("Bearer "):]


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
        def _query():
            return (
                _supabase.table("agents")
                .select("id, user_id, plan_type, evaluation_limit, evaluations_this_month, "
                        "last_reset_date, evaluations_today, last_eval_date, "
                        "aes_key_encrypted, hmac_secret_encrypted, "
                        "is_active")
                .eq("api_key", api_key)
                .execute()
            )
        result = await asyncio.to_thread(_query)
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
        # Development fallback only.
        dev_key = os.environ.get("DEV_API_KEY", "")
        if not hmac_module.compare_digest(api_key, dev_key):
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


async def usage_gate(auth: dict = Depends(verify_api_key)) -> dict:
    if not _supabase:
        return auth
    import math
    now = datetime.now(timezone.utc)
    plan = auth.get("plan_type", "free")
    user_id = auth.get("user_id")

    # The authoritative monthly limit is the ACCOUNT limit for the plan.
    account_limit = ACCOUNT_LIMITS.get(plan, 500)
    month_used = 0
    today_used = 0

    # Read the shared account counter from account_usage (migration 08). This is
    # the single source of truth: one pool per account, shared by all its agents.
    if user_id:
        def _q():
            return (_supabase.rpc("get_account_quota", {"p_user_id": user_id})
                    .execute())
        try:
            res = await asyncio.to_thread(_q)
            rows = res.data or []
            if rows:
                row = rows[0]
                # Trust the plan-derived limit, but prefer the stored one if set.
                account_limit = row.get("evaluation_limit") or account_limit
                month_used = row.get("evaluations_this_month", 0) or 0
            # Daily counter still read directly (separate column).
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
            # Fail closed on the monthly ceiling would block legitimate users on a
            # transient DB error; instead fall back to the agent's own counter,
            # which is conservative (never grants more than the account pool).
            month_used = auth.get("evaluations_this_month", 0) or 0
            today_used = auth.get("evaluations_today", 0) or 0

    # Monthly ceiling.
    if month_used >= account_limit:
        if plan == "free":
            detail = (f"Monthly account limit reached ({account_limit}). "
                      "Upgrade at https://hbeval.com/pricing for 5,000 evaluations/month.")
        else:
            detail = f"Monthly account limit of {account_limit} reached. Contact support."
        raise HTTPException(status_code=429, detail=detail)

    # Daily ceiling (account-wide): allowance spread across 28 days.
    daily_cap = max(1, math.ceil(account_limit / 28))
    if today_used >= daily_cap:
        raise HTTPException(
            status_code=429,
            detail=(f"Daily account limit reached ({daily_cap}/day). Your monthly "
                    "allowance is spread across the month; please continue tomorrow."),
        )

    auth["account_month_used"] = month_used
    auth["account_limit"] = account_limit
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
@app.get("/health", tags=["Infrastructure"])
async def health() -> dict:
    return {"status": "ok", "version": PROTOCOL_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat()}


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
        asyncio.create_task(_store_evaluation(run_id, project_id, agent_id, payload, result))
        # Layer 1 — EDM selective storage: consolidate only if PEI>=0.8 AND TI>=4.0
        asyncio.create_task(edm_guard.consolidate(_supabase, run_id, project_id, payload, result))

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
        asyncio.create_task(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/evaluate", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))
        if success:
            asyncio.create_task(_increment_usage(auth.get("user_id")))


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

        gated = _apply_plan_gates(report, plan_type)
        asyncio.create_task(_store_evaluation(run_id, project_id, agent_id, payload, report))
        # EDM consolidation uses the aggregate report (high-quality episodes).
        asyncio.create_task(edm_guard.consolidate(_supabase, run_id, project_id, payload, report))

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
        asyncio.create_task(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/evaluate_battery", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))
        if success:
            asyncio.create_task(_increment_usage(auth.get("user_id"), billable_units))



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
        # ── Paid-plan gate: verified path is not available on the free plan ──
        if plan_type in (None, "free", "trial"):
            status_code, error_code = 402, "UPGRADE_REQUIRED"
            raise HTTPException(
                status_code=402,
                detail=("The verified evaluation path requires a paid plan. "
                        "Use /evaluate_battery (local run) on the free plan."),
            )

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
        asyncio.create_task(_store_evaluation(run_id, project_id, agent_id, payload, report))
        asyncio.create_task(edm_guard.consolidate(_supabase, run_id, project_id, payload, report))

        success, status_code, error_code = True, 200, None
        return {**gated, "run_id": run_id}

    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in /evaluate_verified (run %s).", run_id)
        status_code, error_code = 500, "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw = http_request.client.host if http_request.client else None
        asyncio.create_task(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/evaluate_verified", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))
        if success:
            asyncio.create_task(_increment_usage(auth.get("user_id"), billable_units))


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
        asyncio.create_task(_store_evaluation(run_id, project_id, agent_id, payload, result))
        asyncio.create_task(edm_guard.consolidate(_supabase, run_id, project_id, payload, result))
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
        asyncio.create_task(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/evaluate_plain", method="POST", status_code=status_code,
            request_id=run_id, error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))
        if success:
            asyncio.create_task(_increment_usage(auth.get("user_id")))


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
        asyncio.create_task(_audit_log(
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
        asyncio.create_task(_audit_log(
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

        # Anonymous aggregate contribution, only if this account opted in.
        # Fired as a background task: the user's own session is already
        # stored, and a slow or failing contribution must not delay their
        # response.
        asyncio.create_task(_contribute_to_observatory(auth.get("user_id"), summary))

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
        asyncio.create_task(_audit_log(
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
        asyncio.create_task(_audit_log(
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
        asyncio.create_task(_audit_log(
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
        asyncio.create_task(_audit_log(
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
        return (_supabase.table("agents")
                .select("id, name, agent_id, plan_type")
                .eq("user_id", user_id)
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

        result = await mcp_tools.call_tool(
            tool_name, args,
            supabase=_supabase, to_thread=asyncio.to_thread,
            user_id=ctx["user_id"], agent=agent, deps=deps,
        )
        # isError is derived from the payload the tool itself returned, so a
        # refusal (wrong plan, missing consent) reads as a failed call to the
        # model rather than a successful one with an error inside it.
        is_error = '"ok": false' in result
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
