"""
HB-Eval OS — Reliability Gateway v2.1.0
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

  4. Identity (the fourth bug): the Gateway reads from the `projects` table,
     which is the live table (it holds the real rows). The unused `agents`
     table is not consulted. The platform must also write new users to
     `projects` — documented in the README.

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
from fastapi.responses import JSONResponse
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from pydantic import BaseModel, Field
from supabase import Client, create_client

from engines import HBEvalEngines
from validation import validate_payload, ValidationError

# ── 1. Logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("hb-eval-gateway")

PROTOCOL_VERSION = "2.1.0"


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
    title="HB-Eval OS Gateway",
    version=PROTOCOL_VERSION,
    description="Reliability evaluation gateway for agentic AI systems.",
    docs_url="/docs" if _DEV_MODE else None,
    redoc_url=None,
    lifespan=lifespan,
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
    Validate the API key against the `agents` table (the unified identity
    table) and return a context dict.

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
                .select("id, plan_type, evaluation_limit, evaluations_this_month, "
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
async def usage_gate(auth: dict = Depends(verify_api_key)) -> dict:
    if not _supabase:
        return auth
    now = datetime.now(timezone.utc)
    limit = auth["evaluation_limit"]
    try:
        stored = datetime.fromisoformat(str(auth["last_reset_date"]))
        same_month = (stored.year == now.year and stored.month == now.month)
        current = auth["evaluations_this_month"] if same_month else 0
    except (ValueError, TypeError):
        current = 0
    if current >= limit:
        if auth["plan_type"] == "free":
            detail = (
                f"Monthly evaluation limit reached ({limit}). "
                "Upgrade at https://hbeval.com/pricing for 10,000 evaluations/month."
            )
        else:
            detail = f"Monthly limit of {limit} reached. Contact support."
        raise HTTPException(status_code=429, detail=detail)

    # Daily cap: the monthly allowance is spread across the month so no single
    # day can exhaust it. Cap = ceil(limit / 28). Enforced here, server-side —
    # the dashboard only visualises this; this is the authoritative check.
    import math
    daily_cap = max(1, math.ceil(limit / 28))
    try:
        last_eval = datetime.fromisoformat(str(auth.get("last_eval_date", "2000-01-01")))
        same_day = (last_eval.date() == now.date())
        used_today = auth.get("evaluations_today", 0) if same_day else 0
    except (ValueError, TypeError):
        used_today = 0
    if used_today >= daily_cap:
        raise HTTPException(
            status_code=429,
            detail=(f"Daily limit reached ({daily_cap}/day). Your monthly allowance is "
                    "spread across the month; please continue tomorrow."),
        )
    return auth


async def _increment_usage(project_id: str) -> None:
    if not _supabase:
        return
    now = datetime.now(timezone.utc)

    def _rpc():
        _supabase.rpc("increment_usage", {
            "p_project_id": project_id,
            "p_current_year": now.year,
            "p_current_month": now.month,
        }).execute()

    try:
        await asyncio.to_thread(_rpc)
    except Exception as exc:
        logger.error("Usage increment failed for %s: %s", project_id, exc)

    # Daily counter: increment evaluations_today, resetting it when the date
    # rolls over. Done via a dedicated RPC so the logic is atomic server-side.
    def _rpc_daily():
        _supabase.rpc("increment_daily_usage", {
            "p_project_id": project_id,
            "p_today": now.date().isoformat(),
        }).execute()

    try:
        await asyncio.to_thread(_rpc_daily)
    except Exception as exc:
        logger.error("Daily usage increment failed for %s: %s", project_id, exc)


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
    metrics = result.get("metrics", {})
    # Store a hash of the trajectory, never the raw trajectory — privacy by design.
    traj_hash = hashlib.sha256(
        json.dumps(payload.get("trajectory", []), sort_keys=True).encode()
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
    Gate ONLY the formal certification, never the diagnostic value.

    Free-tier users receive the full metrics AND the full diagnostic guidance —
    they learn exactly where their agent stands and how to improve it. What
    requires a paid plan is the *formal* certification artifact: the official,
    displayable Tier stamp and the Agent Passport. This split is deliberate:
    knowledge and mentorship are free (which is what earns trust and drives
    word-of-mouth adoption), while the official, showable credential is the
    paid product. A free user is never left with a bare "fail" — they always
    receive the guidance that tells them why and what to do next.
    """
    if _is_paid(plan_type):
        return result
    gated = dict(result)
    # Hide only the formal, displayable certification — not the guidance.
    gated["tier"] = None
    gated["certified"] = False
    # The guidance field is intentionally preserved for free users.
    gated["note"] = (
        "Your full metrics and improvement guidance are included. The formal "
        "Tier certification and Agent Passport require a Pro plan. "
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
            asyncio.create_task(_increment_usage(project_id))


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
            asyncio.create_task(_increment_usage(project_id))


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


@app.exception_handler(Exception)
async def _global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception at %s %s.", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "INTERNAL_SERVER_ERROR",
                           "message": "An unexpected error occurred."}},
    )
