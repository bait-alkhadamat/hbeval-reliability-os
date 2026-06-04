"""
HB-Eval OS — Reliability Gateway v2.0.0
========================================
Production-ready FastAPI application deployed on Railway (private repo).

Architecture overview
─────────────────────
Request → Authentication → Usage Gate → Rate Limiting → Decryption
        → engines.py (pure computation) → Persist → Increment Usage
        → Audit Log → Response

Freemium model
──────────────
Every project (API key) belongs to a plan: free | pro | enterprise.
Free plan: 500 evaluations/month. Counter resets on the 1st of each month.
The usage gate sits between auth and processing so that over-limit
requests are rejected before any CPU-heavy computation happens.

Premium-only features (plan_type != 'free'):
  - Agent Passport (GET /api/v1/agent/{agent_id}) — full signed passport
  - HB-Certified badge in evaluation response
  - EDM retrieval: free tier limited to 3 memories, paid unlimited

Repository: private — github.com/hb-evalSystem/hb-eval-gateway
Platform  : Railway (auto-deploys from main branch)
Entry point: uvicorn gateway:app --host 0.0.0.0 --port $PORT

Required environment variables (set in Railway dashboard):
    API_KEY       — production bearer token (legacy single-key mode)
    AES_KEY       — base64-encoded 32-byte AES-256 key
    SUPABASE_URL  — Supabase project URL
    SUPABASE_KEY  — Supabase service_role key
    REDIS_URL     — Redis connection string

Optional:
    DEV_MODE      — "true" to show Swagger UI and relax /evaluate_plain warnings
    DEV_API_KEY   — fallback key used when Supabase is unreachable in dev
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

# ══════════════════════════════════════════════════════════════════════════════
# 1 ─ Logging
# ══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("hb-eval-gateway")


# ══════════════════════════════════════════════════════════════════════════════
# 2 ─ Environment variables
#     Required secrets use os.environ[] so a missing value crashes at
#     startup (visible in Railway logs) rather than failing silently at
#     request time with a confusing error.
# ══════════════════════════════════════════════════════════════════════════════

def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        msg = f"Required environment variable '{name}' is missing or empty."
        logger.critical(msg)
        raise RuntimeError(msg)
    return value


try:
    _API_KEY     = _require_env("API_KEY")
    _AES_KEY_B64 = _require_env("AES_KEY")
    _SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
    _SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
    _REDIS_URL    = os.environ.get("REDIS_URL", "redis://localhost:6379")
    _DEV_MODE     = os.environ.get("DEV_MODE", "false").lower() == "true"
except RuntimeError:
    raise

try:
    _AES_KEY = base64.b64decode(_AES_KEY_B64)
    if len(_AES_KEY) != 32:
        raise ValueError(f"AES key is {len(_AES_KEY)} bytes — must be exactly 32.")
except Exception as exc:
    logger.critical("Invalid AES_KEY: %s", exc)
    raise RuntimeError(f"Invalid AES_KEY: {exc}") from exc


# ══════════════════════════════════════════════════════════════════════════════
# 3 ─ Supabase client
# ══════════════════════════════════════════════════════════════════════════════

_supabase: Client | None = None
if _SUPABASE_URL and _SUPABASE_KEY:
    _supabase = create_client(_SUPABASE_URL, _SUPABASE_KEY)
    logger.info("Supabase client initialised.")
else:
    logger.warning("Supabase not configured — storage, auditing, and usage tracking disabled.")


# ══════════════════════════════════════════════════════════════════════════════
# 4 ─ Lifespan (startup / shutdown)
# ══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        redis_conn = await aioredis.from_url(_REDIS_URL, decode_responses=True)
        await FastAPILimiter.init(redis_conn)
        logger.info("Rate limiter initialised (Redis: %s).", _REDIS_URL)
    except Exception as exc:
        logger.error("Rate limiter unavailable: %s. Proceeding without.", exc)
    yield
    logger.info("Gateway shutting down.")


# ══════════════════════════════════════════════════════════════════════════════
# 5 ─ FastAPI app
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="HB-Eval OS Gateway",
    version="2.0.0",
    description="Reliability evaluation gateway for agentic AI systems.",
    docs_url="/docs" if _DEV_MODE else None,
    redoc_url=None,
    lifespan=lifespan,
)


# ══════════════════════════════════════════════════════════════════════════════
# 6 ─ Request / response models
# ══════════════════════════════════════════════════════════════════════════════

class EncryptedEvaluationRequest(BaseModel):
    ciphertext: str = Field(..., description="AES-256-GCM encrypted payload, hex-encoded.")

class PlainEvaluationRequest(BaseModel):
    trajectory:            list[dict] = Field(default_factory=list)
    sub_tasks:             int        = Field(default=1, ge=1)
    constraint_violations: int        = Field(default=0, ge=0)
    recovery_episodes:     list[dict] = Field(default_factory=list)
    context:               str        = Field(default="")
    agent_id:              str        = Field(default="unknown-agent")
    project_id:            str        = Field(default="00000000-0000-0000-0000-000000000001")

class MemoryRetrieveRequest(BaseModel):
    context:    str = Field(..., description="Natural language task description.")
    project_id: str = Field(default="00000000-0000-0000-0000-000000000001")
    top_k:      int = Field(default=5, ge=1, le=20)


# ══════════════════════════════════════════════════════════════════════════════
# 7 ─ Authentication
#     verify_api_key returns a rich context dict that includes plan info.
#     This is used downstream by the usage gate and by feature-gating logic.
# ══════════════════════════════════════════════════════════════════════════════

async def _extract_api_key(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    return authorization[len("Bearer "):]


async def verify_api_key(api_key: str = Depends(_extract_api_key)) -> dict[str, Any]:
    """
    Validate the API key and return a context dict that includes:
        project_id            — UUID of the calling project
        api_key_hash          — SHA-256 of the raw key (for audit logs)
        raw_api_key           — needed for HMAC signature verification
        plan_type             — 'free' | 'pro' | 'enterprise'
        evaluation_limit      — monthly evaluation cap
        evaluations_this_month — current month usage (before this request)
        last_reset_date       — ISO date string of last counter reset
    """
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    if _supabase:
        result = (
            _supabase
            .table("projects")
            .select("id, plan_type, evaluation_limit, evaluations_this_month, last_reset_date")
            .eq("api_key", api_key)
            .execute()
        )
        if not result.data:
            logger.warning("Rejected unknown API key (hash: %s...).", api_key_hash[:8])
            raise HTTPException(status_code=401, detail="Invalid API key.")

        row = result.data[0]
        return {
            "project_id":              row["id"],
            "api_key_hash":            api_key_hash,
            "raw_api_key":             api_key,
            "plan_type":               row.get("plan_type", "free"),
            "evaluation_limit":        row.get("evaluation_limit", 500),
            "evaluations_this_month":  row.get("evaluations_this_month", 0),
            "last_reset_date":         row.get("last_reset_date", "2000-01-01"),
        }
    else:
        # Development fallback — compare_digest prevents timing side-channels.
        dev_key = os.environ.get("DEV_API_KEY", "")
        if not hmac_module.compare_digest(api_key, dev_key):
            raise HTTPException(status_code=401, detail="Invalid API key.")
        return {
            "project_id":             "00000000-0000-0000-0000-000000000001",
            "api_key_hash":           api_key_hash,
            "raw_api_key":            api_key,
            "plan_type":              "pro",    # dev mode bypasses plan limits
            "evaluation_limit":       999999,
            "evaluations_this_month": 0,
            "last_reset_date":        "2000-01-01",
        }


# ══════════════════════════════════════════════════════════════════════════════
# 8 ─ Usage gate
#     This dependency sits between auth and the actual evaluation logic.
#     It checks the monthly limit before any expensive computation runs,
#     and delegates the atomic increment-or-reset to a Postgres function
#     to avoid race conditions under concurrent requests.
#
#     Why a Postgres function (RPC) for the increment?
#     ─────────────────────────────────────────────────
#     A naive "read current count → check → write incremented count" in
#     Python has a race condition: two simultaneous requests both read 499,
#     both check 499 < 500 (OK), both write 500 — so the user gets 2
#     evaluations but the counter only moves by 1. The increment_usage()
#     Postgres function uses FOR UPDATE row locking to make the
#     read-increment-write atomic at the database level.
# ══════════════════════════════════════════════════════════════════════════════

async def usage_gate(auth: dict = Depends(verify_api_key)) -> dict:
    """
    Check whether the project has remaining evaluations this month.
    Returns the same auth dict unchanged — it is used as a pass-through
    dependency so endpoints that need both auth and usage checking can
    depend on this single function.

    Raises HTTP 429 with a descriptive message if the limit is exceeded.
    """
    if not _supabase:
        return auth  # dev mode: no usage tracking

    now   = datetime.now(timezone.utc)
    limit = auth["evaluation_limit"]

    # Parse the stored reset date to compare year and month.
    try:
        stored_date  = datetime.fromisoformat(auth["last_reset_date"])
        same_month   = (stored_date.year == now.year and stored_date.month == now.month)
        current_count = auth["evaluations_this_month"] if same_month else 0
    except (ValueError, TypeError):
        current_count = 0  # malformed date — treat as fresh month

    if current_count >= limit:
        plan = auth["plan_type"]
        if plan == "free":
            detail = (
                f"Monthly evaluation limit reached ({limit} evaluations). "
                "Upgrade to Pro at https://hb-eval.com/pricing for 10,000 evaluations/month."
            )
        else:
            # Pro/Enterprise hitting limits is unexpected — flag it.
            detail = f"Monthly limit of {limit} evaluations reached. Contact support."
        raise HTTPException(status_code=429, detail=detail)

    return auth


async def _increment_usage(project_id: str) -> None:
    """
    Atomically increment the usage counter for this month.
    Called after a successful evaluation — we only charge for successful runs.
    Uses the Postgres RPC function created in migration_freemium.sql.
    """
    if not _supabase:
        return

    now = datetime.now(timezone.utc)

    def _rpc() -> None:
        _supabase.rpc("increment_usage", {
            "p_project_id":    project_id,
            "p_current_year":  now.year,
            "p_current_month": now.month,
        }).execute()

    try:
        await asyncio.to_thread(_rpc)
    except Exception as exc:
        # A failed increment is unfortunate but must not fail the user's request.
        # The slight under-count is acceptable; it self-corrects next month.
        logger.error("Usage increment failed for project %s: %s", project_id, exc)


# ══════════════════════════════════════════════════════════════════════════════
# 9 ─ Rate limiting identifier
#     Keyed on API key hash, not IP, so clients behind the same NAT
#     don't share a quota.
# ══════════════════════════════════════════════════════════════════════════════

async def _api_key_identifier(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        key = auth_header[len("Bearer "):]
        return hashlib.sha256(key.encode()).hexdigest()
    return request.client.host if request.client else "anonymous"


# ══════════════════════════════════════════════════════════════════════════════
# 10 ─ Audit logging
# ══════════════════════════════════════════════════════════════════════════════

async def _audit_log(
    *,
    project_id:   str,
    api_key_hash: str,
    endpoint:     str,
    method:       str,
    status_code:  int,
    request_id:   str | None = None,
    error_code:   str | None = None,
    latency_ms:   int        = 0,
    ip_raw:       str | None = None,
) -> None:
    if not _supabase:
        return

    # Hash the IP before storage — no raw addresses in the database.
    ip_hashed = hashlib.sha256(ip_raw.encode()).hexdigest() if ip_raw else None

    def _write() -> None:
        _supabase.table("audit_logs").insert({
            "project_id":   project_id,
            "api_key_hash": api_key_hash,
            "endpoint":     endpoint,
            "method":       method,
            "status_code":  status_code,
            "request_id":   request_id,
            "error_code":   error_code,
            "latency_ms":   latency_ms,
            "ip_address":   ip_hashed,
            "created_at":   datetime.now(timezone.utc).isoformat(),
        }).execute()

    try:
        await asyncio.to_thread(_write)
    except Exception as exc:
        logger.error("Audit log write failed: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
# 11 ─ Supabase helpers (persist + history)
# ══════════════════════════════════════════════════════════════════════════════

async def _fetch_history(project_id: str, agent_id: str) -> dict[str, list]:
    """Fetch the last 100 evaluation results for CSI computation."""
    if not _supabase:
        return {"pei_scores": [], "irs_scores": [], "outcomes": []}

    def _query() -> dict:
        result = (
            _supabase
            .table("evaluations")
            .select("pei_score, irs_score, verdict")
            .eq("project_id", project_id)
            .eq("agent_id", agent_id)
            .order("created_at", desc=True)
            .limit(100)
            .execute()
        )
        rows = result.data or []
        return {
            "pei_scores": [r["pei_score"] for r in rows if r.get("pei_score") is not None],
            "irs_scores": [r["irs_score"] for r in rows if r.get("irs_score") is not None],
            "outcomes":   [r["verdict"] == "SAFE" for r in rows],
        }

    try:
        return await asyncio.to_thread(_query)
    except Exception as exc:
        logger.error("History fetch failed: %s", exc)
        return {"pei_scores": [], "irs_scores": [], "outcomes": []}


async def _store_evaluation(
    run_id: str, project_id: str, agent_id: str, result: dict[str, Any]
) -> None:
    if not _supabase:
        return
    metrics = result.get("metrics", {})

    def _write() -> None:
        _supabase.table("evaluations").insert({
            "id":          run_id,
            "project_id":  project_id,
            "agent_id":    agent_id,
            "verdict":     result["verdict"],
            "tier":        result.get("tier"),
            "pei_score":   metrics.get("pei"),
            "irs_score":   metrics.get("irs"),
            "frr_score":   metrics.get("frr"),
            "ti_score":    metrics.get("ti"),
            "csi_score":   metrics.get("csi"),
            "memory_hit":  result.get("memory_hit", False),
            "created_at":  datetime.now(timezone.utc).isoformat(),
        }).execute()

    try:
        await asyncio.to_thread(_write)
    except Exception as exc:
        logger.error("Evaluation persist failed: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
# 12 ─ HMAC signature verification
#     Signature = HMAC-SHA256(key=api_key, message=nonce+timestamp+ciphertext)
#     This matches the reference implementation in docs/6-api.md.
# ══════════════════════════════════════════════════════════════════════════════

def _verify_signature(
    api_key: str, nonce: str, timestamp: str, ciphertext: str, received_sig: str
) -> None:
    try:
        request_time = int(timestamp)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid X-HBEval-Timestamp.")

    if abs(int(time.time()) - request_time) > 300:
        raise HTTPException(status_code=403, detail="Request expired (clock skew > 5 min).")

    message  = (nonce + timestamp + ciphertext).encode()
    expected = hmac_module.new(api_key.encode(), message, digestmod="sha256").hexdigest()

    if not hmac_module.compare_digest(expected, received_sig):
        raise HTTPException(status_code=403, detail="Invalid signature.")


# ══════════════════════════════════════════════════════════════════════════════
# 13 ─ Feature gating helpers
#     These are used to gate premium features at the response level.
#     Rather than raising an error, they shape the response differently
#     for free vs paid plans — the free user can still evaluate, they just
#     don't get the full certification badge or Agent Passport details.
# ══════════════════════════════════════════════════════════════════════════════

def _is_paid(plan_type: str) -> bool:
    return plan_type in ("pro", "enterprise")


def _apply_plan_gates(result: dict[str, Any], plan_type: str) -> dict[str, Any]:
    """
    Modify the evaluation result based on the project's plan.
    Free tier: tier and certified fields are hidden.
    Paid tier: full result including certification status.
    """
    if _is_paid(plan_type):
        return result

    # Free plan: return metrics but suppress tier certification.
    gated = dict(result)
    gated["tier"]      = None
    gated["certified"] = False
    gated["note"]      = (
        "Tier certification and Agent Passport require a Pro plan. "
        "See https://hb-eval.com/pricing"
    )
    return gated


# ══════════════════════════════════════════════════════════════════════════════
# 14 ─ Endpoints
# ══════════════════════════════════════════════════════════════════════════════

# ── 14.1  Health check ───────────────────────────────────────────────────────

@app.get("/health", tags=["Infrastructure"])
async def health() -> dict:
    return {
        "status":    "ok",
        "version":   "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── 14.2  POST /evaluate  (encrypted, production) ───────────────────────────

@app.post("/evaluate", tags=["Evaluation"])
async def evaluate(
    http_request: Request,
    body:         EncryptedEvaluationRequest,
    auth:         dict = Depends(usage_gate),   # usage_gate wraps verify_api_key
    _rate:        bool = Depends(
        RateLimiter(times=100, seconds=60, identifier=_api_key_identifier)
    ),
) -> dict:
    run_id       = str(uuid.uuid4())
    project_id   = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    plan_type    = auth["plan_type"]
    start_time   = time.monotonic()
    status_code  = 500
    error_code   = "UNKNOWN_ERROR"
    success      = False

    try:
        # Security headers
        nonce     = http_request.headers.get("X-HBEval-Nonce", "")
        timestamp = http_request.headers.get("X-HBEval-Timestamp", "")
        signature = http_request.headers.get("X-HBEval-Signature", "")

        if not all([nonce, timestamp, signature]):
            status_code = 400
            error_code  = "MISSING_SECURITY_HEADERS"
            raise HTTPException(
                status_code=400,
                detail="X-HBEval-Nonce, X-HBEval-Timestamp, and X-HBEval-Signature are required.",
            )

        try:
            _verify_signature(auth["raw_api_key"], nonce, timestamp, body.ciphertext, signature)
        except HTTPException as exc:
            status_code = exc.status_code
            error_code  = "INVALID_SIGNATURE" if exc.status_code == 403 else "INVALID_TIMESTAMP"
            raise

        # Decrypt
        try:
            aesgcm    = AESGCM(_AES_KEY)
            raw_bytes = bytes.fromhex(body.ciphertext)
            gcm_nonce = bytes.fromhex(nonce[:24])   # 12-byte GCM nonce from first 24 hex chars
            decrypted = aesgcm.decrypt(gcm_nonce, raw_bytes, None)
            payload   = json.loads(decrypted.decode())
        except Exception as exc:
            status_code = 400
            error_code  = "DECRYPTION_FAILED"
            logger.warning("Decryption failed (run %s): %s", run_id, exc)
            raise HTTPException(status_code=400, detail="Payload decryption failed.")

        # Compute
        agent_id = payload.get("agent_id", "unknown-agent")
        history  = await _fetch_history(project_id, agent_id)
        result   = HBEvalEngines.evaluate(payload, history)

        # Apply plan gates before returning
        gated_result = _apply_plan_gates(result, plan_type)

        # Persist (fire-and-forget — don't block the response)
        asyncio.create_task(_store_evaluation(run_id, project_id, agent_id, result))

        success     = True
        status_code = 200
        error_code  = None
        return {**gated_result, "run_id": run_id}

    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in /evaluate (run %s).", run_id)
        status_code = 500
        error_code  = "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw     = http_request.client.host if http_request.client else None
        asyncio.create_task(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/evaluate", method="POST",
            status_code=status_code, request_id=run_id,
            error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))
        # Only increment usage on successful evaluations
        if success:
            asyncio.create_task(_increment_usage(project_id))


# ── 14.3  POST /evaluate_plain  (development only) ──────────────────────────

@app.post("/evaluate_plain", tags=["Evaluation"])
async def evaluate_plain(
    http_request: Request,
    body:         PlainEvaluationRequest,
    auth:         dict = Depends(usage_gate),
    _rate:        bool = Depends(
        RateLimiter(times=100, seconds=60, identifier=_api_key_identifier)
    ),
) -> dict:
    if not _DEV_MODE:
        logger.warning(
            "/evaluate_plain called in production by project %s. Use /evaluate instead.",
            auth["project_id"],
        )

    run_id       = str(uuid.uuid4())
    project_id   = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    plan_type    = auth["plan_type"]
    start_time   = time.monotonic()
    status_code  = 500
    error_code   = "UNKNOWN_ERROR"
    success      = False

    try:
        payload  = body.model_dump()
        agent_id = payload.get("agent_id", "unknown-agent")
        history  = await _fetch_history(project_id, agent_id)
        result   = HBEvalEngines.evaluate(payload, history)

        gated_result = _apply_plan_gates(result, plan_type)
        asyncio.create_task(_store_evaluation(run_id, project_id, agent_id, result))

        success     = True
        status_code = 200
        error_code  = None
        return {**gated_result, "run_id": run_id}

    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in /evaluate_plain (run %s).", run_id)
        status_code = 500
        error_code  = "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw     = http_request.client.host if http_request.client else None
        asyncio.create_task(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/evaluate_plain", method="POST",
            status_code=status_code, request_id=run_id,
            error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))
        if success:
            asyncio.create_task(_increment_usage(project_id))


# ── 14.4  POST /api/v1/memory/retrieve ──────────────────────────────────────

@app.post("/api/v1/memory/retrieve", tags=["Memory"])
async def memory_retrieve(
    http_request: Request,
    body:         MemoryRetrieveRequest,
    auth:         dict = Depends(verify_api_key),   # no usage gate — memory is free
    _rate:        bool = Depends(
        RateLimiter(times=100, seconds=60, identifier=_api_key_identifier)
    ),
) -> dict:
    """
    Free plan: returns up to 3 memories.
    Paid plan: returns up to top_k memories (max 20).
    """
    run_id       = str(uuid.uuid4())
    project_id   = auth["project_id"]
    api_key_hash = auth["api_key_hash"]
    start_time   = time.monotonic()
    status_code  = 500
    error_code   = "UNKNOWN_ERROR"

    # Apply memory retrieval limit based on plan
    effective_top_k = body.top_k if _is_paid(auth["plan_type"]) else min(body.top_k, 3)

    try:
        if not _supabase:
            raise HTTPException(status_code=503, detail="Memory service unavailable.")

        def _query() -> list[dict]:
            result = (
                _supabase
                .table("edm_memory")
                .select("*")
                .eq("project_id", body.project_id)
                .order("created_at", desc=True)
                .limit(effective_top_k)
                .execute()
            )
            return result.data or []

        memories    = await asyncio.to_thread(_query)
        status_code = 200
        error_code  = None

        response = {"memories": memories, "total_retrieved": len(memories)}
        if not _is_paid(auth["plan_type"]) and body.top_k > 3:
            response["note"] = (
                "Free plan returns up to 3 memories. "
                "Upgrade to Pro for unlimited retrieval."
            )
        return response

    except HTTPException:
        raise
    except Exception:
        logger.exception("Unhandled error in /api/v1/memory/retrieve.")
        status_code = 500
        error_code  = "INTERNAL_SERVER_ERROR"
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        ip_raw     = http_request.client.host if http_request.client else None
        asyncio.create_task(_audit_log(
            project_id=project_id, api_key_hash=api_key_hash,
            endpoint="/api/v1/memory/retrieve", method="POST",
            status_code=status_code, request_id=run_id,
            error_code=error_code, latency_ms=latency_ms, ip_raw=ip_raw,
        ))


# ── 14.5  GET /api/v1/agent/{agent_id}  (Phase III) ─────────────────────────

@app.get("/api/v1/agent/{agent_id}", tags=["Agent Passport"])
async def get_agent_passport(
    agent_id:  str,
    auth:      dict = Depends(verify_api_key),
) -> JSONResponse:
    """
    Agent Passport — Phase III.
    Free plan: returns "Uncertified" placeholder.
    Paid plan: will return full signed passport when Phase III ships.
    """
    if not _is_paid(auth["plan_type"]):
        return JSONResponse(
            status_code=200,
            content={
                "agent_id":   agent_id,
                "status":     "uncertified",
                "message":    (
                    "Agent Passport requires a Pro plan. "
                    "Upgrade at https://hb-eval.com/pricing"
                ),
            },
        )

    # Paid plan — Phase III implementation pending
    return JSONResponse(
        status_code=200,
        content={
            "status":          "coming_soon",
            "agent_id":        agent_id,
            "available_in":    "Phase III (Q3 2026)",
            "preview_schema": {
                "agent_id":    "string",
                "tier":        "integer | null",
                "certified_at":"ISO 8601",
                "expires_at":  "ISO 8601",
                "metrics":     {"pei":"float","irs":"float","frr":"float","ti":"float","csi":"float"},
                "signature":   "string",
            },
        },
    )


# ══════════════════════════════════════════════════════════════════════════════
# 15 ─ Global exception handler
# ══════════════════════════════════════════════════════════════════════════════

@app.exception_handler(Exception)
async def _global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception at %s %s.", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "INTERNAL_SERVER_ERROR",
                           "message": "An unexpected error occurred."}},
    )
