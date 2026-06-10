"""
EDM Selective Storage Guard — Layer 1 (Persistence Governance)
===============================================================

Implements the selective-consolidation rule from Eval-Driven Memory (EDM,
Adam 2026, DOI 10.20944/preprints202601.0195.v1):

    A trajectory is consolidated into long-term memory (edm_memory)
    IF AND ONLY IF   PEI >= 0.80  AND  TI >= 4.0   (simultaneously).

Everything failing either threshold is discarded as noise, with the reason
logged transparently. This is the "governance core" of the EDM pipeline:
memory becomes a quality-preserving store, not a quantity-accumulating one.

DESIGN PRINCIPLES (all deliberate):
  • Fail-safe: if embedding or storage fails, the core evaluation is NEVER
    affected. The trajectory simply isn't consolidated. Reliability first.
  • Privacy by design: we store a short trajectory_summary, never the raw
    trajectory (mirrors the trajectory-hash approach in _store_evaluation).
  • Lazy, light embedding: the sentence-transformers model (all-MiniLM-L6-v2,
    384-dim, ~90 MB) loads once on first use, matching edm_memory.embedding
    vector(384). If the model can't load (e.g. memory limits on the host),
    the guard degrades gracefully and logs — it does not crash the Gateway.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger("hb-eval-gateway.edm")

# ── Governance thresholds (from the EDM paper — do NOT relax silently) ───────
PEI_STORAGE_THRESHOLD = 0.80
TI_STORAGE_THRESHOLD = 4.0

# ── Lazy-loaded embedding model (loads once, on first consolidation) ─────────
_embedder: Any | None = None
_embedder_failed = False  # once True, we stop retrying to avoid repeated cost


def _get_embedder():
    """
    Load all-MiniLM-L6-v2 lazily. Returns the model, or None if unavailable.
    Never raises — embedding is best-effort and must not break evaluation.
    """
    global _embedder, _embedder_failed
    if _embedder is not None:
        return _embedder
    if _embedder_failed:
        return None
    try:
        from sentence_transformers import SentenceTransformer
        # 384-dim output, matches edm_memory.embedding vector(384)
        _embedder = SentenceTransformer("all-MiniLM-L6-v2")
        logger.info("EDM embedder loaded (all-MiniLM-L6-v2, 384-dim).")
        return _embedder
    except Exception as exc:
        _embedder_failed = True
        logger.warning(
            "EDM embedder unavailable (%s). Consolidation will be skipped; "
            "core evaluation is unaffected.", exc
        )
        return None


def _embed(text: str) -> list[float] | None:
    """Embed text to a 384-dim list[float], or None if the model is down."""
    model = _get_embedder()
    if model is None:
        return None
    try:
        vec = model.encode(text, normalize_embeddings=True)
        return [float(x) for x in vec]
    except Exception as exc:
        logger.warning("EDM embedding failed: %s", exc)
        return None


def _build_summary(payload: dict, metrics: dict) -> str:
    """
    Build a compact, privacy-preserving plan summary for embedding + storage.
    We summarise the strategic structure, never raw sensitive trajectory data.
    """
    traj = payload.get("trajectory", []) or []
    domain = payload.get("domain", "unspecified")
    n_steps = len(traj)
    pei = metrics.get("pei")
    ti = metrics.get("ti")
    # The first action/intent of each step gives the plan shape without leaking
    # full state. Keep it short — this is a summary, not the trajectory.
    shape = []
    for step in traj[:12]:  # cap to keep the summary compact
        if isinstance(step, dict):
            shape.append(str(step.get("action") or step.get("intent") or "step"))
    shape_str = " > ".join(shape) if shape else "n/a"
    return (
        f"domain={domain}; steps={n_steps}; pei={pei}; ti={ti}; "
        f"plan={shape_str}"
    )


def qualifies(pei: float | None, ti: float | None) -> bool:
    """The EDM governance rule: PEI >= 0.80 AND TI >= 4.0, both required."""
    if pei is None or ti is None:
        return False
    return float(pei) >= PEI_STORAGE_THRESHOLD and float(ti) >= TI_STORAGE_THRESHOLD


async def consolidate(supabase, run_id: str, project_id: str,
                      payload: dict, result: dict) -> None:
    """
    Apply the selective-storage guard after an evaluation completes.

    Called fire-and-forget (asyncio task) right after _store_evaluation, so it
    never sits on the request path. Any failure is logged and swallowed —
    consolidation is best-effort governance, not a core guarantee.
    """
    if supabase is None:
        return

    metrics = result.get("metrics", {}) or {}
    pei = metrics.get("pei")
    ti = metrics.get("ti")

    # ── The governance decision ──────────────────────────────────────────
    if not qualifies(pei, ti):
        logger.info(
            "EDM DISCARD run=%s pei=%s ti=%s (rule: PEI>=%.2f AND TI>=%.1f)",
            run_id, pei, ti, PEI_STORAGE_THRESHOLD, TI_STORAGE_THRESHOLD,
        )
        return

    # ── Qualified: build summary, embed, store ───────────────────────────
    summary = _build_summary(payload, metrics)
    embedding = _embed(summary)
    if embedding is None:
        # Model unavailable — degrade gracefully. We do NOT write a row with a
        # null/!=384-dim vector, since edm_memory.embedding is vector(384).
        logger.warning(
            "EDM SKIP run=%s — qualified (pei=%s ti=%s) but embedder "
            "unavailable; not consolidated.", run_id, pei, ti,
        )
        return

    fault_context = payload.get("fault_context") or payload.get("domain") or "general"

    def _write():
        supabase.table("edm_memory").insert({
            "project_id": project_id,
            "fault_context": str(fault_context)[:500],
            "trajectory_summary": summary[:2000],
            "embedding": embedding,
            "pei_score": float(pei),
            "ti_score": float(ti),
            "irs_score": metrics.get("irs"),
        }).execute()

    try:
        await asyncio.to_thread(_write)
        logger.info(
            "EDM STORE run=%s pei=%s ti=%s — consolidated to edm_memory.",
            run_id, pei, ti,
        )
    except Exception as exc:
        logger.error("EDM consolidation write failed run=%s: %s", run_id, exc)
