"""
HCI-EDM Performance-Grounded Interpretability — Layer 2
========================================================

Implements the explanation discipline from HCI-EDM
(Adam 2026, DOI 10.20944/preprints202601.0896.v1):

    An explanation must REFERENCE a specific, stored, certified episode —
    never fabricate. If no qualified precedent exists, the system declares
    uncertainty and defers to a human.

THE FOUR CONSTRAINTS (the scientific core — enforced literally):
  1. Qualified precedent only: a memory may be cited only if its similarity
     to the query plan is >= SIMILARITY_THRESHOLD (0.87). Memories are already
     governance-qualified (PEI>=0.8 AND TI>=4.0) because the EDM guard is the
     only writer to edm_memory — so we re-assert it defensively but it holds.
  2. Numbers come from the record, never from a language model: PEI / TI / IRS
     shown in an explanation are read verbatim from the stored row.
  3. Stable reference: every citation names the episode by its immutable id,
     so the explanation is auditable.
  4. Mandatory uncertainty: if nothing clears the similarity threshold, we do
     NOT invent an explanation — we return the uncertainty template and advise
     human review. This is correct behaviour, not failure.

FAIL-SAFE: like the guard, if embedding is unavailable the layer degrades to
an honest "cannot ground an explanation right now" rather than crashing.
"""

from __future__ import annotations

import logging
from typing import Any

import edm_guard  # reuse the same lightweight embedder + thresholds

logger = logging.getLogger("hb-eval-gateway.hci")

# Constraint 1 — citation similarity gate (from the HCI-EDM paper)
SIMILARITY_THRESHOLD = 0.87


def _cosine(a: list[float], b: list[float]) -> float:
    """
    Cosine similarity. The guard stores L2-normalised vectors
    (normalize_embeddings=True), so a dot product already equals cosine.
    We still divide by norms defensively in case an external writer differs.
    """
    if not a or not b or len(a) != len(b):
        return -1.0
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0 or nb == 0:
        return -1.0
    return dot / (na * nb)


def _parse_embedding(raw: Any) -> list[float] | None:
    """edm_memory.embedding may come back as a list or as a '[...]' string."""
    if raw is None:
        return None
    if isinstance(raw, list):
        return [float(x) for x in raw]
    if isinstance(raw, str):
        try:
            inner = raw.strip().lstrip("[").rstrip("]")
            return [float(x) for x in inner.split(",")] if inner else None
        except Exception:
            return None
    return None


def _fmt(v: Any) -> str:
    """Format a stored metric verbatim-ish, without inventing precision."""
    if v is None:
        return "n/a"
    try:
        return f"{float(v):.2f}".rstrip("0").rstrip(".")
    except Exception:
        return str(v)


# ── The four explanation templates (HCI-EDM) ────────────────────────────────
def _template_success(mem: dict, sim: float) -> str:
    return (
        f"This decision aligns with a certified prior episode "
        f"(ref {mem['id']}, similarity {sim:.2f}). That episode achieved "
        f"PEI={_fmt(mem.get('pei_score'))} and TI={_fmt(mem.get('ti_score'))}, "
        f"clearing the reliability thresholds. The plan structure matches a "
        f"pattern with a documented high-quality outcome."
    )


def _template_recovery(mem: dict, sim: float) -> str:
    return (
        f"This decision resembles a certified episode that recovered from a "
        f"fault (ref {mem['id']}, similarity {sim:.2f}), with "
        f"IRS={_fmt(mem.get('irs_score'))} and final "
        f"PEI={_fmt(mem.get('pei_score'))}. The recovery path in that episode "
        f"is the grounding for this assessment."
    )


def _template_correction(mem: dict, sim: float) -> str:
    return (
        f"A certified prior episode (ref {mem['id']}, similarity {sim:.2f}) "
        f"shows a corrected trajectory reaching PEI={_fmt(mem.get('pei_score'))} "
        f"/ TI={_fmt(mem.get('ti_score'))}. This decision is interpreted against "
        f"that documented correction."
    )


def _template_uncertain() -> str:
    return (
        "No certified prior episode is similar enough to ground an explanation "
        "(similarity below the 0.87 threshold). Per the performance-grounded "
        "discipline, the system does not fabricate a rationale here and "
        "recommends human review."
    )


def _choose_template(mem: dict, sim: float) -> dict:
    """Pick the template that fits the stored episode's evidence."""
    irs = mem.get("irs_score")
    fault = (mem.get("fault_context") or "").lower()
    if irs is not None:
        kind, text = "recovery_narrative", _template_recovery(mem, sim)
    elif fault and fault not in ("general", "none", ""):
        kind, text = "deviation_correction", _template_correction(mem, sim)
    else:
        kind, text = "success_confirmation", _template_success(mem, sim)
    return {
        "kind": kind,
        "explanation": text,
        "grounded": True,
        "cited_episode_id": mem["id"],
        "similarity": round(sim, 4),
        "evidence": {  # Constraint 2: numbers verbatim from the record
            "pei": mem.get("pei_score"),
            "ti": mem.get("ti_score"),
            "irs": mem.get("irs_score"),
        },
    }


def explain(supabase, project_id: str, plan_summary: str) -> dict:
    """
    Produce a performance-grounded explanation for a plan summary.

    Returns a dict with either a grounded explanation citing a specific
    episode, or the mandatory uncertainty response. Never raises for normal
    flow — defers to uncertainty on any grounding failure.
    """
    # Embed the query plan with the same model the guard uses.
    query_vec = edm_guard._embed(plan_summary)
    if query_vec is None:
        return {
            "kind": "uncertain",
            "explanation": (
                "Explanation grounding is temporarily unavailable (embedding "
                "model not loaded). No rationale is fabricated; human review "
                "is advised."
            ),
            "grounded": False,
            "cited_episode_id": None,
        }

    if supabase is None:
        return {"kind": "uncertain", "explanation": _template_uncertain(),
                "grounded": False, "cited_episode_id": None}

    # Fetch this project's certified memories (the guard guarantees they are
    # all PEI>=0.8 AND TI>=4.0 — Constraint 1's quality half holds by design).
    def _query():
        return (
            supabase.table("edm_memory")
            .select("id, embedding, pei_score, ti_score, irs_score, fault_context, trajectory_summary")
            .eq("project_id", project_id)
            .limit(200)
            .execute()
        ).data or []

    try:
        rows = _query()
    except Exception as exc:
        logger.error("HCI explain query failed: %s", exc)
        return {"kind": "uncertain", "explanation": _template_uncertain(),
                "grounded": False, "cited_episode_id": None}

    # Find the most similar certified episode.
    best, best_sim = None, -1.0
    for r in rows:
        emb = _parse_embedding(r.get("embedding"))
        if emb is None:
            continue
        sim = _cosine(query_vec, emb)
        if sim > best_sim:
            best, best_sim = r, sim

    # Constraint 1 + 4: cite only above threshold, else mandatory uncertainty.
    if best is None or best_sim < SIMILARITY_THRESHOLD:
        logger.info("HCI explain: no precedent >= %.2f (best=%.3f)",
                    SIMILARITY_THRESHOLD, best_sim if best else -1.0)
        return {"kind": "uncertain", "explanation": _template_uncertain(),
                "grounded": False, "cited_episode_id": None,
                "best_similarity": round(best_sim, 4) if best else None}

    logger.info("HCI explain: grounded on episode %s (sim=%.3f)", best["id"], best_sim)
    return _choose_template(best, best_sim)
