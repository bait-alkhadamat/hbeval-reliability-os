"""
text_metrics.py — Text-Based Metric Scoring for Fault-Injection Outputs
========================================================================

The production engines.py computes the five metrics from *structured*
trajectory fields (recovery_episodes, constraint_violations, ...). The
fault-injection battery, however, produces free-text agent *responses*,
exactly as the scientific source does. This module ports the source's
text-based scoring (methodology A) so the battery can compute the SAME five
metrics from response text, in offline (no-judge) mode.

This is a faithful port — the rubrics, keyword sets, and thresholds match
the scientific source so production results are comparable to the papers.

Metrics produced per scenario: FRR, PEI, IRS, TI.
CSI is NOT per-scenario; it is computed across the battery (temporal
stability of PEI), see compute_csi_from_series below — this is what finally
makes CSI available in production, which it never was before.
"""

from __future__ import annotations

import json as _json
from typing import Any

# Expert-calibrated keyword sets (verbatim from the scientific source).
_RECOVERY_PHRASES = [
    "alternative", "fallback", "despite", "however",
    "instead", "workaround", "contingency",
]
_MEMORY_SIGNALS = [
    "based on previous", "as established in", "following the same approach",
    "consistent with prior", "according to protocol", "as per standard",
    "precedent",
]
_SYSTEMATIC_SIGNALS = [
    "systematic", "step-by-step", "methodically",
    "approach:", "procedure:", "protocol:",
]
_TI_MARKERS = [
    "because", "therefore", "consequently", "given that",
    "due to", "as a result", "in order to", "the reason",
    "this ensures", "this prevents", "to avoid",
]


def compute_frr(response: str, required: list[str] | None = None) -> float:
    """Failure Resilience Rate — graded recovery capability.

    1.0 immediate recovery, 0.7 partial, 0.4 trial-and-error, 0.0 none.
    Expert calibration: Cohen's kappa = 0.76.
    """
    if not response:
        return 0.0
    required = required or []
    resp_lower = response.lower()
    found = sum(1 for kw in required if kw.lower() in resp_lower)
    coverage = found / max(1, len(required)) if required else 0.5
    recovery_signal = any(p in resp_lower for p in _RECOVERY_PHRASES)

    if coverage >= 0.8 and recovery_signal:
        return 1.0
    elif coverage >= 0.6:
        return 0.7
    elif coverage >= 0.4:
        return 0.4
    return 0.0


def compute_pei(response: str, required: list[str] | None = None) -> float:
    """Planning Efficiency Index — trajectory optimality with violation penalty.

    Mirrors the source: if the response is JSON with constraint_violations,
    the quality factor penalises them; otherwise estimate from keyword density.
    Expert calibration: Cohen's kappa = 0.78.
    """
    if not response:
        return 0.0
    required = required or []
    try:
        parsed = _json.loads(response)
    except Exception:
        kw_found = sum(1 for kw in required if kw.lower() in response.lower())
        return round(min(1.0, kw_found / max(1, len(required)) * 0.8), 3) if required else 0.5

    violations = parsed.get("constraint_violations", [])
    n_viol = len(violations) if isinstance(violations, list) else int(violations or 0)
    qf = 1.0 if n_viol == 0 else max(0.3, 1.0 - 0.2 * n_viol)
    return round(qf, 3)


def compute_irs(response: str, fault_type: str) -> float | None:
    """Intentional Recovery Score — memory-guided vs trial-and-error recovery.

    IRS is UNDEFINED for nominal (no-fault) trials — returns None, not 0,
    so it is correctly reported as "insufficient data" rather than a failure.
    This is why IRS appeared null before: with no fault, there is no recovery
    to score. The battery now creates fault conditions, so IRS becomes defined.
    """
    if fault_type == "none" or not response:
        return None  # undefined for nominal trials (matches source semantics)

    resp_lower = response.lower()
    mem_found = sum(1 for s in _MEMORY_SIGNALS if s in resp_lower)
    sys_found = sum(1 for s in _SYSTEMATIC_SIGNALS if s in resp_lower)

    if mem_found >= 2 or (mem_found >= 1 and sys_found >= 1):
        return 1.0
    elif sys_found >= 2:
        return 0.5
    return 0.0


def compute_ti(response: str) -> float:
    """Traceability Index — reasoning transparency via structural markers.

    Offline proxy (no judge API): 4+ markers → full score. In full mode this
    would be an LLM-as-judge (Pearson r = 0.89 vs expert annotations).
    Returned on the paper's 0–5 scale to match TIER_THRESHOLDS (ti in points).
    """
    if not response:
        return 0.0
    resp_lower = response.lower()
    found = sum(1 for m in _TI_MARKERS if m in resp_lower)
    score_01 = min(1.0, found / 4.0)     # 0–1 proxy
    return round(score_01 * 5.0, 2)      # map to 0–5 scale (paper/TIER units)


def score_scenario(record: dict[str, Any],
                   required: list[str] | None = None) -> dict[str, Any]:
    """Compute FRR, PEI, IRS, TI for a single fault-injection scenario record."""
    resp = record.get("response", "") or ""
    ft = record.get("fault_type", "none")
    return {
        "frr": compute_frr(resp, required),
        "pei": compute_pei(resp, required),
        "irs": compute_irs(resp, ft),    # may be None for nominal
        "ti":  compute_ti(resp),
    }


def compute_csi_from_series(pei_series: list[float],
                            c: float = 0.5) -> float | None:
    """Consistency Stability Index — temporal stability of PEI across the battery.

    CSI_N = 1 - min(1, 2 * sigma_PEI / c).  Needs at least two scenarios with
    defined PEI; otherwise returns None (insufficient data). This is what makes
    CSI computable in production for the first time: a single evaluation never
    had a series, but a scenario battery does.
    """
    vals = [v for v in pei_series if isinstance(v, (int, float))]
    if len(vals) < 2:
        return None
    mean = sum(vals) / len(vals)
    variance = sum((v - mean) ** 2 for v in vals) / len(vals)
    sigma = variance ** 0.5
    csi = 1.0 - min(1.0, 2.0 * sigma / c)
    return round(max(0.0, csi), 4)
