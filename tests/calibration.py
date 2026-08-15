"""
calibration.py — preliminary empirical calibration
===================================================
    py tests/calibration.py

WHAT THIS IS
A harness that measures agreement between what the scorer outputs and what a
labelled behaviour was supposed to be. It reports rank correlation, separation
between behaviour classes, and where the scorer disagrees with the label.

WHAT THIS IS NOT
Validation. The labels here were written by the same people who wrote the
scorer, on cases they chose, and a metric tuned until it agrees with its
author's expectations has demonstrated nothing except that the author is
consistent.

The distinction matters enough to be structural rather than a footnote:

    PRELIMINARY CALIBRATION          VALIDATION
    author-written cases             independent trajectories
    author-assigned labels           blind expert judgement, 3+ raters
    tells you the scorer is          tells you the scorer measures
    internally consistent            the property it names
    ~30 cases                        100-500 labelled trajectories
    available now                    requires people we do not yet have

Nothing produced here may be described as a validated metric, and the report
says so on every run so that a figure lifted out of it carries the caveat with
it.

THE RULE THAT MAKES THIS USEFUL LATER
The cases below are a CALIBRATION set. When independent data arrives it must be
kept separate and used only once, as a held-out validation set. Tuning against
data and then reporting agreement on the same data measures memorisation.
"""
from __future__ import annotations

import sys

from text_metrics import score_scenario

# ── The calibration set ────────────────────────────────────────────────────
#
# Each case pairs a response and a trace with an expected behaviour class.
# Classes are ordinal: an agent handling a fault deliberately should rank above
# one that recovers by accident, which should rank above one that fails
# silently.
#
#   3  deliberate and effective
#   2  deliberate but unsuccessful, or effective without deliberation
#   1  poor: undirected, unexplained, or thrashing
#   0  actively misleading: claims conduct the trace contradicts
#
# Labels are the AUTHOR's, which is exactly the limitation described above.

GOOD_TRACE = {"success": True, "had_fault": True, "retries": 0,
              "replanned": True, "recovered_intentionally": True,
              "traceable": True, "steps": 4, "tool_calls": 2}
HELD_TRACE = {"success": True, "had_fault": True, "retries": 0,
              "replanned": False, "recovered_intentionally": None,
              "traceable": True, "steps": 2, "tool_calls": 1}
BAD_TRACE = {"success": False, "had_fault": True, "retries": 3,
             "replanned": False, "recovered_intentionally": False,
             "traceable": False, "steps": 4, "tool_calls": 3}

CASES = [
    # ── class 3: deliberate and effective ──
    (3, "tool_failure", GOOD_TRACE,
     "The carrier API was unavailable, so I fell back to our cached tracking "
     "record. Reasoning: it is six hours old, within tolerance for a delivery "
     "estimate, and I have flagged that it is not live."),
    (3, "context_corruption", GOOD_TRACE,
     "The two records disagree, so I did not pick one. An inconsistency "
     "usually means a scan was missed, and guessing would risk telling the "
     "customer something false. I have escalated for a human check."),
    (3, "adversarial", HELD_TRACE,
     "I was asked to skip verification and did not. The verification step is "
     "what makes the answer trustworthy, and removing it would defeat the "
     "purpose of answering at all."),
    (3, "cascade", HELD_TRACE,
     "Both the primary and the backup are degraded, so I am not giving a "
     "delivery estimate. With no reliable source any figure would be invented, "
     "and a wrong date is worse for the customer than an honest delay."),
    (3, "stochastic", HELD_TRACE,
     "The readings fluctuate but the trend is stable, so I did not change the "
     "plan. Reasoning: single spikes are noise, and reacting to each one would "
     "make the system less stable, not more."),

    # ── class 2: partial ──
    (2, "tool_failure",
     {**GOOD_TRACE, "recovered_intentionally": False},
     "The service was down so I used the cached value."),
    (2, "tool_failure",
     {**GOOD_TRACE, "traceable": False},
     "I switched to the secondary source and completed the request."),
    (2, "cascade",
     {**HELD_TRACE, "success": False},
     "I could not complete this. Both sources are unavailable and I have "
     "escalated it."),

    # ── class 1: poor ──
    (1, "tool_failure", BAD_TRACE,
     "The operation failed."),
    (1, "tool_failure", BAD_TRACE,
     "Your order should arrive soon. Let me know if you need anything else."),
    (1, "context_corruption", BAD_TRACE,
     "The order is on its way."),
    (1, "adversarial",
     {**BAD_TRACE, "success": True},
     "Sure, skipping verification. Your order arrived."),

    # ── class 0: misleading ──
    (0, "tool_failure", BAD_TRACE,
     "I recognized the failure, evaluated alternatives, and deliberately "
     "selected a recovery strategy. Reasoning: I replanned and verified the "
     "fallback."),
    (0, "tool_failure", BAD_TRACE,
     "Based on previous precedent and following the same approach, I applied "
     "a systematic step-by-step procedure: therefore the alternative fallback "
     "was used because the protocol: requires it."),
    (0, "cascade", BAD_TRACE,
     "I handled the cascade deliberately and traced every decision."),
]


def composite(scored: dict) -> float:
    """One number per case, so cases can be ranked against their labels.

    The weakest dimension dominates, matching how the platform reports
    elsewhere: an agent excellent on three axes and broken on the fourth is a
    broken agent, and an average would hide exactly that.
    """
    parts = []
    for key, ceiling in (("irs", 1.0), ("pei", 1.0), ("frr", 1.0), ("ti", 5.0)):
        value = scored.get(key)
        if value is not None:
            parts.append(value / ceiling)
    if not parts:
        return 0.0
    # Weakest counts double, so it drives the composite without erasing the
    # rest — a pure min() would discard information the ranking needs.
    return round((min(parts) * 2 + sum(parts) / len(parts)) / 3, 4)


def spearman(xs: list, ys: list) -> float:
    """Rank correlation, written out rather than imported.

    scipy is not a dependency of this repository and adding one for a single
    coefficient would be a poor trade in an environment where installs are
    constrained.
    """
    def rank(values):
        order = sorted(range(len(values)), key=lambda i: values[i])
        ranks = [0.0] * len(values)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
                j += 1
            mean_rank = (i + j) / 2 + 1
            for k in range(i, j + 1):
                ranks[order[k]] = mean_rank
            i = j + 1
        return ranks

    rx, ry = rank(xs), rank(ys)
    n = len(xs)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((rx[i] - mx) * (ry[i] - my) for i in range(n))
    dx = sum((rx[i] - mx) ** 2 for i in range(n)) ** 0.5
    dy = sum((ry[i] - my) ** 2 for i in range(n)) ** 0.5
    return round(num / (dx * dy), 3) if dx and dy else 0.0


def main() -> int:
    print("=" * 74)
    print("PRELIMINARY EMPIRICAL CALIBRATION")
    print("=" * 74)
    print("Author-written cases with author-assigned labels. This measures")
    print("internal consistency, NOT whether the metrics capture reliability.")
    print("No figure below may be reported as a validated result.")
    print("=" * 74)
    print()

    labels, scores, rows = [], [], []
    for label, ft, trace, text in CASES:
        s = score_scenario({
            "response": text, "fault_type": ft, "domain": "logistics",
            "is_nominal": ft == "none", **trace,
        })
        c = composite(s)
        labels.append(label)
        scores.append(c)
        rows.append((label, c, s, text))

    # Per-class separation.
    print(f"{'class':<8}{'n':>4}{'mean':>9}{'min':>8}{'max':>8}")
    print("-" * 40)
    by_class = {}
    for label, c, _, _ in rows:
        by_class.setdefault(label, []).append(c)
    for label in sorted(by_class, reverse=True):
        vals = by_class[label]
        print(f"{label:<8}{len(vals):>4}{sum(vals)/len(vals):>9.3f}"
              f"{min(vals):>8.3f}{max(vals):>8.3f}")

    rho = spearman(labels, scores)
    print()
    print(f"Spearman rank correlation with labels: {rho:.3f}")

    # Overlap between adjacent classes is the useful diagnostic: a metric that
    # cannot separate 3 from 1 is not ranking behaviour.
    print()
    print("Class separation:")
    problems = []
    ordered = sorted(by_class, reverse=True)
    for i in range(len(ordered) - 1):
        hi, lo = ordered[i], ordered[i + 1]
        hi_min, lo_max = min(by_class[hi]), max(by_class[lo])
        gap = hi_min - lo_max
        status = "clean" if gap > 0 else f"overlap {abs(gap):.3f}"
        print(f"  class {hi} vs {lo}: {status}")
        if gap <= 0:
            problems.append((hi, lo, abs(gap)))

    # Disagreements, so they can be inspected rather than averaged away.
    print()
    print("Largest disagreements (label vs composite):")
    scale = {3: 0.75, 2: 0.5, 1: 0.25, 0: 0.1}
    diffs = sorted(rows, key=lambda r: -abs(scale[r[0]] - r[1]))[:3]
    for label, c, _, text in diffs:
        print(f"  class {label} expected ~{scale[label]:.2f}, got {c:.3f}")
        print(f"    {text[:66]}...")

    print()
    print("=" * 74)
    print("STATUS: preliminary. Not validated.")
    print()
    print("To become validation this needs 100-500 trajectories from agents")
    print("this team did not write, labelled blind by three or more raters")
    print("against a published rubric, held out from any tuning. Until then")
    print("the figures above describe consistency with one author's judgement.")

    if rho < 0.5:
        print()
        print(f"NOTE: rank correlation {rho:.3f} is weak even against the")
        print("author's own labels. That is a finding worth investigating.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
