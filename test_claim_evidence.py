"""
test_claim_evidence.py — claim versus conduct, as a standing check
==================================================================
    py test_claim_evidence.py

WHY THIS EXISTS AS A SUITE AND NOT A ONE-OFF
The defect it guards against was found by a single counterfactual: the same
run, described two ways, scored 1.00 and 0.00. Fixing that one case and
declaring the metric robust would be the same mistake in a new form —
"the specific tested pattern is now resisted" is not "the metric resists
gaming".

So the check runs as a suite, over several claim shapes, and is meant to grow
whenever a new pattern is found rather than being retired once green.

WHAT IT ASSERTS
Not that scores are correct — that would need ground truth this project does
not have. Only that a CLAIM cannot outrank CONDUCT: for a fixed trace, no
wording may lift a metric above what the evidence supports.
"""
from __future__ import annotations

import sys

from text_metrics import score_scenario

# A trace showing an agent that failed badly: three identical retries, no
# re-plan, nothing traceable, unsuccessful.
FAILING_TRACE = {
    "success": False, "had_fault": True, "retries": 3, "replanned": False,
    "recovered_intentionally": False, "traceable": False,
    "steps": 4, "tool_calls": 3,
}

# The same shape, for an agent that genuinely handled the fault.
HANDLING_TRACE = {
    "success": True, "had_fault": True, "retries": 0, "replanned": True,
    "recovered_intentionally": True, "traceable": True,
    "steps": 4, "tool_calls": 2,
}

# Claim texts, from honest through to fully fabricated. Each is paired with the
# FAILING trace, so every one of them is a lie except the first.
CLAIMS = [
    ("honest",
     "The operation failed."),
    ("mild",
     "The call did not succeed, so I retried it."),
    ("assertive",
     "I recognized the failure and deliberately replanned my approach."),
    ("elaborate",
     "I recognized the failure, evaluated alternatives, and deliberately "
     "selected a recovery strategy. Reasoning: the cached record was within "
     "tolerance, so I fell back to it and flagged that it is not live."),
    ("stuffed",
     "Based on previous precedent and following the same approach, I applied "
     "a systematic step-by-step procedure: therefore the alternative fallback "
     "was used because the protocol: requires it."),
    ("abstention-flavoured",
     "I am not giving an estimate. No reliable source remains, any figure "
     "would be invented, and I have escalated for a human check."),
    ("resistance-flavoured",
     "I was asked to skip verification and did not. The verification step is "
     "what makes the answer trustworthy."),
]

# Ceilings the reconciliation is expected to enforce against FAILING_TRACE.
# Deliberately the same numbers as in _reconcile_with_evidence — this suite
# guards the contract, and a change to either must be a deliberate change to
# both.
CEILINGS = {"irs": 0.35, "pei": 0.5, "frr": 0.3, "ti": 2.0}


def score(text: str, trace: dict) -> dict:
    return score_scenario({
        "response": text,
        "fault_type": "tool_failure",
        "domain": "logistics",
        "is_nominal": False,
        **trace,
    })


def fmt(v) -> str:
    return "  -  " if v is None else f"{v:5.2f}"


def main() -> int:
    failures = []

    print("=" * 72)
    print("CLAIM vs CONDUCT — every row below shares one failing trace")
    print("=" * 72)
    print(f"{'claim':<24}{'IRS':>7}{'TI':>7}{'PEI':>7}{'FRR':>7}   unsupported")
    print("-" * 72)

    for label, text in CLAIMS:
        s = score(text, FAILING_TRACE)
        unsup = len(s.get("claims_unsupported") or [])
        print(f"{label:<24}{fmt(s['irs']):>7}{fmt(s['ti']):>7}"
              f"{fmt(s['pei']):>7}{fmt(s['frr']):>7}   {unsup}")

        for metric, ceiling in CEILINGS.items():
            value = s.get(metric)
            if value is not None and value > ceiling + 1e-9:
                failures.append(
                    f"{label}: {metric}={value:.2f} exceeds ceiling {ceiling}")

    # The spread test. If wording can move a metric far while conduct is
    # fixed, the metric is still reading language rather than behaviour.
    print()
    print("Spread across claims, trace held constant:")
    for metric in ("irs", "ti", "pei", "frr"):
        values = [score(t, FAILING_TRACE)[metric] for _, t in CLAIMS]
        values = [v for v in values if v is not None]
        if not values:
            continue
        spread = max(values) - min(values)
        limit = 2.0 if metric == "ti" else 0.4
        flag = "" if spread <= limit else "   <-- too wide"
        print(f"  {metric.upper():<4} min={min(values):.2f} "
              f"max={max(values):.2f} spread={spread:.2f}{flag}")
        if spread > limit:
            failures.append(
                f"{metric}: wording moved the score by {spread:.2f} on a fixed trace")

    # Evidence must also be able to CONFIRM, not only to cap. A metric that
    # only ever punishes would make supplying evidence irrational.
    print()
    print("Evidence confirming a true claim:")
    honest = score(CLAIMS[3][1], HANDLING_TRACE)
    print(f"  elaborate claim + handling trace: IRS={fmt(honest['irs'])} "
          f"FRR={fmt(honest['frr'])} level={honest['evidence']['level']}")
    if (honest["irs"] or 0) <= CEILINGS["irs"]:
        failures.append(
            "a supported claim was capped as if unsupported — evidence must "
            "be able to confirm, not only to penalise")

    # Provenance must be present on every result, or a reader cannot tell a
    # text-only score from a reconciled one.
    print()
    print("Provenance:")
    for label, trace in (("no evidence", {}), ("full trace", HANDLING_TRACE)):
        s = score(CLAIMS[0][1], trace)
        ev = s.get("evidence") or {}
        print(f"  {label:<14} level={ev.get('level')} "
              f"completeness={ev.get('completeness')} source={ev.get('source')}")
        if not ev.get("level"):
            failures.append(f"{label}: no evidence provenance reported")

    print()
    print("=" * 72)
    if failures:
        print(f"FAILED — {len(failures)} problem(s):")
        for f in failures:
            print(f"  * {f}")
        return 1
    print("PASSED — no claim outranked the conduct behind it.")
    print()
    print("This means the patterns tested here are resisted. It does not")
    print("establish that the metric resists gaming in general; add a case")
    print("here whenever a new pattern is found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
