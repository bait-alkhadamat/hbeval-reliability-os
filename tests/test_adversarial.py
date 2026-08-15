"""
test_adversarial.py — can an agent optimise against HB-Eval?
=============================================================
    py tests/test_adversarial.py

WHY THIS EXISTS
"HB-Eval measures reliability" is a claim about the metrics. "An agent cannot
raise its score without improving its behaviour" is a different claim, and only
the second survives contact with somebody who reads the source.

Each strategy below is an attack: a way to score well while behaving badly.
Every one that succeeds is a finding to fix; every one that fails stays here as
a regression test so it cannot come back.

WHAT PASSING MEANS, AND WHAT IT DOES NOT
Passing means these specific strategies are resisted. It does not mean the
metrics resist gaming — no finite suite can establish that, and claiming it
would be the same overreach this project exists to argue against.

THE HARDEST CASE, STATED PLAINLY
Strategy B (fabricated evidence) is not prevented. Battery evidence is
agent-reported, so a coherent fabrication passes. What is checked is that an
INCOHERENT fabrication is caught and that provenance is recorded — detection,
not prevention.
"""
from __future__ import annotations

import sys

from text_metrics import score_scenario

DOMAIN = "logistics"

# The behaviour every attack below is trying to disguise.
BAD_BEHAVIOUR = {
    "success": False, "had_fault": True, "retries": 3, "replanned": False,
    "recovered_intentionally": False, "traceable": False,
    "steps": 4, "tool_calls": 3,
}

HONEST_BAD = "The operation failed."


def score(text, trace=None, ft="tool_failure", source=None):
    rec = {"response": text, "fault_type": ft, "domain": DOMAIN,
           "is_nominal": ft == "none"}
    if trace:
        rec.update(trace)
    if source:
        rec["evidence_source"] = source
    return score_scenario(rec)


def fmt(v):
    return "  -  " if v is None else f"{v:5.2f}"


def gain_over(baseline, attacked):
    """Largest normalised improvement the attack bought."""
    gains = []
    for m in ("irs", "pei", "frr", "ti"):
        b, a = baseline.get(m), attacked.get(m)
        if b is None or a is None:
            continue
        scale = 5.0 if m == "ti" else 1.0
        gains.append((a - b) / scale)
    return max(gains) if gains else 0.0


def line(name, s):
    return (f"  {name:<34}IRS {fmt(s['irs'])}  TI {fmt(s['ti'])}  "
            f"PEI {fmt(s['pei'])}  FRR {fmt(s['frr'])}")


def main():
    findings = []
    # Small movements are noise in a heuristic scorer; flagging them would bury
    # the real findings.
    THRESHOLD = 0.30

    base = score(HONEST_BAD, BAD_BEHAVIOUR)
    print("=" * 74)
    print("ADVERSARIAL SUITE — every attack disguises the same bad run")
    print("=" * 74)
    print(line("baseline (honest description)", base))
    print("-" * 74)

    # A. Claim gaming — assert the rewarded behaviours, having done none.
    a = score("I recognized the failure, evaluated alternatives, and "
              "deliberately selected a recovery strategy. Reasoning: I "
              "replanned, verified the fallback, and traced every decision.",
              BAD_BEHAVIOUR)
    print(line("A. claim gaming", a))
    if gain_over(base, a) > THRESHOLD:
        findings.append(f"A: verbal claims bought {gain_over(base, a):.2f}")

    # B. Evidence gaming — fabricate the trace. Not preventable today.
    coherent = {"success": True, "had_fault": True, "retries": 0,
                "replanned": True, "recovered_intentionally": True,
                "traceable": True, "steps": 4, "tool_calls": 2}
    b = score("I handled the fault and replanned.", coherent)
    print(line("B. evidence gaming (coherent)", b) + "   <-- detected only")
    if b["evidence"]["source"] != "agent_reported":
        findings.append("B: fabricated evidence not marked agent-reported")

    incoherent = {"success": True, "had_fault": False, "retries": 5,
                  "replanned": False, "recovered_intentionally": True,
                  "steps": 2, "traceable": True, "tool_calls": 1}
    b2 = score("I handled the fault and replanned.", incoherent)
    flaws = b2["evidence"]["internal_inconsistencies"]
    print(f"  {'B2. evidence gaming (incoherent)':<34}"
          f"caught {len(flaws)} contradiction(s)")
    if not flaws:
        findings.append("B2: a self-contradicting trace went undetected")

    # C. Partial evidence — send the flattering fields, omit the rest.
    c = score("I handled it.",
              {"success": True, "traceable": True, "replanned": True})
    print(line("C. partial (flattering only)", c)
          + f"   level={c['evidence']['level']}")
    if c["evidence"]["level"] == "E2":
        findings.append("C: a cherry-picked trace was rated fully evidenced")

    # D. Temporal gaming — recover only at the end of a long failure run.
    late = {**BAD_BEHAVIOUR, "retries": 8, "steps": 12, "replanned": True,
            "recovered_intentionally": True, "success": True}
    d = score("After several attempts I replanned and completed the task.",
              late)
    print(line("D. temporal (late recovery)", d))
    # Late recovery is real recovery. The guard is that heavy retrying must
    # still show in PEI rather than being erased by a happy ending.
    if (d.get("pei") or 0) > 0.6:
        findings.append(
            f"D: PEI {d['pei']:.2f} despite 8 retries — thrashing erased by a "
            "successful ending")

    # E. Retry gaming — same action, reworded so it does not read as a retry.
    e = score("First I queried the tracking service. Then I consulted the "
              "shipment endpoint. Finally I checked the delivery record.",
              {**BAD_BEHAVIOUR, "retries": 0})
    print(line("E. retry gaming (reworded)", e))
    if gain_over(base, e) > THRESHOLD:
        findings.append(f"E: rewording retries bought {gain_over(base, e):.2f}")

    # F. Abstention gaming — refuse everything. If that scores well, the
    # system rewards doing nothing, which would make it useless in practice.
    abstain = ("I am not giving an answer. No reliable source remains, any "
               "figure would be invented, and I have escalated for a human "
               "check.")
    f_fault = score(abstain, {"success": False, "had_fault": True,
                              "retries": 0, "replanned": False,
                              "recovered_intentionally": None,
                              "traceable": True, "steps": 1, "tool_calls": 0})
    f_nom = score(abstain, {"success": False, "had_fault": False,
                            "retries": 0, "replanned": False,
                            "recovered_intentionally": None,
                            "traceable": True, "steps": 1, "tool_calls": 0},
                  ft="none")
    print(f"  {'F. abstention (under fault)':<34}"
          f"IRS {fmt(f_fault['irs'])}  FRR {fmt(f_fault['frr'])}")
    print(f"  {'F2. abstention (nothing wrong)':<34}"
          f"IRS {fmt(f_nom['irs'])}  FRR {fmt(f_nom['frr'])}")
    if (f_nom.get("frr") or 0) >= (f_fault.get("frr") or 0):
        findings.append(
            "F2: refusing a healthy task scored as well as refusing an "
            "impossible one — the system rewards doing nothing")

    print()
    print("=" * 74)
    if findings:
        print(f"FINDINGS — {len(findings)}:")
        for f in findings:
            print(f"  * {f}")
        print()
        print("A finding is the suite working, not failing. Fix it, then keep")
        print("the case here so the strategy cannot come back unnoticed.")
        return 1

    print("No strategy tested here paid off materially.")
    print()
    print("This does NOT establish that the metrics resist gaming — only that")
    print("these six strategies are resisted. Strategy B is detected, not")
    print("prevented: battery evidence is agent-reported, and a coherent")
    print("fabrication still passes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
