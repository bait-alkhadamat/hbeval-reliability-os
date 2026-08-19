"""
test_provenance.py — where each fact came from
===============================================
    py tests/test_provenance.py

WHY PROVENANCE NEEDS ITS OWN TESTS
Signing a record proves it was not altered after it was written. It says
nothing about whether what was written is true — an agent that reports a
re-plan it never performed, signed by the SDK on its behalf, produces
tamper-evident falsehood.

The defence is not stronger cryptography. It is knowing, per field, whether a
value was observed, derived, or simply asserted. These tests hold that
distinction in place.

THE RULE UNDER TEST
The caller supplies facts; the SDK decides provenance. An agent-facing API
accepting source="runtime_observed" would let the party being measured award
itself the strongest evidence class, so no such parameter exists.
"""
from __future__ import annotations

import sys

from text_metrics import (EVIDENCE_SOURCES, evidence_mix, field_evidence,
                          FREEZE_REASON, FROZEN)


def main() -> int:
    failures = []

    print("=" * 70)
    print("EVIDENCE PROVENANCE")
    print("=" * 70)

    print("\nLevels:")
    live = {k: v for k, v in EVIDENCE_SOURCES.items()
            if not v.get("deprecated")}
    for name in sorted(live, key=lambda k: live[k]["rank"]):
        print(f"  {live[name]['rank']}  {name:<22} {live[name]['label']}")

    expected = ["agent_reported", "runtime_inferred",
                "runtime_observed", "externally_observed"]
    ordered = sorted(live, key=lambda k: live[k]["rank"])
    if ordered != expected:
        failures.append(f"levels out of order: {ordered}")

    # Source and strength are independent axes. A deterministic inference can
    # outrank a claim: three identical calls with identical arguments is
    # firmer ground for "retry" than an agent asserting it retried. Tying
    # strength to source would force the inference down to match its class.
    print("\nSource and strength are independent:")
    strong = field_evidence(3, "runtime_inferred", "high")
    weak = field_evidence(True, "agent_reported", "low")
    print(f"  runtime_inferred + high  -> strength={strong['strength']}")
    print(f"  agent_reported   + low   -> strength={weak['strength']}")
    if strong["strength"] != "high":
        failures.append("strength was overridden by source")

    print("\nInvalid input is refused, not coerced:")
    for bad in ("magic", "runtime_verified", ""):
        try:
            field_evidence(1, bad)
            failures.append(f"accepted unknown source {bad!r}")
            print(f"  {bad!r:<20} ACCEPTED — should have been refused")
        except ValueError:
            print(f"  {bad!r:<20} refused")
    try:
        field_evidence(1, "runtime_observed", "very_high")
        failures.append("accepted unknown strength")
    except ValueError:
        print(f"  {'strength=very_high':<20} refused")

    # A session routinely mixes an observed timeout, an inferred re-plan and a
    # reported intent. One session-level label either flatters the weakest
    # field or buries the strongest.
    print("\nA mixed session:")
    fields = {
        "tool_timeout": field_evidence(True, "runtime_observed", "high"),
        "retries": field_evidence(3, "runtime_observed", "high"),
        "plan_transition": field_evidence(True, "runtime_inferred", "high"),
        "recovered_intentionally": field_evidence(True, "agent_reported",
                                                  "low"),
    }
    mix = evidence_mix(fields)
    for src, share in sorted(mix["distribution"].items()):
        print(f"  {src:<24} {share:.0%}")
    print(f"  weakest: {mix['weakest']}")

    if mix["weakest"] != "agent_reported":
        failures.append(f"weakest should be agent_reported, got "
                        f"{mix['weakest']}")
    if abs(sum(mix["distribution"].values()) - 1.0) > 1e-9:
        failures.append("distribution does not sum to 1")

    clean = {
        "tool_timeout": field_evidence(True, "runtime_observed"),
        "retries": field_evidence(2, "runtime_observed"),
    }
    if evidence_mix(clean)["weakest"] != "runtime_observed":
        failures.append("a fully observed session was not reported as such")

    legacy = {"x": field_evidence(1, "externally_verified")}
    if evidence_mix(legacy)["weakest"] != "externally_observed":
        failures.append("legacy externally_verified did not map forward")
    print("\nLegacy externally_verified -> externally_observed: ok")

    # The freeze STATE is not asserted, only that it is stated and reasoned.
    #
    # An earlier version required FROZEN to be True, which was right during the
    # validation round and wrong the moment it ended. A test that must be
    # edited whenever the project moves is a test that will be edited
    # carelessly.
    #
    # What must always hold is that the flag carries a reason: a freeze without
    # one cannot be audited, and a lifted freeze without one cannot be told
    # apart from a forgotten one.
    print(f"\nScoring frozen: {FROZEN}")
    print(f"  reason: {FREEZE_REASON[:58]}...")
    if not FREEZE_REASON or len(FREEZE_REASON) < 20:
        failures.append("the freeze flag carries no stated reason")

    print()
    print("=" * 70)
    if failures:
        print(f"FAILED — {len(failures)}:")
        for f in failures:
            print(f"  * {f}")
        return 1

    print("Provenance holds.")
    print()
    print("This establishes that the labels are applied and enforced. It does")
    print("not establish that a runtime_observed fact is true — only that the")
    print("system distinguishes what it saw from what it was told.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
