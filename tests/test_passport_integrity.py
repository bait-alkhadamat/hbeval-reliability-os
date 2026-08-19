"""
test_passport_integrity.py — what a signature does and does not protect
=======================================================================
    py tests/test_passport_integrity.py

WHY THIS EXISTS AS A TEST AND NOT A PARAGRAPH
A passport is the one artefact HB-Eval hands to somebody who was not present
and cannot re-run anything. Its value rests entirely on a third party being
able to check it, so every property the book claims for it has to be
demonstrable rather than described.

Each case below corresponds to a claim made in Part VII. If a case fails, the
claim is wrong and the text must change — not the other way round.

WHAT THESE TESTS DO NOT ESTABLISH
That the figures inside a valid passport are correct, that the agent still
behaves as recorded, or that the model named in the provenance block is the
model that ran. A signature covers integrity and issuer, and nothing else.
"""
from __future__ import annotations

import base64
import copy
import json
import os
import sys
from datetime import datetime, timedelta, timezone


def _install_key():
    """A throwaway signing key, so the test never touches production material."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    from cryptography.hazmat.primitives import serialization as ser

    key = Ed25519PrivateKey.generate()
    os.environ["PASSPORT_SIGNING_KEY"] = base64.b64encode(
        key.private_bytes(encoding=ser.Encoding.Raw,
                          format=ser.PrivateFormat.Raw,
                          encryption_algorithm=ser.NoEncryption())).decode()
    os.environ["PASSPORT_KEY_ID"] = "test-1"


_install_key()

import passport as P   # noqa: E402  — imported after the key is in the env


def base_passport(**overrides) -> dict:
    now = datetime.now(timezone.utc)
    doc = {
        "schema_version": "1.1",
        "passport_id": "HBP-2026-TESTTESTTEST",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=90)).isoformat(),
        "identity": {"agent_id": "agent-test", "name": "Test"},
        "reliability": {
            "metrics": {"pei": 1.0, "frr": 0.5, "irs": 1.0,
                        "ti": 5.0, "csi": None},
            "weakest": {"metric": "frr", "name": "Failure Resilience",
                        "value": 0.5},
            "undefined": ["csi"],
        },
        "operational_record": {"sessions": 6, "steps_executed": 23},
        "measurement": {"fingerprint": "TESTFINGERPRINT0",
                        "metric_versions": {"pei": "2.0", "irs": "2.0"}},
    }
    doc.update(overrides)
    return P.sign_passport(doc)


def main() -> int:
    failures = []
    pub = P.public_key_info()["public_key_b64"]

    print("=" * 72)
    print("PASSPORT INTEGRITY")
    print("=" * 72)

    # ── A valid passport verifies ──────────────────────────────────────
    good = base_passport()
    ok, reason = P.verify_passport(good, pub)
    print(f"\n  {'untouched':<34}{'valid' if ok else 'INVALID'}")
    if not ok:
        failures.append(f"a freshly signed passport did not verify: {reason}")

    # ── Mutations: every one must be caught ────────────────────────────
    #
    # These are the specific edits somebody would make to improve a passport
    # they were handed. Each must break the signature.
    print("\n  Mutations — each must be rejected:")

    mutations = [
        ("raise a metric",
         lambda d: d["reliability"]["metrics"].__setitem__("frr", 0.99)),
        ("add a metric that was undefined",
         lambda d: d["reliability"]["metrics"].__setitem__("csi", 0.95)),
        ("remove the undefined list",
         lambda d: d["reliability"].pop("undefined")),
        ("rename the weakest metric",
         lambda d: d["reliability"]["weakest"].__setitem__("value", 0.95)),
        ("change the agent identity",
         lambda d: d["identity"].__setitem__("agent_id", "agent-someone-else")),
        ("inflate the session count",
         lambda d: d["operational_record"].__setitem__("sessions", 600)),
        ("swap the measurement fingerprint",
         lambda d: d["measurement"].__setitem__("fingerprint", "OTHERPRINT00")),
        ("downgrade a metric version",
         lambda d: d["measurement"]["metric_versions"].__setitem__("pei", "1.0")),
        ("extend the expiry",
         lambda d: d.__setitem__("expires_at", "2099-01-01T00:00:00+00:00")),
    ]

    for label, mutate in mutations:
        doc = copy.deepcopy(good)
        mutate(doc)
        ok, _ = P.verify_passport(doc, pub)
        caught = not ok
        print(f"    {label:<32}{'caught' if caught else 'MISSED'}")
        if not caught:
            failures.append(f"mutation not caught: {label}")

    # ── Expiry is enforced, not merely recorded ────────────────────────
    print("\n  Expiry:")
    past = datetime.now(timezone.utc) - timedelta(days=1)
    expired = base_passport(expires_at=past.isoformat())
    ok, reason = P.verify_passport(expired, pub)
    print(f"    {'expired passport':<32}{'rejected' if not ok else 'ACCEPTED'}")
    if ok:
        failures.append("an expired passport verified as valid")
    elif "expired" not in reason.lower():
        failures.append(f"expiry rejection did not say why: {reason}")
    else:
        # The reason must distinguish stale from forged. An operator told
        # only "invalid" would look for tampering that did not happen.
        print(f"      reason mentions expiry, not forgery: ok")

    # ── A wrong key rejects ────────────────────────────────────────────
    print("\n  Wrong key:")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    from cryptography.hazmat.primitives import serialization as ser
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=ser.Encoding.Raw, format=ser.PublicFormat.Raw)
    ok, _ = P.verify_passport(good, base64.b64encode(other).decode())
    print(f"    {'verified against another key':<32}"
          f"{'rejected' if not ok else 'ACCEPTED'}")
    if ok:
        failures.append("a passport verified against the wrong public key")

    # ── An unsigned passport says so ───────────────────────────────────
    print("\n  Unsigned:")
    unsigned = copy.deepcopy(good)
    unsigned["signature"] = {"signed": False, "reason": "no key configured"}
    ok, reason = P.verify_passport(unsigned, pub)
    print(f"    {'signature.signed = false':<32}"
          f"{'rejected' if not ok else 'ACCEPTED'}")
    if ok:
        failures.append("an unsigned passport verified as valid")

    # ── Canonical bytes are stable across key order ────────────────────
    #
    # JSON guarantees neither key order nor float formatting. If the signer and
    # a verifier disagree on either, valid passports are reported as forged —
    # which is the worst failure mode available, because it discredits genuine
    # documents.
    print("\n  Canonical form:")
    reordered = json.loads(json.dumps(good))
    reordered = {k: reordered[k] for k in reversed(list(reordered))}
    same = P.canonical_bytes(good) == P.canonical_bytes(reordered)
    print(f"    {'key order does not change bytes':<32}"
          f"{'stable' if same else 'UNSTABLE'}")
    if not same:
        failures.append("canonical bytes depend on key order")

    ok, _ = P.verify_passport(reordered, pub)
    print(f"    {'reordered passport still valid':<32}"
          f"{'valid' if ok else 'INVALID'}")
    if not ok:
        failures.append("a reordered but unaltered passport failed to verify")

    # ── The signature block is excluded from what is signed ────────────
    body_keys = set(json.loads(P.canonical_bytes(good)).keys())
    print(f"\n  Signature block excluded from signed bytes: "
          f"{'yes' if 'signature' not in body_keys else 'NO'}")
    if "signature" in body_keys:
        failures.append("the signature block is inside its own signed bytes")

    print()
    print("=" * 72)
    if failures:
        print(f"FAILED — {len(failures)}:")
        for f in failures:
            print(f"  * {f}")
        return 1

    print("Integrity holds.")
    print()
    print("This establishes that the document cannot be altered without")
    print("detection, and that it was issued by the holder of the signing key.")
    print("It establishes nothing about whether the figures inside are a good")
    print("description of the agent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
