"""
passport.py — the Agent Passport
=================================
A signed, verifiable record of how an agent has actually behaved.

WHAT IT IS
Every figure traces to a row in a table. Nothing is asserted, summarised into a
grade, or carried over from a claim made elsewhere:

    identity          agents
    five metrics      averaged across monitored sessions
    sessions          monitoring_sessions
    halt decisions    halt_audit_log, with the policy that caused each one
    alerts            webhook_deliveries, including the ones that failed
    overhead          measured p50/p99 per step
    battery spec      the fingerprint the runs were scored under

WHAT IT IS NOT
Not a certification. HB-Eval is not an accreditation body, performs no
third-party audit, and carries no liability for what an agent does. It records
observed behaviour and signs the record.

That is a smaller claim than certification, and it is one this system can
actually support — a verifiable record of what happened is worth more than an
unbacked assurance about what will. The word "certification" is absent
throughout, deliberately: it cost this project a desk rejection once already,
and re-earning that with a nicer noun would be the same mistake with better
branding.

NO SINGLE GRADE
There is no "HIGH RELIABILITY" banner. A passport reports five numbers and
names the weakest, because a single label is exactly where a weak dimension
goes to hide — the failure this system spent a release fixing in tier
assignment. An agent excellent at four dimensions and broken at the fifth is a
broken agent, and a summary word would say otherwise.

SIGNING
Ed25519, with the public key published at /api/v1/passport/key.

The point is not the algorithm — an HMAC would be cryptographically fine — but
WHO CAN CHECK. An HMAC keyed with a server-side secret proves authenticity only
to us, so every verifier has to ask us and take the answer on trust. A published
public key means an auditor, a regulator or a customer verifies the passport
themselves, offline, without our involvement or permission.

A record only we can validate rests on trusting us, which is precisely what a
passport exists to avoid needing.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger("hb-eval-gateway.passport")

PASSPORT_SCHEMA_VERSION = "1.1"
DEFAULT_WINDOW_DAYS = 90

# How long a passport stands before it should be reissued.
#
# It expires because BEHAVIOUR CHANGES. A model is swapped, a prompt is edited,
# an upstream dependency degrades — and a record of how an agent behaved in
# August says nothing certain about November. A document with no expiry invites
# exactly the misuse it should prevent: somebody attaching last year's passport
# to this year's agent.
#
# Ninety days matches the retention window, so a passport never outlives the
# step-level evidence behind it.
VALIDITY_DAYS = 90

# Evidence depth. NOT a quality rating, and named so it cannot be read as one.
#
# A metal-tier scale (bronze/silver/gold/platinum) was considered and rejected.
# It would carry the same fact — how much data stands behind these numbers —
# while being read by every human who sees it as a verdict on the agent. An
# agent with a thousand sessions and IRS at 0.31 would carry a "Platinum" badge
# into a board deck, and nobody would read the 0.31.
#
# That is the single-grade problem this document exists to avoid, returning
# through a side door — and worse, because an explicit grade gets argued with
# while a metal badge gets believed.
EVIDENCE_LEVELS = (
    (0, "insufficient", "Too little data for these figures to mean much."),
    (5, "preliminary", "Early evidence. Treat the figures as indicative."),
    (50, "established", "Enough runs for the figures to be reasonably stable."),
    (300, "extensive", "A large body of evidence across many runs."),
)

# Environment: base64 of the 32 raw private key bytes. Generated once and kept
# out of the database entirely — a signing key stored beside the data it signs
# lets anyone who reaches the data forge signatures over it.
ENV_PRIVATE_KEY = "PASSPORT_SIGNING_KEY"
# Identifies which key signed a passport, so rotation does not invalidate every
# record already issued.
ENV_KEY_ID = "PASSPORT_KEY_ID"

METRICS = ("pei", "frr", "irs", "ti", "csi")
METRIC_NAMES = {
    "pei": "Planning Efficiency",
    "frr": "Failure Resilience",
    "irs": "Intentional Recovery",
    "ti": "Traceability",
    "csi": "Consistency Stability",
}
# TI is 0-5; the rest are 0-1. Needed to compare "how far below par" across
# metrics on different scales when naming the weakest.
METRIC_MAX = {"pei": 1.0, "frr": 1.0, "irs": 1.0, "ti": 5.0, "csi": 1.0}


# -- Canonical form ----------------------------------------------------------
def _normalise_numbers(value):
    """Render whole floats as integers, recursively.

    THIS FUNCTION IS WHY CROSS-LANGUAGE VERIFICATION WORKS.

    Python serialises a float of 10.0 as "10.0"; JavaScript's JSON.stringify
    writes "10". Same number, different bytes — and a signature covers bytes.
    Without this, every genuine passport would be reported as altered by any
    browser-based verifier, which is the worst failure available: not a
    document that fails to verify, but a valid one that appears forged.

    Found by running the public page's own verification logic against a real
    signed passport before shipping it — not by reading both implementations
    and assuming they agreed.

    Normalising in the SIGNER rather than asking verifiers to compensate is
    deliberate: there is one signer and an unknown number of verifiers, and a
    canonical form that only works if every consumer applies a correction is
    not canonical.
    """
    if isinstance(value, bool):
        # Checked before the numeric branch: bool subclasses int in Python, so
        # True would otherwise become 1.
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else value
    if isinstance(value, dict):
        return {k: _normalise_numbers(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise_numbers(v) for v in value]
    return value


def canonical_bytes(passport: dict) -> bytes:
    """The exact bytes that get signed.

    Sorted keys, no whitespace, UTF-8, whole floats rendered as integers.
    Signer and every verifier must produce identical bytes from the same
    document, and JSON guarantees neither key order nor float formatting — so
    both are imposed here rather than hoped for.

    The signature block is excluded: a document cannot contain its own
    signature and still hash to the value that was signed.

    Verified in the other direction too: signed here, verified in a browser
    with the Web Crypto API.
    """
    body = {k: v for k, v in passport.items() if k != "signature"}
    return json.dumps(_normalise_numbers(body), sort_keys=True,
                      separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def content_hash(passport: dict) -> str:
    return hashlib.sha256(canonical_bytes(passport)).hexdigest()


# -- Keys --------------------------------------------------------------------
def _load_private_key():
    raw_b64 = os.environ.get(ENV_PRIVATE_KEY, "").strip()
    if not raw_b64:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        raw = base64.b64decode(raw_b64)
        if len(raw) != 32:
            logger.error(
                "%s must decode to 32 bytes, got %d. Passports will be issued "
                "unsigned.", ENV_PRIVATE_KEY, len(raw),
            )
            return None
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        logger.error("Could not load the passport signing key: %s", exc)
        return None


def public_key_info() -> dict:
    """The public key, for anyone who wants to verify a passport themselves.

    Served unauthenticated: a public key that requires permission to obtain
    defeats the purpose of publishing one.
    """
    key = _load_private_key()
    if key is None:
        return {
            "available": False,
            "reason": (
                f"{ENV_PRIVATE_KEY} is not set, so passports are issued "
                f"unsigned and cannot be verified."
            ),
        }
    from cryptography.hazmat.primitives import serialization
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "available": True,
        "algorithm": "Ed25519",
        "key_id": os.environ.get(ENV_KEY_ID, "default"),
        "public_key_b64": base64.b64encode(raw).decode(),
        "verify": {
            "canonicalisation": (
                "JSON with sorted keys, no whitespace, UTF-8, with the "
                "'signature' block removed"
            ),
            "steps": [
                "Remove the 'signature' object from the passport.",
                "Render whole numbers without a decimal point (10.0 -> 10).",
                "Serialise as JSON with sorted keys and no whitespace, UTF-8.",
                "Verify signature.value (base64) over those bytes.",
            ],
            "note": (
                "Step two matters: Python writes 10.0 where JavaScript writes "
                "10, and a signature covers bytes. JSON.stringify already "
                "produces the required form, so JavaScript verifiers need no "
                "special handling."
            ),
        },
    }


def sign_passport(passport: dict) -> dict:
    """Attach a signature, or record honestly that there is none.

    An unsigned passport is still a useful record — the numbers are real — but
    it cannot be verified by a third party, and saying so plainly beats
    shipping something that looks signed and is not.
    """
    key = _load_private_key()
    if key is None:
        passport["signature"] = {
            "signed": False,
            "reason": "No signing key is configured on this deployment.",
            "content_sha256": content_hash(passport),
        }
        return passport

    payload = canonical_bytes(passport)
    passport["signature"] = {
        "signed": True,
        "algorithm": "Ed25519",
        "key_id": os.environ.get(ENV_KEY_ID, "default"),
        "value": base64.b64encode(key.sign(payload)).decode(),
        "content_sha256": hashlib.sha256(payload).hexdigest(),
        "public_key_url": "/api/v1/passport/key",
    }
    return passport


def verify_passport(passport: dict, public_key_b64: str):
    """Verify a passport against a public key. Returns (valid, reason).

    Deliberately in the same module as the signer: a verifier written later
    from prose drifts from the signer, and the first symptom is valid passports
    being rejected.
    """
    sig = passport.get("signature") or {}
    if not sig.get("signed"):
        return False, "This passport was issued unsigned."
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_key_b64))
        key.verify(base64.b64decode(sig["value"]), canonical_bytes(passport))
        return True, "Signature is valid."
    except Exception:
        # No detail: distinguishing "wrong key" from "altered document" tells
        # someone probing which of the two to change.
        return False, "Signature does not match this document."


# -- Identity and comparability ----------------------------------------------
def passport_id(agent_id: str, issued_at: str, key_id: str) -> str:
    """A stable, human-quotable identifier for THIS passport.

    Derived rather than sequential, for two reasons. A counter leaks how many
    passports have ever been issued, which is commercially informative to
    anyone counting. And a derived id can be recomputed by a verifier from the
    document itself, so it cannot be swapped for another passport's id without
    the change being detectable.

    Format: HBP-YYYY-XXXXXXXXXXXX
    """
    year = (issued_at or "")[:4] or "0000"
    digest = hashlib.sha256(
        f"{agent_id}|{issued_at}|{key_id}".encode("utf-8")).hexdigest()
    return f"HBP-{year}-{digest[:12].upper()}"


def measurement_fingerprint(*, protocol_version: str,
                            battery_spec: Optional[str],
                            scoring_method: str = "heuristic_v2",
                            scoring_version: str = "v2") -> str:
    """Identifies HOW these figures were produced, not what they say.

    A fingerprint derived from metric VALUES would change on every session and
    identify nothing — it would be a hash of the weather.

    This hashes the measurement context instead: protocol, fault specification,
    metric set and scoring method. That makes it answer a question nobody can
    currently answer about agent evaluations — are these two results
    comparable? Same fingerprint means measured the same way. Different
    fingerprint means the numbers rest on different foundations and should not
    be placed side by side, however similar they look.
    """
    spec = {
        "protocol": protocol_version,
        "battery_spec": battery_spec,
        "metrics": list(METRICS),
        "metric_scales": METRIC_MAX,
        "scoring_method": scoring_method,
        # Included because the scoring DEFINITIONS changed, not just the code.
        # In v2, IRS widened from deliberate recovery to deliberate handling —
        # an agent that resists pressure or abstains now scores where it
        # previously scored zero. Two passports sharing a battery fingerprint
        # but differing in scoring version are still not comparable, and
        # without this field they would look identical.
        "scoring_version": scoring_version,
    }
    canonical = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16].upper()


def _metric_versions() -> dict:
    """Per-metric definition versions, read from the scorer that produced them.

    Imported lazily so passport issuing keeps working if the scorer is
    unavailable: a passport that cannot state its versions is worse than one
    that can, and far better than one that fails to issue at all.
    """
    try:
        from text_metrics import METRIC_VERSIONS
        return dict(METRIC_VERSIONS)
    except Exception:
        return {"schema": "unknown",
                "note": "Scoring module unavailable; metric versions could "
                        "not be read. Treat comparisons with caution."}


def session_evidence(sessions: list) -> dict:
    """Evidence provenance for the sessions in this window.

    WHY THIS EXISTS
    A passport was reporting E0 — "scored from response text alone" — for an
    agent whose sessions were fully instrumented. The battery path had learned
    to record provenance; the monitoring path had not, so the passport defaulted
    to the weakest class and understated its own evidence.

    That is the safe direction to be wrong in, but it is still wrong: an
    operator who instrumented their agent properly deserves a passport that
    says so.

    HOW THE LEVEL IS INFERRED
    Monitoring does not store the raw per-step fields; it stores the metrics
    computed from them. But a metric cannot be computed from a field that was
    never supplied, so a non-null metric IS evidence that its input arrived:

        frr_live present  ->  had_fault and success were recorded
        irs_live present  ->  recovery judgements were recorded
        ti_live present   ->  traceability was recorded
        pei_live present  ->  re-planning was recorded

    WHY runtime_observed AND NOT agent_reported
    These fields were recorded step by step as execution proceeded, and the
    session's own tallies constrain them — a caller cannot claim forty steps
    while recording four. That is weaker than independent observation and
    stronger than a trace assembled after the fact, which is exactly the middle
    class the provenance scheme was built to hold.
    """
    if not sessions:
        return {
            "level": "E0",
            "source": "none",
            "claims_reconciled": False,
            "note": "No sessions in this window.",
        }

    fields = ("pei_live", "frr_live", "irs_live", "ti_live")
    per_session = []
    for s in sessions:
        present = sum(1 for k in fields if s.get(k) is not None)
        per_session.append(present / len(fields))

    # The weakest session governs, for the same reason a battery reports its
    # weakest scenario: a window is only as well-evidenced as its thinnest run,
    # and an average would let well-instrumented sessions mask bare ones.
    weakest = min(per_session)
    mean = round(sum(per_session) / len(per_session), 3)

    if weakest >= 0.75:
        level = "E2"
    elif weakest > 0:
        level = "E1"
    else:
        level = "E0"

    note = {
        "E2": "Every session in this window recorded the behavioural fields "
              "the metrics are computed from, step by step during execution.",
        "E1": "Some sessions recorded fewer behavioural fields than others. "
              "The weakest governs, so parts of this window rest on less "
              "evidence than the rest.",
        "E0": "At least one session recorded no behavioural fields at all. "
              "The figures for it rest on what was reported rather than on "
              "what was observed of its conduct.",
    }[level]

    return {
        "level": level,
        "completeness": mean,
        "source": "runtime_observed" if level != "E0" else "none",
        "source_note": (
            "Recorded step by step during execution and constrained by the "
            "session's own tallies. Stronger than a trace assembled "
            "afterwards, weaker than independent observation — HB-Eval did not "
            "watch the agent run."
        ),
        "claims_reconciled": level != "E0",
        "sessions_evaluated": len(sessions),
        "note": note,
    }


def evidence_depth(sessions: int, steps: int) -> dict:
    """How much data stands behind the figures. Not a judgement of the agent.

    Keyed on sessions rather than steps: one very long run is not the same
    evidence as fifty short ones, because reliability is about behaviour across
    situations and a single session only ever saw one.
    """
    chosen = EVIDENCE_LEVELS[0]
    for threshold in EVIDENCE_LEVELS:
        if sessions >= threshold[0]:
            chosen = threshold
    return {
        "level": chosen[1],
        "meaning": chosen[2],
        "sessions": sessions,
        "steps": steps,
        "note": (
            "Evidence depth describes how much data supports the figures "
            "above. It is not a rating of the agent: an agent with extensive "
            "evidence of poor reliability has extensive evidence."
        ),
    }


# Labels the passport reads out of session metadata. Only these, and only
# strings: metadata is caller-supplied, and copying arbitrary keys into a
# signed document would let anyone have us sign text of their choosing.
PROVENANCE_KEYS = (
    "model", "model_version", "prompt_version", "framework",
    "framework_version", "sdk_version", "environment", "commit",
)

# What a reader is told when a label is absent, rather than leaving the field
# out. An absent field looks like an oversight; "not recorded" is a fact about
# the run, and it tells the reader what to ask the operator for.
NOT_RECORDED = "not recorded"


def _extract_provenance(sessions: list) -> dict:
    """What produced these numbers — model, prompt, framework, commit.

    WHY THIS IS A DEFECT FIX AND NOT A FEATURE

    A passport records how an agent behaved. Until now it did not record WHAT
    behaved. Swap the model and you have a different agent; edit the system
    prompt and you may have a different agent. The old passport described
    neither, so a document could outlive the thing it described and nobody
    reading it could tell.

    That makes a passport without provenance a record about nothing in
    particular — the numbers are real, but they are not attached to anything a
    reader can identify or reproduce.

    CHANGES ARE REPORTED, NOT COLLAPSED

    If sessions in the window ran under two different models, both are listed.
    Showing only the most recent would hide the most important fact in the
    document: that the figures average across a change, and the earlier half
    describes a system that no longer exists.
    """
    seen: dict = {k: [] for k in PROVENANCE_KEYS}

    for s in sessions:
        meta = s.get("metadata")
        if not isinstance(meta, dict):
            continue
        for key in PROVENANCE_KEYS:
            value = meta.get(key)
            if value is None:
                continue
            # Strings only, and bounded. This lands inside signed bytes.
            text = str(value)[:120]
            if text and text not in seen[key]:
                seen[key].append(text)

    out: dict = {}
    changed = []
    for key in PROVENANCE_KEYS:
        values = seen[key][:5]
        if not values:
            out[key] = None
        elif len(values) == 1:
            out[key] = values[0]
        else:
            out[key] = values
            changed.append(key)

    out["changed_during_window"] = changed
    out["note"] = (
        "Read from session metadata supplied by the SDK caller. HB-Eval cannot "
        "observe which model or prompt an agent used — it records what the "
        "caller labelled. Fields showing null were never labelled, and a "
        "passport with no provenance describes behaviour without identifying "
        "what behaved."
        if any(out[k] for k in PROVENANCE_KEYS) else
        "No provenance was recorded. Pass model, prompt_version and framework "
        "as session metadata so a passport identifies what produced these "
        "numbers; without them the figures describe an unnamed system."
    )
    if changed:
        out["warning"] = (
            "These figures average across a change in "
            + ", ".join(changed)
            + ". Sessions before and after the change describe different "
              "systems, and comparing them as one agent is a mistake."
        )
    return out


def _bucket_timeline(sessions: list, now: datetime) -> list:
    """Metric averages over 30, 60 and 90 days.

    Reported because a trajectory carries information a snapshot cannot. An
    agent at FRR 0.6 having fallen from 0.9 is a different proposition from one
    that climbed there from 0.3 — the same figure, opposite conclusions — and a
    passport showing only the current value would hide which it was.

    Windows are cumulative from today, so a reader compares like with like
    rather than reconstructing periods from raw dates.
    """
    out = []
    for days in (30, 60, 90):
        cutoff = now - timedelta(days=days)
        in_window = []
        for s in sessions:
            raw = s.get("started_at")
            if raw is None:
                continue
            try:
                # started_at arrives as epoch seconds from the SDK and as a
                # timestamp from some paths; both are accepted rather than
                # assuming one and silently dropping the other.
                when = (datetime.fromtimestamp(float(raw), tz=timezone.utc)
                        if isinstance(raw, (int, float))
                        else datetime.fromisoformat(
                            str(raw).replace("Z", "+00:00")))
            except (ValueError, TypeError, OSError):
                continue
            if when >= cutoff:
                in_window.append(s)

        out.append({
            "window_days": days,
            "sessions": len(in_window),
            "metrics": {
                m: _avg([s.get(f"{m}_live") for s in in_window])
                for m in METRICS
            },
        })
    return out


# -- Assembly ----------------------------------------------------------------
def _avg(values: list):
    """Mean of the defined values, or None if none were defined.

    Undefined is skipped, never counted as zero. Averaging a null into a mean
    would report a measured failure on a dimension nothing examined — the rule
    that governs every layer of this system.
    """
    present = [v for v in values if v is not None]
    return round(sum(present) / len(present), 4) if present else None


def _weakest(metrics: dict):
    """The metric furthest below its ceiling, as a fraction of that ceiling.

    Named rather than folded into a grade. A single label is where a weak
    dimension hides, and an agent excellent at four and broken at the fifth is
    a broken agent.
    """
    scored = [
        (k, v / METRIC_MAX[k]) for k, v in metrics.items()
        if v is not None and k in METRIC_MAX
    ]
    if not scored:
        return None
    key, normalised = min(scored, key=lambda kv: kv[1])
    return {
        "metric": key,
        "name": METRIC_NAMES[key],
        "value": metrics[key],
        "of_maximum": round(normalised, 4),
    }


async def build_passport(
    supabase: Any, to_thread: Any, *,
    agent_id: str, user_id: str,
    window_days: int = DEFAULT_WINDOW_DAYS,
    battery_fingerprint: Optional[str] = None,
    protocol_version: str = "",
    evidence_provenance: Optional[dict] = None,
) -> dict:
    """Assemble a passport from stored records.

    Every section degrades to empty rather than failing: an agent with no
    monitoring history still gets a passport that says so. A passport that
    refuses to exist until an agent is interesting is useless precisely when
    somebody is deciding whether to adopt one.
    """
    since = datetime.now(timezone.utc) - timedelta(days=window_days)

    def _query(table: str, select: str, filters: list,
               order: tuple = None, limit: int = None):
        def _run():
            q = supabase.table(table).select(select)
            for col, val in filters:
                q = q.eq(col, val)
            if order:
                q = q.order(order[0], desc=order[1])
            if limit:
                q = q.limit(limit)
            return q.execute()
        return _run

    # -- Identity --
    try:
        res = await to_thread(_query(
            "agents", "agent_id, name, created_at, plan_type, is_active",
            [("agent_id", agent_id), ("user_id", user_id)], limit=1))
        rows = res.data or []
        if not rows:
            raise PermissionError("No such agent on this account.")
        a = rows[0]
        identity = {
            "agent_id": a.get("agent_id"),
            "name": a.get("name"),
            "created_at": a.get("created_at"),
            "plan": a.get("plan_type"),
            "active": a.get("is_active"),
        }
    except PermissionError:
        raise
    except Exception as exc:
        logger.error("Passport identity lookup failed: %s", exc)
        raise PermissionError("Could not load this agent.")

    # -- Sessions --
    sessions: list = []
    try:
        res = await to_thread(_query(
            "monitoring_sessions",
            "session_id, started_at, duration_seconds, step_count, "
            "breach_count, halted, pei_live, frr_live, irs_live, ti_live, "
            "csi_live, overhead_p50_ms, overhead_p99_ms, metadata",
            [("agent_id", agent_id), ("user_id", user_id)],
            order=("created_at", True), limit=500))
        sessions = res.data or []
    except Exception as exc:
        logger.debug("Passport session lookup failed: %s", exc)

    metrics = {m: _avg([s.get(f"{m}_live") for s in sessions]) for m in METRICS}
    total_steps = sum(int(s.get("step_count") or 0) for s in sessions)
    total_seconds = sum(int(s.get("duration_seconds") or 0) for s in sessions)
    halted_sessions = sum(1 for s in sessions if s.get("halted"))

    # -- Halt decisions --
    halts: list = []
    try:
        res = await to_thread(_query(
            "halt_audit_log",
            "session_id, metric, metric_value, threshold, consecutive_steps, "
            "step_index, policy, reason, trigger_source, occurred_at",
            [("agent_id", agent_id), ("user_id", user_id)],
            order=("occurred_at", True), limit=100))
        halts = res.data or []
    except Exception as exc:
        logger.debug("Passport halt lookup failed: %s", exc)

    # -- Alerts --
    alerts_total = alerts_delivered = 0
    try:
        res = await to_thread(_query(
            "webhook_deliveries", "delivered, event_type",
            [("agent_id", agent_id), ("user_id", user_id)], limit=1000))
        rows = res.data or []
        alerts_total = len(rows)
        alerts_delivered = sum(1 for r in rows if r.get("delivered"))
    except Exception as exc:
        logger.debug("Passport alert lookup failed: %s", exc)

    now = datetime.now(timezone.utc)
    issued_at = now.isoformat()
    key_id = os.environ.get(ENV_KEY_ID, "default")

    passport = {
        "schema_version": PASSPORT_SCHEMA_VERSION,

        # Quotable in an email, a slide or an audit response without pasting
        # the whole document.
        "passport_id": passport_id(agent_id, issued_at, key_id),

        "issued_at": issued_at,
        # Expires because behaviour changes. A record with no end date invites
        # exactly the misuse it should prevent — last year's passport attached
        # to this year's agent.
        "expires_at": (now + timedelta(days=VALIDITY_DAYS)).isoformat(),
        "validity_days": VALIDITY_DAYS,

        "window": {"days": window_days, "since": since.isoformat()},
        "issuer": {
            "name": "HB-Eval",
            "url": "https://hbeval.com",
            "protocol_version": protocol_version,
            # Says what this document is, inside the document, so it cannot be
            # separated from its own disclaimer.
            # "Issued by", never "Verified by". HB-Eval recorded what
            # happened and signed the record; it did not audit the agent.
            # "Verified" would imply third-party assurance — the same claim as
            # "certification" wearing a different word.
            "issued_by": "HB-Eval",
            "statement": (
                "This is a record of observed behaviour, signed by HB-Eval. "
                "It is not a certification: HB-Eval is not an accreditation "
                "body, performs no third-party audit, and makes no warranty "
                "about future behaviour."
            ),
        },

        "identity": identity,

        "reliability": {
            "metrics": metrics,
            "metric_names": METRIC_NAMES,
            # Absence is stated, not inferred from a missing key.
            "undefined": [m for m in METRICS if metrics[m] is None],
            "weakest": _weakest(metrics),

            # How much data stands behind the figures. Deliberately worded so
            # it cannot be read as a verdict on the agent — see EVIDENCE_LEVELS
            # for why a metal-tier scale was rejected.
            "evidence": evidence_depth(len(sessions), total_steps),

            # The trajectory, not just the endpoint. Falling to 0.6 from 0.9 is
            # a different proposition from climbing there from 0.3, and a
            # single figure cannot tell a reader which happened.
            "timeline": _bucket_timeline(sessions, now),

            "note": (
                "Averages across monitored sessions in the window. An "
                "undefined metric was never measured — CSI needs repeated "
                "runs, IRS needs an observed fault — and is reported as "
                "undefined rather than as zero. No overall grade is given: "
                "the weakest dimension is named instead, because a single "
                "label is where a weak dimension hides."
            ),
        },

        "operational_record": {
            "sessions": len(sessions),
            "steps_executed": total_steps,
            "runtime_seconds": total_seconds,
            "runtime_hours": round(total_seconds / 3600, 2) if total_seconds else 0,
            "sessions_halted": halted_sessions,
            "total_breaches": sum(int(s.get("breach_count") or 0) for s in sessions),
        },

        "safety_record": {
            "halt_decisions": len(halts),
            # The full decision, not a count. A halt that cannot be explained
            # is a halt nobody will leave enabled.
            "halts": [
                {
                    "session_id": h.get("session_id"),
                    "metric": h.get("metric"),
                    "value": h.get("metric_value"),
                    "threshold": h.get("threshold"),
                    "consecutive_steps": h.get("consecutive_steps"),
                    "policy": h.get("policy"),
                    "reason": h.get("reason"),
                    "triggered_by": h.get("trigger_source"),
                    "at": h.get("occurred_at"),
                }
                for h in halts[:25]
            ],
            "alerts_raised": alerts_total,
            # Failures are counted too. An alerting record that hides
            # undelivered alerts is worse than none, because the silence reads
            # as "nothing happened".
            "alerts_delivered": alerts_delivered,
            "alerts_failed": alerts_total - alerts_delivered,
        },

        # What produced these numbers. A passport that records behaviour
        # without recording what behaved is a record about nothing in
        # particular.
        "provenance": _extract_provenance(sessions),

        "measurement": {
            # Identifies HOW these figures were produced. Two passports with
            # the same fingerprint were measured the same way and can be
            # compared; two with different fingerprints cannot, however similar
            # the numbers look.
            "fingerprint": measurement_fingerprint(
                protocol_version=protocol_version,
                battery_spec=battery_fingerprint,
            ),
            # METRIC VERSIONING
            #
            # A passport read two years from now must say which definition of
            # each metric produced its figures. IRS changed meaning in v2 —
            # from deliberate recovery to deliberate handling — so the same
            # name denotes different quantities either side of that line, and a
            # passport that recorded only the name would be unreadable later.
            # Read from the scorer rather than restated here. Two copies of a
            # version table drift, and the copy in the passport is the one
            # somebody will still be reading in two years - it must not be the
            # stale one.
            "metric_versions": _metric_versions(),
            # PROVENANCE OF THE EVIDENCE
            #
            # Two identical scores are not equally trustworthy when one was
            # reconciled against a behavioural trace and the other inferred
            # from prose. Recorded so a reader can weigh them differently.
            #
            #   E0  response text only, no claim checked against conduct
            #   E1  partial trace, some claims checkable
            #   E2  complete trace, every claim testable
            "evidence": evidence_provenance or session_evidence(sessions) or {
                "level": "E0",
                "source": "response_text",
                "claims_reconciled": False,
                "note": "No behavioural evidence recorded for the sessions in "
                        "this window. The figures rest on what the agent "
                        "reported, not on what was observed of its conduct.",
            },
            "battery_spec_fingerprint": battery_fingerprint,
            "monitoring_overhead_p50_ms": _avg(
                [s.get("overhead_p50_ms") for s in sessions]),
            "monitoring_overhead_p99_ms": _avg(
                [s.get("overhead_p99_ms") for s in sessions]),
            "note": (
                "The fingerprint identifies the fault specification these "
                "results were produced under. Two passports with different "
                "fingerprints were not measured against the same battery and "
                "are not directly comparable."
            ),
        },
    }

    return sign_passport(passport)
