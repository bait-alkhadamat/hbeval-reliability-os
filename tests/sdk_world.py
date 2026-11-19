"""Builds an ACTIVE enrolment for tests, from the SDK's public API only (no SDK test files).

The two baselines are committed fixtures (tests/fixtures/*.json), sealed artefacts of the frozen battery;
ReliabilityBaseline.from_dict re-verifies their hashes on load.
"""
import json, os
from hb_eval_sdk.attestation import attest
from hb_eval_sdk.baseline import ReliabilityBaseline
from hb_eval_sdk.context_assessment import INVALIDATING_FIELDS, NON_INVALIDATING_FIELDS, assess_context
from hb_eval_sdk.enrollment import EnrollmentPolicy, activate, approve_enrollment, new_enrollment, request_enrollment
from hb_eval_sdk.lineage import EvidenceAttribution, EvidenceLineage
from hb_eval_sdk.policy_document import policy_document_from_slo
from hb_eval_sdk.readiness_passport import ScopeLevel, issue_readiness_passport
from hb_eval_sdk.reliability_decision import SLOCondition, SLOPolicy, decide
from hb_eval_sdk.reliability_diff import diff_baselines
from hb_eval_sdk.topology import Participant, ParticipantKind, Relation, RelationKind, SystemTopology

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return ReliabilityBaseline.from_dict(json.load(fh))


def build():
    ref, cand = _load("ref.json"), _load("cand.json")
    slo = SLOPolicy("org-v1", (SLOCondition("frr", "gte", 0.8),))
    attestation = attest(decide(diff_baselines(ref, cand), slo), cand)
    policy = policy_document_from_slo(slo)
    system = Participant(ParticipantKind.SYSTEM, "sys", system_id="sys-1")
    a = Participant(ParticipantKind.AGENT, "planner", system_id="sys-1", agent_id="A", agent_instance_id="A#1")
    b = Participant(ParticipantKind.SUB_AGENT, "booker", system_id="sys-1", agent_id="B", agent_instance_id="B#7")
    tool = Participant(ParticipantKind.TOOL, "payments", system_id="sys-1")
    d = Relation(RelationKind.DELEGATED_TO, a.participant_id, b.participant_id, delegation_id="dlg-1", execution_id="EX-1")
    u = Relation(RelationKind.USES_TOOL, b.participant_id, tool.participant_id, execution_id="EX-1")
    topo = SystemTopology("sys-1", (system, a, b, tool), (d, u))
    lineage = EvidenceLineage(topo, (EvidenceAttribution("STEP:1", a.participant_id, "A#1", "EX-1", relation_ids=(d.relation_id,)),))
    ctx = assess_context(attestation, {f: getattr(attestation, f) for f in INVALIDATING_FIELDS + NON_INVALIDATING_FIELDS})
    passport = issue_readiness_passport(attestation=attestation, subject_baseline=cand, policy_document=policy, topology=topo,
                                        lineage=lineage, subject_participant_id=a.participant_id, scope_level=ScopeLevel.AGENT,
                                        context_assessment=ctx)
    pol = EnrollmentPolicy("enr-v1", accepted_policy_ids=(passport.policy_id,), max_passport_age_seconds=10**9)
    t0 = attestation.produced_at
    e = new_enrollment(pol, system_id=passport.system_id, subject_participant_id=passport.subject_participant_id,
                       configuration_fingerprint=passport.configuration_fingerprint)
    e = request_enrollment(e, passport, now=t0 + 0.001)
    e = approve_enrollment(e, passport=passport, enrollment_policy=pol, attestation=attestation, policy_document=policy,
                           topology=topo, lineage=lineage, now=t0 + 0.002, context_assessment=ctx)
    e = activate(e, enrollment_policy=pol, now=t0 + 0.003)
    # Real wall-clock time must be later than the last ledger entry, or the Gateway (which derives evidence
    # "as of now") would refuse to describe a future it has not seen.
    import time; time.sleep(0.05)
    return dict(enrollment=e, passport=passport, policy=pol, topology=topo, booker=b, planner=a, t0=t0)
