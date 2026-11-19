"""
enforcement_api.py — R11-C: the Gateway's enforcement surface
WHY THIS FILE EXISTS
    R11-A measured it: no V2 domain object appears anywhere in either
    platform repository, and the Gateway does not depend on hb-eval-sdk at
    all. So the platform cannot consume a single V2 contract.
    This module is the first place the Gateway reaches into the SDK. It is
    deliberately the ENFORCE surface, because Enforce is the only required
    product surface with nothing behind it, and because proving it end to end
    forces the whole chain:
        UI -> Platform API -> Gateway -> SDK contract -> boundary
           -> EnforcementEvent -> persistence -> operational evidence -> UI
THE RULE THIS MODULE IS BUILT AROUND
    NO DECISION LOGIC LIVES HERE.
    Every allow/deny/halt outcome comes from `hb_eval_sdk.enforcement
    .decide_enforcement`. This module transports, authenticates and records.
    If a threshold, a comparison or a policy rule ever appears below, the
    platform has grown a second reliability model — the exact failure R11
    exists to prevent — and `test_no_local_decision_logic` fails.
WHAT IS DELIBERATELY NOT HERE
    Persistence. Enrollment ledgers, topologies and operational logs must be
    loaded from somewhere, and the platform schema is not in version control
    (DW-035), so R11-B is blocked. The dependency is expressed as a
    PROTOCOL — `EnforcementStateProvider` — with an in-memory implementation
    for tests. The database-backed implementation is R11-C.4 and waits on
    R11-B.
    The enforcement MECHANISM. The Gateway decides; it does not block. A
    boundary outside the agent's process does that (R8), and its result is
    submitted back here.
"""
from __future__ import annotations
from typing import Any, Optional, Protocol
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from hb_eval_sdk.enforcement import (ActionKind, EnforcementError,
                                     EnforcementPolicy, EnforcementRequest,
                                     EnforcementResult, Mechanism,
                                     decide_enforcement, record_result)
router = APIRouter(prefix="/api/v1/enforce", tags=["Enforcement"])
# ── the dependency R11-B must eventually satisfy ────────────────────
class EnforcementStateProvider(Protocol):
    """What the Gateway needs in order to decide, and cannot yet load.
    Declared as a protocol so the boundary is explicit: when R11-B unblocks,
    a Supabase-backed implementation satisfies this and nothing else in the
    chain changes.
    """
    def policy(self, agent_id: str) -> EnforcementPolicy: ...
    def enrollment(self, agent_id: str): ...
    def topology(self, agent_id: str): ...
    def recorder(self, agent_id: str, execution_id: str): ...
    def readiness_passport(self, agent_id: str): ...
class InMemoryStateProvider:
    """For tests and local runs. NOT a persistence implementation: it keeps
    nothing across processes, which is precisely why R11-C.4 exists."""
    def __init__(self, entries: Optional[dict] = None):
        self._entries = entries or {}
    def register(self, agent_id: str, *, policy, enrollment, topology,
                 recorder, readiness_passport=None):
        self._entries[agent_id] = {
            "policy": policy, "enrollment": enrollment, "topology": topology,
            "recorder": recorder, "readiness_passport": readiness_passport}
    def _get(self, agent_id, key):
        if agent_id not in self._entries:
            raise KeyError(agent_id)
        return self._entries[agent_id][key]
    def policy(self, agent_id):
        return self._get(agent_id, "policy")
    def enrollment(self, agent_id):
        return self._get(agent_id, "enrollment")
    def topology(self, agent_id):
        return self._get(agent_id, "topology")
    def recorder(self, agent_id, execution_id):
        return self._get(agent_id, "recorder")
    def readiness_passport(self, agent_id):
        return self._get(agent_id, "readiness_passport")
_provider: EnforcementStateProvider = InMemoryStateProvider()
def set_state_provider(provider: EnforcementStateProvider) -> None:
    global _provider
    _provider = provider
def get_state_provider() -> EnforcementStateProvider:
    return _provider
# ── wire contracts ──────────────────────────────────────────────────
class DecisionRequest(BaseModel):
    agent_id: str
    correlation_id: str
    action: str
    target: str
    arguments: dict = Field(default_factory=dict)
    participant_id: str
    agent_instance_id: str
    execution_id: str
    session_id: Optional[str] = None
    requested_at: float
class EvidenceQuery(BaseModel):
    agent_id: str
    tool_logs: list = Field(default_factory=list)
class ResultSubmission(BaseModel):
    agent_id: str
    decision_id: str
    mechanism: str
    outcome: str
    observed_at: float
    detail: str = ""
_PENDING: dict[str, tuple] = {}
"""decision_id -> (request, decision). In-process only; R11-C.4 replaces it
with persistence. Held here rather than trusting the caller to return the
request and decision it was given, which would let a boundary submit a
result against a decision that was never made."""
@router.post("/decide")
async def decide(body: DecisionRequest,
                 provider: EnforcementStateProvider =
                 Depends(get_state_provider)) -> dict:
    """Transport only. The verdict is the SDK's."""
    try:
        policy = provider.policy(body.agent_id)
        enrollment = provider.enrollment(body.agent_id)
        topology = provider.topology(body.agent_id)
    except KeyError:
        raise HTTPException(404, "no enforcement state for this agent")
    if body.action not in ActionKind.ALL:
        raise HTTPException(422, f"unknown action kind {body.action!r}")
    try:
        request = EnforcementRequest.create(
            correlation_id=body.correlation_id, action=body.action,
            target=body.target, arguments=body.arguments,
            participant_id=body.participant_id,
            agent_instance_id=body.agent_instance_id,
            execution_id=body.execution_id, session_id=body.session_id,
            enrollment_hash=enrollment.enrollment_hash,
            requested_at=body.requested_at)
        decision = decide_enforcement(request, policy=policy,
                                      enrollment=enrollment,
                                      topology=topology)
    except EnforcementError as exc:
        raise HTTPException(409, str(exc))
    _PENDING[decision.decision_id] = (request, decision)
    return {"decision_id": decision.decision_id,
            "decision": decision.decision, "rule": decision.rule,
            "reason": decision.reason,
            "enforcement_policy_id": decision.enforcement_policy_id,
            "enrollment_state": decision.enrollment_state,
            "passport_hash": decision.passport_hash,
            "decision_hash": decision.hash}
@router.post("/result")
async def submit_result(body: ResultSubmission,
                        provider: EnforcementStateProvider =
                        Depends(get_state_provider)) -> dict:
    """The boundary reports what it did. The event is sealed by the SDK and
    recorded as operational evidence; the Gateway adds no interpretation."""
    pending = _PENDING.pop(body.decision_id, None)
    if pending is None:
        raise HTTPException(404, "no such decision, or its result was "
                                 "already submitted")
    request, decision = pending
    if body.mechanism not in Mechanism.ALL:
        raise HTTPException(422, f"unknown mechanism {body.mechanism!r}")
    try:
        result = EnforcementResult(decision_id=decision.decision_id,
                                   decision_hash=decision.hash,
                                   mechanism=body.mechanism,
                                   outcome=body.outcome,
                                   observed_at=body.observed_at,
                                   detail=body.detail)
        event = record_result(request, decision, result)
        recorder = provider.recorder(body.agent_id, request.execution_id)
        recorder.record_enforcement(event)
    except (EnforcementError, KeyError) as exc:
        raise HTTPException(409, str(exc))
    return {"event_id": event.event_id, "event_type": event.event_type,
            "conformance": event.conformance, "forced": event.forced,
            "independent_of_agent": event.result["independent_of_agent"],
            "event_hash": event.hash}
@router.post("/evidence")
async def evidence(body: EvidenceQuery,
                   provider: EnforcementStateProvider =
                   Depends(get_state_provider)) -> dict:
    """The platform's evidence surface for Enforce (data source for the UI).
    Derived by the SDK from the operational log and, where supplied, the
    tool's own execution log — the Gateway adds no interpretation.
    """
    from hb_eval_sdk.enforcement_evidence import ToolExecutionLog
    from hb_eval_sdk.operational_passport import derive_operational_passport
    import time as _t
    try:
        recorder = provider.recorder(body.agent_id, "")
        enrollment = provider.enrollment(body.agent_id)
        passport = provider.readiness_passport(body.agent_id)
    except (KeyError, AttributeError):
        raise HTTPException(404, "no enforcement state for this agent")
    logs = tuple(ToolExecutionLog(
        tool=l["tool"], window_start=l["window_start"],
        window_end=l["window_end"], complete=l["complete"],
        observations=tuple(l["observations"]))
        for l in body.tool_logs)
    log = recorder.log()
    op = derive_operational_passport(
        readiness_passport=passport, enrollment=enrollment,
        operational_logs=(log,), as_of=_t.time(), tool_logs=logs)
    return {"lineage_valid": recorder.lineage().verify()["valid"],
            "operational_log": {"log_hash": log.log_hash,
                                "valid": log.verify()["valid"],
                                "events": [e.to_dict() for e in log.events]},
            "operational_passport": op.to_dict() | {
                "valid": op.verify()["valid"]}}
