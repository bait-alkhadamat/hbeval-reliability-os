"""Gateway enforcement surface — tests.

Self-contained: the enrolment is built from the SDK's public API (tests/sdk_world.py), never from the SDK's
own test files.
"""
import ast, os, time
from pathlib import Path
import pytest
os.environ.setdefault("HBEVAL_ALLOW_FAULT_INJECTION", "true")
from fastapi import FastAPI
from fastapi.testclient import TestClient
import enforcement_api as api
import sdk_world
from hb_eval_sdk.enforcement import ActionKind, EnforcementPolicy
from hb_eval_sdk.operational import OperationalRecorder


@pytest.fixture()
def world():
    w = sdk_world.build(); enr = w["enrollment"]
    prov = api.InMemoryStateProvider()
    prov.register("agent-1",
        policy=EnforcementPolicy("enf-v1", allowed_actions=(ActionKind.TOOL_CALL,), denied_targets=("payments.transfer",)),
        enrollment=enr, topology=w["topology"],
        recorder=OperationalRecorder(topology=w["topology"], enrollment=enr, execution_id="EX-1", session_id="SN-1"),
        readiness_passport=w["passport"])
    api.set_state_provider(prov); api._PENDING.clear()
    app = FastAPI(); app.include_router(api.router)
    ident = dict(participant_id=w["booker"].participant_id, agent_instance_id="B#7", execution_id="EX-1", session_id="SN-1")
    return TestClient(app), ident


def _decide(c, ident, target, n=1, action="TOOL_CALL", agent="agent-1"):
    return c.post("/api/v1/enforce/decide", json={
        "agent_id": agent, "correlation_id": f"c{n}", "action": action,
        "target": target, "arguments": {"amount": 1}, "requested_at": time.time(),
        **ident})


def test_denied_target_is_denied(world):
    c, ident = world
    r = _decide(c, ident, "payments.transfer"); assert r.status_code == 200
    assert r.json()["decision"] == "DENY" and r.json()["decision_id"]


def test_allowed_target_is_allowed(world):
    c, ident = world
    assert _decide(c, ident, "search.web").json()["decision"] == "ALLOW"


def test_unknown_agent_404(world):
    c, ident = world
    assert _decide(c, ident, "search.web", agent="nobody").status_code == 404


def test_unknown_action_422(world):
    c, ident = world
    assert _decide(c, ident, "search.web", action="TELEPORT").status_code == 422


def _result(c, did, mech="SIDECAR", outcome="BLOCKED"):
    return c.post("/api/v1/enforce/result", json={
        "agent_id": "agent-1", "decision_id": did, "mechanism": mech,
        "outcome": outcome, "observed_at": time.time()})


def test_result_seals_event_and_cannot_be_replayed(world):
    c, ident = world
    did = _decide(c, ident, "payments.transfer").json()["decision_id"]
    r = _result(c, did); assert r.status_code == 200, r.text
    assert r.json()["independent_of_agent"] is True and r.json()["event_hash"]
    assert _result(c, did).status_code == 404          # single-use


def test_result_for_a_decision_never_made_is_404(world):
    c, _ = world
    assert _result(c, "does-not-exist").status_code == 404


def test_unknown_mechanism_422(world):
    c, ident = world
    did = _decide(c, ident, "search.web").json()["decision_id"]
    assert _result(c, did, mech="MAGIC", outcome="ALLOWED").status_code == 422


def test_evidence_verifies_after_a_blocked_action(world):
    c, ident = world
    did = _decide(c, ident, "payments.transfer").json()["decision_id"]
    _result(c, did)
    ev = c.post("/api/v1/enforce/evidence", json={"agent_id": "agent-1"}).json()
    assert ev["lineage_valid"] and ev["operational_log"]["valid"]
    assert ev["operational_passport"]["valid"]


def test_no_local_decision_logic():
    """The Gateway transports, authenticates and records. A numeric comparison
    here would be a second reliability model."""
    tree = ast.parse(Path(api.__file__).read_text(encoding="utf-8"))
    bad = [n for n in ast.walk(tree) if isinstance(n, ast.Compare)
           and any(isinstance(o, (ast.Lt, ast.Gt, ast.LtE, ast.GtE)) for o in n.ops)]
    assert not bad, f"threshold-style comparison at line {bad[0].lineno}"
    src = Path(api.__file__).read_text(encoding="utf-8")
    assert "decide_enforcement(" in src


# ── mounting on the production Gateway ──────────────────────────────
def _mounted(env):
    import enforcement_mount
    app = FastAPI(); status = enforcement_mount.mount(app, env)
    return TestClient(app), status


def test_mount_is_off_without_a_key():
    c, st = _mounted({})
    assert st["enforcement_api"] == "disabled"
    assert c.post("/api/v1/enforce/evidence", json={"agent_id": "x"}).status_code == 404


def test_mount_refuses_a_short_key():
    assert _mounted({"HBEVAL_ENFORCE_API_KEY": "short"})[1]["enforcement_api"] == "disabled"


def test_mounted_surface_requires_the_key(world):
    c0, ident = world            # populates the provider
    KEY = "k" * 32
    c, st = _mounted({"HBEVAL_ENFORCE_API_KEY": KEY})
    assert st["enforcement_api"] == "enabled"
    body = {"agent_id": "agent-1"}
    assert c.post("/api/v1/enforce/evidence", json=body).status_code == 401
    assert c.post("/api/v1/enforce/evidence", json=body,
                  headers={"X-HBEval-Enforce-Key": "wrong" * 8}).status_code == 401
    assert c.post("/api/v1/enforce/evidence", json=body,
                  headers={"X-HBEval-Enforce-Key": KEY}).status_code == 200
