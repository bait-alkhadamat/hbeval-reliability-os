"""
SDK 2.13.0 <-> Gateway, end to end, with the real client and the real application.
See tests/e2e_support.py for exactly what is and is not replaced.
"""
import asyncio, json, re, time
import pytest
import requests
from hb_eval_sdk import client as client_mod
from hb_eval_sdk.exceptions import AuthenticationError, ConnectionError as HBConnectionError, SafeHaltError
from hb_eval_sdk.models import Verdict

NO_FAULTS = {
    "trajectory": [{"step": 1, "action": "search", "success": True}, {"step": 2, "action": "book", "success": True}],
    "sub_tasks": 2, "constraint_violations": 0, "agent_id": "travel-agent-1",
}
WITH_FAULT = {
    **NO_FAULTS, "ti_score": 4.0,
    "recovery_episodes": [{"fault_onset_step": 1, "recovered": True, "steps_to_recovery": 1, "approach_correct": True,
                           "memory_query_step": 1, "memory_similarity_met": True, "modification_verified": True}],
}


# ── the happy paths ──────────────────────────────────────────────────
def test_an_agent_with_no_faults_gets_insufficient_data_never_safe(world):
    """The normal first-use answer. It used to crash the SDK's typed evaluate()."""
    c = world.make_client(); r = c.evaluate(dict(NO_FAULTS))
    assert r.verdict == Verdict.INSUFFICIENT_DATA and r.verdict != Verdict.SAFE
    assert set(r.unmeasured_metrics) == {"frr", "irs", "ti"} and r.metrics.pei is not None
    assert r.metrics.frr is None and r.metrics.irs is None and r.tier is None and r.certified is False


def test_a_fully_measured_run_gets_a_real_verdict_and_numbers(world):
    r = world.make_client().evaluate(dict(WITH_FAULT))
    assert r.verdict in (Verdict.SAFE, Verdict.UNSAFE) and r.run_id
    assert None not in (r.metrics.pei, r.metrics.frr, r.metrics.irs, r.metrics.ti) and r.unmeasured_metrics == []


def test_the_wire_looks_right_and_the_protocols_agree(world):
    c = world.make_client(); c.evaluate(dict(WITH_FAULT))
    path, headers, body = world.bridge.calls[0]
    assert path == "/evaluate" and set(body) == {"ciphertext"} and headers["Authorization"] == "Bearer " + world.api_key
    assert "AGENT" not in json.dumps(body) and "travel-agent-1" not in json.dumps(body)
    assert c.gateway_protocol == "2.8.0" and c.protocol_compatibility.level == "ok"
    assert world.gateway.PROTOCOL_VERSION == "2.8.0" and world.gateway.MEASUREMENT_PROTOCOL_VERSION == "2.7.0"


def test_a_battery_run_round_trips_with_the_sdks_own_fingerprint(world):
    from hb_eval_sdk.battery import battery_spec_fingerprint
    out = world.make_client().evaluate_with_battery({"system": "s", "question": "book a flight"},
                                                    lambda s, q: "booked flight 42 confirmed", n_scenarios=6, seed=1)
    assert out["verdict"] in ("SAFE", "UNSAFE", "INSUFFICIENT_DATA")
    assert battery_spec_fingerprint() == "ce481b32763df1ca", "the frozen battery fingerprint must not move"


def test_health_publishes_both_protocol_numbers(world):
    h = world.http.get("/health"); body = h.json()
    assert h.status_code in (200, 503) and body["protocol_version"] == "2.8.0" and body["measurement_protocol_version"] == "2.7.0"
    assert body["version"] == "2.8.0" and h.headers["X-HBEval-Protocol"] == "2.8.0"


# ── protocol negotiation ─────────────────────────────────────────────
def test_every_response_advertises_the_protocol_even_errors(world):
    assert world.http.get("/no-such-route").headers["X-HBEval-Protocol"] == "2.8.0"
    assert world.http.post("/evaluate", json={}).headers["X-HBEval-Protocol"] == "2.8.0"


@pytest.mark.parametrize("declared,status,warns", [("2.8.0", None, False), ("2.8.9", None, False), ("2.7.0", None, True), ("2.9.1", None, True),
                                                   ("3.0.0", 400, False), ("1.9.0", 400, False), ("garbage", None, False), ("", None, False)])
def test_protocol_negotiation_rules(world, declared, status, warns):
    r = world.http.get("/health", headers={"X-HBEval-Protocol": declared})
    if status: assert r.status_code == status and "Unsupported protocol major" in r.json()["detail"]
    else: assert r.status_code in (200, 503)
    assert ("X-HBEval-Protocol-Warning" in r.headers) is warns and r.headers["X-HBEval-Protocol"] == "2.8.0"


def test_a_client_without_the_header_is_still_served(world):
    assert world.http.get("/health").status_code in (200, 503)


def test_an_sdk_that_speaks_an_older_minor_is_warned_not_refused(world, monkeypatch):
    from hb_eval_sdk import config
    monkeypatch.setattr(config, "PROTOCOL_VERSION", "2.7.0")
    with pytest.warns(Warning, match="minor protocol mismatch"):
        r = world.make_client().evaluate(dict(WITH_FAULT))
    assert r.verdict in (Verdict.SAFE, Verdict.UNSAFE)


def test_the_measurement_stamp_never_follows_the_wire_version():
    src = open(world_gateway_path(), encoding="utf-8").read()
    assert "protocol_version=PROTOCOL_VERSION" not in src, \
        "passports must be stamped with MEASUREMENT_PROTOCOL_VERSION: the wire version moves with endpoints, the measurement one does not"
    assert src.count("protocol_version=MEASUREMENT_PROTOCOL_VERSION") >= 2


def world_gateway_path():
    import gateway; return gateway.__file__


# ── authentication, signing and replay ───────────────────────────────
def test_a_replayed_request_is_refused(world):
    c = world.make_client(); c.evaluate(dict(WITH_FAULT))
    path, headers, body = world.bridge.calls[0]
    again = world.http.post(path, json=body, headers=headers)
    assert again.status_code in (403, 409) and "replay" in json.dumps(again.json()).lower() or again.status_code in (403, 409)


def test_a_wrong_signing_secret_is_an_authentication_error(world):
    import base64
    with pytest.raises(AuthenticationError):
        world.make_client(signing_secret=base64.b64encode(bytes(range(100, 132))).decode()).evaluate(dict(WITH_FAULT))


def test_an_unknown_api_key_is_an_authentication_error(world):
    with pytest.raises(AuthenticationError): world.make_client(api_key="hb_not_a_real_key").evaluate(dict(WITH_FAULT))


def test_a_wrong_encryption_key_cannot_be_decrypted_and_is_not_a_pass(world):
    import base64
    with pytest.raises((HBConnectionError, AuthenticationError)):
        world.make_client(aes_key=base64.b64encode(bytes(range(200, 232))).decode()).evaluate(dict(WITH_FAULT))


def test_a_stale_timestamp_is_refused(world, monkeypatch):
    monkeypatch.setattr(client_mod, "generate_timestamp", lambda: str(int(time.time()) - 3600))
    with pytest.raises((AuthenticationError, HBConnectionError)): world.make_client().evaluate(dict(WITH_FAULT))


def test_a_tampered_ciphertext_is_refused_before_it_is_decrypted(world):
    c = world.make_client(); nonce_hex, ct = c._encrypt(dict(WITH_FAULT))
    h = c._build_headers(nonce_hex, str(int(time.time())), ct)
    tampered = ("00" if ct[:2] != "00" else "ff") + ct[2:]
    r = world.http.post("/evaluate", json={"ciphertext": tampered}, headers=h)
    assert r.status_code in (400, 401, 403)


def test_an_empty_bearer_token_is_refused(world):
    r = world.http.post("/evaluate", json={"ciphertext": "00"}, headers={"Authorization": "Bearer "})
    assert r.status_code == 401
    r = world.http.post("/evaluate", json={"ciphertext": "00"}, headers={"Authorization": "Bearer    "})
    assert r.status_code == 401


def test_over_the_plan_limit_is_a_clear_error_not_an_evaluation(world):
    world.db.rpc_results["get_account_quota"] = [{"evaluation_limit": 10, "evaluations_this_month": 10}]
    n_before = len(world.bridge.calls)
    with pytest.raises(HBConnectionError, match="limit"): world.make_client().evaluate(dict(WITH_FAULT))
    assert len(world.bridge.calls) == n_before + 1, "refused on the first attempt: a 429 is not retried"
    world.db.rpc_results["get_account_quota"] = [{"evaluation_limit": 10, "evaluations_this_month": 3}]
    assert world.make_client().evaluate(dict(WITH_FAULT)).verdict in (Verdict.SAFE, Verdict.UNSAFE)


# ── fail closed when the auth backend is missing (regression: it used to fail OPEN) ──
def test_without_a_configured_backend_every_request_is_refused_even_with_the_default_secrets(world, monkeypatch):
    """Supabase unset + DEV_MODE off used to fall through to a dev key that defaults to the empty string,
    with default AES and signing secrets that are public in the source. An empty bearer matched it."""
    monkeypatch.setattr(world.gateway, "_supabase", None)
    r = world.http.post("/evaluate", json={"ciphertext": "00"}, headers={"Authorization": "Bearer hb_anything"})
    assert r.status_code == 503 and "not configured" in r.json()["detail"]
    r2 = world.http.post("/evaluate", json={"ciphertext": "00"}, headers={"Authorization": "Bearer "})
    assert r2.status_code in (401, 503)


def test_dev_mode_still_needs_a_non_empty_dev_key(world, monkeypatch):
    monkeypatch.setattr(world.gateway, "_supabase", None); monkeypatch.setattr(world.gateway, "_DEV_MODE", True)
    monkeypatch.delenv("DEV_API_KEY", raising=False)
    assert world.http.post("/evaluate", json={"ciphertext": "00"}, headers={"Authorization": "Bearer x"}).status_code == 401


def test_the_plaintext_key_fallback_is_off_when_switched_off(world, monkeypatch):
    row = world.db.agents[0]; plain = "hb_legacy_plaintext_key"
    row.pop("api_key_hash"); row["api_key"] = plain                          # an agent the hash backfill has not reached
    import hashlib; world.db.agents[0]["api_key_hash"] = None
    monkeypatch.setattr(world.gateway, "_ALLOW_PLAINTEXT_KEY_LOOKUP", True)
    ok = world.make_client(api_key=plain).evaluate(dict(WITH_FAULT)); assert ok.verdict in (Verdict.SAFE, Verdict.UNSAFE)
    monkeypatch.setattr(world.gateway, "_ALLOW_PLAINTEXT_KEY_LOOKUP", False)
    with pytest.raises(AuthenticationError): world.make_client(api_key=plain).evaluate(dict(WITH_FAULT))


# ── background work is tracked, not forgotten ────────────────────────
def test_spawned_tasks_are_strongly_referenced_until_done_and_failures_are_logged(world, caplog):
    g = world.gateway
    async def scenario():
        gate = asyncio.Event()
        async def waits(): await gate.wait()
        async def fails(): raise RuntimeError("billing write failed")
        t1 = g._spawn(waits(), name="waits"); t2 = g._spawn(fails(), name="fails")
        assert t1 in g._BACKGROUND_TASKS, "an unreferenced task can be garbage-collected mid-flight"
        await asyncio.sleep(0.05)
        assert t2 not in g._BACKGROUND_TASKS and t1 in g._BACKGROUND_TASKS
        gate.set(); await asyncio.sleep(0.05); assert t1 not in g._BACKGROUND_TASKS
    with caplog.at_level("ERROR", logger="hb-eval-gateway"):
        asyncio.run(scenario())
    assert "Background task fails failed" in caplog.text and "billing write failed" in caplog.text


def test_no_fire_and_forget_task_creation_remains_in_the_gateway():
    src = open(world_gateway_path(), encoding="utf-8").read()
    assert len(re.findall(r"asyncio\.create_task\(", src)) == 1, "only _spawn itself may call create_task"


# ── transport hardening ──────────────────────────────────────────────
def test_security_headers_are_on_every_response(world):
    for r in (world.http.get("/health"), world.http.get("/no-such-route"), world.http.post("/evaluate", json={})):
        assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
        assert r.headers["cache-control"] == "no-store" and r.headers["referrer-policy"] == "no-referrer"
        assert "max-age" in r.headers["strict-transport-security"]
    assert "default-src 'none'" in world.http.get("/health").headers["content-security-policy"]


def test_an_oversized_body_is_refused_before_it_is_read(world, monkeypatch):
    monkeypatch.setattr(world.gateway, "MAX_BODY_BYTES", 1000, raising=False)
    # the middleware captured max_bytes at app construction, so exercise it directly with its own limit
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient
    async def echo(request): return PlainTextResponse(str(len(await request.body())))
    small = Starlette(routes=[Route("/", echo, methods=["POST"])])
    small.add_middleware(world.gateway._BodyLimitMiddleware, max_bytes=1000)
    c = TestClient(small)
    assert c.post("/", content=b"x" * 900).text == "900"
    r = c.post("/", content=b"x" * 1001); assert r.status_code == 413 and "too large" in r.json()["detail"]
    chunked = c.post("/", content=(b"x" * 600 for _ in range(3)))                  # no Content-Length: counted as it streams
    assert chunked.status_code == 413


def test_the_real_gateway_refuses_a_huge_evaluation_body(world):
    big = world.http.post("/evaluate", content=b"{" + b'"a":"' + b"x" * (world.gateway.MAX_BODY_BYTES + 10) + b'"}',
                          headers={"Authorization": "Bearer " + world.api_key, "Content-Type": "application/json"})
    assert big.status_code == 413 and big.headers["X-HBEval-Protocol"] == "2.8.0"


def test_a_wildcard_origin_is_refused_in_production_and_listed_origins_are_not_reflected_for_strangers(monkeypatch):
    import importlib, sys
    monkeypatch.setenv("ALLOWED_ORIGINS", "*"); monkeypatch.setenv("DEV_MODE", "false")
    sys.modules.pop("gateway", None)
    g = importlib.import_module("gateway")
    assert g._allowed_origins == [], "a production wildcard must collapse to an empty allow-list"
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://hbeval.com"); sys.modules.pop("gateway", None)
    g2 = importlib.import_module("gateway")
    from fastapi.testclient import TestClient
    c = TestClient(g2.app)
    ok = c.get("/health", headers={"Origin": "https://hbeval.com"}); bad = c.get("/health", headers={"Origin": "https://evil.example"})
    assert ok.headers.get("access-control-allow-origin") == "https://hbeval.com"
    assert "access-control-allow-origin" not in bad.headers
    sys.modules.pop("gateway", None); monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
