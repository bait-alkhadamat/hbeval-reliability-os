"""The Gateway's API surface is a contract: any change to it is deliberate, visible in review, and noted."""
import json, os, importlib, sys
import pytest

SURFACE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_surface.json")


def _operations(app):
    spec = app.openapi()
    return sorted(f"{m.upper()} {p}" for p, ops in spec["paths"].items() for m in ops)


def test_the_default_api_surface_matches_the_committed_snapshot(world):
    expected = json.load(open(SURFACE, encoding="utf-8"))["operations"]
    assert _operations(world.gateway.app) == expected, \
        "the API surface changed. If that is intended, update tests/api_surface.json and CHANGELOG.md in the same commit."


def test_the_enforcement_api_is_absent_by_default_and_present_only_with_a_key(monkeypatch):
    monkeypatch.delenv("HBEVAL_ENFORCE_API_KEY", raising=False); sys.modules.pop("gateway", None)
    assert not any("/enforce/" in o for o in _operations(importlib.import_module("gateway").app))
    monkeypatch.setenv("HBEVAL_ENFORCE_API_KEY", "k" * 32); sys.modules.pop("gateway", None)
    assert {"POST /api/v1/enforce/decide", "POST /api/v1/enforce/result", "POST /api/v1/enforce/evidence"} <= set(_operations(importlib.import_module("gateway").app))
    sys.modules.pop("gateway", None)


def test_every_operation_is_tagged_and_operation_ids_are_unique(world):
    spec = world.gateway.app.openapi(); ids = []
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            assert op.get("tags"), f"{method.upper()} {path} has no tag"
            ids.append(op["operationId"])
    assert len(ids) == len(set(ids))


def test_the_plaintext_evaluation_route_is_refused_outside_dev_mode(world):
    r = world.http.post("/evaluate_plain", headers={"Authorization": "Bearer " + world.api_key},
                        json={"trajectory": [{"step": 1}], "sub_tasks": 1, "agent_id": "a"})
    assert r.status_code == 403 and "disabled in production" in r.json()["detail"]
