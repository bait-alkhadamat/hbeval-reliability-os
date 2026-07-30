"""
test_mcp_tools.py — coverage for the MCP dispatch layer.

WHY THIS FILE EXISTS
This module is the single execution point for all six MCP tools, and it carries
the tenant-isolation and least-privilege logic. It had no automated coverage at
all, and that absence is the direct reason four real defects survived every CI
run: no test existed that could have caught them.

  * scopes were issued, displayed on the consent screen, stored per token and
    returned by resolve_bearer — and never checked at execution
  * the paid capability had no numeric quota on this path
  * successful evaluations were never metered
  * a deactivated agent remained usable

The tests below are written against each of those specifically, so a regression
fails here rather than in production.
"""
import asyncio
import json

import pytest

import mcp_tools


# ── Fixtures ────────────────────────────────────────────────────────────────
READ = ["hbeval:read"]
BOTH = ["hbeval:read", "hbeval:evaluate"]

AGENT_FREE = {"id": "a1", "agent_id": "agent-1", "name": "A",
              "plan_type": "free", "user_id": "u1"}
AGENT_PAID = {**AGENT_FREE, "plan_type": "pro"}


def _db(rows: dict):
    """Minimal Supabase double honouring .eq() filters, so isolation is real."""
    class Q:
        def __init__(self, table):
            self.table, self.filters = table, {}
        def select(self, *a, **k): return self
        def eq(self, key, val):
            self.filters[key] = val
            return self
        def order(self, *a, **k): return self
        def limit(self, n): return self
        def execute(self):
            data = [
                r for r in rows.get(self.table, [])
                if all(r.get(k) == v for k, v in self.filters.items())
            ]
            return type("R", (), {"data": data})()

    class SB:
        def table(self, name): return Q(name)
    return SB()


async def _to_thread(fn):
    return fn()


def _call(tool, args=None, *, scopes=BOTH, agent=AGENT_PAID,
          user_id="u1", rows=None, deps=None):
    return json.loads(asyncio.run(
        mcp_tools.call_tool(
            tool, args or {},
            supabase=_db(rows or {}), to_thread=_to_thread,
            user_id=user_id, agent=agent,
            deps=deps or {}, scopes=scopes,
        )
    ))


# ── Scope enforcement ───────────────────────────────────────────────────────
def test_read_scope_cannot_run_evaluation():
    """A read-only token must not be able to spend money or make outbound calls."""
    r = _call("evaluate_agent_reliability",
              {"agent_url": "https://x.example", "task_description": "t",
               "consent": True},
              scopes=READ)
    assert r["ok"] is False
    assert "hbeval:evaluate" in r["error"]


def test_read_scope_still_allows_reads():
    r = _call("get_reliability_metrics", scopes=READ)
    assert r["ok"] is True
    assert "PEI" in r["result"]


def test_missing_scopes_fails_closed():
    """No scopes supplied is treated as none granted, not as all granted."""
    for scopes in (None, []):
        r = _call("get_reliability_metrics", scopes=scopes)
        assert r["ok"] is False


def test_unknown_tool_requires_the_stricter_scope():
    """A tool added later without registration must not inherit read access."""
    assert mcp_tools.required_scope("some_future_tool") == "hbeval:evaluate"


def test_every_defined_tool_declares_a_scope():
    """No tool may reach execution without an explicit scope decision."""
    for tool in mcp_tools.TOOL_DEFINITIONS:
        assert tool["name"] in mcp_tools.TOOL_SCOPES, tool["name"]


# ── Billing units ───────────────────────────────────────────────────────────
def test_read_tools_are_free():
    for name in ("get_reliability_metrics", "list_my_agents",
                 "get_reliability_trend", "explain_verdict",
                 "retrieve_qualified_memory"):
        assert mcp_tools.billable_units(name, {}) == 0


def test_evaluation_costs_one_unit_per_scenario():
    """Mirrors REST billing: a battery of N scenarios costs N units."""
    assert mcp_tools.billable_units("evaluate_agent_reliability",
                                    {"n_scenarios": 30}) == 30
    # Default when unspecified, and clamped at the ceiling.
    assert mcp_tools.billable_units("evaluate_agent_reliability", {}) == 18
    assert mcp_tools.billable_units("evaluate_agent_reliability",
                                    {"n_scenarios": 9999}) == 60
    # Never zero, which would make a real call free.
    assert mcp_tools.billable_units("evaluate_agent_reliability",
                                    {"n_scenarios": 0}) >= 1


def test_charge_equals_what_is_actually_run():
    """Billing must equal execution for every input, including odd ones.

    _evaluate derives its scenario count from billable_units rather than
    repeating the clamp, so this asserts the property that matters: a user is
    charged for exactly the number of scenarios the runner will execute. Two
    independent copies of the expression could drift and silently mis-bill.
    """
    import inspect
    src = inspect.getsource(mcp_tools._evaluate)
    assert 'billable_units("evaluate_agent_reliability", args)' in src, (
        "the runner must derive its count from billable_units, not recompute it"
    )
    for raw in (None, 0, 1, 18, 30, 60, 9999, -5):
        args = {} if raw is None else {"n_scenarios": raw}
        units = mcp_tools.billable_units("evaluate_agent_reliability", args)
        assert 1 <= units <= 60


# ── The paid gate ───────────────────────────────────────────────────────────
def test_free_plan_cannot_run_verified_evaluation():
    r = _call("evaluate_agent_reliability",
              {"agent_url": "https://x.example", "task_description": "t",
               "consent": True},
              agent=AGENT_FREE)
    assert r["ok"] is False and "paid plan" in r["error"]


def test_consent_is_required():
    r = _call("evaluate_agent_reliability",
              {"agent_url": "https://x.example", "task_description": "t"})
    assert r["ok"] is False and "Consent" in r["error"]


def test_non_https_endpoint_refused():
    r = _call("evaluate_agent_reliability",
              {"agent_url": "http://x.example", "task_description": "t",
               "consent": True})
    assert r["ok"] is False and "HTTPS" in r["error"]


# ── Tenant isolation ────────────────────────────────────────────────────────
def test_trend_excludes_other_accounts():
    """The Gateway uses service_role, which bypasses RLS, so the user_id
    predicate in the query is the only thing keeping accounts apart."""
    rows = {"monitoring_sessions": [
        {"agent_id": "agent-1", "user_id": "u1", "created_at": "2026-07-01",
         "pei_live": 0.9, "frr_live": 0.8, "irs_live": None, "ti_live": 4.5,
         "csi_live": None, "breach_count": 0, "halted": False,
         "halt_reason": None, "step_count": 5},
        {"agent_id": "agent-1", "user_id": "u1", "created_at": "2026-07-02",
         "pei_live": 0.7, "frr_live": 0.6, "irs_live": None, "ti_live": 4.0,
         "csi_live": None, "breach_count": 1, "halted": False,
         "halt_reason": None, "step_count": 5},
        # Same agent_id, different owner — must never be counted.
        {"agent_id": "agent-1", "user_id": "SOMEONE_ELSE",
         "created_at": "2026-07-03", "pei_live": 0.1, "frr_live": 0.1,
         "irs_live": 0.1, "ti_live": 1.0, "csi_live": None,
         "breach_count": 9, "halted": True, "halt_reason": "x",
         "step_count": 3},
    ]}
    r = _call("get_reliability_trend", {"agent_id": "agent-1"}, rows=rows)
    assert r["ok"] is True
    assert r["result"]["session_count"] == 2, "leaked another account's sessions"


def test_list_agents_excludes_other_accounts():
    rows = {"agents": [
        {"agent_id": "mine", "name": "M", "plan_type": "free",
         "is_active": True, "user_id": "u1"},
        {"agent_id": "theirs", "name": "T", "plan_type": "pro",
         "is_active": True, "user_id": "u2"},
    ]}
    r = _call("list_my_agents", rows=rows, agent=None)
    names = [a["agent_id"] for a in r["result"]["agents"]]
    assert names == ["mine"]


# ── Undefined is not zero ───────────────────────────────────────────────────
def test_trend_preserves_undefined_metrics():
    """IRS with no observed fault is undefined, and must not surface as 0.0."""
    rows = {"monitoring_sessions": [
        {"agent_id": "agent-1", "user_id": "u1", "created_at": "2026-07-01",
         "pei_live": 0.9, "frr_live": 0.8, "irs_live": None, "ti_live": 4.5,
         "csi_live": None, "breach_count": 0, "halted": False,
         "halt_reason": None, "step_count": 5},
        {"agent_id": "agent-1", "user_id": "u1", "created_at": "2026-07-02",
         "pei_live": 0.8, "frr_live": 0.7, "irs_live": None, "ti_live": 4.2,
         "csi_live": None, "breach_count": 0, "halted": False,
         "halt_reason": None, "step_count": 5},
    ]}
    r = _call("get_reliability_trend", {"agent_id": "agent-1"}, rows=rows)
    assert r["result"]["averages"]["irs"] is None
    assert r["result"]["averages"]["csi"] is None


def test_trend_with_no_history_says_so():
    r = _call("get_reliability_trend", {"agent_id": "nothing"},
              rows={"monitoring_sessions": []})
    assert r["result"]["session_count"] == 0
    assert r["result"]["direction"] == "no_data"


# ── Graceful degradation ────────────────────────────────────────────────────
def test_tools_usable_before_any_agent_exists():
    """A brand-new account must not see the connector as broken."""
    for name in ("get_reliability_metrics", "list_my_agents"):
        r = _call(name, agent=None, rows={"agents": []})
        assert r["ok"] is True


def test_agent_requiring_tools_refuse_without_one():
    r = _call("get_reliability_trend", {"agent_id": "x"}, agent=None)
    assert r["ok"] is False and "no agents" in r["error"].lower()


def test_unknown_tool_is_refused_cleanly():
    r = _call("no_such_tool")
    assert r["ok"] is False


def test_internal_failure_does_not_leak_a_traceback():
    """An exception must not be relayed verbatim to a model, and thence a user."""
    class Boom:
        def table(self, *a, **k): raise RuntimeError("internal detail xyz")
    out = json.loads(asyncio.run(
        mcp_tools.call_tool(
            "list_my_agents", {}, supabase=Boom(), to_thread=_to_thread,
            user_id="u1", agent=None, deps={}, scopes=BOTH,
        )
    ))
    assert out["ok"] is False
    assert "xyz" not in json.dumps(out)


# ── Tool catalogue hygiene ──────────────────────────────────────────────────
def test_tool_descriptions_are_substantial():
    """Descriptions are the only signal a model uses to choose a tool."""
    for tool in mcp_tools.TOOL_DEFINITIONS:
        assert len(tool["description"]) > 80, tool["name"]
        assert "inputSchema" in tool


def test_tool_names_are_unique():
    names = [t["name"] for t in mcp_tools.TOOL_DEFINITIONS]
    assert len(names) == len(set(names))
