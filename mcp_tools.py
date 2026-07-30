"""
mcp_tools.py — the six HB-Eval MCP tools, implemented natively in the Gateway
=============================================================================
WHY THIS FILE EXISTS
--------------------
The first version of the remote MCP endpoint imported the tools from the
client SDK (hb_eval_sdk.mcp_server). That was wrong in two ways at once:

  1. The Gateway does not install the client SDK — it is a separate service
     with its own dependencies. The import failed, tools/list returned an
     error, and connected clients reported "no tools available".

  2. Even with the SDK installed it would still have been wrong. The SDK's
     tools build an HTTP client from environment credentials and call the
     Gateway over the network. In remote mode the Gateway IS the MCP server,
     so that means calling itself: an extra hop, a second authentication, and
     a hard dependency on the Gateway being able to reach its own public URL.

Here the tools call internal logic directly. The account comes from the OAuth
token, not from environment variables, which is also what makes the remote
server genuinely multi-tenant: every caller acts as themselves.

TOOL RESULTS ARE JSON STRINGS
MCP returns tool output as text content. Returning structured JSON as a string
lets the model parse it reliably instead of guessing at prose.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

logger = logging.getLogger("hb-eval-gateway.mcp_tools")


# ── Tool catalogue ──────────────────────────────────────────────────────────
# Descriptions matter more than they look: this text is the ONLY thing a model
# uses to decide whether a tool fits a request. Vague descriptions produce
# tools that are never called, or called for the wrong thing.
# ── Which OAuth scope each tool requires ─────────────────────────────────────
# The scope system existed end-to-end on the issuing side — declared in
# SUPPORTED_SCOPES, shown to the user on the consent screen, stored per token,
# returned by resolve_bearer — and was never once consulted at the point of
# execution. A token granted hbeval:read could run evaluate_agent_reliability,
# which makes real outbound calls to the user's endpoint and spends paid quota.
#
# That is not a partial implementation of least privilege; it is a consent
# screen making a promise the code does not keep. A scope that is displayed but
# unenforced is worse than no scope at all, because the user believes they
# restricted something.
TOOL_SCOPES: dict[str, str] = {
    "get_reliability_metrics":     "hbeval:read",
    "list_my_agents":              "hbeval:read",
    "get_reliability_trend":       "hbeval:read",
    "retrieve_qualified_memory":   "hbeval:read",
    "explain_verdict":             "hbeval:read",
    # The only tool that acts rather than reads: it calls the agent's endpoint
    # across up to 60 scenarios and consumes metered quota.
    "evaluate_agent_reliability":  "hbeval:evaluate",
}

# Tools that consume evaluation quota, and how the unit count is derived.
# Mirrors REST billing: a battery of N scenarios costs N units, not one.
BILLABLE_TOOLS: frozenset[str] = frozenset({"evaluate_agent_reliability"})


def required_scope(tool_name: str) -> str:
    """Scope a tool needs. Unknown tools default to the stricter scope.

    Defaulting to 'evaluate' rather than 'read' means a tool added later
    without being registered here fails closed instead of inheriting read
    access silently.
    """
    return TOOL_SCOPES.get(tool_name, "hbeval:evaluate")


def billable_units(tool_name: str, args: dict) -> int:
    """Quota units this call will consume."""
    if tool_name not in BILLABLE_TOOLS:
        return 0
    return max(1, min(int(args.get("n_scenarios", 18) or 18), 60))


TOOL_DEFINITIONS: list[dict] = [
    {
        "name": "get_reliability_metrics",
        "description": (
            "Explain HB-Eval's five reliability metrics and how the verdict is "
            "decided. Use when someone asks what PEI, FRR, IRS, TI or CSI mean, "
            "how tiers work, or how to read a reliability report. Needs no "
            "account data and always works."
        ),
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_reliability_trend",
        "description": (
            "Show whether an agent's reliability is improving or degrading over "
            "time, from its recorded runtime-monitoring sessions. Use when "
            "someone asks how an agent has been behaving lately, or whether a "
            "change helped. Requires monitoring sessions to exist for that agent."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string",
                             "description": "The agent identifier used when monitoring."},
                "window": {"type": "integer", "default": 20,
                           "description": "How many recent sessions to consider."},
            },
            "required": ["agent_id"],
        },
    },
    {
        "name": "retrieve_qualified_memory",
        "description": (
            "Retrieve past episodes that cleared HB-Eval's reliability bar, for "
            "a given situation. Unlike a plain log, this memory only holds "
            "episodes that were measured as reliable, so results are usable "
            "precedent rather than a record of everything that happened. Use "
            "when someone asks how similar situations were handled well before."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "context": {"type": "string",
                            "description": "The situation to find precedent for."},
                "top_k": {"type": "integer", "default": 5},
            },
            "required": ["context"],
        },
    },
    {
        "name": "explain_verdict",
        "description": (
            "Explain WHY an agent received a reliability verdict, grounded in a "
            "specific qualified episode and its real recorded metrics — not a "
            "rationale written after the fact. If no sufficiently similar "
            "qualified precedent exists, it says so and defers to human review "
            "rather than inventing a reason. Use when someone asks why a verdict "
            "came out the way it did."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "plan_summary": {"type": "string",
                                 "description": "The decision or plan to explain."},
            },
            "required": ["plan_summary"],
        },
    },
    {
        "name": "list_my_agents",
        "description": (
            "List the agents on this account, with the plan and the account-wide "
            "evaluation usage they share. Use "
            "first when someone refers to 'my agent' without naming one, or to "
            "find the right agent_id for another tool."
        ),
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "evaluate_agent_reliability",
        "description": (
            "Run HB-Eval's fault-injection battery against a deployed agent and "
            "return its verdict and the five metrics. The platform calls the "
            "agent's public HTTPS endpoint across many perturbed scenarios, so "
            "the result is verified rather than self-reported. Requires a paid "
            "plan and explicit consent, because it makes outbound calls to that "
            "endpoint."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_url": {"type": "string",
                              "description": "Public HTTPS endpoint of the agent."},
                "task_description": {"type": "string",
                                     "description": "The base task to perturb."},
                "consent": {"type": "boolean", "default": False,
                            "description": "Must be true; the platform will call the endpoint."},
                "n_scenarios": {"type": "integer", "default": 18},
            },
            "required": ["agent_url", "task_description"],
        },
    },
]


def _ok(data: Any) -> str:
    return json.dumps({"ok": True, "result": data}, ensure_ascii=False, indent=2, default=str)


def _err(message: str) -> str:
    return json.dumps({"ok": False, "error": message}, ensure_ascii=False, indent=2)


# ── Static reference ────────────────────────────────────────────────────────
_METRICS_REFERENCE = {
    "PEI": {
        "name": "Planning Efficiency Index",
        "measures": "Whether the plan is coherent and economical rather than "
                    "wasteful. Repeated re-planning drives it down.",
        "range": "0 to 1",
    },
    "FRR": {
        "name": "Failure Resilience Rate",
        "measures": "Whether the agent keeps functioning when a fault is "
                    "injected, rather than collapsing.",
        "range": "0 to 1",
    },
    "IRS": {
        "name": "Intentional Recovery Score",
        "measures": "Whether recovery from failure was deliberate rather than "
                    "accidental. Defined only on faulted episodes: recovery is "
                    "meaningless with nothing to recover from.",
        "range": "0 to 1, or undefined",
    },
    "TI": {
        "name": "Traceability Index",
        "measures": "Whether the agent's behaviour can be followed and audited "
                    "step by step.",
        "range": "0 to 5",
    },
    "CSI": {
        "name": "Consistency Stability Index",
        "measures": "Whether the agent behaves the same way across repeated "
                    "runs, or drifts. Needs several runs, so it is undefined "
                    "within a single session.",
        "range": "0 to 1, or undefined",
    },
    "aggregation": {
        "rule": "Weakest-link",
        "meaning": "The tier is governed by the worst required metric, not the "
                   "average. An agent cannot average its way to trustworthiness "
                   "by excelling on some dimensions while failing a critical one.",
    },
    "tiers": {
        "Tier 1": "Supervised — operation under direct human supervision.",
        "Tier 2": "Production with oversight — humans monitoring.",
        "Tier 3": "Autonomous — the most demanding thresholds on all five at once.",
        "note": "An internal performance qualification, not an accredited safety "
                "certification.",
    },
    "undefined_is_not_zero": (
        "A metric reported as undefined was not measured, and is never scored as "
        "zero. Treating it as zero would report a failure on a dimension nothing "
        "examined."
    ),
}


# ── Tool implementations ────────────────────────────────────────────────────
async def call_tool(name: str, args: dict, *, supabase: Any, to_thread: Any,
                    user_id: str, agent: Optional[dict],
                    deps: dict, scopes: Optional[list[str]] = None) -> str:
    """Dispatch one tool call.

    Args:
        supabase: the Gateway's Supabase client.
        to_thread: asyncio.to_thread, injected so this module stays importable
            without pulling asyncio semantics into its own namespace.
        user_id: resolved from the OAuth token — never from a parameter, so a
            caller cannot act as another account by passing an id.
        agent: the account's selected agent row, or None if it owns none.
        scopes: granted by the OAuth token. Enforced below — a tool is refused
            when its required scope was not granted. None means "not supplied",
            which is treated as no scopes at all rather than as all of them:
            a caller that forgets to pass them must fail closed.
        deps: Gateway internals this module must not import directly, to avoid
            a circular import: hci_edm, run_verified_battery,
            aggregate_battery_results, is_paid.
    """
    # ── Scope enforcement, before anything else happens ──
    granted = set(scopes or [])
    needed = required_scope(name)
    if needed not in granted:
        return _err(
            f"This connection was not granted the '{needed}' scope, which "
            f"'{name}' requires. Reconnect and approve that permission to use "
            f"it. Granted: {sorted(granted) or 'none'}."
        )

    try:
        if name == "get_reliability_metrics":
            return _ok(_METRICS_REFERENCE)

        if name == "list_my_agents":
            return await _list_agents(supabase, to_thread, user_id)

        if agent is None:
            return _err(
                "This account has no agents yet. Create one at "
                "https://hbeval.com/dashboard/agents, then try again."
            )

        if name == "get_reliability_trend":
            return await _trend(supabase, to_thread, user_id,
                                str(args.get("agent_id", "")),
                                int(args.get("window", 20) or 20))

        if name == "retrieve_qualified_memory":
            return await _memory(supabase, to_thread, agent,
                                 str(args.get("context", "")),
                                 int(args.get("top_k", 5) or 5))

        if name == "explain_verdict":
            return await _explain(supabase, to_thread, agent,
                                  str(args.get("plan_summary", "")), deps)

        if name == "evaluate_agent_reliability":
            return await _evaluate(agent, args, deps)

        return _err(f"Unknown tool: {name}")

    except Exception:
        # Never surface a stack trace to a model: it would be relayed verbatim
        # to the user and may carry internal detail.
        logger.exception("MCP tool failed: %s", name)
        return _err(f"The tool '{name}' failed. The incident has been logged.")


_ACCOUNT_LIMITS = {"free": 500, "pro": 5_000, "enterprise": 2_147_483_647}


async def _list_agents(supabase, to_thread, user_id: str) -> str:
    """List the account's agents, with usage read from the right place.

    The monthly pool belongs to the ACCOUNT and is shared by every agent it
    owns (migration 08). The per-agent evaluations_this_month column stopped
    being maintained when that change landed, so reporting it here showed zero
    no matter how much the account had actually used — which reads as a broken
    counter rather than as the stale column it is.
    """
    def _agents():
        return (supabase.table("agents")
                .select("agent_id, name, plan_type, is_active")
                .eq("user_id", user_id)
                .order("created_at", desc=True).limit(25).execute())
    res = await to_thread(_agents)
    rows = res.data or []
    if not rows:
        return _ok({"agents": [], "note": "This account has no agents yet. "
                                          "Create one at https://hbeval.com/dashboard/agents"})

    def _quota():
        return (supabase.table("account_usage")
                .select("plan_type, evaluation_limit, evaluations_this_month, evaluations_today")
                .eq("user_id", user_id).execute())
    used = limit = None
    plan = rows[0].get("plan_type", "free")
    try:
        qres = await to_thread(_quota)
        qrows = qres.data or []
        if qrows:
            q = qrows[0]
            plan = q.get("plan_type") or plan
            used = q.get("evaluations_this_month", 0) or 0
            limit = q.get("evaluation_limit") or _ACCOUNT_LIMITS.get(plan, 500)
    except Exception as exc:
        logger.error("Account quota read failed for %s: %s", user_id, exc)

    if used is None:
        used, limit = 0, _ACCOUNT_LIMITS.get(plan, 500)

    return _ok({
        "agents": rows,
        "count": len(rows),
        "account_usage": {
            "plan": plan,
            "evaluations_this_month": used,
            "monthly_limit": limit,
            "note": ("This pool is shared across every agent on the account. "
                     "Runtime monitoring sessions are NOT counted - they run on "
                     "the user's own machine."),
        },
    })


async def _trend(supabase, to_thread, user_id: str, agent_id: str, window: int) -> str:
    if not agent_id.strip():
        return _err("agent_id is required.")
    window = max(1, min(window, 200))

    def _q():
        # Scoped to the token's account explicitly. The Gateway uses the
        # service-role key, so row level security does NOT apply here — without
        # this filter the tool would read other accounts' sessions.
        return (supabase.table("monitoring_sessions")
                .select("created_at, step_count, breach_count, halted, halt_reason, "
                        "pei_live, frr_live, irs_live, ti_live, csi_live")
                .eq("agent_id", agent_id).eq("user_id", user_id)
                .order("created_at", desc=True).limit(window).execute())
    res = await to_thread(_q)
    rows = res.data or []

    if not rows:
        return _ok({
            "agent_id": agent_id, "session_count": 0, "direction": "no_data",
            "note": ("No monitoring sessions recorded for this agent. Run the "
                     "agent inside client.monitor(...) to build history."),
        })

    series = list(reversed(rows))

    def avg(key):
        vals = [r[key] for r in series if r.get(key) is not None]
        return round(sum(vals) / len(vals), 4) if vals else None

    half = max(1, len(series) // 2)

    def half_avg(rows_, key):
        vals = [r[key] for r in rows_ if r.get(key) is not None]
        return sum(vals) / len(vals) if vals else None

    per_metric, improving, declining, comparable = {}, 0, 0, 0
    for col, label in (("pei_live", "pei"), ("frr_live", "frr"), ("irs_live", "irs"),
                       ("ti_live", "ti"), ("csi_live", "csi")):
        a, b = half_avg(series[:half], col), half_avg(series[half:], col)
        if a is None or b is None:
            # An undefined metric yields no direction rather than a fabricated
            # one. This is why a single session reports "insufficient_data"
            # instead of the false confidence of "stable".
            per_metric[label] = {"direction": "undefined"}
            continue
        comparable += 1
        delta = round(b - a, 4)
        if delta > 0.01:
            per_metric[label] = {"direction": "improving", "delta": delta}; improving += 1
        elif delta < -0.01:
            per_metric[label] = {"direction": "declining", "delta": delta}; declining += 1
        else:
            per_metric[label] = {"direction": "stable", "delta": delta}

    if comparable == 0:
        overall = "insufficient_data"
    elif improving and not declining:
        overall = "improving"
    elif declining and not improving:
        overall = "declining"
    elif improving or declining:
        overall = "mixed"
    else:
        overall = "stable"

    halted = [r for r in series if r.get("halted")]
    return _ok({
        "agent_id": agent_id,
        "session_count": len(series),
        "averages": {"pei": avg("pei_live"), "frr": avg("frr_live"),
                     "irs": avg("irs_live"), "ti": avg("ti_live"), "csi": avg("csi_live")},
        "total_breaches": sum(r.get("breach_count", 0) or 0 for r in series),
        "halted_sessions": len(halted),
        "halt_reasons": [r.get("halt_reason") for r in halted if r.get("halt_reason")][:5],
        "per_metric": per_metric,
        "direction": overall,
        "note": "Values shown as null were undefined for those runs, not zero.",
    })


async def _memory(supabase, to_thread, agent: dict, context: str, top_k: int) -> str:
    if not context.strip():
        return _err("A non-empty context is required.")

    paid = agent.get("plan_type") in ("pro", "enterprise")
    effective = min(max(1, top_k), 10 if paid else 3)

    def _q():
        return (supabase.table("edm_memory").select("*")
                .eq("project_id", agent["id"])
                .order("created_at", desc=True).limit(effective).execute())
    res = await to_thread(_q)
    rows = res.data or []

    out = {"retrieved": len(rows), "episodes": rows}
    if not paid and top_k > 3:
        out["note"] = "Free plan returns up to 3 episodes. Upgrade for more."
    return _ok(out)


async def _explain(supabase, to_thread, agent: dict, plan_summary: str, deps: dict) -> str:
    if not plan_summary.strip():
        return _err("plan_summary is required.")
    explain_fn = deps.get("hci_explain")
    if explain_fn is None:
        return _err("The interpretability layer is unavailable on this deployment.")
    result = await to_thread(lambda: explain_fn(supabase, agent["id"], plan_summary))
    return _ok(result)


async def _evaluate(agent: dict, args: dict, deps: dict) -> str:
    consent = bool(args.get("consent", False))
    agent_url = str(args.get("agent_url", ""))
    task = str(args.get("task_description", ""))
    # Derived from the same function that computes the charge, not a second
    # copy of the clamp. Two copies of this expression would let billing and
    # execution drift apart silently — under- or over-charging for work that
    # was actually done.
    n = billable_units("evaluate_agent_reliability", args)

    if not consent:
        return _err(
            "Consent required. This calls your agent's endpoint across multiple "
            "fault scenarios. Re-run with consent=true to proceed."
        )
    if not agent_url.lower().startswith("https://"):
        return _err("agent_url must be a public HTTPS endpoint.")
    if not task.strip():
        return _err("task_description is required.")

    # The paid gate is enforced here as well as at the HTTP endpoint. A second
    # door into the same capability must carry the same lock, or it becomes the
    # way around it.
    if agent.get("plan_type") not in ("pro", "enterprise"):
        return _err(
            "Verified evaluation requires a paid plan. On the free plan, run the "
            "battery locally with the SDK: client.evaluate_with_battery(...)."
        )

    runner = deps.get("run_verified_battery")
    aggregate = deps.get("aggregate_battery_results")
    if runner is None or aggregate is None:
        return _err("Verified evaluation is unavailable on this deployment.")

    try:
        records = await runner(agent_url=agent_url,
                               base_task={"question": task},
                               n_scenarios=n, headers={})
    except Exception as exc:
        return _err(f"Could not run the battery against that endpoint: {type(exc).__name__}")

    report = aggregate(records, [])
    report["verification"] = "verified"
    report["scenarios_run"] = len(records) if records else 0
    return _ok(report)
