"""
verified_runner.py — Secure Agent Caller for the Verified Path (A)
==================================================================

In the verified path the PLATFORM calls the user's agent endpoint across the
fault-injection battery, so the user never touches the middle — no tampering
is possible, and the result earns a `verified` mark.

That power demands strict containment. Every outbound call here is:
  * SSRF-validated (ssrf_guard) BEFORE the request, and pinned to the
    validated public IP to defeat DNS rebinding;
  * bounded by a per-call timeout (a slow/hanging agent cannot tie up the
    platform);
  * bounded by a total battery ceiling (DoS / cost control);
  * redirect-checked (a 3xx to an internal target is re-validated, else refused);
  * response-size capped (a huge response cannot exhaust memory).

This module makes outbound HTTPS requests. It holds no platform secrets and
stores nothing; it returns raw agent responses for the orchestrator to score.
"""

from __future__ import annotations

from typing import Any

from ssrf_guard import validate_agent_url, SSRFValidationError
from fault_injection import build_scenario_battery, inject_fault

# ── Containment limits (fail-closed defaults) ────────────────────────────────
PER_CALL_TIMEOUT_S = 30          # one agent call may not exceed this
MAX_RESPONSE_BYTES = 256 * 1024  # 256 KB cap per agent response
MAX_VERIFIED_SCENARIOS = 100     # verified path may go up to 100 (full CSI)
MAX_REDIRECTS = 0                # do NOT auto-follow redirects (SSRF safety)


class VerifiedRunError(Exception):
    """Raised when the verified run cannot proceed safely."""


async def run_verified_battery(
    agent_url: str,
    base_task: dict[str, Any],
    n_scenarios: int = 30,
    headers: dict[str, str] | None = None,
    seed: int | None = None,
) -> list[dict[str, Any]]:
    """Call the user's agent across a fault-injected battery, securely.

    Returns per-scenario records (same shape the orchestrator expects):
        {scenario_index, domain, fault_type, is_nominal, injected_question,
         response, runner_error}

    Raises VerifiedRunError / SSRFValidationError on unsafe configuration.
    """
    # 1) Validate the URL up front (fail-closed). Pin to the public IP.
    validated = validate_agent_url(agent_url)      # raises if unsafe

    # 2) Clamp battery size to the verified ceiling.
    n = max(6, min(int(n_scenarios), MAX_VERIFIED_SCENARIOS))
    battery = build_scenario_battery(n, seed=seed)

    system = base_task.get("system", "")
    question = base_task.get("question", "")

    # httpx is imported lazily so the module imports even where it is absent;
    # the verified path requires it at call time.
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover
        raise VerifiedRunError(
            "httpx is required for the verified path. Install httpx."
        ) from exc

    records: list[dict[str, Any]] = []

    # Strict transport: no auto-redirects, hard timeout, capped reads.
    timeout = httpx.Timeout(PER_CALL_TIMEOUT_S)
    limits = httpx.Limits(max_connections=5, max_keepalive_connections=2)

    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, limits=limits,
        headers=headers or {},
    ) as client:
        for idx, scenario in enumerate(battery):
            injected_q = inject_fault(question, scenario["fault_type"])
            payload = {"system": system, "input": injected_q,
                       "scenario": scenario["domain"]}
            response_text, err = "", ""
            try:
                resp = await client.post(validated["url"], json=payload)

                # Reject redirects to anything (re-validation is strict; the
                # safest stance for a security tool is not to follow them).
                if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                    err = "agent endpoint attempted a redirect; refused for safety"
                elif resp.status_code >= 400:
                    err = f"agent returned HTTP {resp.status_code}"
                else:
                    raw = resp.content[:MAX_RESPONSE_BYTES]
                    response_text = raw.decode("utf-8", errors="replace")
            except httpx.TimeoutException:
                err = f"agent call timed out after {PER_CALL_TIMEOUT_S}s"
            except Exception as exc:                       # any transport error
                err = f"agent call failed: {type(exc).__name__}"

            records.append({
                "scenario_index": idx,
                "domain": scenario["domain"],
                "fault_type": scenario["fault_type"],
                "is_nominal": scenario["is_nominal"],
                "injected_question": injected_q,
                "response": response_text,
                "runner_error": err,
            })

    return records
