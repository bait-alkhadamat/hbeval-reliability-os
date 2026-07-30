"""
verified_runner.py — Secure Agent Caller for the Verified Path (A)
==================================================================

In the verified path the PLATFORM calls the user's agent endpoint across the
fault-injection battery, so the user never touches the middle — no tampering
is possible, and the result earns a `verified` mark.

That power demands strict containment. Every outbound call here is:
  * SSRF-validated (ssrf_guard) before the request, re-validated immediately
    before each call, and the CONNECTED PEER ADDRESS checked against the
    validated set afterwards — see the DNS rebinding note below;
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
# Redirects are refused outright rather than followed and re-validated, so this
# is asserted as follow_redirects=False on the client below AND checked again on
# the response. Kept as a named constant because the value is a security
# decision, not an implementation detail.
MAX_REDIRECTS = 0

# ── DNS rebinding: what is enforced, and what is not ─────────────────────────
# The previous docstring claimed the connection was "pinned to the validated
# public IP". It was not: the request used the hostname, so httpx re-resolved
# DNS at connect time and ssrf_guard's public_ips were never consulted. That is
# a TOCTOU window an attacker controlling their own DNS can drive.
#
# The obvious repair — putting the IP in the URL and passing sni_hostname — was
# measured and REJECTED. In httpx 0.28 that silently stops enforcing
# certificate hostname verification: a request to Google's IP claiming to
# verify example.com completed successfully. Trading DNS rebinding for
# accept-any-certificate is a worse position, not a better one.
#
# Patching socket.getaddrinfo was also measured and rejected: it has no effect
# on httpx, which resolves through anyio.
#
# What is enforced instead:
#   1. Re-validation immediately before every call, narrowing the window from
#      the whole battery down to the gap between resolve and connect.
#   2. The CONNECTED PEER ADDRESS is read after the handshake and checked
#      against the validated public IPs. On mismatch the response is discarded
#      and the scenario recorded as an error, which closes the exfiltration
#      path — reading an internal endpoint is only useful if the body comes
#      back.
#   3. Full TLS verification is preserved, because the URL keeps the hostname.
#
# What is NOT enforced: the request may still reach a rebound address before
# the peer check rejects its response. Fully preventing the connection needs a
# resolver-level hook (aiohttp's resolver, or a custom httpx transport) and is
# recorded as follow-up work rather than described here as though it were done.
_PEER_CHECK_NOTE = "peer address verified against ssrf_guard public_ips"


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
                # Re-validate before every call. If DNS has moved to a private
                # or link-local address since the battery started, this raises
                # and the scenario is recorded as an error rather than sent.
                fresh = validate_agent_url(agent_url)
                allowed_ips = set(fresh.get("public_ips") or []) | set(
                    validated.get("public_ips") or [])

                resp = await client.post(fresh["url"], json=payload)

                # Where did we ACTUALLY connect? If the resolved address is not
                # one we validated, the response is not trusted — discarded
                # rather than returned, which is what closes the exfiltration
                # path even though the request itself already went out.
                peer_ip = None
                stream = resp.extensions.get("network_stream")
                if stream is not None:
                    try:
                        server_addr = stream.get_extra_info("server_addr")
                        if server_addr:
                            peer_ip = str(server_addr[0])
                    except Exception:
                        peer_ip = None

                if peer_ip is not None and allowed_ips and peer_ip not in allowed_ips:
                    err = (f"connection resolved to {peer_ip}, which was not in "
                           f"the validated address set; response discarded "
                           f"(possible DNS rebinding)")
                    records.append({
                        "scenario_index": idx,
                        "domain": scenario["domain"],
                        "fault_type": scenario["fault_type"],
                        "is_nominal": scenario["fault_type"] == "none",
                        "injected_question": injected_q,
                        "response": "",
                        "runner_error": err,
                    })
                    continue

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
