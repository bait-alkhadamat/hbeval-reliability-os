"""
alerts.py — outbound notification for reliability events
=========================================================
Turns a detected collapse into something that reaches a person.

WHY THIS EXISTS
---------------
The platform could detect a breach, record it, halt the agent, and store an
audit trail — and tell nobody unless they were watching a dashboard at that
moment. Monitoring that requires an audience is not operational monitoring.

Infrastructure pushes. This is the push.

THE SECURITY POSITION
---------------------
This module makes outbound HTTPS requests to URLs supplied by users, which is
the textbook SSRF vector. Everything below is shaped by that.

  * Every URL passes ssrf_guard.validate_agent_url before any request, so the
    same fail-closed policy that protects verified evaluation protects this:
    HTTPS only, port 443 only, public addresses only.

  * Redirects are refused rather than followed. Following one and re-validating
    reopens the window the refusal closes.

  * The connected peer address is checked after the handshake, exactly as in
    verified_runner, and a mismatch discards the response.

  * Webhook URLs are credentials. A Slack incoming-webhook URL grants anyone
    holding it the ability to post as that integration, so no URL is ever
    logged, echoed in an error, or returned to a client.

WHY DEDUPLICATION LIVES IN THE DATABASE
----------------------------------------
A breach is recorded on every step a metric stays below its floor. Alerting on
each one would post twenty identical messages for one degradation, and the
third is where somebody mutes the channel. An alerting system people mute is
worse than none, because it looks like coverage.

The unique index on webhook_deliveries decides once. An application-level check
would let two Gateway instances processing batches concurrently both pass and
both send — the constraint is the only place that can be authoritative.

DELIVERY IS FIRE-AND-FORGET, DELIBERATELY
------------------------------------------
Alerts are dispatched as background tasks. A slow Slack endpoint must never add
latency to the monitoring path that an agent is waiting on. A lost alert is a
missed notification; a blocked monitoring endpoint is a degraded agent.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("hb-eval-gateway.alerts")

# Short, because nothing downstream is waiting on the result and a hung
# endpoint should not hold a worker.
DELIVERY_TIMEOUT_S = 8.0

# Disabled after this many consecutive failures. Without it, one user's stale
# URL becomes a permanent outbound load, retried on every breach of every
# session forever.
MAX_CONSECUTIVE_FAILURES = 10

# Bodies are capped: a hostile endpoint could otherwise reply with gigabytes.
MAX_RESPONSE_BYTES = 8192

DASHBOARD_URL = "https://hbeval.com/dashboard/monitoring"


# ── Message formatting ──────────────────────────────────────────────────────
def _severity(event_type: str) -> tuple[str, str]:
    """Colour and emoji per event. Halt outranks breach: one is a warning, the
    other is an action already taken on the operator's behalf."""
    if event_type == "halt":
        return "#dc2626", "🛑"
    return "#f59e0b", "⚠️"


def _summary_line(event: dict) -> str:
    if event["event_type"] == "halt":
        return f"Safe Halt stopped {event['agent_id']}"
    return (f"{str(event.get('metric', '')).upper()} fell below its floor "
            f"on {event['agent_id']}")


def format_slack(event: dict) -> dict:
    """Slack incoming-webhook payload.

    Uses attachments rather than blocks because attachments render acceptably
    in every Slack client including old mobile ones, and an alert that renders
    badly on the phone someone is holding at 3am has failed at its only job.
    """
    colour, icon = _severity(event["event_type"])
    fields = [
        {"title": "Agent", "value": event["agent_id"], "short": True},
        {"title": "Step", "value": str(event.get("step_index", "—")), "short": True},
    ]
    if event.get("metric"):
        fields.append({
            "title": str(event["metric"]).upper(),
            "value": (f"{event.get('metric_value', '—')} "
                      f"(floor {event.get('threshold', '—')})"),
            "short": True,
        })
    if event["event_type"] == "halt" and event.get("reason"):
        fields.append({"title": "Reason", "value": event["reason"], "short": False})

    return {
        "text": f"{icon} {_summary_line(event)}",
        "attachments": [{
            "color": colour,
            "fields": fields,
            "footer": "HB-Eval",
            "actions": [{"type": "button", "text": "Open session",
                         "url": f"{DASHBOARD_URL}/{event['session_id']}"}],
        }],
    }


def format_pagerduty(event: dict, routing_key: str = "") -> dict:
    """PagerDuty Events API v2.

    dedup_key is set to the session so PagerDuty groups every alert from one
    run into a single incident. Without it a degrading agent would page the
    on-call once per metric.
    """
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": f"hbeval-{event['session_id']}",
        "payload": {
            "summary": _summary_line(event),
            "severity": "critical" if event["event_type"] == "halt" else "warning",
            "source": event["agent_id"],
            "component": "hb-eval",
            "custom_details": {
                k: v for k, v in event.items()
                if k in ("metric", "metric_value", "threshold", "step_index", "reason")
            },
        },
        "links": [{"href": f"{DASHBOARD_URL}/{event['session_id']}",
                   "text": "Open session"}],
    }


def format_generic(event: dict) -> dict:
    """Plain JSON for anything else, including Teams and custom receivers.

    Deliberately flat and stable: this is the shape people write parsers
    against, so it changes only additively.
    """
    return {
        "source": "hb-eval",
        "event": event["event_type"],
        "agent_id": event["agent_id"],
        "session_id": event["session_id"],
        "metric": event.get("metric"),
        "value": event.get("metric_value"),
        "threshold": event.get("threshold"),
        "step_index": event.get("step_index"),
        "reason": event.get("reason"),
        "url": f"{DASHBOARD_URL}/{event['session_id']}",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
    }


def build_payload(destination: str, event: dict, url: str) -> dict:
    dest = (destination or "generic").lower()
    if dest == "slack":
        return format_slack(event)
    if dest == "pagerduty":
        # PagerDuty carries its routing key in the body, not the URL, so it is
        # taken from the fragment of the stored URL rather than adding a column.
        key = url.rsplit("#", 1)[-1] if "#" in url else ""
        return format_pagerduty(event, key)
    return format_generic(event)


# ── Delivery ────────────────────────────────────────────────────────────────
async def _post(url: str, payload: dict, ssrf_guard: Any) -> tuple[bool, int | None, str | None, int]:
    """One HTTPS POST under the SSRF policy. Returns (ok, status, error, ms).

    Never returns the URL in an error string: webhook URLs are credentials.
    """
    import httpx

    started = time.monotonic()
    try:
        validated = ssrf_guard.validate_agent_url(url.split("#", 1)[0])
    except Exception as exc:
        return False, None, f"rejected by SSRF policy: {type(exc).__name__}", 0

    allowed = set(validated.get("public_ips") or [])

    try:
        async with httpx.AsyncClient(
            timeout=DELIVERY_TIMEOUT_S,
            follow_redirects=False,   # see the module docstring
        ) as client:
            resp = await client.post(
                validated["url"], json=payload,
                headers={"Content-Type": "application/json",
                         "User-Agent": "HB-Eval/alerts"},
            )

            # Where did we actually connect? A mismatch means DNS moved between
            # validation and connection, and the response is not trusted.
            stream = resp.extensions.get("network_stream")
            if stream is not None and allowed:
                try:
                    peer = stream.get_extra_info("server_addr")
                    if peer and str(peer[0]) not in allowed:
                        ms = int((time.monotonic() - started) * 1000)
                        return False, None, "peer address not in validated set", ms
                except Exception:
                    pass

            ms = int((time.monotonic() - started) * 1000)

            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                return False, resp.status_code, "redirect refused", ms

            ok = 200 <= resp.status_code < 300
            err = None
            if not ok:
                body = resp.text[:200] if len(resp.content) < MAX_RESPONSE_BYTES else ""
                err = f"HTTP {resp.status_code}{': ' + body if body else ''}"
            return ok, resp.status_code, err, ms

    except Exception as exc:
        ms = int((time.monotonic() - started) * 1000)
        # Type only. The message could contain the URL.
        return False, None, type(exc).__name__, ms


async def _load_webhooks(supabase: Any, to_thread: Any, user_id: str,
                         event_type: str, metric: Optional[str]) -> list[dict]:
    """Active destinations for this user that want this event."""
    def _q():
        return (supabase.table("webhooks")
                .select("id, destination, url, event_filter, metric_filter, "
                        "consecutive_failures")
                .eq("user_id", user_id).eq("is_active", True).execute())
    try:
        res = await to_thread(_q)
    except Exception as exc:
        logger.error("Webhook lookup failed for %s: %s", user_id, exc)
        return []

    out = []
    for w in (res.data or []):
        events = w.get("event_filter") or []
        if events and event_type not in events:
            continue
        metrics = w.get("metric_filter") or []
        # A metric filter only applies to breaches. Filtering halts by metric
        # would silently drop halts triggered by a custom signal, which carry
        # no metric at all — and a halt is the last thing to drop.
        if metric and metrics and metric not in metrics:
            continue
        out.append(w)
    return out


async def _record_and_send(supabase: Any, to_thread: Any, webhook: dict,
                           user_id: str, event: dict, ssrf_guard: Any) -> None:
    """Claim the alert, then send it. Claim first, on purpose.

    Inserting the ledger row BEFORE sending means the unique index decides who
    sends. If two Gateway instances race, one insert fails and that instance
    stops — so the alert goes out once even though nothing coordinates them.
    Sending first and recording after would let both through.
    """
    row = {
        "webhook_id": webhook["id"],
        "user_id": user_id,
        "session_id": event["session_id"],
        "agent_id": event["agent_id"],
        "event_type": event["event_type"],
        "metric": event.get("metric"),
        "metric_value": event.get("metric_value"),
        "threshold": event.get("threshold"),
        "step_index": event.get("step_index"),
        "delivered": False,
    }

    def _claim():
        return supabase.table("webhook_deliveries").insert(row).execute()

    try:
        res = await to_thread(_claim)
    except Exception:
        # Almost always the dedup constraint: this metric already alerted for
        # this session. Expected and correct, so it is not logged as an error.
        return

    delivery_id = (res.data or [{}])[0].get("id") if getattr(res, "data", None) else None

    payload = build_payload(webhook.get("destination", "generic"), event, webhook["url"])
    ok, status, err, ms = await _post(webhook["url"], payload, ssrf_guard)

    def _finish():
        if delivery_id:
            supabase.table("webhook_deliveries").update({
                "delivered": ok, "status_code": status,
                "error": (err[:500] if err else None), "duration_ms": ms,
            }).eq("id", delivery_id).execute()

        if ok:
            supabase.table("webhooks").update({
                "consecutive_failures": 0, "last_error": None,
                "last_status": status,
                "last_fired_at": datetime.now(timezone.utc).isoformat(),
                "total_delivered": (webhook.get("total_delivered", 0) or 0) + 1,
            }).eq("id", webhook["id"]).execute()
        else:
            fails = (webhook.get("consecutive_failures", 0) or 0) + 1
            update = {
                "consecutive_failures": fails,
                "last_error": (err[:500] if err else "unknown"),
                "last_status": status,
            }
            if fails >= MAX_CONSECUTIVE_FAILURES:
                # Disabled, with the reason recorded, so the owner sees why in
                # the dashboard rather than wondering where their alerts went.
                update["is_active"] = False
                update["auto_disabled_at"] = datetime.now(timezone.utc).isoformat()
                logger.warning(
                    "Webhook %s disabled after %d consecutive failures.",
                    webhook["id"], fails,
                )
            supabase.table("webhooks").update(update).eq("id", webhook["id"]).execute()

    try:
        await to_thread(_finish)
    except Exception as exc:
        logger.error("Webhook bookkeeping failed for %s: %s", webhook["id"], exc)


async def dispatch(supabase: Any, to_thread: Any, ssrf_guard: Any, *,
                   user_id: Optional[str], event: dict) -> None:
    """Send one reliability event to every destination that wants it.

    Fails silently by contract. An alerting failure must never propagate into
    the monitoring path: a missed notification is a problem, and a monitoring
    endpoint that errors because Slack is down is a worse one.
    """
    if not supabase or not user_id:
        return
    try:
        hooks = await _load_webhooks(
            supabase, to_thread, user_id,
            event["event_type"], event.get("metric"),
        )
        if not hooks:
            return
        await asyncio.gather(*[
            _record_and_send(supabase, to_thread, w, user_id, event, ssrf_guard)
            for w in hooks
        ], return_exceptions=True)
    except Exception:
        logger.debug("Alert dispatch failed", exc_info=True)
