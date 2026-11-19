"""enforcement_mount.py — mounts the enforcement surface on the production
Gateway, OFF by default and authenticated when on.

WHY THIS EXISTS (authored in this tree)
    enforcement_api.router carries no authentication of its own: it was built
    as transport for the Sidecar/Platform bridge and proven in a closed
    harness. Mounting it bare on a public Gateway would let any caller read
    evidence for any agent_id and submit forged results. So:
      * it mounts only when HBEVAL_ENFORCE_API_KEY is set (>= 24 chars);
      * every request must carry X-HBEval-Enforce-Key, compared in constant
        time;
      * if the SDK is not installed it stays off and says so — it never
        pretends enforcement is available.
    This is a shared-secret stopgap. Workload identity / mTLS between the
    Sidecar and the Gateway remains an open deployment requirement.
"""
from __future__ import annotations
import hmac, logging, os
from typing import Optional

log = logging.getLogger("hb-eval-gateway")
MIN_KEY_LEN = 24


def mount(app, env: Optional[dict] = None) -> dict:
    env = os.environ if env is None else env
    key = env.get("HBEVAL_ENFORCE_API_KEY", "")
    if not key:
        return {"enforcement_api": "disabled", "reason": "HBEVAL_ENFORCE_API_KEY not set"}
    if len(key) < MIN_KEY_LEN:
        log.error("HBEVAL_ENFORCE_API_KEY shorter than %d chars; enforcement API stays OFF", MIN_KEY_LEN)
        return {"enforcement_api": "disabled", "reason": "key too short"}
    try:
        from fastapi import Depends, Header, HTTPException
        import enforcement_api as api
    except ImportError as exc:
        log.error("enforcement API unavailable (hb-eval-sdk missing?): %s", exc)
        return {"enforcement_api": "disabled", "reason": "hb-eval-sdk not importable"}

    async def _require_key(x_hbeval_enforce_key: str = Header(default="")):
        if not hmac.compare_digest(x_hbeval_enforce_key.encode(), key.encode()):
            raise HTTPException(status_code=401, detail="enforcement key required")

    app.include_router(api.router, dependencies=[Depends(_require_key)])
    return {"enforcement_api": "enabled", "reason": None}
