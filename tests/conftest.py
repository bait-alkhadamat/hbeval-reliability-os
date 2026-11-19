import base64, os, sys
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]
SDK = os.environ.get("HB_EVAL_SDK_PATH")
if SDK and SDK not in sys.path:
    sys.path.insert(0, SDK)

import e2e_support as S                                  # noqa: E402  (sets the environment before gateway is imported)

API_KEY = "hb_test_key_0123456789"
AGENT_AES = bytes(range(32))
SIGNING = bytes(range(32, 64))


@pytest.fixture()
def world(monkeypatch):
    """A running Gateway (real code) with a fake Supabase holding one agent, fakeredis, and an SDK client bridged to it."""
    import fakeredis.aioredis as fr
    import gateway
    from fastapi.testclient import TestClient
    import requests
    from hb_eval_sdk.client import HBEvalClient

    db = S.FakeSupabase(); db.add_agent(API_KEY, AGENT_AES, SIGNING)
    monkeypatch.setattr(gateway, "_supabase", db)
    monkeypatch.setattr(gateway, "_DEV_MODE", False)
    monkeypatch.setattr(gateway.aioredis, "from_url", lambda *a, **k: _async_value(fr.FakeRedis(decode_responses=True)))
    monkeypatch.setattr(gateway, "_retention_loop", _idle_loop)
    with TestClient(gateway.app, base_url="https://gateway.test") as tc:
        bridge = S.Bridge(tc); monkeypatch.setattr(requests, "post", bridge)
        b64 = lambda b: base64.b64encode(b).decode()
        def make_client(**kw):
            kw.setdefault("api_key", API_KEY); kw.setdefault("aes_key", b64(AGENT_AES)); kw.setdefault("signing_secret", b64(SIGNING))
            kw.setdefault("gateway_url", "https://gateway.test"); kw.setdefault("max_retries", 0)
            return HBEvalClient(**kw)
        yield type("World", (), dict(gateway=gateway, db=db, http=tc, bridge=bridge, make_client=staticmethod(make_client),
                                    api_key=API_KEY, aes=AGENT_AES, signing=SIGNING))


async def _async_value(v): return v
async def _idle_loop():
    import asyncio
    await asyncio.sleep(3600)
