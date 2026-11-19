"""
Harness for testing the REAL SDK client against the REAL Gateway application.

Only the two external services are replaced: Supabase (a small in-memory stand-in that stores the agents
table and records every other write) and Redis (fakeredis, so the nonce guard and the rate limiter run
for real). Everything between the SDK's `evaluate()` and the Gateway's response is genuine code:
encryption, signing, header parsing, signature verification, replay protection, decryption, validation,
the engines, plan gates and response shaping.
"""
import base64, hashlib, os, sys, time
from types import SimpleNamespace

MASTER = bytes(range(64, 96))                       # the Gateway's master AES key (test value)
os.environ.setdefault("AES_KEY", base64.b64encode(MASTER).decode())
os.environ.pop("SUPABASE_URL", None); os.environ.pop("SUPABASE_KEY", None)   # we install our own stub
os.environ["DEV_MODE"] = "false"
os.environ.setdefault("OBSERVATORY_SALT", "")

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (os.path.dirname(HERE),):
    if p not in sys.path: sys.path.insert(0, p)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def seal_secret(secret: bytes) -> str:
    """How the Gateway stores a per-agent secret: base64(nonce[12] || AES-GCM(master, secret))."""
    nonce = os.urandom(12)
    return base64.b64encode(nonce + AESGCM(MASTER).encrypt(nonce, secret, None)).decode()


class Result(SimpleNamespace):
    pass


class Query:
    """A chainable stand-in for a supabase-py query builder."""
    def __init__(self, db, table):
        self.db, self.table, self.filters, self.op, self.payload = db, table, {}, "select", None
        self.rpc_name = table[4:] if table.startswith("rpc:") else None

    def __getattr__(self, name):                      # order, limit, gte, in_, range, single ... all chain
        def chain(*a, **k): return self
        return chain

    def select(self, *a, **k): self.op = "select"; return self
    def eq(self, col, val): self.filters[col] = val; return self
    def insert(self, payload, **k): self.op, self.payload = "insert", payload; return self
    def upsert(self, payload, **k): self.op, self.payload = "upsert", payload; return self
    def update(self, payload, **k): self.op, self.payload = "update", payload; return self
    def delete(self): self.op = "delete"; return self

    def execute(self):
        self.db.calls.append((self.table, self.op, dict(self.filters), self.payload))
        if self.rpc_name is not None:
            rows = self.db.rpc_results.get(self.rpc_name, [])
            return Result(data=rows, count=len(rows))
        if self.op == "select" and self.table == "agents":
            rows = [r for r in self.db.agents if all(r.get(k) == v for k, v in self.filters.items())]
            return Result(data=rows, count=len(rows))
        return Result(data=[], count=0)


class FakeSupabase:
    def __init__(self): self.agents, self.calls, self.rpc_results = [], [], {}
    def table(self, name): return Query(self, name)
    def rpc(self, name, params=None): return Query(self, f"rpc:{name}")
    def add_agent(self, api_key, aes_key, signing_secret, **extra):
        row = dict(id="agent-uuid-1", user_id="user-uuid-1", plan_type="pro", evaluation_limit=100000,
                   evaluations_this_month=0, evaluations_today=0, last_reset_date="2000-01-01", last_eval_date="2000-01-01",
                   is_active=True, api_key_hash=hashlib.sha256(api_key.encode()).hexdigest(),
                   aes_key_encrypted=seal_secret(aes_key), hmac_secret_encrypted=seal_secret(signing_secret))
        row.update(extra); self.agents.append(row); return row
    def writes(self, table, op=None):
        return [c for c in self.calls if c[0] == table and (op is None or c[1] == op)]


class Bridge:
    """Routes `requests.post` into the ASGI app, so HBEvalClient talks to the Gateway with no socket."""
    def __init__(self, test_client, base="https://gateway.test"):
        self.client, self.base, self.calls = test_client, base, []

    def __call__(self, url, json=None, headers=None, timeout=None, **kw):
        path = url[len(self.base):] if url.startswith(self.base) else url
        self.calls.append((path, dict(headers or {}), json))
        return self.client.post(path, json=json, headers=headers)
