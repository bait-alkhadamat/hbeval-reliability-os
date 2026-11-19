# HB-Eval Gateway

The hosted service behind [HB-Eval](https://hbeval.com): it receives encrypted, signed evaluation requests from
the [`hb-eval-sdk`](https://pypi.org/project/hb-eval-sdk/) client, computes the reliability metrics server-side,
and returns a verdict. It also serves episodic memory (EDM), interpretability (HCI-EDM), signed agent passports,
the monitoring endpoints, and an MCP/OAuth surface.

> **Wire protocol 2.8.0 · measurement protocol 2.7.0.** These are different numbers on purpose; see
> *Protocol versions* below. Requires `hb-eval-sdk` 2.13 or newer.

## What it guarantees, and what it does not
- **The client never scores itself.** Metrics are computed here from the payload the SDK sends, so an agent cannot
  award itself a result.
- **Every request is encrypted (AES-256-GCM) and signed (HMAC-SHA256 under a separate secret)**, with a fresh nonce
  per request that is recorded in Redis, so a captured request cannot be replayed. If Redis is unavailable the nonce
  guard **fails closed**.
- **Authentication fails closed.** If the auth backend is not configured and `DEV_MODE` is off, every request is
  refused with 503. An empty bearer token is never valid.
- **`INSUFFICIENT_DATA` is not a pass.** When a metric cannot be measured (most often because no fault occurred) the
  answer says so, `tier` is null, and the unmeasured metrics are listed. Unmeasured values are `null`, never `0`.
- **It is not a certification body.** The metrics describe observed behaviour; they do not predict production failures.

## API
The committed contract is [`tests/api_surface.json`](tests/api_surface.json); CI fails if the surface changes without it.

| Area | Operations |
|---|---|
| Evaluation (encrypted, signed) | `POST /evaluate`, `/evaluate_battery`, `/evaluate_verified` |
| Evaluation (plaintext) | `POST /evaluate_plain` — **refused (403) unless `DEV_MODE`** |
| Memory and interpretability | `POST /api/v1/memory/retrieve`, `/api/v1/explain` |
| Monitoring | `POST /api/v1/monitoring/session`, `/stream`, `/trend`; `POST /api/v1/battery/preview` |
| Passports | `GET /api/v1/passport/key`, `GET /api/v1/passport/{agent_id}`, `POST /api/v1/passport/demo`, `/verify` |
| Observatory | `GET /api/v1/observatory`, `POST /api/v1/observatory/consent` |
| MCP / OAuth | `/mcp`, `/.well-known/*`, the OAuth endpoints |
| Health | `GET /health` |
| **Enforcement (off by default)** | `POST /api/v1/enforce/decide`, `/result`, `/evidence` — mounted only when `HBEVAL_ENFORCE_API_KEY` is set |

Every response carries `X-HBEval-Protocol`. A request declaring a different **major** protocol gets `400`; a different
**minor** is served with `X-HBEval-Protocol-Warning`; no header is served (older SDKs, curl).

### Protocol versions
- `PROTOCOL_VERSION` (**2.8.0**) is the *wire* protocol: which requests exist and how they are signed and shaped.
- `MEASUREMENT_PROTOCOL_VERSION` (**2.7.0**) is stamped into every passport's measurement fingerprint. Results under
  different values are not comparable, so it moves only when how a metric is computed moves, never because an endpoint
  was added. Raising it for 2.8.0 would have claimed a measurement change that did not happen.

## Configuration
Copy `.env.example`. Secrets belong in the host's secret store, never in the repository.

| Variable | Purpose |
|---|---|
| `AES_KEY` | **Required.** Master key sealing each agent's secrets in the database. The process refuses to start without it. |
| `SUPABASE_URL`, `SUPABASE_KEY` | Storage, auditing, usage metering. Without them the Gateway refuses all requests unless `DEV_MODE`. |
| `REDIS_URL` | Nonce guard and rate limiter. |
| `ALLOWED_ORIGINS` | Exact browser origins, comma-separated. **A wildcard is refused outside `DEV_MODE`.** |
| `MAX_BODY_BYTES` | Request size limit (default 5,000,000); larger bodies get `413`. |
| `ALLOW_PLAINTEXT_API_KEY_LOOKUP` | Default `true`: agents whose `api_key_hash` is not yet populated still authenticate. **Set `false` as soon as every agent has a hash**, so plaintext keys are no longer read. |
| `HBEVAL_ENFORCE_API_KEY` | Enables the enforcement API (≥ 24 chars). Callers send `X-HBEval-Enforce-Key`. |
| `PASSPORT_SIGNING_KEY`, `PASSPORT_KEY_ID` | Ed25519 key that signs passports. Keep it out of the database it signs. |
| `FORWARDED_ALLOW_IPS` | Proxy addresses whose `X-Forwarded-*` headers are trusted (default loopback). |
| `DEV_MODE`, `DEV_*` | Local development only. **Never set in production.** |

## Run
```text
pip install -r requirements.lock && pip install "hb-eval-sdk==2.13.0"     # reproducible, hash-pinned
python serve.py                                                          # reads PORT; see FORWARDED_ALLOW_IPS
```
```text
docker build -t hb-eval-gateway .                              # core
docker build --build-arg WITH_EMBEDDINGS=1 -t hb-eval-gateway .   # with episodic memory (adds PyTorch)
```
The image runs as a non-root user, uses hash-pinned dependencies, and has a `/health` healthcheck.
Episodic memory uses `all-MiniLM-L6-v2` (384-dimensional), imported lazily; without it the Gateway runs and memory
degrades to "not stored".

## Test
```text
pip install -r requirements-dev.txt && pip install hb-eval-sdk && pytest
```
`tests/test_e2e_sdk_gateway.py` runs the **real** SDK client against the **real** application, with only Supabase and
Redis replaced (see `tests/e2e_support.py`). It covers round trips, replay, tampering, wrong keys, plan limits,
protocol negotiation, and the fail-closed authentication paths.

## Security
See [SECURITY.md](SECURITY.md). Report vulnerabilities privately; do not open a public issue.

## License
**Not yet chosen.** Until a `LICENSE` file is added, all rights are reserved. (An earlier version of this README
marked the code private and confidential; that status is unchanged until the maintainer decides otherwise.)
