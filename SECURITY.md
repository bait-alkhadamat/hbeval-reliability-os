# Security Policy: HB-Eval Gateway

## Reporting a vulnerability
Email **abuelgasim.hbeval@outlook.com** with the affected version or commit, a minimal reproduction, and the impact
you believe it has. Please do not open a public issue for an unpatched vulnerability. We will acknowledge receipt and
tell you what we can and cannot confirm; we will not claim a fix we have not verified.

## What this service defends
| Threat | Control | Test |
|---|---|---|
| Replay of a captured request | Per-request nonce stored in Redis; **fails closed** if Redis is down | `test_e2e_sdk_gateway.py` |
| Forged or altered request | HMAC-SHA256 over nonce, timestamp and ciphertext under a separate secret, verified before decryption; AES-GCM authenticates the ciphertext | same |
| Stale request | Timestamp window | same |
| Anonymous access when the auth backend is missing | Authentication **fails closed** (503); empty bearer tokens refused | same |
| Cross-origin abuse | Exact-origin allow-list; a wildcard is refused outside `DEV_MODE` | same |
| Memory exhaustion by large bodies | `MAX_BODY_BYTES` by `Content-Length` and by streamed byte count | same |
| Framing, sniffing, caching, referrer leaks | Security headers on every response | same |
| Dropped billing or audit writes | Background tasks are tracked and drained on shutdown; failures are logged | same |
| SSRF through the verified-evaluation path | `ssrf_guard` resolves and rejects private/internal targets | `tests/` |
| Breakage between SDK and Gateway | The real client is run against the real app in CI | `test_e2e_sdk_gateway.py` |

## Known limits: read these
1. **Plaintext API keys may still be stored and read** while `ALLOW_PLAINTEXT_API_KEY_LOOKUP=true` (the default, kept only
   so the change that introduced the flag cannot lock out existing agents). Set it to `false` once every agent has an
   `api_key_hash`.
2. **The enforcement API uses a shared secret** (`X-HBEval-Enforce-Key`). That is a stop-gap; workload identity (mTLS)
   between the sidecar and the Gateway is still required for a real deployment. It is off unless the key is set.
3. **Enforcement state is held in memory** and is lost on restart until persistence (R11-C.4) lands.
4. **Dependencies are audited at build time, not forever.** CI re-audits weekly. "No known advisory" is not "no
   vulnerability", and this is automated analysis and testing, not an independent audit or penetration test.
5. The Gateway is only as trustworthy as its host: whoever holds `AES_KEY` and the database can read every agent's secrets.

## Supported versions
Security fixes target the current release only.
