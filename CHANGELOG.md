# Changelog

## 2.13.0 (Gateway release that goes with hb-eval-sdk 2.13.0)

### Security
- **Authentication now fails closed.** With Supabase unconfigured and `DEV_MODE` off, the Gateway used to fall through to a
  development key that defaults to the empty string, using default AES and signing secrets that are public in the source,
  so any caller could authenticate. It now refuses every request (503), and empty bearer tokens are rejected (401).
- `ALLOWED_ORIGINS=*` is refused outside `DEV_MODE` (it combined with `allow_credentials=True` to reflect any Origin).
- Request bodies are limited (`MAX_BODY_BYTES`, default 5 MB); security headers are added to every response.
- The plaintext API-key lookup is behind `ALLOW_PLAINTEXT_API_KEY_LOOKUP` (default `true` to avoid locking out agents).
- Background work (usage metering, audit log, evaluation storage; 27 call sites) is tracked and drained on shutdown. It was
  fire-and-forget, so an unreferenced task could be garbage-collected mid-flight and its exceptions were reported nowhere.

### Protocol
- Wire protocol **2.7.0 → 2.8.0** (additive: the enforcement surface). **`MEASUREMENT_PROTOCOL_VERSION` stays 2.7.0** and is
  what passports are stamped with. Previously one constant served both.
- Every response advertises `X-HBEval-Protocol`; a major mismatch is refused (400), a minor mismatch is served with a warning.
- `/health` reports `protocol_version` and `measurement_protocol_version` (and keeps `version`).

### Added
- Opt-in enforcement API (`/api/v1/enforce/decide|result|evidence`), mounted only when `HBEVAL_ENFORCE_API_KEY` is set.
- End-to-end tests of the real SDK client against the real application; an API-surface contract test.
- `LICENSE` decision pending; `SECURITY.md`, `CONTRIBUTING.md`, `Dockerfile`, `.env.example`, hash-pinned `requirements.lock`, CI.

### Fixed
- `requirements.txt` pinned `cryptography<44`, which cannot be installed with `hb-eval-sdk>=2.13` (`cryptography>=50`).
- `README.md` documented `/api/v1/evaluate` (the path is `/evaluate`) and "Version 1.0".

### Compatibility
- Found by the end-to-end test: the SDK's typed `evaluate()` crashed on `INSUFFICIENT_DATA`, this Gateway's normal answer for
  an agent with no faults. Fixed in `hb-eval-sdk` 2.13.0. Older SDKs still work with this Gateway.
