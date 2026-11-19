# Contributing to the HB-Eval Gateway

1. **Run the tests:** `pip install -r requirements-dev.txt && pip install hb-eval-sdk && pytest`.
2. **The API surface is a contract.** Adding, removing or renaming an operation fails `tests/test_api_surface.py` until
   `tests/api_surface.json` and `CHANGELOG.md` are updated in the same commit.
3. **Two protocol numbers.** `PROTOCOL_VERSION` moves with the wire format; `MEASUREMENT_PROTOCOL_VERSION` moves only when
   a metric's computation does. Never bump the second for a new endpoint.
4. **Fail closed.** A missing dependency, secret or backend must refuse requests, never relax a check.
5. **No fire-and-forget.** Use `_spawn()`, never a bare `asyncio.create_task()`; a test enforces it.
6. **No secrets in the tree.** Configuration comes from the environment; `.env.example` holds placeholders only.
7. **Say what a change does not do**, in the changelog entry.
