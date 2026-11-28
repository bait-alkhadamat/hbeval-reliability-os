# Production binding and shipment evidence, 2026-11-28

The [production alias](https://www.hbeval.com/login) resolved to [READY deployment 2itKZp](https://vercel.com/hb-evalsystems-projects/hbeval-platform/2itKZpKRPTUbKpkDMT2g5FxdMkvZ), built from [platform 7af8230](https://github.com/hb-evalSystem/hbeval-platform/commit/7af8230999a4156bc9caaf96eb12d5c55af8c985). The login document and its referenced [client bundle](https://www.hbeval.com/_next/static/chunks/app/login/page-f61b99083dafe00c.js) both returned 200. The bundle references the API hostname for [project rpxcndjxcmukkzmutytp](https://supabase.com/dashboard/project/rpxcndjxcmukkzmutytp). Read-only catalog inspection returned 23 public tables, including agents.

The [Railway gateway deployment log](https://railway.com/project/fe875c64-fd27-404b-b625-a00a3f8ee50e/service/4b509ce4-80b3-41cd-918b-5782994073f0?environmentId=32be1bd0-ee28-414a-adec-cec108422ff6&id=0c57ebb7-ed61-4169-9857-8e263a3e11fc) supplies the runtime evidence missing from [PR 23](https://github.com/bait-alkhadamat/hbeval-reliability-os/pull/23). On November 28 at 06:32:01.602108634 UTC the deployment resolved rpxcndjxcmukkzmutytp.supabase.co. At 06:32:10.917281214 UTC its HTTP client logged GET to that host and path /rest/v1/agents with HTTP/2 200 OK. Query parameters and response data are omitted. This verifies the observed gateway read path. Write paths and other endpoints are outside this observation.

## Isolated contract check

Based on [PR 24 at 3aac97e](https://github.com/bait-alkhadamat/hbeval-reliability-os/commit/3aac97e4d3d1159758cbfc914b4d07c57e5cbda3). The [new development test](https://github.com/bait-alkhadamat/hbeval-reliability-os/blob/13994a90ac38a16e7cd4cd667ca8deffb5896387/tests/test_shipment_carrier_restart.py) uses a simulated carrier. A spawned sender commits one shipment and a generated receipt to SQLite and exits with status 23. The surviving process opens a read-only connection and requires exactly one ledger row. Missing evidence gives UNKNOWN, a matching receipt and scope give APPLIES, a changed carrier version gives RETEST, and a receipt from another tenant gives UNKNOWN. These are evidence decisions only.

Python 3.12.14, isolated directory, focused unittest runs:

```sh
python -m unittest discover -s tests -p 'test_*worker*.py' -v
python -m unittest discover -s tests -p test_registered_cases.py -v
python -m unittest discover -s tests -p test_shipment_carrier_restart.py -v
```

Results in order: 2 passed, 1 passed (8 previously registered comparisons), 1 passed. Total 4 passed, 0 failed, 0 skipped. The new development case is separate from the frozen evaluation denominator. The broader pytest suite was not run because pytest is absent in this environment. No carrier API or Stripe operation was invoked. [PR 25](https://github.com/bait-alkhadamat/hbeval-reliability-os/pull/25) tracks a separate staged worker experiment.
