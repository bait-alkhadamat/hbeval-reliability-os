# Production platform reconciliation and refund recovery, 2026-11-20

## Deployed client

1. Vercel identifies [the READY production deployment](https://vercel.com/hb-evalsystems-projects/hbeval-platform/2itKZpKRPTUbKpkDMT2g5FxdMkvZ) as the deployment for www.hbeval.com. Its Git source is [hb-evalSystem/hbeval-platform at 7af8230](https://github.com/hb-evalSystem/hbeval-platform/commit/7af8230999a4156bc9caaf96eb12d5c55af8c985).
2. The [production login page](https://www.hbeval.com/login) serves [this client bundle](https://www.hbeval.com/_next/static/chunks/app/login/page-f61b99083dafe00c.js). Its public Supabase hostname is `rpxcndjxcmukkzmutytp.supabase.co`.
3. The Supabase project URL API independently returned that exact HTTPS origin for [project rpxcndjxcmukkzmutytp](https://supabase.com/dashboard/project/rpxcndjxcmukkzmutytp). The project inventory reported ACTIVE_HEALTHY in eu-north-1.

This verifies the deployed login client's configured endpoint. Server-side Gateway database binding, Railway deployment identity and a successful end-to-end transaction remain unverified.

## Isolated action evidence

[PR 15](https://github.com/bait-alkhadamat/hbeval-reliability-os/pull/15) covers loss after commit and reopening SQLite. [PR 16](https://github.com/bait-alkhadamat/hbeval-reliability-os/pull/16) adds the shipment and shared-dependency controls. Both were open at verification. The new [process-restart test](../tests/test_refund_worker_restart.py) runs against PR 16 head `a782e06024ce031051186a1e2d6ede98aee933bf`. A spawned process commits a synthetic receipt and exits with code 23 before replying. The caller observes UNKNOWN without evidence. A second spawned process opens the ledger read-only, finds one matching operation and assesses APPLIES. The test exercises evidence recovery only.

Reproduce from repository root:

```sh
python -m unittest discover -s tests -p test_refund_worker_restart.py -v
```

Local result: 1 passed, 0 failed, 0 skipped. The two pre-existing pytest modules were not run locally because pytest was unavailable. No live action or deployment was performed.
