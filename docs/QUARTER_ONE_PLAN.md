# HB-Eval V2 — approved first 90 days
Owner: Abuelgasim Mohamed Ibrahim Adam. Baseline adopted 2026-11-19.
Scope changes must be recorded with rationale. Days are relative to kickoff. Record actual results separately from targets.

| Days | Deliverable | Exit evidence |
|---|---|---|
| 1–5 | Pin and reconcile SDK, Gateway, platform, database and deployment sources. Build in clean environments and run baseline and integration tests. | Identifiable commits, archive checksums, repeatable commands, pass/fail/skip counts, mapping of actual deployed sources and unresolved differences. |
| 6–15 | Version the action evidence contract: tested action, dependencies, conditions, immutable versions, outcome source and required test. Model APPLIES, RETEST and UNKNOWN separately from permission. | Refund and shipment example, shared dependency control, lost response after commit and worker restart; independent tool ledger. Register metrics and held-out cases before tuning. |
| 16–30 | Local and CI release check: compare baseline and candidate, explain affected actions and restoration test, emit human and machine readable results; cover legacy and incomplete inputs. | External developer reproduces a result within 30 minutes; explicit CI policy. |
| 31–45 | Connect SDK, Gateway, Sidecar, tenant-scoped durable evidence and platform review page. Handle late, duplicate and concurrent requests. | Reviewable migrations, two-tenant isolation checks, Vercel preview, end-to-end audit including restart. |
| 46–60 | Compare against full evaluation, trajectory-based selection and customer rules on held-out scenarios. | Report misses, unnecessary suspensions, sample sizes, uncertainty, revalidation cost/time and decision P95/P99. Target 30% lower time or cost subject to pre-agreed error ceiling. |
| 61–75 | Shadow evaluation across real partner updates. Define independent ground truth and preserve unknown outcomes. | Document correctness and false alarms. In shadow mode measure recommendation quality; in enforcement mode verify physical tool effect. |
| 76–90 | Limited opt-in enforcement where a partner explicitly authorizes scope. Verify rollback, restart, outages, retention, key rotation and support. | Release pinned to source, actual deployment verified, rollback evidence, technical/commercial go-or-revise decision. |

## Adoption evidence
Interview 12 teams; seek three deidentified cases from two organizations, including cost, incumbent solution and budget owner. Targets: five independent teams reach first result, two reuse on a second release, one paid pilot. External outreach requires approval of recipients and message. Treat internal data and customer results separately.

## Operating rules
Use existing repositories, small reviewed changes, tests and preview before production. Verify the actual production database and Gateway before migrations or deployment. Seek explicit approval for destructive production changes, new spend, first public release of a private component, or live effects beyond customer scope.

## Baseline evidence, November 19
- SDK and Gateway 2.13.0 archive manifests verified (264 and 50 entries). SDK archive: 1049 passed, 5 skipped. Gateway archive: 149 passed with test infrastructure. Conformance 20/20; mutation checks 6/6.
- SDK PR https://github.com/hb-evalSystem/sdk/pull/1 merged: six fixture tests for declared action scope. These fixtures do not establish real-world fitness.
- Gateway main snapshot 877f10a: 23 tracked files. Relative to the archive manifest 18 match, five differ and 27 archive entries are absent. Production SHA and Railway service binding remain open.
- Vercel platform production previously mapped to 7af8230. Supabase schema was readable; binding to production still needs independent confirmation.
