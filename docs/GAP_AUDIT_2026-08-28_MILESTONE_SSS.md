# Gap Audit — Milestone SSS (2026-08-30)

**Scope:** Milestone QQQ's own recommendation #1 — port
`evidence-retry.spec.ts` (dev-stack-only) to the test-stack profile,
closing the error/retry parity gap between the two failure shapes
already covered: Milestone QQQ handled the upload-**request**-stage
failure (MinIO); this handles the **parse**-stage failure (OpenSearch),
the one `evidence-retry.spec.ts` already proved works on the dev stack.

---

## What shipped

- `frontend/e2e/TestStackOpenSearchFaultInjector.ts`: new class, targets
  `kronos-test-opensearch-1` via the shared `ContainerFaultInjector` base
  (Milestone QQQ). Kept as a separate class from `TestStackFaultInjector`
  (MinIO) rather than widening either it or `ContainerFaultInjector` to
  handle multiple named targets per instance — `ContainerFaultInjector`
  is deliberately single-target by design (matches
  `DevStackFaultInjector`'s own shape exactly), and this is the normal,
  intended use of multiple thin subclasses sharing one base, not the
  "duplicated core logic" anti-pattern Milestone PPP's lesson warned
  against.
- `frontend/e2e/evidence-parse-retry.spec.ts`: the test-stack analogue
  of `evidence-retry.spec.ts`, identical structure by design — same real
  dependency-failure shape (intake never touches OpenSearch at all, only
  parsing/indexing does, so stopping it *before* upload always lands
  cleanly on a retryable parse-stage `ERROR`, no race window to time,
  unlike MinIO's upload-request-stage failure Milestone QQQ had to
  design around differently).
- `.github/workflows/security-integration-tests.yml`: wired in as a 7th
  `frontend-e2e-smoke` step.

## Verification (CLAUDE.md §F)

1. New spec run alone against a freshly-built isolated stack (project
   `kronos-test`, no `-p` override, matching the real CI job exactly) —
   **passed** (~2.3 min, matching `evidence-retry.spec.ts`'s own
   documented dev-stack timing).
2. All 6 other specs re-run against the same stack to confirm no
   regression — **6 passed**.

Isolated stack torn down (`down -v --remove-orphans` + built-image
cleanup); live dev stack confirmed untouched throughout.

## A real methodology near-miss during this cycle's own verification

Running the other 6 specs immediately after step 1, several failed —
briefly looking like real regressions. They weren't: this cycle's own
local-verification override file (built fresh, not reused from
Milestone QQQ's) never published `postgres`'s or `keycloak`'s host
ports, so `KRONOS_E2E_POSTGRES_DSN`/`KRONOS_E2E_KEYCLOAK_URL` pointed at
`localhost:5432`/`localhost:18080` with nothing real behind them (or, in
the Postgres case, silently reaching whatever else happens to be
listening on the host's own `5432` — this host's live dev stack) —
**the exact same class of self-inflicted false-positive Milestone OOO's
own incident was about**, caught immediately this time via the specific
error messages (`org alias kronos-test not found`,
`password authentication failed for user "kronos"`) rather than chasing
a phantom bug, and fixed by publishing both ports and re-provisioning
(`keycloak-init` after recreating `keycloak`, whose `dev-mem` storage
doesn't survive a container recreate). Recorded here specifically
because it's a recurring trap in this initiative's own local-verification
practice, not a one-off — see the memory update alongside this doc.

## Status

`frontend-e2e-smoke` now runs all 7 specs in `frontend/e2e/` — real
error/retry coverage exists for both failure shapes (upload-request via
MinIO, parse-stage via OpenSearch) on both compose profiles (dev via the
original specs, test via Milestone QQQ/SSS's new ones).

## Recommendation for the next cycle

1. Heavy-parser CI coverage (carried since Milestone PPP) — add a
   `plaso-worker` service to `docker-compose.test.yml` mirroring dev,
   plus a heavy-format fixture sample.
2. `security-stack` also booting `kronos-backend`, RBAC access-denial
   specs, or `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 remain open.
3. Milestone RRR's own finding (no workflow in this repo has ever
   executed against this branch) is still unresolved and outside this
   initiative's tooling/authority — re-check periodically whether a
   merge or manual dispatch has happened, since that would be the first
   opportunity for a genuinely new class of confirmation (or failure)
   this initiative hasn't been able to observe yet.
4. Given every viable spec-coverage increment from the original research
   pass is now either shipped or explicitly scoped-out
   (`evidence-retry.spec.ts` itself remains dev-only by design), the
   next cycle may be a natural point for a fresh multi-scenario subagent
   assessment across the accumulated Milestones QQQ-SSS.
