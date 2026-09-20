# Gap Audit — Milestone NNN (2026-08-28)

**Scope:** Milestone MMM's own recommendation — `detection-triage.spec.ts`/
`detection-triage-race.spec.ts` as the next-cheapest CI increment (pure
Postgres/OpenSearch CRUD, no Celery needed), given the explicit "same
run-it-first treatment, don't assume it just works" instruction. It
didn't just work — one real, confirmed blocker found and fixed before
either spec could run against `docker-compose.test.yml` for the first
time.

---

## The bug

Both specs use `DetectionSeeder`, which shells out to a real Python
script (`frontend/e2e/fixtures/seed_detection.py`) that inserts through
the real `PostgresDetectionRepository`/`DetectionRiskScorer` domain code
rather than a hand-written INSERT (deliberate, documented design — stays
correct automatically if the schema changes). That script hardcoded two
values that only match `docker-compose.dev.yml`:

- `POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"`
  — `docker-compose.test.yml`'s own Postgres uses a different password
  AND database name (`kronos_test_password` / `kronos_test`, not
  `kronos_dev_password` / `kronos`), confirmed by reading both compose
  files directly rather than assumed.
- `DetectionSeeder.ts`'s own `seed()` defaulted `orgAlias` to
  `"kronos-dev"` (the dev stack's own `keycloak-init`-provisioned org).
  `docker-compose.test.yml`'s `keycloak-init` provisions `"kronos-test"`
  instead — a detection seeded under the wrong default org would never
  match the logged-in `case-lead` user's actual `org_id` on this profile.

A third value, `KEYCLOAK_INTERNAL_URL = "http://localhost:8080"`, is
correct for *either* profile alone (both publish Keycloak on host `8080`
unremapped) — not a real CI gap, since CI only ever runs one stack at a
time. It only became a problem for this milestone's own local
verification, which needed an isolated, differently-port-mapped instance
on a host that also has the real dev stack's Keycloak already holding
`8080`. Made overridable anyway for consistency and because it directly
unblocked local re-verification without touching the host's other stack.

## The fix

Three env-var overrides, matching the pattern already established by
`pythonFixture.ts`'s own `KRONOS_E2E_PYTHON`:

- `seed_detection.py`: `KRONOS_E2E_POSTGRES_DSN`, `KRONOS_E2E_KEYCLOAK_URL`
  (both default to the existing dev-stack values — no behavior change for
  any existing dev-stack run).
- `DetectionSeeder.ts`: `seed()`'s `orgAlias` default reads
  `process.env.KRONOS_E2E_SEED_ORG_ALIAS ?? "kronos-dev"` — same
  no-change-by-default guarantee.

`.github/workflows/security-integration-tests.yml`'s `frontend-e2e-smoke`
job: added `actions/setup-python@v5` + `pip install -e ".[dev]"` (copied
verbatim from the already-working `security-stack` job's own steps — this
job's earlier steps never needed Python before now, since
`DetectionSeeder`'s fixture script runs directly on the CI runner via
`execFileSync`, not inside a container). Set
`KRONOS_E2E_POSTGRES_DSN`/`KRONOS_E2E_SEED_ORG_ALIAS`/`KRONOS_E2E_PYTHON`
on the test-run step; `KEYCLOAK_URL` doesn't need overriding in CI itself
since there's no local-multi-stack-host collision there. Added both new
specs to the test command; `timeout-minutes` raised `40` → `45`.

## Verification (CLAUDE.md §F)

Same technique as every prior milestone in this initiative: isolated
Compose project, no host ports published for services Playwright reaches
via container IP, `--host-resolver-rules` for `kronos.local`, but this
time ALSO needed Postgres and Keycloak reachable from the host directly
(the Python fixture script runs on the host, not in a browser) — remapped
those two specifically (`15432:5432`, `18080:8080`) to avoid this host's
own live dev stack, which already holds the unremapped ports.

1. `detection-triage.spec.ts` alone against the isolated stack with the
   new overrides — **passed** (real org_id resolution logged, real
   detection seeded, real triage transition observed live + confirmed via
   a fresh independent API call).
2. `detection-triage-race.spec.ts` alone — **passed** (real two-context
   concurrent triage race: one real `200`, one real `409`, both tabs'
   UIs converged).
3. All four specs together (`login`, `evidence-upload`,
   `detection-triage`, `detection-triage-race`) against the same stack,
   with `celery-worker` also running — **4 passed**, no cross-spec
   interference, no regression to Milestone MMM's own upload work.

Isolated stack torn down (`down -v --remove-orphans` + built-image
cleanup); live dev stack (`docker ps`, project `docker`, 15 containers)
confirmed untouched throughout.

Not separately re-verified this cycle: a full fresh mirror of the exact
committed CI job's `pip install -e ".[dev]"` step specifically (as
distinct from the underlying spec-plus-env-var mechanism, which was
fully verified above). That exact command is copied verbatim from
`security-stack`'s own already-working, already-CI-proven step — judged
low-risk enough not to warrant standing up a fourth isolated stack for
this pass; flagged here explicitly rather than silently assumed, per
this initiative's own verification-first discipline.

## Status

Both detection-tier specs are real, verified, and CI-wired.
`frontend-e2e-smoke` now covers four of the six existing `frontend/e2e/`
specs: login (smoke), evidence-upload, detection-triage,
detection-triage-race (all flow-tier). Two remain unwired:
`evidence-retry.spec.ts` (deliberately, needs a test-stack-aware
fault-injection mechanism — see Milestone LLL) and
`cross-tenant-isolation.spec.ts` (needs a second Keycloak org provisioned
via `SecondOrgSeeder`, which has the identical hardcoded-DSN issue this
milestone just fixed in `seed_detection.py` — not yet ported to
`seed_second_org.py`).

## Recommendation for the next cycle

1. **Checked, not just assumed**: `seed_second_org.py` (used by
   `SecondOrgSeeder`/`cross-tenant-isolation.spec.ts`) has no Postgres
   dependency at all — it's Keycloak-Admin-API-only, so this milestone's
   `POSTGRES_DSN` fix doesn't apply there. It does share the same
   `KEYCLOAK_INTERNAL_URL = "http://localhost:8080"` constant, but per
   this milestone's own finding that specific value is correct for either
   compose profile alone (both publish 8080 unremapped) and is only a
   problem for local multi-stack-host verification, not real CI. So
   wiring `cross-tenant-isolation.spec.ts` into CI is NOT blocked by the
   class of bug this milestone fixed — re-verify it directly (run it
   against an isolated test-stack first, per this initiative's own
   run-it-first discipline) rather than assuming either "it's fine" or
   "it has the same bug."
2. `evidence-retry.spec.ts` needs a real design decision (not just a
   wiring exercise): either a test-stack-aware fault-injection class
   alongside the dev-stack-only `DevStackFaultInjector`, or a different
   mechanism for forcing a retryable failure against this profile
   specifically.
3. Otherwise, `security-stack` also booting `kronos-backend`, a permanent
   concurrent-`/auth/refresh` regression spec, or
   `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 remain open per Milestone
   LLL's own still-standing recommendations.
