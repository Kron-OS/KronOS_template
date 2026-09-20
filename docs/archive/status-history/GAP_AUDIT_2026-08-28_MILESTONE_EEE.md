# Gap Audit — Milestone EEE (2026-08-28)

**Scope:** continuation of the frontend↔backend connectivity initiative
(started 2026-08-28, see `docs/PLAYWRIGHT_E2E_TEST_PLAN.md`). This cycle:
landed §5 items 2-4 of the E2E delivery order (real specs, real bugs found
and fixed), then — per the cycle's own instructions — ran a multi-scenario
subagent assessment once that implementation had landed, and closed out
the highest-priority findings from it.

---

## Part 1 — E2E delivery order, items 2-4

Already committed individually (`68ab052`, `fc55ed4`, `1605a2a`,
`a173426`); summarized here for the consolidated record.

- **Item 2 (upload-to-COMPLETE):** passed. Found a real, reproduced (not
  flaky) Playwright cross-file worker collision — two specs logging in as
  the same shared `case-lead` account at nearly the same instant caused a
  genuine Keycloak auth rejection. Fixed via `workers: 1`.
- **Item 3 (Retry button):** closed the exact gap
  `poc/evidence_parse_retry/README.md` had left open. Found a **real
  product bug**: `useEvidenceSSE` permanently closes its SSE stream once
  evidence first reaches a terminal state and never reopens it, so a
  successful retry recovered silently on the backend with the UI frozen on
  the stale error forever. Fixed via a `kronos:sse-reconnect` CustomEvent
  bridge.
- **Item 4 (detection triage, real half):** real NEW→INVESTIGATING
  transition, confirmed live and via an independent API call. Found (not
  fixed — a design question, not a bug) that `PostgresDetectionRepository.stream_by_org`
  sorts ascending by `synced_at`, so freshly-seeded detections land on the
  last page of `/detections` given this repo's accumulated PoC history;
  worked around via direct per-detection navigation.

Full four-spec suite (login + evidence-upload + evidence-retry +
detection-triage) confirmed passing together in one run.

---

## Part 2 — Multi-scenario subagent assessment

Three subagents dispatched in parallel, each given a distinct real-world
lens on the same code (the new E2E infra + the SSE-reconnect fix):
security, maintainability, and adversarial coverage-gap probing.

### Security scenario — 1 real, verified finding

**Confirmed live**: `docker-compose.dev.yml` and `docker-compose.test.yml`
both defaulted to the identical Compose project name (`docker`, derived
from the shared `docker/` directory — no explicit `name:` anywhere,
confirmed via `docker compose config` on both). Running both on the same
host (e.g. a live dev stack up alongside `make test-integration`) would
have Compose treat them as the SAME project and silently recreate the
live dev containers to match `test.yml`'s differing service definitions —
a real container-collision hazard this session's own
`DevStackFaultInjector.ts` (which does real `docker stop`/`start
docker-opensearch-1`) implicitly depends on NOT happening.
**Fixed**: explicit `name: kronos-dev` / `kronos-test` / `kronos-prod`
added to all three compose files.

**Real, self-inflicted incident during the fix, corrected same session**:
applying that fix and then running a routine `docker compose -f
docker-compose.dev.yml build/up nginx` (the exact redeploy command used
throughout this cycle) against the *already-running* legacy stack
triggered precisely the class of hazard just described — Compose read the
new `name: kronos-dev`, treated it as a different project from the
already-running `docker`-named one, and attempted to stand up a second,
parallel stack, hitting a real port collision (`0.0.0.0:9000` already
bound by the running `docker-minio-1`) before most of the new containers
started. **No data loss or downtime**: the failed `up` only got as far as
`Created` (never `Started`) on the new-named containers before aborting;
the entire live `docker`-named stack was untouched throughout, confirmed
via `docker ps` before and after. Cleaned up the orphaned `Created`
containers (`docker rm`), then completed the intended nginx redeploy by
explicitly pinning `-p docker` to keep targeting the real running project.
**A loud, permanent operator warning was added directly in
`docker-compose.dev.yml`** next to the `name:` line: any compose command
against this host's already-running stack must pass `-p docker`
explicitly until a deliberate, owner-approved `down`/`up` cutover happens
(not scriptable unattended — Postgres/MinIO/OpenSearch data volumes are
also project-name-scoped, so a naive cutover starts from empty volumes,
losing weeks of accumulated real dev/PoC data).

Two other scenarios probed, both clean: the new `kronos:sse-reconnect`
window CustomEvent adds no real attack surface (ticket-issuance is already
fully authenticated; dispatching the event without valid auth achieves
nothing an XSS couldn't already do directly). Credential hygiene in the
new test fixtures (`kronos-backend-secret`, dev user passwords) is
consistent with 40+ existing `poc/*` scripts and the compose files' own
long-standing defaults — not a new or worse exposure.

### Maintainability scenario — 3 findings, all deferred to a future cycle

1. **`workers: 1` + one shared account won't scale.** Measured: 4 specs
   take 2.7 min serialized, ~85% of it one fault-injection spec
   (`evidence-retry`). Extrapolated to the plan's full ~20-spec scope:
   7-14 minutes even after splitting specs across `DEV_USERS`, since
   fault-injection specs (targeting one shared, process-wide container)
   can never safely parallelize regardless of account. Real problem,
   worth fixing before the suite grows much further (`storageState` auth
   reuse + separating "flow" vs "fault-injection" Playwright projects) —
   not fixed this cycle, noted in `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` for
   the next infra pass.
2. **TS+Python dual toolchain has undocumented seams.** The
   reuse-over-drift trade-off itself is sound; the operational gaps
   (hardcoded `~/venv/bin/python3` default, zero README, no CI mention)
   are real onboarding/CI blockers. Recommendation for §3.4/§3.5's next
   fixtures: don't repeat the ad hoc script pattern a third time —
   consolidate into one documented dispatcher or drop the second
   interpreter. Not addressed this cycle.
3. **Early page-object duplication, cheap to fix now, expensive later.**
   `fetchDecodedAccessTokenClaims`/`fetchRealTriageStateFromApi` are
   near-duplicate token-fetch blocks; `watchEvidenceStateLive`'s
   `seedState` guard (added reactively after 3 failed runs) isn't
   generalized — `detection-triage.spec.ts`'s own inline poll has no such
   guard, "safe today only by coincidence." Recommended: extract a shared
   `fetchJson()` helper and a generic `pollLiveText()` on `KronosPage`
   before the next ~15 specs land. Not addressed this cycle — flagged as
   the first thing to do before item 5 of the delivery order.

### Coverage-gap scenario — 1 real bug (fixed this cycle), 1 real gap (documented), 2 confirmed clean

**Real bug, ranked highest by the assessing subagent, fixed this
cycle:** a concurrent-triage race (two analysts triaging the same
Detection near-simultaneously) was correctly detected by the real
optimistic-concurrency check
(`PostgresDetectionRepository.update(..., expected_state=...)`,
`InMemoryDetectionRepository`'s equivalent) but surfaced as a **generic
503** (the global `StorageError` handler) — indistinguishable from a real
infrastructure outage — and the frontend's losing tab did not refetch on
error, leaving `TriageStatePill` and the same now-invalid action button
rendering the **stale pre-race state indefinitely**, produceable
repeat-failures with no path to the correct state short of a manual
reload.

**Fix, verified live, not just by source-reading:**
- `src/exceptions.py`: new `ConcurrentModificationError(StorageError)`.
- `src/adapter/repository/postgres_detection.py` /
  `src/adapter/repository/detection.py` (in-memory): raise the new,
  specific exception when `expected_state` was supplied and the row's
  real current state didn't match — not the generic `StorageError`.
- `src/external/fastapi_app.py`: new global handler → 409 (registered
  before/independent of the route's own catch, mirroring
  `StorageQuotaExceededError`'s existing precedent in the same file).
- `src/external/routes/detections.py`: explicit route-level catch → 409,
  documenting intent at the call site.
- `frontend/src/pages/DetectionDetailPage.tsx`: the triage mutation's
  `onError` now also invalidates the `['detection', detectionId]` query,
  so the loser's UI converges on the real current state instead of
  staying stale.
- New unit test (`tests/unit/application/test_routes_detections.py::test_concurrent_modification_returns_409_not_503`)
  exercises the real repository's real race-detection logic via a small
  wrapper that applies a second, real, already-committed transition
  inside the route's own `get_by_id()` call — not a mock.
- New real E2E spec (`frontend/e2e/detection-triage-race.spec.ts`): two
  real, independently-authenticated browser contexts race a real
  simultaneous triage POST against the real backend. **First run failed**
  — not because the backend fix was wrong (the real response codes were
  already correct: one 200, one 409, zero 503s), but because the running
  frontend hadn't been rebuilt/redeployed with the `DetectionDetailPage.tsx`
  fix yet. Rebuilt and redeployed (via the `-p docker`-pinned command,
  see Part 2's security finding above), re-ran — **passed**: real 200 +
  real 409 (verified via `page.on('response')` on both contexts), zero
  503s, both browser contexts' UI converged on the real `Investigating`
  state, including the loser's.
- Full regression reconfirmed after all of the above: backend
  `pytest tests/unit tests/integration` (2049 passed, 2 skipped, 0
  failures — including 275 detection-related tests), frontend
  `npm run build`/`npm run test` (103/103)/`npm run lint` (0 errors), and
  all five E2E specs together (login + evidence-upload + evidence-retry +
  detection-triage + detection-triage-race) passing in one 2.6-minute run.

**Real gap, documented, not fixed this cycle (design question, not a
clear bug):** multi-tab session inconsistency. The access token lives
only in an in-memory per-tab store with no `BroadcastChannel`/storage-event
cross-tab sync (confirmed: zero hits for either anywhere in
`frontend/src`). Each tab runs its own Keycloak instance and its own
silent-refresh timer scheduled off its own token's expiry. A "logout" in
one tab does not notify sibling tabs — because the refresh token lives in
a shared HttpOnly cookie, a backend-side logout does eventually cut a
sibling tab off, but only when that tab's own refresh timer next fires,
scheduled at `accessTokenLifespan (900s) - 60s` in the realm config — so
a tab left open elsewhere can keep reading/writing case, evidence, and
detection data for **up to ~14 minutes** after the user believes they've
logged out elsewhere. For a SOC/forensics tool where multi-tab is a
plausible real workflow, this is a real, user-visible gap, not
theoretical — added to `docs/PLAYWRIGHT_E2E_TEST_PLAN.md`'s open-items
list for a future cycle to scope properly (this is a design change —
cross-tab session sync — not a quick patch).

**Confirmed already correctly handled, no action needed:**
- The `kronos:sse-reconnect` fix's own edge case (user clicks Retry then
  immediately navigates away before the reconnect fires): traced the real
  current cleanup code — the effect's `cancelled` flag and listener
  removal correctly prevent both a leaked connection and a state update on
  an unmounted component. No real race.
- Error-catalogue coverage: every real backend `error_reason` (9 exact
  strings + 2 dynamic prefixes, cross-checked via
  `grep -rn "with_error(" src/`) has a legible, correctly-classified
  `ErrorCatalogue.tsx` entry. No silent fallthrough to a generic message.

---

## Part 3 — Updated open-items list

Superseding the equivalent list in `docs/PLAYWRIGHT_E2E_TEST_PLAN.md`
(also updated there directly):

- §5 delivery order items 5-7 (admin/org-settings — blocked on a real
  backend stub, dashboards-embed/resilience/a11y specs) and the §3.5
  cross-tenant UI isolation half of item 4 — not started.
- The `docker-compose.test.yml` CI-capability gap (no OpenSearch-security/
  TLS/Keycloak scaffolding) — not started, still the blocker for running
  any of this suite unattended in CI.
- Maintainability findings 1-3 above (suite runtime scaling, TS+Python
  toolchain documentation, page-object duplication) — recommend tackling
  #3 (cheap, mechanical) before adding the next batch of specs.
- Multi-tab cross-session sync gap — real, needs its own scoped design
  pass, not a quick fix.
- The dev-stack Compose project-name cutover (`docker`-named live stack →
  `kronos-dev`) remains explicitly un-executed, by design — an
  owner-approved decision, not something to automate.

## Recommendation for the next cycle

1. Quick maintainability win first (page-object `fetchJson()`/
   `pollLiveText()` extraction) — cheap now, compounds if deferred
   further per the assessment's own reasoning.
2. Then continue the E2E delivery order: §3.5 cross-tenant isolation
   (needs a second real org — bigger lift than triage was).
3. The `docker-compose.test.yml` CI-capability gap is the other large,
   disjoint piece of remaining work — real, verification-first
   infrastructure work in its own right (pin versions, PoC the security/
   TLS/Keycloak scaffolding against a real container before touching the
   shared file), matching how `docker-compose.prod.yml` was hardened in
   the prior DDD milestone.
