# Gap Audit — Milestone PPP (2026-08-29)

**Scope:** the second multi-scenario subagent assessment (security,
CI-reliability, real-world coverage-gap) run against Milestones
MMM/NNN/OOO's landed work, per this initiative's own cycle instructions.
Two concrete, cheap fixes applied; larger findings documented for the
next cycle.

---

## Fixed this cycle

### 1. Shared `KRONOS_E2E_*` config module (CI-reliability + coverage-gap both flagged this independently as top priority)

Both review agents converged on the same finding without seeing each
other's report: `seed_detection.py` (Milestone NNN) and
`seed_second_org.py` (Milestone OOO) each independently redefined
`KEYCLOAK_INTERNAL_URL = os.environ.get("KRONOS_E2E_KEYCLOAK_URL", ...)`.
That exact duplication is what let Milestone OOO's real incident
happen — one sibling script got the override, the other didn't, for an
entire cycle, and the gap wasn't caught until it caused a real, costly
debugging session chasing what looked like a Keycloak bug. Neither
review found any NEW instance of drift between the two copies (both
matched exactly by the time this review ran, since OOO's own fix used
the same pattern) — but both flagged that nothing structurally prevents
a third fixture script from reintroducing the same gap.

**Fixed**: new `frontend/e2e/fixtures/_e2e_env.py`, exporting
`KEYCLOAK_INTERNAL_URL` and `POSTGRES_DSN`. Both existing scripts now
import from it instead of redefining their own copy. Deliberately does
**not** add a "verify this is the intended stack" runtime assertion —
the actual risk this override exists for (a host running two stacks
side by side, both publishing Keycloak on the same unremapped port) is
a local multi-stack-host verification concern only; real CI never runs
two stacks at once, so there's nothing to assert against there, and
adding a check anyway would be validating a scenario that can't happen
in the only environment this code ships to (against CLAUDE.md's own
guidance). The fix for the local-verification case is procedural —
Milestone OOO's own lesson: print the resolved constant and look at it
before trusting an override took effect — not a new runtime check baked
into every fixture script.

Verified for real: both scripts' resolved constants printed correctly
after the refactor; both run successfully standalone against the live
dev stack; both run successfully through the real TypeScript
`execFileSync` path (`npx playwright test e2e/detection-triage.spec.ts
e2e/cross-tenant-isolation.spec.ts` against the live dev stack, 2
passed); a full isolated-test-stack mirror of the final CI job sequence
re-run with the refactored module, all 5 specs passing as 5 separate
steps (see fix #2 below).

### 2. Split the bundled 5-spec CI step into 5 separate steps (CI-reliability's other concrete finding)

`frontend-e2e-smoke`'s "Run the smoke + flow-tier..." step ran all 5
specs in one `npx playwright test <5 files>` invocation. The
CI-reliability review's concrete concern: a single bundled step means
one spec's failure is buried in list-reporter console output rather
than surfaced as its own red X in the GitHub Actions job summary — real
friction for whoever triages the first failure on a real GHA runner
(which this job has still never run on).

**Fixed**: split into 5 named steps (`E2E: login`, `E2E: evidence-upload`,
`E2E: detection-triage`, `E2E: detection-triage-race`,
`E2E: cross-tenant-isolation`), each its own `npx playwright test
<one file>`. Every step after the first uses `if: always()` — without
it, GitHub Actions' default behavior stops the whole job at the first
failing step, losing information about whether the *remaining* specs
would also have failed, exactly the wrong tradeoff for a job whose
purpose is diagnostic signal on an unproven profile. The job's overall
pass/fail conclusion is unaffected — it still fails if any step failed;
only the "stop early" behavior changes.

Verified for real: all 5 specs run as 5 separate `npx playwright test`
invocations (mirroring the exact new step structure) against a
freshly-built isolated stack, in sequence, matching the committed
workflow file exactly — all 5 passed.

## Documented, not fixed this cycle

### CI-reliability: `timeout-minutes` confidence has gone down, not up

The 25→35→40→45 progression across four milestones has never been
re-anchored to an actual measurement — the one real data point (MMM's
15.3s for 2 specs, warm cache) predates `pip install -e ".[dev]"` (NNN)
and a live Keycloak org-creation round trip (OOO), neither of which was
separately re-measured. Not fixed this cycle: there is no way to
actually measure this without a real GHA run, which this initiative
cannot trigger itself (nightly-schedule + manual-dispatch only, no PR
trigger). The next real signal will be this job's own first execution
on a real runner — until then, 45 minutes remains an informed guess,
now explicitly flagged as such rather than implied-improving via its
own upward trend.

### Coverage-gap: heavy parsers structurally unexercised

`evidence-upload.spec.ts` only exercises `CloudTrailParser`
(`ParserType.FAST`). `docker-compose.test.yml` has no `plaso-worker`
service at all, and `celery-worker`'s queues never include
`q.parse.plaso`. Every `ParserType.HEAVY` module (`PlasoParser`,
`ArchiveParser`, `TarArchiveParser`, `VolatilityModule`) would hit
**the exact same silent-accumulation failure mode as Milestone MMM's
bug #6** (evidence stuck non-terminally, zero error) if exercised
against this profile today — and nothing in CI would notice. This is
real and structural, not hypothetical, but closing it needs a new
`plaso-worker` service in `docker-compose.test.yml` (mirroring dev) plus
a heavy-parser-friendly fixture sample — medium-cost design work, not a
quick wiring pass, deliberately deferred rather than rushed.

### Coverage-gap: only happy-path error/retry coverage

`process_intake`'s own retry path (`max_retries=3`) and the
`auto_dispatch_received` beat-task recovery mechanism (CLAUDE.md §E.4)
are never exercised against this profile — all 5 wired specs are
happy-path only. Cheapest of the open items to close (per the
coverage-gap review's own prioritization): reuse the
`DevStackFaultInjector`-style pattern but target `q.intake`/MinIO
instead of OpenSearch, or force a `ValidationError` path.

### Coverage-gap: RBAC access-denial paths — already tracked, reconfirmed

Confirmed via code (`DEV_USERS.analyst`/`.admin` defined in
`frontend/e2e/fixtures.ts` but unused by any spec) that this remains a
real, zero-coverage gap — but it was already listed in
`docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.3/§3.4/§0.1 before this review, so
nothing new to add beyond confirming it still stands.

### Security: clean

No exploitable findings across all three milestones' changes. Confirmed:
no external trigger (`pull_request`/`pull_request_target`) exists on
`frontend-e2e-smoke`'s workflow, so none of the new `KRONOS_E2E_*` env
vars are externally influenceable; the MinIO CORS/public-endpoint/`:9444`
changes are byte-for-byte identical to the already-reviewed
`docker-compose.dev.yml` pattern; `celery-worker`'s new `q.intake` queue
introduces no isolation-boundary crossing (test-only profile); hardcoded
fixture credentials confirmed absent from `docker-compose.prod.yml`.

## Status

Two structural fixes landed (shared config module, per-spec CI step
attribution), both verified against a freshly-built isolated stack
mirroring the exact final committed workflow. Three real, larger-scope
gaps (heavy-parser coverage, error/retry-path coverage, RBAC-denial
coverage) are now explicitly tracked rather than implicit — the natural
input for the next planning cycle.

## Recommendation for the next cycle

In rough cost order, per the coverage-gap review's own prioritization:
1. A retry/error-path spec (cheapest) — reuse
   `DevStackFaultInjector`-style fault injection, targeted at
   `q.intake`/MinIO instead of OpenSearch.
2. Heavy-parser CI coverage (medium) — add `plaso-worker` to
   `docker-compose.test.yml`, mirroring dev, plus a heavy-format fixture
   sample.
3. `evidence-retry.spec.ts`'s still-open test-stack-aware fault-injection
   design (carried over from Milestone LLL/NNN/OOO).
4. Otherwise: `security-stack` also booting `kronos-backend`, RBAC
   access-denial specs, or `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8
   remain open per prior milestones' own still-standing recommendations.
