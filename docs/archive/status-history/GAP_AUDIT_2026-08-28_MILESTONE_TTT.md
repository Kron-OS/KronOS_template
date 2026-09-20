# Gap Audit — Milestone TTT (2026-08-30)

**Scope:** the third multi-scenario subagent assessment (security,
CI-reliability, real-world coverage-gap — same pattern as Milestones
EEE, PPP) run against Milestones QQQ, RRR (docs-only), and SSS's landed
work. Two concrete, cheap fixes applied and verified; larger findings
documented for the next cycle.

---

## Fixed this cycle

### 1. `ContainerFaultInjector.ensureRunning()` never actually waited for health (CI-reliability review's own finding)

The `finally { injector.ensureRunning() }` pattern every fault-injection
spec uses (`evidence-retry.spec.ts`, `evidence-upload-storage-outage.spec.ts`,
`evidence-parse-retry.spec.ts`) is the last line of defense restoring a
deliberately-broken dependency. Reading it closely: it only checked
`.State.Status == "running"` and returned immediately — never
`.State.Health.Status`. A container is `running` from the instant
`docker start` launches it, but MinIO/OpenSearch's own real startup work
(OpenSearch's security-plugin demo-cert provisioning in particular) can
still be in progress for seconds afterward. Since every spec in
`frontend-e2e-smoke` runs as a separate, sequential CI step against one
shared, never-recreated stack, a genuinely possible failure mode existed:
a spec that crashed between `stop()` and its own `restartAndWaitHealthy()`
would leave `ensureRunning()` to "restore" the container — but
returning the instant `docker start` fired, before the dependency was
actually ready, would let the NEXT spec in the same job start against a
still-warming-up dependency, producing a misleading cascading failure
instead of one clear root cause.

**Fixed**: `ensureRunning()` now reuses the same health-polling loop
`restartAndWaitHealthy()` already had, and is `async` (every call site
updated to `await` it). Verified for real, not just by re-reading the
diff: ran the exact declared CI step order —
`evidence-upload-storage-outage` immediately followed by
`evidence-parse-retry`, as two separate `npx playwright test`
invocations (matching real CI step boundaries, not one combined
command) — against a freshly-built isolated stack. Both passed. Also
re-ran the other 5 specs (no regression) and the dev-stack
`evidence-retry.spec.ts` (shares the same fix via `DevStackFaultInjector`
→ `ContainerFaultInjector` — still passes, ~2.6min, matching its own
documented timing).

### 2. No committed local-verification override — the exact process risk that caused Milestone OOO's incident and recurred in Milestone SSS

Coverage-gap review flagged this directly: two separate cycles
(Milestones OOO and SSS) each independently hand-built a throwaway
`/tmp` override file for the same purpose — verify
`docker-compose.test.yml` against a real isolated stack on this
multi-stack host without colliding with the live dev stack — and each
time forgot to publish a port a host-side Python fixture script needed,
reproducing the exact false-positive class Milestone OOO's own incident
was about.

**Fixed**: `docker/docker-compose.test.local-verify.override.yml`, a
committed, documented, reusable override with a full usage walkthrough
in its own header comment (which ports, why those specific ones and not
others, the exact env vars each spec category needs, and the reasoning
for reaching nginx via container IP rather than a published port). Used
it for real this cycle (see verification above) rather than just writing
it and hoping — this is the first time this initiative's own
local-verification tooling has itself been committed and reused instead
of rebuilt from memory each cycle.

## Documented, not fixed this cycle

### CI-reliability: `timeout-minutes` re-derived, not just re-bumped

The number had been raised twice before (35→40→45) without ever being
tied to real per-step ceilings — flagged directly as "headroom is
asserted, not demonstrated." Re-derived this time: the two
fault-injection specs' own explicit worst-case timeouts
(`evidence-upload-storage-outage`: 2min, `evidence-parse-retry`: 7min —
Celery's real `max_retries=3` @ 30s + up to 90s OpenSearch health-wait)
had never been folded into the job-level number at all. Raised
`45` → `55` specifically to account for that 9-minute combined ceiling
explicitly, on top of the review's own pessimistic-but-bounded ~20-29min
estimate for the rest of the job. The genuinely unbounded risk (Docker
Hub pull-rate limiting, cold-build time with no BuildKit/GHA cache
configured) is NOT something any fixed timeout number can fully protect
against — that's mitigated instead by the `cancelled()`-handling and
full-log-capture already in place (Milestone LLL), not by this number.
First real GHA run remains the only way to get an actual measurement
(Milestone RRR).

### Coverage-gap: intake-stage retry has zero E2E coverage

Both new fault-injection specs stop their dependency *before* upload
starts — a clean, deterministic failure. A dependency going down
*mid*-intake (after `finalize_upload`, before `_promote()` completes)
hits Celery's own automatic retry first (up to ~90s with no client-visible
error), and only on exhaustion lands in a client-visible, retryable
`ERROR` via the real `retryIntake()`/`retryAction: 'intake'` path
(`frontend/src/api/evidence.ts`, wired in `EvidenceDetailDrawer.tsx`) —
currently exercised only by a mocked unit test, never a real E2E spec.
This is exactly the racier scenario Milestone QQQ explicitly declined to
build a flaky test for; the underlying gap remains real and is now
explicitly named rather than left implicit.

### Coverage-gap: no spec covers two dependencies down at once, or degraded-not-down

`ContainerFaultInjector` is deliberately single-target; a real
simultaneous MinIO+OpenSearch degradation, or a slow/timing-out (not
hard-refused) dependency, would exercise different code paths
(`parse_artefact_heavy`'s `time_limit`/`soft_time_limit`) than any
current spec's `docker stop`-produced immediate connection-refused.

### Security: clean

No exploitable findings across QQQ/RRR/SSS. Confirmed: every
`execSync` container-name interpolation in `ContainerFaultInjector` and
its subclasses uses only hardcoded constructor literals, never
caller/env-supplied input; the `assertExpectedProject()` label check has
no realistic bypass given how this code is actually invoked (a CI
runner or a developer's own Docker-controlling host); `docker/docker-compose.prod.yml`
and all of `src/` remain completely untouched by this diff range. One
low-severity DX note (not fixed): a hard-killed local `npx playwright
test` run (not CI, where the job-level teardown always runs) has no
automatic recovery for a container left stopped — self-inflicted,
local-only, easily recovered by re-running `docker compose up`.

## Status

Both concrete, verifiable findings from this cycle's assessment are
fixed and verified against a real, freshly-built isolated stack — the
`ensureRunning()` health-wait gap (a genuine correctness fix in shared
test infrastructure) and the missing committed local-verification
override (a genuine process-risk fix, now used for real by this very
cycle's own verification). The `timeout-minutes` number is on firmer,
evidence-grounded footing without pretending to have solved the
genuinely unmeasurable cold-GHA-run risk. Three real, larger-scope
coverage gaps remain explicitly tracked, not fixed.

## Recommendation for the next cycle

1. Heavy-parser CI coverage (carried since Milestone PPP) — add a
   `plaso-worker` service to `docker-compose.test.yml` mirroring dev,
   plus a heavy-format fixture sample.
2. Intake-stage retry E2E coverage (this cycle's own new finding) — a
   real design question (how to force a mid-intake, not pre-upload,
   dependency failure reliably), not a quick wiring pass.
3. `security-stack` also booting `kronos-backend`, RBAC access-denial
   specs, or `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 remain open.
4. Periodically re-check Milestone RRR's finding (no workflow has ever
   run against this branch) — a merge or manual dispatch would be a
   genuinely new class of signal this initiative hasn't had yet.
