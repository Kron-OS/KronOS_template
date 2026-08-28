# Gap Audit — Milestone LLL (2026-08-28)

**Scope:** the multi-scenario subagent assessment (security, CI-reliability,
real-world coverage-gap — same pattern as Milestone EEE) run against
Milestone JJJ + KKK's landed work, per this initiative's own cycle
instructions ("once implementation lands, spawn assessment subagents
across different real-world scenarios, collect their reports, and turn
gaps into the next plan iteration"). Three parallel subagents; findings
below, fixes applied where cheap and concrete, gaps documented for the
next cycle where not.

---

## Fixed this cycle

### 1. Real, previously-unguarded safety-rule violation risk: `DevStackFaultInjector.ts`

Coverage-gap review flagged: `frontend/e2e/DevStackFaultInjector.ts`
hardcodes the container name `docker-opensearch-1` (the real dev stack's
own Compose project naming). Not currently triggered — `evidence-retry.spec.ts`
is only ever run against the live dev stack today, its documented,
intended target — but nothing in the code enforced that assumption. If a
future cycle wires flow-tier specs (this one included) into a
`docker-compose.test.yml`-based CI job, as Milestone KKK's own
recommendation suggests doing incrementally, this exact class, unmodified,
would either fail to find a same-named container under the test profile's
own distinct project name (Milestone EEE already gave each compose file
its own `name:` to prevent collisions) or — on a shared host running both
stacks side by side, which CLAUDE.md explicitly authorizes for this
initiative — could silently reach into the **live dev stack's** OpenSearch
container instead of an isolated one, a direct violation of CLAUDE.md's
"never touch containers you didn't create" rule.

**Fixed**: added `assertDevStackProject()`, checking the target
container's real `com.docker.compose.project` label matches `"docker"`
before any stop/start, called at the top of every public method. Verified
for real: ran `ensureRunning()` against the actual live dev stack's
`docker-opensearch-1` — guard passed (label confirmed `docker` via direct
`docker inspect`), method completed normally, no regression to its
existing, intended use.

### 2. CI-reliability: `frontend-e2e-smoke`'s failure diagnostics would silently no-op on the most likely first-failure mode

CI-reliability review's top finding: `timeout-minutes: 25` cancels
(doesn't fail) the job if the cold, multi-image-build stack overruns —
GitHub Actions treats a timeout-cancelled job as `cancelled`, not
`failed`, so `if: failure()`-gated steps (the log dump, the report
upload) silently do not run. Given this job does strictly more than the
adjacent `security-stack` job (which the workflow's own header comment
already flags as having unmeasured GHA cold-pull risk) for only 5 more
minutes of budget, and has never run on a real GHA runner yet, this was
assessed as the single most likely first-real-run failure mode — and the
one where diagnostics would be missing.

**Fixed**:
- `timeout-minutes: 25` → `35`, with an inline comment explaining this is
  still an unmeasured guess, budgeted above the lighter job's own
  known-unmeasured figure, not a confirmed number.
- Both diagnostic steps changed from `if: failure()` to
  `if: failure() || cancelled()` — applied to `frontend-e2e-smoke`'s new
  steps AND retrofitted to the pre-existing `security-stack` job's own
  log-dump step, which had the identical latent gap.
- `docker compose logs --tail=200` (thin across 9 real services — easily
  consumed by one chatty service's own startup logging, truncating
  exactly the nginx/tls-init/kronos-backend lines most likely to hold the
  real signal) replaced with a full, untrimmed dump written to a file and
  uploaded as its own `compose-logs` artifact.
- `npx playwright test e2e/login.spec.ts --reporter=list` → dropped the
  `--reporter=list` override entirely, since it was silently discarding
  `playwright.config.ts`'s own configured `html` reporter (the CLI flag
  replaces, not adds to, the config's reporter list). A failing run now
  gets the real HTML report (traces, screenshots) uploaded, not just the
  raw `test-results/` directory. Verified for real: ran
  `npx playwright test e2e/login.spec.ts` with no CLI override against
  the live dev stack — passed, and `frontend/e2e-report/index.html` was
  genuinely produced.

## Documented, not fixed this cycle (real, but lower urgency or larger scope)

### Security review (two low-severity findings, no exploitable issue found)

1. The new `frontend-e2e-smoke` job's on-failure trace upload
   (`trace: "retain-on-failure"` in `playwright.config.ts`, pre-existing)
   can capture a real minted Keycloak JWT for the `case-lead` test login
   inside the trace zip. Low practical impact: the same job's mandatory
   `if: always()` teardown destroys the issuing Keycloak instance and its
   signing keys before the 7-day artifact retention window means anything
   — the token is unverifiable/unusable by the time it could be
   downloaded. Not fixed this cycle (would need header/cookie redaction
   tooling for marginal benefit against a short-lived, self-destructing
   token); worth remembering if this trace-on-failure pattern is ever
   reused against a longer-lived or shared stack.
2. `KC_PROXY_HEADERS: xforwarded` (added Milestone JJJ) makes Keycloak
   trust `X-Forwarded-Proto` from anyone who can reach its still-published
   `:8080` host port directly, theoretically bypassing the realm's
   `sslRequired: "external"` check for a spoofed already-HTTPS request.
   Assessed as not exploitable in this profile as configured (Keycloak's
   own internal/loopback classification already treats this network as
   internal regardless of headers; this is single-tenant CI/test infra).
   Worth a one-line warning comment if this exact config is ever copied
   into a genuinely shared/multi-tenant network — not done this cycle to
   avoid comment bloat on an already-heavily-commented service block.

Confirmed (no action needed): `docker-compose.prod.yml` untouched by any
commit this initiative has made; `verify=False`/`ignoreHTTPSErrors`
remain confined to test/PoC code; `KC_HOSTNAME` pinning (Milestone JJJ)
is a correctness fix eliminating a previously-broken, not previously-protective,
state — `KeycloakTokenValidator` independently enforces both issuer and
audience unchanged by that diff; no fork-PR trigger exists on the new
job (`schedule`/`workflow_dispatch` only), so no secret-exfiltration path
via a malicious PR.

### Coverage-gap review (real gaps for the next planning cycle, not bugs in what shipped)

1. **The exact refresh-token race Milestone III fixed isn't re-exercised
   by CI.** `login.spec.ts`'s two `/auth/refresh` calls (bootstrap +
   `fetchDecodedAccessTokenClaims()`) are sequential, never concurrent —
   a regression reintroducing the two-independent-callers bug could ship
   silently past both CI jobs. Only the mocked Vitest unit test
   (`frontend/src/__tests__/keycloak.test.ts`) locks in the mechanism
   today.
2. **`security-stack`'s own "both real consumers coexist" proof was a
   manual verification, not something nightly CI itself re-runs.** That
   job never boots `kronos-backend` at all — it validates JWTs with a
   hand-built `KeycloakTokenValidator` in the test file itself, not the
   app's own DI-wired one. Milestone JJJ's claim that both consumers
   (browser-via-nginx and the pytest suite's direct `:8080` path) coexist
   was proven in an ad hoc manual stack that did include `kronos-backend`;
   nightly CI's only real check against the backend's own JWT-config path
   is `frontend-e2e-smoke`'s single non-racing login.
3. **`celery-worker` isn't brought up by `frontend-e2e-smoke`.** Wiring
   `evidence-upload.spec.ts`/`evidence-retry.spec.ts` in next as Milestone
   KKK's own recommendation suggested "incrementally" would hang/timeout
   today — parsing never progresses past `RECEIVED` without the worker.
4. **Python-fixture specs need infrastructure this job doesn't set up**:
   `SecondOrgSeeder.ts`/`DetectionSeeder.ts` shell out to a real Python
   venv with backend deps installed; the job only runs `setup-node`.
   `cross-tenant-isolation.spec.ts` also needs a second Keycloak org,
   provisioned only by `security-stack`'s separate step.
5. `tls-init`'s 1-day cert TTL is lower-risk than it might sound:
   `ignoreHTTPSErrors: true` + `curl -k` mean expiry doesn't currently
   break anything, and CI always does a fresh `up`/`down -v`. Real
   exposure is narrower (a locally kept-up stack surviving >24h, or a
   future strict-TLS check) than "known recurring friction" language
   elsewhere in this initiative's docs might suggest.

None of items 1-4 above are regressions from this cycle's work — they're
honest scope boundaries of a deliberately smoke-tier-only first CI job,
now explicitly named rather than left implicit.

## Verification

`DevStackFaultInjector.ts`: real `ensureRunning()` invocation against the
live dev stack's actual `docker-opensearch-1` container — guard passed,
no behavior change to the intended path. `tsc --noEmit` clean; `oxlint`
clean except one pre-existing, already-documented false positive in
`fixtures.ts` unrelated to this change.

Workflow: YAML re-validated (`python3 -c "import yaml; ..."`).
`npx playwright test e2e/login.spec.ts` re-run with the corrected
(no-override) reporter config against the live dev stack — passed, real
HTML report produced at `frontend/e2e-report/index.html`.

## Status

All three subagent reviews' concrete, cheap findings are fixed. The
larger-scope coverage gaps (items 1-4 above) are real and now explicitly
tracked rather than implicit gaps nobody wrote down — they're the
natural next planning cycle's input, not something this pass should have
rushed to close in one go.

## Recommendation for the next cycle

Per the coverage-gap review, in rough order of cost/value:
1. Add `celery-worker` to `frontend-e2e-smoke` and wire in
   `evidence-upload.spec.ts` as the next incremental flow-tier spec (per
   Milestone KKK's own recommendation) — but note it also needs the
   Python-fixture tooling gap (item 4) closed first if it uses
   `SecondOrgSeeder`/`DetectionSeeder`-style fixtures.
2. Consider whether `security-stack` should also boot `kronos-backend`
   directly (closing item 2) so nightly CI actually re-proves the "both
   consumers coexist" claim itself, not just a one-time manual pass.
3. If wanted, a real concurrent-`/auth/refresh` regression spec (closing
   item 1) — force two overlapping refresh calls in a real browser
   against a real Keycloak, the same technique Milestone III used to
   originally root-cause the race, promoted into a permanent CI check
   instead of a one-off diagnostic.
4. Otherwise, `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 (dashboards
   embed, resilience, a11y/visual) or Milestone EEE's still-open
   maintainability findings remain available.
