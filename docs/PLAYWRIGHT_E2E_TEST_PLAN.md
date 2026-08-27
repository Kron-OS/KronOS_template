# KronOS — Advanced Playwright E2E Test Plan

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_EEE.md` for the full account of
this cycle's multi-scenario subagent assessment** (security, maintainability,
adversarial coverage-gap review) run once items 2-4 below landed, including
a real concurrent-triage-race bug found and fixed
(`ConcurrentModificationError`, 409 not 503), a real Compose
project-name-collision security finding (fixed: explicit `name:` in all
three compose files — with a loud operator warning in
`docker-compose.dev.yml` about the already-running legacy-named stack),
and three maintainability findings queued for the next cycle (suite
runtime scaling, TS+Python toolchain docs, page-object duplication).

**Status (updated 2026-08-28, Gap Audit continuation):** partially proven,
not yet a maintained suite. Correcting this doc's own earlier "nothing
implemented yet" claim — untrue as of this update. Between this plan being
written and now, **six separate real-browser (Python Playwright) passes
already ran against the real dev stack** and proved most of §3's flow-tier
scenarios work at least once: `poc/keycloak_browser_login/` (real PKCE
login/logout), `poc/evidence_sse_realtime/browser_verify.py` (real upload →
live SSE status flip), `poc/detection_containment_ui/` (real step-up MFA
with real TOTP), `poc/detection_risk_score_ui/` (real triage UI),
`poc/evidence_download_ui/` (real download round-trip, hash-verified),
`poc/dashboards_embed/autoload_verification/` (real Dashboards iframe
embed, zero-click autoload). One more, `poc/frontend_theme_fix/`, used a
real browser but a **mocked** backend/auth harness — do not cite it as
end-to-end evidence for anything auth-related.

The maintained `frontend/e2e/` suite §1 below describes now exists and has
its first real, passing spec (§5 item 1, done) — this closes the "no
maintained suite" gap structurally, though only one of §3's many scenarios
is covered so far; the rest of §5's delivery order is still open. Before
this suite existed, all six real passes above were scattered, one-off
scripts, several of them fighting the same recurring friction (see the new
§0.1) independently instead of sharing
fixtures. This update's job is to promote that proven-but-scattered
coverage into the real suite, per §5's own delivery order, still following
CLAUDE.md's §F verification-first / OOP discipline: pin the real version,
build the smallest real thing first, capture real output, only then grow
the suite.

## 0. Where this starts from (verified facts, not assumed)

- `playwright` (Python) **1.61.0** is installed in this host's venv with
  `chromium-1228` cached and working — this is what all six real passes
  above actually used. **`@playwright/test` (the TypeScript runner) is a
  different story**: `frontend/package.json` lists a bare `playwright`
  (not `@playwright/test`) devDependency added incidentally by
  `frontend_theme_fix` — **but `frontend/node_modules/playwright` does not
  exist on a fresh checkout**, no `playwright.config.*` exists anywhere,
  and no `frontend/e2e/` directory exists. That `package.json` entry is
  dead weight, not a working install — §1 replaces it with a real,
  verified one rather than building on top of it.
- Real pages that exist today (`frontend/src/pages/`): `LoginPage`,
  `CasesPage`, `CaseDetailPage`, `DetectionsPage`, `DetectionDetailPage`,
  `AdminPage`. Real components: `UploadDrawer`, `EvidenceDetailDrawer`,
  `RbacGuard`, `AuthGuard`, `StatusPill`/`TriageStatePill`,
  `ErrorCatalogue`. **Correction: `UploadDrawer` is NOT Uppy/TUS** despite
  this doc previously saying so and `@uppy/*` sitting in `package.json`
  dependencies — `grep -rn uppy frontend/src` returns zero matches. The
  real, shipped mechanism is hand-rolled: client-side magic-byte + SHA-256
  pre-check, `POST /api/evidence/upload/request` for a single presigned
  PUT URL, a raw `XMLHttpRequest` PUT of the whole file, then
  `finalizeUploadWithHash()`. Six real-browser PoCs have exercised this
  exact real path successfully — treat the Uppy dependencies in
  `package.json` as unused residue, not as documentation of how upload
  actually works.
- Auth is real Keycloak 26.2 (`keycloak-js`), PKCE, with real step-up
  (aal2/TOTP) for privileged actions — any E2E suite touching admin/triage/
  destructive actions must drive the real step-up flow, not bypass it.
- `docker-compose.test.yml` (the CI-shaped compose file) currently
  **disables the OpenSearch security plugin and has no `step-ca`/
  `kronos.local`/`keycloak-init` scaffolding** (confirmed by I1's own
  investigation, `docs/NEXTGEN_SOC_ROADMAP.md` §I1) — meaning **no real E2E
  suite can run in CI today** without that infrastructure gap being closed
  first. This plan treats that as its own prerequisite item (§4), not
  something to route around with a mocked backend (mocking the backend
  would defeat the point of an E2E suite in a platform this session's own
  history shows breaks in exactly the seams between real services).

### 0.1 Recurring friction found independently by 3+ of the six real passes (fix once, in shared fixtures, not per-spec)

- **`kronos.local`'s step-ca leaf cert has a 24h TTL** and had expired mid
  session for both `poc/keycloak_browser_login/` and
  `poc/detection_containment_ui/`, each independently working around it
  with `docker compose ... up -d tls-init && docker restart docker-nginx-1`.
  A maintained suite needs a shared pre-flight fixture that checks/refreshes
  this once, not N specs rediscovering the same expired-cert error.
- **Org IDs churn across dev-stack recreations** (`poc/detection_risk_score_ui/README.md`
  flags this explicitly) — any fixture must resolve `org_id` live via the
  Keycloak Admin API at setup time, never hardcode a value copied from a
  previous session.
- **TOTP secrets are reusable** — `case-lead`'s real enrolled TOTP secret
  from `poc/detection_containment_ui/case_lead_totp_secret.txt` avoids
  re-enrolling on every run; a shared fixture should read/seed this once
  rather than each spec re-deriving it.

## 1. Framework choice: `@playwright/test`, not more Python scripts

**Decision: adopt `@playwright/test` (TypeScript) in `frontend/`, in a new
`frontend/e2e/` directory, as the maintained E2E suite. Keep
`poc/evidence_sse_realtime/browser_verify.py`-style Python scripts for what
they're good at (a one-off, throwaway verification during a bug-hunt) —
they are not a substitute for a suite that runs on every change.**

Why not keep extending the Python pattern:
- `@playwright/test` gets test isolation (fresh browser context per test),
  parallelization, trace/video-on-failure, and HTML reporting for free —
  all real, maintained-suite necessities the hand-rolled `check()`/`PASS`/
  `FAIL` pattern in `browser_verify.py` doesn't provide.
- It lives next to the frontend it tests, in the same TypeScript project,
  so it can import real frontend types (e.g. the `OrgSettings`/
  `EvidenceOut` interfaces) instead of re-deriving field-name contracts by
  hand — the exact class of bug (`evidenceId` vs `evidence_id`) that
  `browser_verify.py` was built to catch in the first place.
- CI-friendliness: `npx playwright test` is the standard, well-documented
  GitHub Actions integration; a Python-script suite would need its own
  bespoke runner/reporter.

Concretely: `npm install -D @playwright/test` (pin whatever the real
current 1.6x release is at implementation time — don't assume, check
`npm view @playwright/test versions` against the already-installed Python
1.61.0 so browser binary versions don't drift between the two), then
`npx playwright install --with-deps chromium` (start with one real browser,
add firefox/webkit only if a real cross-browser bug is ever found —
speculative multi-browser coverage is not worth the CI time cost up front).

## 2. Layered proof discipline (mirrors roadmap §2, applied to E2E)

Not every test is worth writing at the same depth. Three tiers:

- **Smoke (L1-shaped):** does the app boot, can a real user log in, does
  the shell render. Fast, run on every PR.
- **Flow (L2/L3-shaped):** a real, complete user journey against the real
  backend + real Keycloak + real OpenSearch/Postgres/MinIO (`docker-compose
  .dev.yml`, not a mocked API layer) — evidence upload to COMPLETE,
  detection triage, admin user management. These are the heart of the
  suite and should be the majority of test count.
- **Adversarial/isolation (L4-shaped):** two real tenants, one browser
  context each, proving the UI itself never leaks cross-tenant data —
  the browser-level analogue of `poc/global_l4_e2e/`'s own backend-level
  isolation assertions. Fewer of these, but non-negotiable given how
  central tenant isolation is to this platform (roadmap invariant #3).

## 3. Concrete test scenarios (the actual "advanced" list)

Grouped by area; each bullet is one real spec file's worth of scope, not
one test — a `describe` block, several `test()`s inside.

### 3.1 Auth & session
- Real PKCE login (happy path) → lands on `CasesPage`, real JWT claims
  reflected in the UI (org name, role-gated nav items via `RbacGuard`).
- Real step-up challenge: an aal1-only session attempting a privileged
  action (e.g. triage, admin user removal) gets the real step-up prompt;
  completing real TOTP unlocks it; a second attempt without re-entering
  TOTP is correctly one-shot (mirrors the backend's own ticket
  one-shot-consumption invariant, proven at the UI layer this time).
- Session expiry / token refresh mid-session (real short-lived token,
  wait for real expiry, confirm the UI's `axios` refresh-interceptor path
  works rather than silently logging the user out or looping).
- Logout clears real client-side state (no case/evidence data visible
  after logout+back-button).

### 3.2 Evidence lifecycle (the platform's core loop)
- Real case creation → real file upload via the actual `UploadDrawer`
  (hand-rolled presigned-PUT, not Uppy — see §0) → **no manual reload** → `StatusPill` transitions
  live via real SSE, UPLOADING → ... → COMPLETE (this is exactly what
  `browser_verify.py` proved once by hand; promote it into the suite so a
  future regression is caught automatically, not by another bug report).
  Fixture: a small real EVTX/CloudTrail sample already in
  `tests/fixtures/samples/`, not a synthetic blob.
  - Not part of this test's own assertions, but note the fixture choice
    should also exercise a client-side magic-byte pre-check path (a real,
    previously-found bug class — `docs/NEXTGEN_SOC_ROADMAP.md` mentions
    the frontend's magic-byte check missing E01 support at one point).
- A genuinely oversized/corrupt/unsupported file → real, correct error
  surfaced via `ErrorCatalogue`, not a silent hang.
- Retry-intake / retry-parse buttons: `docs/NEXTGEN_SOC_ROADMAP.md`'s own
  Part 1 table flags "a real browser click-through of the parse-stage
  Retry button *succeeding* ... is still unverified" — this is a named,
  already-known gap this plan should close, using a deliberately-broken
  dependency (e.g. temporarily point at a bad ClamAV host, or intercept the
  request) to force a retryable error, then click Retry, then confirm real
  recovery to COMPLETE.
- Legal hold toggle in the UI reflects the real backend state and blocks
  deletion (a real 409/403, not just a disabled button — click the
  disabled button's underlying action via the API directly in-test to
  confirm the *server*, not just the UI, enforces it).
- Evidence detail drawer: real hash values, real chain-of-custody audit
  entries rendered, matching a fresh `GET /api/audit` call made
  independently in the test (not trusted from the same page load).

### 3.3 Detections & triage
- `DetectionsPage` real list + filter by triage state, real ATT&CK tags
  rendered from real `Detection` rows (reuse data already seeded by this
  session's own `poc/detection_api_triage_ui/`-style real backend calls
  as fixtures, or seed fresh via the real API in a `beforeAll`).
- `DetectionDetailPage` → real triage transition (`NEW` → `INVESTIGATING`)
  via the UI, confirm `TriageStatePill` updates without reload, confirm
  independently via a real API call that the transition and its audit row
  actually persisted.
- Illegal transition attempt (a terminal-state Detection) → UI correctly
  disables/hides the action, not just relying on a 409 the user never sees.
- Role-gated triage: a read-only role's session sees no triage buttons at
  all (RBAC UI gating, not just a 403 experienced as a dead click).

### 3.4 Admin & org management
- Real user invite → real role assignment → real removal, each step
  confirmed via a fresh page load (not just optimistic UI state).
- Org settings page — **note for whoever implements this section**:
  `src/external/routes/admin.py`'s `OrgSettingsOut`/`update_org_settings`
  is currently a complete stub with no real persistence (confirmed
  2026-08-08, see the tenant-quota work landing alongside this plan) — an
  E2E test against it today would only be testing that stub, not real
  behavior. Sequence this test to land *after* real settings persistence
  ships (the storage-quota work is the first real consumer of that), not
  before, or it will be testing something intentionally fake.

### 3.5 Cross-tenant isolation at the UI layer (L4-shaped, small in count, high value)
- Two real orgs, two real browser contexts (Playwright's per-context
  isolation is exactly suited to this — no shared cookies/localStorage
  between them by construction). Org A's authenticated session, given
  org B's real case/evidence/detection ID typed directly into the URL bar,
  gets the real 404 (not a client-side redirect that merely *looks* like
  isolation) — the browser-level version of `poc/global_l4_e2e/`'s own
  backend isolation assertions.
- Confirm no org-B-identifying string (case title, evidence filename,
  detector name) ever appears in org A's rendered DOM at any point,
  including transient loading states.

### 3.6 Dashboards embed
- The real OpenSearch Dashboards iframe embed (`cases.py`'s
  `get_dashboard_url`) actually loads inside the app shell for a real case,
  with the real case's own timeline data visible — this closes the one
  open question `poc/dashboards_embed/` flagged as needing "a live browser
  to observe" and never got (per its own README).

### 3.7 Resilience / error states
- Backend temporarily unreachable (block the `/api/*` route at the
  Playwright network-interception layer) → the UI shows a real, legible
  error state, not a blank screen or an unhandled promise rejection in the
  console (assert on `page.on("pageerror")` staying empty across the
  scenario).
- SSE connection drop mid-upload → UI recovers (reconnects or falls back
  to a poll) rather than silently freezing the status pill forever.

### 3.8 Accessibility & visual (lighter-touch, still real)
- `@axe-core/playwright` real automated a11y scan on each of the 6 pages
  (not a subjective pass — a real, automated WCAG rule-set check, catching
  e.g. missing form labels, contrast issues in `StatusPill`/
  `TriageStatePill` color coding).
- Visual regression on the pill/badge components specifically (they encode
  meaning through color — `toHaveScreenshot()` snapshots catch an
  accidental Tailwind class change that silently breaks the color coding
  without breaking any functional assertion).

## 4. Prerequisite: a CI-capable, security-enabled compose profile

Every "Flow" and "Isolation" tier test above needs a real Keycloak +
OpenSearch (security enabled) + Postgres + MinIO stack, with the same
`kronos.local` HTTPS/step-ca scaffolding `docker-compose.dev.yml` has and
`docker-compose.test.yml` does not (I1's own finding, restated here because
it directly blocks this plan, not just I1's harness). Before any of §3.2
onward can run anywhere but a developer's own already-running dev stack,
someone needs to do the CI-wiring follow-up work I1 already scoped and
deferred: enable+verify the security plugin in a CI-shaped compose file,
add the TLS/Keycloak scaffolding, confirm the combined footprint fits a
GitHub Actions runner (or accept a self-hosted runner / nightly-only
schedule instead of per-PR, given OpenSearch+Keycloak startup time — I1's
own recommendation). **This is real, separate, verification-first work,
not a one-line CI config change — pin versions, PoC it, capture real
output, exactly like every other integration in this repo, before assuming
it works.**

Until that lands: Smoke-tier tests (§3.1's login/logout, page-boots-with-a-
mocked-401 style checks that don't need a full real backend) can
reasonably run against a lighter, backend-optional setup. Flow/Isolation
tiers should be documented as "run locally against `docker-compose.dev.yml`
before every release" as an interim, honest state — not silently skipped
with no record, and not claimed as CI-covered when they aren't.

## 5. Suggested delivery order (verification-first, smallest real thing first)

1. **[DONE 2026-08-28]** Stood up real `@playwright/test` 1.62.1 (pinned
   to match the already-installed Python 1.61.0 line as closely as npm's
   real published versions allowed) in `frontend/`, with
   `frontend/playwright.config.ts` and an OOP page-object suite
   (`frontend/e2e/pages/KronosPage.ts` base class, `LoginPage`,
   `CasesPage`) reusing the exact selectors
   `poc/keycloak_browser_login/run_poc.py` already proved
   (`#username`/`#password`/`#kc-login`, `text=Sign in with SSO`). One real
   spec, `frontend/e2e/login.spec.ts`, run for real against the live dev
   stack (`docker compose -f docker-compose.dev.yml`, already up) —
   **passed**: real PKCE login through Keycloak's real hosted form, lands
   on `/cases`, real client-side nav to `/detections` without a re-login
   prompt, real decoded access-token claims fetched via the app's own
   `/auth/refresh` cookie proxy. Two real, previously-unknown integration
   bugs found and fixed in the same pass: (a) Vitest's default include
   glob was also picking up `e2e/*.spec.ts` and failing trying to run
   Playwright's `test()` as a Vitest test — fixed via
   `vite.config.ts`'s `test.exclude`; (b) `oxlint`'s `react-hooks/rules-of-hooks`
   false-positived on Playwright's fixture `use()` callback param (not a
   React hook) — fixed via a new `.eslintignore` excluding `e2e/`. Also
   removed the residual, entirely-unused `playwright` (bare) devDependency
   and all five `@uppy/*` dependencies (confirmed zero real usage,
   `grep -rli uppy frontend/src` → nothing — see §0's correction) as a
   direct byproduct of getting this right rather than building on top of
   stale dependency residue. Full existing suite re-confirmed green after:
   `npm run build`, `npm run test` (101/101), `npm run lint` (0 errors, 1
   pre-existing benign warning).
2. **[DONE 2026-08-28]** §3.2's core upload-to-COMPLETE flow. Added
   `CaseDetailPage` (case creation, `uploadEvidence()`, and
   `watchEvidenceStateLive()` — polls the real evidence row's own text
   without reloading, exactly what proves the live SSE push path works)
   and `CasesPage.createCase()`, reusing the exact selectors
   `poc/evidence_sse_realtime/browser_verify.py` already proved. New spec
   `frontend/e2e/evidence-upload.spec.ts`, real fixture
   `tests/fixtures/samples/cloudtrail.json` — **passed**: real case
   creation, real upload, real live state transition to `Complete`
   observed without a reload. Found a real, reproduced (not flaky) bug in
   the same pass: Playwright runs separate spec *files* concurrently
   across workers by default even with `fullyParallel: false` (which only
   serializes within one file) — two specs each logging in as the same
   shared dev-seeded `case-lead` account at nearly the same instant caused
   a genuine Keycloak `"Invalid username or password"` rejection on the
   second login. Confirmed via `--workers=1` passing cleanly. Fixed by
   pinning `workers: 1` in `playwright.config.ts`, documented inline —
   this suite intentionally reuses one real shared fixture account per
   §0.1, so concurrent runs of it are never safe until specs are split
   across `DEV_USERS.caseLead`/`analyst`/`admin`.
3. **[DONE 2026-08-28]** §3.2's Retry-button spec — closes the exact
   already-named gap `poc/evidence_parse_retry/README.md` left open ("a
   real browser click-through of the Retry button succeeding ... was not
   worth burning further effort on" after selector/routing trouble).
   Added `DevStackFaultInjector` (`frontend/e2e/DevStackFaultInjector.ts`)
   reusing that same PoC's own proven trigger — stop real
   `docker-opensearch-1` before upload to force a real, transient
   `ERROR/ingest_failed`, restart it and wait for real `healthy`, then
   drive the real Retry button. New spec
   `frontend/e2e/evidence-retry.spec.ts`.
   **First three real runs found a genuine, previously-unknown product bug,
   not a test bug** (confirmed by cross-referencing real `celery-worker`
   logs showing the backend actually reached `finalize_evidence_done` while
   the UI stayed frozen on `Parsing`/stale `Error`): `useEvidenceSSE.ts`
   permanently closes its SSE stream the first time all evidence reaches a
   terminal state (`src/external/routes/sse.py`'s own "stop streaming once
   all evidence is terminal" `done` event) and had no mechanism to reopen
   it — so a successful retry recovered silently on the backend with the
   UI never finding out short of a manual reload. Real fix: `EvidenceDetailDrawer.tsx`'s
   retry mutation now dispatches a `kronos:sse-reconnect` CustomEvent
   (reusing the exact bridge pattern the existing `kronos:sse-poll`
   fallback already established) on success; `useEvidenceSSE.ts` listens
   for it and reconnects with a fresh ticket. Verified the fix by rebuilding
   and redeploying the real `docker-nginx-1` image
   (`docker compose -f docker-compose.dev.yml build nginx && ... up -d nginx`)
   and re-running the spec against the real running dev stack — passed,
   real live recovery to `Complete` observed without a reload. Also fixed
   a real, reproduced bug in `CaseDetailPage.ts`'s own `watchEvidenceStateLive()`
   test helper along the way: re-watching a row already sitting on a
   terminal state (re-watching after Retry) read the *stale* terminal text
   on its first poll and returned immediately, before the backend had done
   any work — added a `seedState` parameter so only a genuine transition
   away from the seeded state counts. Added unit coverage
   (`EvidenceDetailDrawer.test.tsx`) for the event-dispatch side of the fix
   (the reconnect side itself is only realistically provable against a
   real `EventSource`/backend, which the E2E spec covers). Full suite
   reconfirmed: `npm run build`, `npm run test` (103/103), `npm run lint`
   (0 errors), all three E2E specs together (`login` + `evidence-upload` +
   `evidence-retry`, serialized) passing in one run.
4. **[DONE 2026-08-28, triage half only]** §3.3's core triage transition
   (NEW -> INVESTIGATING). New `frontend/e2e/fixtures/seed_detection.py`
   seeds a real Detection for the E2E suite, reusing two already-proven
   patterns rather than re-deriving them: live `org_id` resolution via
   Keycloak Admin REST (`poc/detection_containment_ui/setup.py`'s own
   pattern — org_id churns across dev-stack recreations, confirmed
   unchanged from `poc/detection_risk_score_ui/`'s original but resolved
   live regardless, not hardcoded) and insertion through the real
   `PostgresDetectionRepository`/`DetectionRiskScorer` domain code
   (`poc/detection_risk_score_ui/seed_detection.py`'s own pattern) rather
   than hand-written SQL, so it can't silently drift from the real schema.
   `frontend/e2e/DetectionSeeder.ts` wraps it (`execFileSync`, parses its
   JSON stdout). New `DetectionDetailPage`/`DetectionsPage` page objects,
   new spec `frontend/e2e/detection-triage.spec.ts` — real click-through
   of "Start Investigating", confirmed both live in the DOM (`expect.poll`,
   no reload) and independently via a fresh real
   `GET /api/detections/{id}` call per this section's own requirement.
   **Real, reproduced finding along the way**:
   `PostgresDetectionRepository.stream_by_org` sorts ascending by
   `synced_at` (not descending) — a freshly-seeded detection lands on the
   LAST page of `/detections` (default `pageSize=50`), not the first, given
   this repo's accumulated PoC history has seeded far more than 50 real
   detections into `kronos-dev` over time. Not fixed (untested whether
   ascending is intentional, e.g. "oldest unresolved first" triage
   priority) — worked around by having `DetectionDetailPage.openById()`
   navigate directly to the real per-detection URL instead of paging
   through the list, which is also more realistic for what this spec
   actually tests. Full suite reconfirmed: `npm run build`, `npm run test`
   (103/103), `npm run lint` (0 errors), all four E2E specs together
   (`login` + `evidence-upload` + `evidence-retry` + `detection-triage`,
   serialized) passing in one 2.7-minute run.
   §3.5 isolation still open (needs a second real org — bigger lift,
   deferred to the next item).
5. §3.4 admin/org-settings — sequenced after real settings persistence
   ships (see the note in §3.4).
6. §3.6 dashboards embed, §3.7 resilience, §3.8 a11y/visual — lower
   urgency, pick up opportunistically.
7. §4's CI-wiring prerequisite can be tackled in parallel with 1-3 (it's a
   disjoint infra surface) so the suite isn't blocked waiting on it to
   start being written, only on it to start running unattended.

Each numbered item above should land as its own PoC-first pass (a
throwaway proof that the exact Playwright API/selector strategy works
against the real running app, captured output, per CLAUDE.md §F) before
being folded into the permanent `frontend/e2e/` suite — no different from
how every backend integration in this repo has been built this session.
