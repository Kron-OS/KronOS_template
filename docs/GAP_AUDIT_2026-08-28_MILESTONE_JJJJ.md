# Gap Audit — Milestone JJJJ (2026-09-01)

**Scope:** closes `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.8 (accessibility &
visual regression), the last item in §3's scenario catalogue. Two real,
concrete things: a real, automated `@axe-core/playwright` WCAG scan on
every real page the app has, and `toHaveScreenshot()` visual regression on
the specific `StatusPill`/`TriageStatePill` elements (not full-page
screenshots), since those components encode meaning entirely through
color and would pass every existing functional assertion in this suite
even if a Tailwind class edit silently broke their color coding.

---

## Real page/component set used (verified against source, not the plan doc's own prose)

`docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §0 already lists the real pages
(`LoginPage`, `CasesPage`, `CaseDetailPage`, `DetectionsPage`,
`DetectionDetailPage`, `AdminPage`) — cross-checked directly against
`frontend/src/App.tsx`'s real route tree before writing anything: 6 routes
map 1:1 to those 6 pages (`/login`, `/cases`, `/cases/$caseId`,
`/detections`, `/detections/$detectionId`, `/admin/org` — `/admin/connectors`
/`ConnectorStatusPage` is a 7th real page not named in the plan's own list,
left out of scope this cycle, same reasoning as everything else the plan
doesn't name). Component names confirmed via `grep`, not assumed:
`frontend/src/components/StatusPill.tsx` (9 states) and
`TriageStatePill.tsx` (4 states) are the real, exact names.

## New dependency

`@axe-core/playwright@^4.13.0` (real current stable at implementation
time — checked `npm view @axe-core/playwright versions` against the
already-pinned `@playwright/test@^1.62.1`, peer dep `playwright-core >=
1.0.0`, compatible) added as a `frontend/` devDependency.

## 1. `frontend/e2e/a11y.spec.ts` — real automated WCAG scan, all 6 pages

`AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])`
against each real, authenticated (where applicable) page, asserting
`results.violations` is empty — a real rule-set check (missing labels,
color contrast, landmark structure, ...), not a subjective pass. Detections
pages are seeded with a real `Detection` first (`DetectionSeeder`) so the
scan covers real row content (pills, tags, links), not just empty-state
copy. The admin-page test logs in as the real dev-seeded `admin` account
(the only `Role.ORG_ADMIN` user) directly, since the shared
`casesPageAsCaseLead`/`casesPageAsAnalyst` fixtures don't cover that role.

### Real violations found and fixed (not weakened assertions)

Running this for real against the live dev stack found **3 real WCAG
violations**, all fixed:

1. **`color-contrast` (serious, WCAG AA), `Layout.tsx`'s org-alias span**
   (`/ kronos-dev` next to the username in the header). `text-gray-400`
   on white measured 2.6:1 — well under the 4.5:1 AA minimum for normal
   text; the `dark:text-gray-600` variant also failed (2.35:1 on the real
   dark background). Computed against Tailwind v4's real rendered hex
   values (`#99a1af` on `#ffffff`, etc.), not estimated. **Fixed** by
   swapping to `text-gray-600 dark:text-gray-400` — matching this same
   file's own established convention two lines above (line 57) — which
   passes both (7.56:1 light, 6.82:1 dark, computed the same way).
2. **`color-contrast` (serious, WCAG AA), `DetectionDetailPage.tsx`'s
   "not present" risk-factor placeholder.** Identical bug, identical fix
   (`text-gray-400 dark:text-gray-600` → `text-gray-600 dark:text-gray-400`),
   matching the same `<td>` classes two lines above in the same file.
3. **`select-name` (critical), `AdminPage.tsx`'s per-row role `<select>`.**
   4 real nodes (one per dev-seeded user row) with no accessible name at
   all — no `<label>`, no `aria-label`, nothing for a screen-reader user
   beyond "combo box". **Fixed** with `aria-label={`Role for
   ${user.username}`}`, naming each select from data already on the page
   rather than a generic label, no visible layout change.

All 3 fixes verified live: before the fix, the affected page's scan failed
with the exact violation printed above (not inferred, the real axe-core
JSON output); after, all 6 pages pass, confirmed twice (once standalone,
once as part of a 12-test regression alongside the visual spec).

### A real blocker found and fixed along the way: `admin` had no TOTP enrollment

The very first live run of the admin-page test hit a real, unrelated wall:
`docker/keycloak/kronos-realm.json`'s `admin` user ships with
`"requiredActions": ["CONFIGURE_TOTP"]`, and — confirmed directly via the
Admin API before assuming anything — this dev stack's live `admin` account
had never actually completed that enrollment (`"totp": false`, no `otp`
credential). The first real browser login attempt landed on Keycloak's own
interactive "Mobile Authenticator Setup" page instead of completing, and
`LoginPage.ts`'s existing `#username`/`#password`/`#kc-login` flow had no
way to get past it.

Investigated and fixed properly rather than special-cased for one account:
`docker-compose.test.yml`'s `keycloak-init` imports the exact same
`kronos-realm.json`, so a fresh CI stack would hit this identical wall on
*every* run, not just once — a one-time manual enrollment (which is what
`poc/admin_totp_enrollment/enroll.py` did first, reusing
`poc/auth_flow/auth_helpers.py`'s already-proven scripted-login TOTP
handling, mirroring `case-lead`'s own original enrollment precedent) would
not have survived a CI run. Built a real, general fix instead:
`frontend/e2e/totp.ts` (RFC 6238 TOTP, HMAC-SHA1/6-digit/30s-step, Node
`crypto` only — no new npm dependency) and
`LoginPage.ts`'s new `completeConfigureTotpIfPresented()`, which races
"already logged in" against "Keycloak showed the CONFIGURE_TOTP page" and
transparently completes the real form (parses `#kc-totp-secret-key` from
the manual view, computes a real code, submits) only when Keycloak
actually presents it — a no-op for every account that doesn't need it.
Verified end-to-end **twice**, live, with two disposable throwaway
`requiredActions: ["CONFIGURE_TOTP"]` Keycloak users driven through the
real `loginWithSso()` (both deleted afterward): first login completes
enrollment and reaches `/cases`; a second login with the same credentials
needs no OTP step at all (confirmed, not assumed — matches `case-lead`'s
already-relied-on behavior throughout this suite). Also confirmed this
doesn't regress any existing spec: `login`/`evidence-upload`/
`detection-triage`/`cross-tenant-isolation`/`rbac-access-denial`/
`case-membership-access-denial` all still pass using the same,
now-slightly-smarter `loginWithSso()`.

## 2. `frontend/e2e/visual-regression-pills.spec.ts` — pill/badge color regression

`toHaveScreenshot()` on the pill `<span>` element itself (never a
full-page screenshot), across every state that's directly, deterministically
reachable without heavy new infrastructure:

- **`TriageStatePill`, all 4 real states** (`NEW`/`INVESTIGATING`/
  `TRUE_POSITIVE`/`FALSE_POSITIVE`) — `DetectionSeeder.seedAtTriageState()`
  (new; `seed_detection.py` gained a `--triage-state` argument) seeds a
  real detection already at the target state via the real
  `PostgresDetectionRepository`, then the spec navigates directly to its
  detail page and screenshots the pill. A real bug in the spec itself (not
  the app) was found and fixed while building this: the first real run
  hit a hard timeout because these 4 tests used a bare, unauthenticated
  `page` fixture — `/detections/{id}` is behind `AuthGuard`, so it just
  silently redirected to `/login`, and the pill text never appeared.
  Fixed by adding the `casesPageAsCaseLead` login fixture (used only for
  its login side effect).
- **`StatusPill`, 2 of 9 real states** (`Complete` via a real
  upload-to-Complete, `Error` via `DevStackFaultInjector`'s existing real
  OpenSearch-outage mechanism, already proven by `evidence-retry.spec.ts`).
  The other 7 (`UPLOADING`/`SCANNING`/`HASHING`/`RECEIVED`/`PARSING`/
  `INGESTING`/`PURGED`) are a **deliberate, documented scope decision, not
  an oversight**: the first 6 are sub-second-to-a-few-second transient
  pipeline states with no deterministic way to freeze the real pipeline on
  them for a screenshot without a materially heavier fault-injection
  mechanism per state; `PURGED` is gated behind a delete/legal-hold flow
  out of this cycle's scope. `Complete`/`Error` are the two states real
  users actually rest on and look at, and are exactly the two mechanisms
  this suite already has proven, real infrastructure for.

### Baselines generated and inspected for real

`--update-snapshots` run once against the live dev stack, all 6 PNGs
(`e2e/visual-regression-pills.spec.ts-snapshots/*.png`) opened and visually
confirmed to show the correct label + color for their state (e.g. the
`Error` pill is genuinely red-on-red-border, `False Positive` genuinely
gray, ...) before committing them — not generated and trusted blindly.
Re-ran without `--update-snapshots` immediately after: all 6 pass against
the just-committed baselines, a real repeatable pass.

### The assertion is load-bearing, not vacuous — proven both directions

Following this initiative's own established discipline (Milestone HHHH's
before/after pattern): temporarily changed `TriageStatePill`'s `NEW` state
from `bg-purple-100 text-purple-700 border-purple-300` to
`bg-blue-100 text-blue-700 border-blue-300` (a realistic accidental-edit
shape), rebuilt and redeployed the real `docker-nginx-1` image, and
re-ran the `NEW` test: **it failed for real** — "38 pixels (ratio 0.04 of
all image pixels) are different", well above the configured 1%
`maxDiffPixelRatio` threshold. Reverted the one line, rebuilt, redeployed,
re-ran the full 12-test combined suite (`a11y.spec.ts` +
`visual-regression-pills.spec.ts`) clean.

### Threshold configuration

`playwright.config.ts` gained `expect.toHaveScreenshot.maxDiffPixelRatio:
0.01` — a small tolerance for genuine sub-pixel anti-aliasing/font-hinting
noise between two runs on the *same* environment (these are tiny,
badge-sized, flat-color elements, not full pages), while still catching a
real color-class regression (which changes far more than 1% of pixels, as
demonstrated above).

## CI-worthiness: `a11y.spec.ts` wired in, `visual-regression-pills.spec.ts` deliberately not

**`a11y.spec.ts` is wired into `security-integration-tests.yml`'s
`frontend-e2e-smoke` job** (new `"E2E: a11y"` step, same
`KRONOS_E2E_POSTGRES_DSN`/`KRONOS_E2E_SEED_ORG_ALIAS`/`KRONOS_E2E_PYTHON`
env vars `detection-triage` already needs). This is squarely
CI-appropriate: axe-core's checks are DOM/ARIA/computed-CSS-color
assertions evaluated by the same Chromium binary in both environments —
no rendering-fidelity dependency. `timeout-minutes`'s own justification
comment updated with the real measured cost (~13s for all 6 tests against
the dev stack) per this job's established practice of citing real
measurements, not guesses.

**`visual-regression-pills.spec.ts` is deliberately NOT wired into CI this
cycle** — a real, reasoned risk, not an assumption that "it worked locally
so it'll work in CI": Tailwind's default font stack
(`ui-sans-serif, system-ui, ...`) resolves to whichever font the *host OS*
actually has installed as its system UI font, which is not guaranteed to
be identical between this dev host and a GitHub Actions `ubuntu-latest`
runner's image — different default font packages would produce different
real sub-pixel glyph rendering for the pill labels, independent of any
application bug. Compounding this: per Milestone RRR (still true, and
directly relevant here, not just a boilerplate caveat), **no workflow in
this repo has ever actually executed on GitHub's own infrastructure for
this branch** — there is no real GHA run to compare a baseline against
yet, so committing baselines generated on this host and immediately
wiring them into a CI job would be shipping an assertion this initiative
cannot currently verify is even meaningful in that environment, let alone
passing. Generating a CI-specific baseline on the first real GHA run
(`workflow_dispatch`, once that becomes available per Milestone RRR's own
open item) is the correct way to close this, not assuming portability now.
The spec itself, its baselines, and this reasoning are all committed and
real — only the CI wiring step is deferred, with the reason stated
explicitly in both this doc and the CI file's own comment, matching this
initiative's established honest-scoping precedent (Milestone HHHH's
dashboards-embed, Milestone WWW's Volatility PoC).

## Real verification summary

- `npx tsc -b`: clean.
- `npx oxlint`: 0 errors, 1 pre-existing unrelated warning
  (`ErrorCatalogue.tsx`).
- `npm run test` (vitest): 104/104 passed, unaffected.
- `npm run build`: clean production build.
- `a11y.spec.ts`: 6/6 passed standalone, and again inside a 12-test
  combined run with `visual-regression-pills.spec.ts`.
- `visual-regression-pills.spec.ts`: 6/6 passed standalone (after fixing
  the auth-fixture bug above), and again inside the same 12-test combined
  run.
- Regression sample confirming `LoginPage.ts`'s new TOTP-handling logic
  doesn't affect any existing spec: `login`, `evidence-upload`,
  `detection-triage`, `cross-tenant-isolation`, `rbac-access-denial`,
  `case-membership-access-denial` — 6/6 passed together.
- Both real WCAG-AA color-contrast fixes and the `select-name` fix
  confirmed live, before-and-after (failing with the exact violation
  before, clean after).
- The visual-regression assertion confirmed load-bearing both directions
  (a real injected color-class change fails it; reverting passes it
  again), not just passing by construction.

## Status

`docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.8 is closed — the last named item in
§3's scenario catalogue. Every scenario §3.1–§3.8 named now has real,
committed, (mostly) CI-wired Playwright coverage; the two deliberate,
documented exceptions remain `dashboards-embed.spec.ts` (Milestone HHHH,
dev-stack-only — no real Dashboards content in the CI profile) and
`visual-regression-pills.spec.ts` (this cycle — real font-rendering
cross-environment risk, no real GHA run yet to validate against).

## Recommendation for the next cycle

1. If/when a real `workflow_dispatch` run against this branch becomes
   available (Milestone RRR's own open item), regenerate
   `visual-regression-pills.spec.ts`'s baselines from that real GHA
   runner's own output before considering CI-wiring it — don't reuse this
   cycle's dev-host baselines for that.
2. `StatusPill`'s 7 not-yet-visually-covered states remain a known,
   documented gap — if a future cycle wants full coverage, the transient
   states would need a materially different technique (e.g., a
   step-level Celery pause/breakpoint) than anything this suite currently
   has, and `PURGED` needs a real delete/legal-hold-release flow to exist
   in the UI first.
3. `frontend/e2e/README.md`'s own "Not yet wired into CI" line is stale
   (pre-dates Milestone KKK) — not touched this cycle since it's a
   pre-existing gap unrelated to §3.8, but worth a follow-up correction
   pass.
