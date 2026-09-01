# Gap Audit — Milestone HHHH (2026-09-01)

**Scope:** closes `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6 — the real
OpenSearch Dashboards iframe embed (`cases.py`'s `get_dashboard_url()`)
actually loads inside the app shell for a real case, with the real case's
own timeline data visible. This is the one open question
`poc/dashboards_embed/README.md` originally flagged as needing "a live
browser to observe" and never got, per its own text. A follow-on PoC,
`poc/dashboards_embed/autoload_verification/`, later did answer it by hand
(a real, one-off Playwright pass with a captured screenshot,
`browser_verification_zero_click_autoload.png`) — but that was a throwaway
script under `poc/`, never promoted into the maintained `frontend/e2e/`
suite, so a regression here would have gone uncaught by anything that runs
repeatedly.

---

## Investigated / Fixed this cycle

### Real, current wiring confirmed before writing anything

Read `src/external/routes/cases.py`'s `get_dashboard_url()` and
`frontend/src/pages/CaseDetailPage.tsx`'s `TimelineTab` directly rather
than trusting the PoC README's description. Current, real state: the case
detail page has a "Timeline" tab (`CaseDetailPage.tsx` line ~405) that
fetches `GET /api/cases/{id}/dashboard-url` and renders
`<iframe title="Timeline Analysis" src={data.url} sandbox="allow-same-origin
allow-scripts allow-forms allow-popups">`, gated by
`isTrustedDashboardsUrl()` (origin allowlist via
`VITE_OPENSEARCH_DASHBOARDS_ORIGIN`). The backend route builds a
`/app/data-explorer/discover` URL with `_a`/`_g`/`_q` RISON state in the
URL **fragment** (not the top-level query string — `autoload_verification`'s
own real finding, already correct) plus a top-level `security_tenant`
param to skip the tenant-selection dialog. Both halves matched what the
PoC docs claimed — no drift found.

### Real, previously-unknown bug found and fixed: default time range hid every real case's data

Built `frontend/e2e/dashboards-embed.spec.ts`: real login → real case
creation → real upload of `tests/fixtures/samples/real/system.evtx` →
watch live SSE to `Complete` → click the real "Timeline" tab → assert on
content **inside** the real iframe via Playwright's `frameLocator()`
(the case's `kronos.case_id` filter pill text and a real `N hits` count),
not just that an `<iframe>` element exists with a plausible `src`.

First real run against the live dev stack's real, SSO-integrated
`opensearch-dashboards` (`docker-compose.dev.yml`) timed out waiting for
`N hits` — Discover genuinely rendered, the case-scoped filter was
genuinely applied (confirmed: its own pill text showed the real case id),
but the chart and hit count stayed at zero. Root cause, read directly from
`cases.py`: `g_state`'s time range was hardcoded `time:(from:now-30d,to:now)`,
copied from a generic Discover-embed example without checking it against
what this platform actually ingests. Checked every real fixture under
`tests/fixtures/samples/real/`: `system.evtx` is real 2015-08-08/09
Windows System event log data (extracted directly with the `evtx` Python
binding, not guessed), `apache_access.log` is 2016-01-13,
`aws_cloudtrail.jsonl` is 2022-02-08, `suricata/eve.json` is 2016-06-08 —
**every single real fixture in this repo predates the `now-30d` window by
years**, and forensic evidence is structurally like this in general (the
whole point of the platform is investigating past incidents). So every
real case's Timeline tab was silently showing an empty chart/"0 hits" by
default, with no error anywhere — a real, previously-unknown product bug,
not a test artifact.

**Fixed** in `src/external/routes/cases.py`: `g_state`'s time range is now
a fixed absolute floor, `time:(from:'2000-01-01T00:00:00.000Z',to:now)`,
wide enough to cover any real-world evidence date without relying on a
"recent" assumption. The `kronos.case_id` filter in `_q` is what actually
scopes the data to the case (unchanged, already correct); this only
controls what's visible without the analyst manually widening the picker.

**Verified both directions, not just after the fix** — the exact
before/after discipline this initiative has used throughout:
1. With the fix applied: `dashboards-embed.spec.ts` passes — real `N hits`
   text and the real case-id filter pill both visible inside the iframe,
   no tenant dialog.
2. Reverted **only** the `g_state` line back to `now-30d` (backend
   restarted, real bind-mounted hot-reload): the exact same spec then
   fails for real — `Test timeout of 30000ms exceeded ... waiting for
   locator(...).getByText(/\d+\s+hits?/i)`, not a different/unrelated
   failure. Confirms the assertion is load-bearing, not vacuous.
3. Restored the real fix, re-ran twice more (once alongside `login.spec.ts`
   and `evidence-upload.spec.ts`, once alongside the full
   `evidence-upload-fast-parsers.spec.ts` set) — 7/7 green, no
   interference.

### New page-object methods (`frontend/e2e/pages/CaseDetailPage.ts`)

`openTimelineTab()`, `getDashboardsFrame()` (returns a
`FrameLocator`, this suite's first use of one), and
`getDashboardsIframeSrc()` — following the same pattern as every other
page-object method in this file, no new abstraction invented.

## Status

`docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6 is closed: a real, permanent,
repeatable spec now asserts on genuine content inside the real Dashboards
iframe (case-scoped filter pill, non-zero hit count, no tenant dialog),
not just DOM presence of an `<iframe>` tag — closing the exact gap the PoC
README left open and the follow-on PoC only ever answered with a one-off
screenshot. A real, previously-unknown, previously-silent bug (every real
case's Timeline tab defaulting to an empty view) is fixed and has
permanent regression coverage for the first time.

**Not CI-wired, honestly, and not attempted as a shortcut**:
`docker-compose.test.yml`'s own `opensearch-dashboards` service is a
deliberate `nginx:alpine` DNS-resolution-only stub — read directly, its
own comment already says *"a minimal DNS-resolvable stub, not a real
Dashboards. Revisit with a real service if/when
docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.6 (dashboards embed spec) is actually
built against this profile."* There is no real Dashboards content in that
profile to assert on — `frame.getByText(...)` would find nothing
regardless of whether the app's own wiring is correct. Standing up a real,
SSO-integrated Dashboards instance in `docker-compose.test.yml` (mirroring
`docker-compose.dev.yml`'s own, itself a full `poc/opensearch_dashboards_sso/`
worth of real Keycloak-openid wiring — auth-domain ordering, subject_key,
redirect_uri, migration-collision handling) is a genuinely separate,
larger piece of work, not a config toggle. `dashboards-embed.spec.ts` is
therefore dev-stack-only and deliberately **not** added to
`security-integration-tests.yml`'s `frontend-e2e-smoke` job — the same
honest scoping precedent as Milestone WWW's Volatility PoC (real
verification captured, CI wiring explicitly declined with a stated
reason, not silently skipped).

## Recommendation for the next cycle

1. §3.7 resilience E2E specs (backend-unreachable / SSE-drop-mid-upload) —
   next item in the plan's own delivery order.
2. §3.8 accessibility/visual-regression specs.
3. If CI coverage of the Dashboards embed is ever prioritized, the real
   scope is standing up `docker-compose.test.yml`'s `opensearch-dashboards`
   as a genuine SSO-integrated instance (mirroring
   `docker-compose.dev.yml`'s service definition) — not a change to this
   spec itself, which already runs correctly against a real instance.
