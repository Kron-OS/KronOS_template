# Gap Audit — Milestone IIII (2026-09-01)

**Scope:** `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.7 ("Resilience / error
states"), the last unclosed item in §5's delivery order before §3.8
(a11y/visual). Two named scenarios: (1) backend temporarily unreachable,
network-blocked at Playwright's own interception layer, with the UI
expected to show a real, legible error state and zero unhandled
rejection; (2) a real SSE connection drop mid-upload, with the UI expected
to recover (reconnect or fall back to polling) rather than freezing the
status pill forever. Both were investigated for real against the running
dev stack before any spec was written, per CLAUDE.md §F.

---

## What was actually investigated (not assumed)

### Scenario 1 — backend unreachable

Read `src/api/client.ts`'s axios response interceptor first: it only
special-cases `401` (token refresh); every other failure — including a
`page.route()` abort, which surfaces to axios as `error.response ===
undefined` — falls through to a bare `Promise.reject(error)`. Read
`CasesPage.tsx` and `DetectionsPage.tsx` next: both already render a real
`<ErrorBanner>` off `useQuery`'s own `error` state
(`"Failed to load cases."` / `"Failed to load detections."`), and
`CasesPage.tsx`'s `CreateCaseModal` already renders one off
`mutation.isError` (`"Failed to create case. Please try again."`).
`App.tsx`'s `QueryClient` sets `retry: 1` for queries (mutations default
to `retry: 0`). So the frontend's own error-surfacing machinery already
existed — the open question wasn't "does a banner exist" but "does the
whole real flow (already-authenticated page, backend genuinely cut off,
real network abort) actually reach it live, with zero unhandled
rejection anywhere," which had never been proven end-to-end.

### Scenario 2 — SSE drop mid-upload

Read `frontend/src/hooks/useEvidenceSSE.ts` and `src/external/routes/sse.py`
(both already carry detailed comments from Milestones SSS/FFFF's own real,
reproduced SSE bugs) before designing anything. Confirmed the real
recovery path: `EventSource.onerror` closes the connection for good and
starts a 5s polling loop (`kronos:sse-poll` → `CaseDetailPage.tsx`'s
listener → `invalidateQueries()`, a plain REST refetch) — it does **not**
reopen a new `EventSource` on its own; that only happens via the
*different*, mutation-triggered `kronos:sse-reconnect` bridge (retry-button
flow, not applicable here).

Two approaches were tried live against the real dev stack and rejected
before landing on the one used:

1. **`browserContext.setOffline(true)`** on an already-open `EventSource`
   — instrumented the real `EventSource` via `page.addInitScript()` and
   watched it for 8+ real seconds while offline: zero `error`/`close`
   events fired. Confirmed this is real Chromium behavior, not a fluke:
   offline network-condition emulation blocks *new* connections, not bytes
   already flowing on an established one. Rejected.
2. **Waiting for the real 60s one-shot ticket to expire** — already
   flagged by the test plan doc itself as too slow for a deterministic
   test. Not attempted.
3. **What worked**: `page.route()` can only ever decide
   continue/abort/fulfill *once*, at the moment a request is first
   observed — confirmed it cannot reach into a connection already in
   flight. So the connection is intercepted at that one decision point and,
   instead of `route.continue()`, proxied for real: a genuine `https.get()`
   against the real backend (through the real nginx/TLS front door, using
   the exact one-shot ticket `useEvidenceSSE.ts` itself minted), forwarding
   real bytes until a genuine non-terminal evidence-state event is
   observed, then severing the real backend connection and
   `route.fulfill()`-ing the browser with exactly what was received. Per
   the WHATWG EventSource spec, an unexpected close is indistinguishable
   from a real network drop from the browser's point of view — confirmed
   live (`readyState` transitions to `CONNECTING` before the app's own
   `onerror` handler closes it for good and starts polling).

   Also confirmed live that a FAST-path fixture (`cloudtrail.json`) races
   to `COMPLETE` in ~2s — too fast to reliably observe a genuine
   non-terminal state before the deliberate cut. Switched to the same real
   Windows 10 prefetch sample (`CMD.EXE-087B4001.pf`,
   `evidence-upload-heavy-parser.spec.ts`'s own fixture) whose real Plaso
   subprocess timing gives a wide, non-racy window.

## What was built

- `frontend/e2e/resilience-backend-unreachable.spec.ts` — two tests, both
  against a real, already-authenticated, already-loaded page:
  1. `page.route("**/api/**", route => route.abort("failed"))`, then a
     real case-creation mutation attempt (`attemptCreateCase` /
     `waitForCreateCaseError`, reusing `CasesPage`'s existing helpers) —
     confirms the real `ErrorBanner` text, that the app shell (header) is
     still rendered (not a blank screen), and `page.on("pageerror")` stays
     empty.
  2. Same block, then a real in-app client-side navigation (no reload) to
     `/detections`, forcing a genuinely fresh `useQuery` against the
     now-unreachable backend — confirms `"Failed to load detections."`,
     the app shell, and zero `pageerror`.
- `frontend/e2e/SseDropInjector.ts` — the real-proxy-then-cut mechanism
  described above, reusable, with a `droppedWhileNonTerminal` getter so a
  caller's own assertion fails loudly (not silently) if the pipeline ever
  raced to a terminal state before the deliberate cut.
- `frontend/e2e/resilience-sse-drop.spec.ts` — arms the injector right
  after navigating into a real case (matching where `useEvidenceSSE.ts`'s
  `EventSource` actually gets created), uploads the real prefetch sample,
  and asserts: the drop genuinely happened while non-terminal (state
  captured and printed on failure), the evidence still reaches `Complete`
  live (`watchEvidenceStateLive`, no reload), exactly one real SSE network
  request happened for the whole test (`page.on("request")` count == 1 —
  proves recovery came from the polling fallback, not a reconnect this
  scenario never exercises), and zero `pageerror`.
- Both specs wired into `.github/workflows/security-integration-tests.yml`'s
  `frontend-e2e-smoke` job: `resilience-backend-unreachable` placed after
  `case-membership-access-grant` (no extra services needed, same reasoning
  as the RBAC specs); `resilience-sse-drop` placed after
  `evidence-upload-heavy-parser-archive` (reuses `celery-worker-plaso`,
  already required by that step, so introduces no new dependency).
  `timeout-minutes: 70`'s own justification comment updated with the two
  new steps' declared worst-case ceiling (210s combined) against real
  measured cost (~17s combined) — still comfortably inside the ~5.5min
  headroom Milestone ZZZ's own accounting established.

## No bug found this cycle — an honest, verified negative result

Unlike Milestones FFFF/HHHH, this cycle did **not** find a new product bug.
Both scenarios were already handled correctly by existing code:

- Scenario 1's error-surfacing machinery (`ErrorBanner` off `useQuery`/
  `useMutation` error state) already existed and was already correct —
  this cycle's contribution is proving it live, end-to-end, with a real
  network-level abort, not a hypothetical.
- Scenario 2's recovery path already worked, specifically *because*
  Milestone FFFF already fixed the one real bug in this exact code path
  (the SSE stream closing permanently on a connection's first observation
  of a stale terminal state). This cycle's real-proxy-then-cut technique
  is a genuinely different failure shape from FFFF's (a mid-stream drop of
  an already-flowing connection vs. a fresh reconnect racing a retry) and
  confirms FFFF's fix generalizes to it, but did not need a further fix.

This is reported plainly rather than manufacturing a fix for a problem
that does not exist, per CLAUDE.md's own instruction not to weaken
assertions or invent a failure mode that isn't real.

## Verification (real, captured output)

- Both new specs run individually against the live dev stack: 3/3 passed
  (`resilience-backend-unreachable.spec.ts` 2 tests + `resilience-sse-drop.spec.ts`
  1 test), ~2.1s / ~2.9s / ~11.8s respectively.
- Run together with `login.spec.ts`, `evidence-upload.spec.ts`, and
  `evidence-retry.spec.ts` (the slowest existing spec, ~2.4min, sharing the
  same shared `case-lead` account) to confirm no interference: **6/6
  passed in one 2.8-minute serialized run.**
- `npx tsc --noEmit`: clean. `npm run lint` (oxlint): 0 errors, the one
  pre-existing benign `ErrorCatalogue.tsx` warning unchanged. `npm run
  build`: clean. `npm run test` (vitest): **104/104 passed**, no
  regression.
- `python3 -c "import yaml; yaml.safe_load(...)"` against the modified
  `security-integration-tests.yml`: parses clean.

## Status

- `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.7 is closed — both named scenarios
  have real, live-verified, CI-wired coverage.
- §5's delivery order has one item left before this plan's own scope is
  exhausted: §3.8 (accessibility + visual regression), tracked as the next
  milestone.

## Recommendation for the next cycle

1. §3.8 (a11y/visual regression) is the last item in §5's delivery order —
   `@axe-core/playwright` automated scans across the 6 real pages, plus
   `toHaveScreenshot()` visual regression on `StatusPill`/`TriageStatePill`
   specifically (they encode meaning through color).
2. `SseDropInjector`'s real-proxy-then-cut technique is generic to any SSE
   endpoint this repo ever adds — worth reusing directly rather than
   re-deriving if a second SSE-backed feature ships.
3. `frontend/e2e/README.md`'s own "Not yet wired into CI" line (Structure
   section prerequisites) is now stale — it predates `frontend-e2e-smoke`
   existing at all (Milestone KKK) and was never corrected by any
   subsequent milestone touching that file. Cheap, low-priority cleanup
   for whichever cycle next touches that README.
