import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";
import { SseDropInjector } from "./SseDropInjector";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Real Windows 10 prefetch sample -- same fixture as
// evidence-upload-heavy-parser.spec.ts, chosen deliberately (not a FAST
// text-parser fixture): the real Plaso subprocess's own startup+parse time
// gives a wide, safe, non-racy window for the real evidence to sit in a
// genuine non-terminal state (Uploading/Received/Parsing) while this spec
// forces the SSE drop -- a FAST-path fixture (cloudtrail.json etc.) was
// tried first during investigation and reached COMPLETE within ~2s, too
// fast to reliably observe a real non-terminal state before cutting (see
// the Milestone IIII gap-audit doc).
const PREFETCH_SAMPLE = path.resolve(__dirname, "../../tests/fixtures/samples/real/CMD.EXE-087B4001.pf");

/**
 * docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.7, scenario 2: "SSE connection drop
 * mid-upload -> UI recovers (reconnects or falls back to a poll) rather
 * than silently freezing the status pill forever."
 *
 * See SseDropInjector's own docstring for the real investigation (two
 * rejected approaches, live-confirmed not to work deterministically)
 * behind why this test forces the drop the way it does. `useEvidenceSSE.ts`
 * (read before writing this spec, per this milestone's own instructions)
 * has exactly one recovery path once its EventSource's `onerror` fires: it
 * closes the connection for good and starts a 5s polling loop that
 * dispatches `kronos:sse-poll`, which `CaseDetailPage.tsx`'s own listener
 * turns into a plain `invalidateQueries()` REST refetch -- it does NOT
 * reopen a new EventSource on its own (that only happens via the
 * *different*, mutation-triggered `kronos:sse-reconnect` bridge Milestone
 * SSS/FFFF added for the retry-button flow, not applicable here). This
 * spec's own `sseConnectionCount` assertion below locks that in: exactly
 * one real SSE network request for the whole test confirms recovery
 * genuinely came from the polling fallback, not a reconnect this scenario
 * never triggers.
 */
test("real SSE drop mid-upload recovers to Complete via the polling fallback, no reload", async ({
  casesPageAsCaseLead,
  page,
}, testInfo) => {
  testInfo.setTimeout(150000);

  const pageErrors: string[] = [];
  page.on("pageerror", (err) => pageErrors.push(err.message));

  // Real network-level instrumentation: counts how many real SSE GET
  // requests the browser ever issues (page.on("request") observes actual
  // network activity, so it doesn't depend on page.addInitScript()'s
  // full-document-navigation requirement -- casesPageAsCaseLead has
  // already logged in and navigated by the time this test body runs, and
  // every subsequent navigation in this spec is client-side SPA routing,
  // never a fresh document load, so an addInitScript-based override would
  // never actually get installed).
  let sseConnectionCount = 0;
  page.on("request", (req) => {
    if (/\/api\/sse\/cases\/.*\/evidence\?ticket=/.test(req.url())) {
      sseConnectionCount++;
    }
  });

  const injector = new SseDropInjector("**/api/sse/cases/**/evidence?ticket=**");
  const title = `E2E SSE-drop spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-SSEDROP-${Date.now()}`);

  // Arm AFTER navigating into the case (matches where useEvidenceSSE.ts's
  // EventSource actually gets created -- on CaseDetailPage's EvidenceTab
  // mount) but BEFORE the upload starts, so the one real SSE connection
  // this case ever opens is the one under test.
  await injector.arm(page);

  await detail.uploadEvidence(PREFETCH_SAMPLE);

  const result = await detail.watchEvidenceStateLive("CMD.EXE-087B4001.pf", 100000);

  expect(injector.hasDropped, "the deliberate SSE drop must have actually happened").toBe(true);
  expect(
    injector.droppedWhileNonTerminal,
    `real backend state observed right before the cut (must be non-terminal): ${injector.capturedBody}`,
  ).not.toBeNull();
  expect(["UPLOADING", "RECEIVED", "HASHING", "SCANNING", "PARSING"]).toContain(
    injector.droppedWhileNonTerminal,
  );

  expect(result.terminal, `observed state sequence: ${result.seenStates.join(" -> ")}`).toBe("Complete");
  expect(
    sseConnectionCount,
    "exactly one real SSE connection for the whole test proves recovery came from the polling fallback, not a reconnect",
  ).toBe(1);
  expect(pageErrors, "no unhandled exception anywhere in the page during the drop/recovery").toEqual([]);
});
