import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";
import { DevStackFaultInjector } from "./DevStackFaultInjector";
import { DetectionSeeder } from "./DetectionSeeder";
import { DetectionDetailPage } from "./pages/DetectionDetailPage";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLOUDTRAIL_SAMPLE = path.resolve(__dirname, "../../tests/fixtures/samples/cloudtrail.json");

/**
 * §3.8 (docs/PLAYWRIGHT_E2E_TEST_PLAN.md): `StatusPill`/`TriageStatePill`
 * encode meaning ENTIRELY through color -- an accidental Tailwind class
 * edit (e.g. a bad find/replace on `bg-red-100` -> `bg-gray-100`) would
 * leave every functional assertion in this suite green (the label text and
 * DOM state are unchanged) while silently breaking the one thing these
 * components exist for. `toHaveScreenshot()` on the pill element itself
 * (not a full-page screenshot, which would be dominated by unrelated
 * layout noise and flaky for reasons that have nothing to do with color
 * coding) is what actually catches that class of regression.
 *
 * Real states used, not synthetic ones -- but deliberately scoped, not
 * exhaustive: `TriageStatePill` has exactly 4 states and all 4 are
 * directly, deterministically seedable (DetectionSeeder.seedAtTriageState,
 * a real insert through the real repository -- see seed_detection.py's own
 * comment for why that's a legitimate way to reach a non-NEW state, not a
 * shortcut around FSM validation). `StatusPill` has 9 states; only 2
 * (COMPLETE, ERROR) are captured here, both via mechanisms this suite
 * already uses elsewhere for other specs (a real upload-to-Complete,
 * DevStackFaultInjector's real OpenSearch outage) -- the other 7
 * (UPLOADING/SCANNING/HASHING/RECEIVED/PARSING/INGESTING/PURGED) are
 * either sub-second transient pipeline states with no deterministic way to
 * freeze the real pipeline on them for a screenshot, or (PURGED) gated
 * behind a delete flow out of this cycle's scope -- a real, documented
 * scoping decision, not an oversight (see docs/GAP_AUDIT_2026-08-28_MILESTONE_JJJJ.md).
 */
test.describe("visual regression: pill/badge color coding", () => {
  test.describe("TriageStatePill (all 4 real states)", () => {
    const cases: Array<{ state: "NEW" | "INVESTIGATING" | "TRUE_POSITIVE" | "FALSE_POSITIVE"; label: string }> = [
      { state: "NEW", label: "New" },
      { state: "INVESTIGATING", label: "Investigating" },
      { state: "TRUE_POSITIVE", label: "True Positive" },
      { state: "FALSE_POSITIVE", label: "False Positive" },
    ];

    for (const { state, label } of cases) {
      test(`${state} pill matches its committed baseline`, async ({ casesPageAsCaseLead, page }) => {
        // `casesPageAsCaseLead` fixture is only used for its login side
        // effect here (real bug found writing this spec: `/detections/{id}`
        // is behind `AuthGuard` -- navigating there with a bare,
        // unauthenticated `page` just silently redirects to `/login`,
        // which is why `waitUntilReady()`'s pill-text wait timed out on
        // every one of these 4 tests the first time this spec ran for
        // real, not a rendering bug).
        void casesPageAsCaseLead;
        const seeded = new DetectionSeeder().seedAtTriageState(`E2E visual ${state} ${Date.now()}`, state);
        await DetectionDetailPage.openById(page, seeded.detectionId);

        const pill = page.locator("span").filter({ hasText: new RegExp(`^${label}$`) }).first();
        await expect(pill).toBeVisible();
        await expect(pill).toHaveScreenshot(`triage-pill-${state.toLowerCase()}.png`);
      });
    }
  });

  test.describe("StatusPill (real reachable states: Complete, Error)", () => {
    test("Complete pill matches its committed baseline", async ({ casesPageAsCaseLead, page }) => {
      const title = `E2E visual complete ${Date.now()}`;
      const detail = await casesPageAsCaseLead.createCase(title, `E2E-VIS-C-${Date.now()}`);
      await detail.uploadEvidence(CLOUDTRAIL_SAMPLE);

      const result = await detail.watchEvidenceStateLive("cloudtrail.json", 60000);
      expect(result.terminal, `observed state sequence: ${result.seenStates.join(" -> ")}`).toBe("Complete");

      const row = page.locator("tr:has-text('cloudtrail.json')");
      const pill = row.locator("span").filter({ hasText: /^Complete$/ }).first();
      await expect(pill).toHaveScreenshot("status-pill-complete.png");
    });

    test("Error pill matches its committed baseline", async ({ casesPageAsCaseLead, page }, testInfo) => {
      // Same real, deterministic failure shape evidence-retry.spec.ts
      // already uses: intake never touches OpenSearch, only indexing does,
      // so stopping it before upload reliably lands evidence on
      // ERROR/ingest_failed. testInfo.setTimeout mirrors that spec's own
      // measured worst-case ceiling (parse_artefact_fast's real 3-retry
      // backoff can take ~2min to reach ERROR) plus the real OpenSearch
      // restart-to-healthy wait.
      testInfo.setTimeout(300000);
      const injector = new DevStackFaultInjector();
      const title = `E2E visual error ${Date.now()}`;
      const detail = await casesPageAsCaseLead.createCase(title, `E2E-VIS-E-${Date.now()}`);

      injector.stopOpenSearch();
      try {
        await detail.uploadEvidence(CLOUDTRAIL_SAMPLE);
        const result = await detail.watchEvidenceStateLive("cloudtrail.json", 150000);
        expect(result.terminal, `observed state sequence: ${result.seenStates.join(" -> ")}`).toBe("Error");

        const row = page.locator("tr:has-text('cloudtrail.json')");
        const pill = row.locator("span").filter({ hasText: /^Error$/ }).first();
        await expect(pill).toHaveScreenshot("status-pill-error.png");
      } finally {
        await injector.restartOpenSearchAndWaitHealthy();
      }
    });
  });
});
