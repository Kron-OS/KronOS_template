import AxeBuilder from "@axe-core/playwright";
import { test, expect } from "./fixtures";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";
import { CaseDetailPage } from "./pages/CaseDetailPage";

const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

/**
 * Real end-to-end coverage for the curated on-demand Volatility plugin
 * picker: real click -> real POST /volatility/run-plugin -> real Celery
 * task -> real VolatilityLauncher.run() -> real evidence fetch from MinIO
 * -> real volatility3 subprocess -> real StructuredArtifact save -> real
 * poll -> real render via ArtifactContent's generic fallback.
 *
 * Uses the real, already-uploaded Challenge.raw evidence (case
 * 43097ab0-aae3-4968-915b-8f0229ac3865, evidence
 * e9f3287f-3858-4018-bcee-42a4bcbb0bc3) on this dev stack -- the same real
 * 1.6GB Windows 7 sample poc/volatility_ondemand_picker/ already real-
 * verified each curated plugin against, rather than re-uploading it (slow,
 * and Milestone EEEEE's own on-demand UI spec already established the
 * "seed instead of re-upload" convention for *rendering* checks -- this
 * spec's whole point is different: proving the real trigger path actually
 * works end to end, which seeding artifacts directly would not prove).
 * Logs in as the real dev admin account (org-wide case access,
 * src/external/middleware/rbac.py's assert_case_access) since this real
 * case has no listed members and this dev stack's own case-lead fixture
 * user isn't its owner.
 */
const REAL_CASE_ID = "43097ab0-aae3-4968-915b-8f0229ac3865";
const REAL_EVIDENCE_FILENAME = "Challenge.raw";

test("running a curated plugin against a real memory dump produces a real artifact", async ({
  page,
}) => {
  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);

  await page.goto(`/cases/${REAL_CASE_ID}`);
  const detail = new CaseDetailPage(page);
  await detail.waitUntilReady();

  await detail.openArtifactsTab();
  await page.getByText(REAL_EVIDENCE_FILENAME, { exact: true }).click();

  await expect(page.getByLabel("Select a plugin to run")).toBeVisible({ timeout: 15000 });

  // Real WCAG scan of the picker UI itself -- the a11y.spec.ts suite's own
  // Artifacts-tab scan depends on a fresh evidence upload reaching
  // COMPLETE, which is currently blocked by a real, pre-existing, already-
  // documented OpenSearch shard-exhaustion issue on this dev stack
  // unrelated to this feature (confirmed via celery-worker logs). Volatility
  // artifacts are Postgres-only, so this real, already-COMPLETE case is
  // unaffected and gives a real scan of the actual new markup regardless.
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  expect(results.violations).toEqual([]);

  await page.getByLabel("Select a plugin to run").selectOption("windows.envars.Envars");
  // Locator built once, before the click -- the button's own accessible
  // name flips "Run" -> "Running…" -> "Run" as the real request lands and
  // completes, so re-querying by name "Run" after clicking would miss the
  // transient "Running…" state entirely (a real race, not flakiness to
  // paper over with a longer timeout).
  const runButton = page.getByRole("button", { name: /^(Run|Running…)$/ });
  await runButton.click();
  await expect(runButton).toHaveText("Running…", { timeout: 5000 });

  // Real Celery task -> real subprocess -> real artifact save; the tab
  // polls every 3s while pending (CaseDetailPage.tsx's own
  // hasPendingOnDemandWork mechanism) -- no manual reload needed.
  await expect(runButton).toHaveText("Run", { timeout: 30000 });

  // The new artifact is real, generic-view-rendered content -- confirm the
  // kind nav picked up the new "Additional Analysis" cluster entry
  // (CaseDetailPage.tsx's KIND_LABELS) and real row data shows up (envars
  // rows always include a "Variable"/"Value" column pair, per the real
  // captured PoC output, poc/volatility_ondemand_picker/output.txt).
  await page.getByRole("button", { name: "Environment Variables", exact: true }).click();
  await expect(page.getByText(/PID/i).first()).toBeVisible({ timeout: 10000 });
});
