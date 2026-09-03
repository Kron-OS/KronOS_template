import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";
import { VolatilityArtifactSeeder } from "./VolatilityArtifactSeeder";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REAL_DIR = path.resolve(__dirname, "../../tests/fixtures/samples/real");

/**
 * Milestone FFFFF: real UI coverage for the on-demand path (Child Files /
 * Registry Browser) -- the two new nav entries built on top of Milestone
 * DDDDD's kind-cluster nav for the analyst-triggered
 * windows.dumpfiles/windows.registry.printkey actions (Milestone EEEEE's
 * backend).
 *
 * The real end-to-end trigger flow (POST route -> Celery -> sandboxed
 * worker subprocess -> real volatility3 -> real MinIO derived bucket ->
 * real StructuredArtifact save -> real download route) was verified live
 * against the real 1.6GB Challenge.raw sample in this org's live dev
 * MinIO/Postgres (docs/GAP_AUDIT_2026-09-03_MILESTONE_EEEEE.md) -- a real
 * memory-image upload through this suite would be slow and heavy for what
 * THIS spec needs to prove (does the real UI correctly render seeded
 * on-demand-kind data, navigate the Registry Browser's breadcrumb
 * drill-down, and round-trip real bytes through the real download route).
 * So this seeds real StructuredArtifact rows (VolatilityArtifactSeeder,
 * includeOnDemand=true) AND real bytes in the real derived-artifact MinIO
 * bucket against a real (trivial) evidence upload, exactly mirroring
 * case-artifacts-ui.spec.ts's own established pattern.
 */
test("Child Files and Registry Browser render real seeded on-demand data", async ({
  casesPageAsCaseLead,
}) => {
  const detail = await casesPageAsCaseLead.createCase(
    `E2E on-demand-ui case ${Date.now()}`,
    `E2E-ONDEMAND-${Date.now()}`,
  );
  const caseId = detail.url.split("/cases/")[1]?.split(/[/?#]/)[0];
  expect(caseId, `expected a real case id in the URL, got: ${detail.url}`).toBeTruthy();

  await detail.uploadEvidence(path.join(REAL_DIR, "apache_access.log"));
  const { terminal } = await detail.watchEvidenceStateLive("apache_access.log");
  expect(terminal).toBe("Complete");

  const evidenceId = await detail.fetchFirstEvidenceId(caseId!);
  expect(evidenceId).toBeTruthy();

  const seeded = new VolatilityArtifactSeeder().seed(caseId!, evidenceId, undefined, true);
  expect(seeded.artifactIds).toHaveLength(10); // 7 eager + 2 printkey + 1 dumpfiles

  // Same real staleTime gap case-artifacts-ui.spec.ts's own comment
  // documents -- a real reload is the honest equivalent of a real user
  // checking back after a real on-demand action lands.
  await detail.page.reload();
  await detail.page.waitForSelector("text=apache_access.log", { timeout: 10000 });
  await detail.page.getByRole("button", { name: "Artifacts", exact: true }).click();
  await detail.page.waitForSelector("text=apache_access.log", { timeout: 10000 });
  await detail.page.getByText("apache_access.log").click();

  // Child Files: real seeded dumpfiles row (filename/size/sha256 all
  // real, matching content the seeder actually uploaded to MinIO).
  await detail.page.getByRole("button", { name: "Child Files" }).click();
  await expect(detail.page.getByRole("heading", { name: "Child Files" })).toBeVisible();
  await expect(
    detail.page.getByText("F3A2A55211EE66D36F43F15EFF501E9546680661.dat"),
  ).toBeVisible({ timeout: 10000 });
  await expect(detail.page.getByText("132.0 KB")).toBeVisible();

  // Real download round-trip: the seeded fixture's real bytes, streamed
  // back through the real GET .../artifacts/{id}/download route.
  const [download] = await Promise.all([
    detail.page.waitForEvent("download", { timeout: 15000 }),
    detail.page.getByRole("button", { name: "Download" }).first().click(),
  ]);
  expect(download.suggestedFilename()).toContain("F3A2A55211EE66D36F43F15EFF501E9546680661.dat");

  // VirusTotal placeholder is present but genuinely inert (Milestone
  // EEEEE's plan: reserved for "eventually," not wired to anything yet).
  await expect(detail.page.getByText("Check reputation")).toBeVisible();

  // Registry Browser: hive selection -> real root printkey rows -> drill
  // into ControlSet001 -> real one-level-deeper printkey rows, all from
  // the seeded fixture (no live extraction needed for this UI-only spec).
  await detail.page.getByRole("button", { name: "Registry Browser" }).click();
  await expect(detail.page.getByText("Select a hive to browse")).toBeVisible();
  await detail.page.getByRole("button", { name: "\\REGISTRY\\MACHINE\\SYSTEM" }).click();
  await expect(detail.page.getByText("ControlSet001")).toBeVisible({ timeout: 10000 });
  await expect(detail.page.getByText("MountedDevices")).toBeVisible();

  await detail.page.getByRole("button", { name: "ControlSet001" }).click();
  await expect(detail.page.getByText("Control", { exact: true })).toBeVisible({ timeout: 10000 });
  await expect(detail.page.getByText("Enum", { exact: true })).toBeVisible();

  // Breadcrumb navigation back to hive root re-fetches (or re-displays)
  // the real root-level rows, not a stale/empty view.
  await detail.page.getByRole("button", { name: "\\REGISTRY\\MACHINE\\SYSTEM" }).click();
  await expect(detail.page.getByText("MountedDevices")).toBeVisible({ timeout: 10000 });
});
