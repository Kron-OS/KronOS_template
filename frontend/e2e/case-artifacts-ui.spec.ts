import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";
import { VolatilityArtifactSeeder } from "./VolatilityArtifactSeeder";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REAL_DIR = path.resolve(__dirname, "../../tests/fixtures/samples/real");

/**
 * Gap Audit Milestone AAAAA: real UI coverage for the Artifacts tab
 * ("scenario 4" of the Volatility-UI design conversation -- dedicated
 * case-level view, kind-aware rendering, dual-emit into OpenSearch already
 * verified separately in poc/volatility_timeline_dual_emit/).
 *
 * Gap Audit Milestone DDDDD: extended for the real, two-level nav (evidence
 * file -> kind cluster) the 5 new eager Volatility plugins (Milestone
 * CCCCC's backend work) required -- one file can now produce 7 real
 * artifact kinds, only one of which renders at a time, so this spec
 * exercises switching between them, not just that content exists somewhere
 * on the page.
 *
 * The real end-to-end volatility3 pipeline (real subprocess against real
 * memory images, real dual-emit, real OpenSearch ingestion/query-back, and
 * -- Milestone CCCCC -- the real shared-context multi-plugin worker
 * against both cridex.vmem and a real 1.6GB user-uploaded image) is already
 * verified for real in poc/volatility_multiplugin/ and
 * poc/volatility_pipeline_ingest/ -- a 512 MiB+ memory-image upload through
 * this suite would be slow and heavy for what THIS spec needs to prove
 * (does the real UI correctly render real StructuredArtifact data, group
 * by evidence file and kind, and route the drawer's "Open full analysis"
 * link correctly). So this uploads a real, small, fast-parsed evidence
 * file first (to get a REAL evidence_id, not a fabricated one), then seeds
 * real StructuredArtifact rows for all 7 real kinds against that real
 * evidence_id via VolatilityArtifactSeeder (real Postgres insert, real
 * captured row shapes -- see that class's own docstring).
 */
test("Artifacts tab renders real StructuredArtifact data, grouped by evidence file and kind", async ({
  casesPageAsCaseLead,
}) => {
  const detail = await casesPageAsCaseLead.createCase(
    `E2E artifacts-ui case ${Date.now()}`,
    `E2E-ARTIFACTS-${Date.now()}`,
  );
  const caseId = detail.url.split("/cases/")[1]?.split(/[/?#]/)[0];
  expect(caseId, `expected a real case id in the URL, got: ${detail.url}`).toBeTruthy();

  await detail.uploadEvidence(path.join(REAL_DIR, "apache_access.log"));
  // Wait for the real pipeline to actually finish, not just the upload
  // dialog's own "Done" (client-side finalize only) -- EvidenceDetailDrawer
  // snapshots `evidence` into local state on click and never re-syncs it,
  // so clicking Details before this settles reliably shows a stale
  // "Uploading" status even after the table row itself has moved on.
  const { terminal } = await detail.watchEvidenceStateLive("apache_access.log");
  expect(terminal).toBe("Complete");

  const evidenceId = await detail.fetchFirstEvidenceId(caseId!);
  expect(evidenceId).toBeTruthy();

  const seeded = new VolatilityArtifactSeeder().seed(caseId!, evidenceId);
  expect(seeded.artifactIds).toHaveLength(7);

  // Real, found-live finding (Milestone AAAAA): the artifacts query has its
  // own 15s staleTime (CaseDetailPage.tsx) -- EvidenceTab already fetched
  // (and cached) an empty artifacts list on mount, before this seed ran,
  // and no SSE event fires for evidence that doesn't change state again
  // (the seeder inserts directly, bypassing the real pipeline that would
  // otherwise trigger the SSE-driven artifacts invalidation this same
  // milestone added). A real reload is the honest equivalent of a real
  // user checking back after a real scan finishes.
  await detail.page.reload();
  await detail.page.waitForSelector("text=apache_access.log", { timeout: 10000 });

  // Real UI path 1: the drawer's "Open full analysis" link.
  await detail.page.getByRole("button", { name: "Details", exact: true }).first().click();
  await expect(detail.page.getByText(/artifacts? found/i)).toBeVisible({ timeout: 15000 });
  await detail.page.getByRole("button", { name: "Open full analysis →", exact: true }).click();

  // Lands on the Artifacts tab, pre-selected to this evidence file.
  await expect(detail.page.getByRole("button", { name: "Artifacts", exact: true })).toHaveClass(
    /text-indigo-600|border-indigo-500/,
  );

  // Real cluster nav (Milestone DDDDD): all 3 real clusters present since
  // this evidence file has kinds in all of them.
  await expect(detail.page.getByText("Process", { exact: true })).toBeVisible({ timeout: 10000 });
  await expect(detail.page.getByText("Suspicious", { exact: true })).toBeVisible();
  await expect(detail.page.getByText("Files & Registry", { exact: true })).toBeVisible();

  // Default-selected kind is the first in cluster order (Process Tree) --
  // real, empty in this seeded data (matches the real cridex.vmem finding
  // that pstree returns 0 rows for that sample) renders its own honest
  // "no processes" empty state, not a blank gap or an error.
  await expect(detail.page.getByRole("heading", { name: /Process Tree/ })).toBeVisible();
  await expect(detail.page.getByText("No processes found by this plugin.")).toBeVisible();

  // Switch to Process List (scan) -- real table with real process rows
  // (svchost.exe, PID 908 -- the same real row this spec's own seeder
  // inserted, sourced from the real captured cridex.vmem output).
  await detail.page.getByRole("button", { name: "Process List (scan)" }).click();
  await expect(detail.page.getByRole("heading", { name: /Process List/ })).toBeVisible();
  await expect(detail.page.getByText("svchost.exe")).toBeVisible();
  await expect(detail.page.getByText("908")).toBeVisible();

  // Switch to Loaded DLLs -- real dlllist row (Milestone CCCCC's new
  // plugin, real data from a real 1.6GB user-uploaded image).
  await detail.page.getByRole("button", { name: "Loaded DLLs" }).click();
  await expect(detail.page.getByRole("heading", { name: /Loaded DLLs/ })).toBeVisible();
  await expect(detail.page.getByText("smss.exe").first()).toBeVisible();

  // Switch to Suspicious Regions -- the real malfind card layout, not a
  // table (Milestone DDDDD's own genuinely new component), showing the
  // real PAGE_EXECUTE_READWRITE injection tell.
  await detail.page.getByRole("button", { name: "Suspicious Regions" }).click();
  await expect(detail.page.getByRole("heading", { name: /Suspicious Regions/ })).toBeVisible();
  await expect(detail.page.getByText("explorer.exe", { exact: false })).toBeVisible();
  await expect(detail.page.getByText("PAGE_EXECUTE_READWRITE")).toBeVisible();

  // Switch to Files in Memory and Registry Hives -- real filescan/hivelist
  // rows.
  await detail.page.getByRole("button", { name: "Files in Memory" }).click();
  await expect(detail.page.getByText("\\Endpoint")).toBeVisible();
  await detail.page.getByRole("button", { name: "Registry Hives" }).click();
  await expect(detail.page.getByRole("heading", { name: /Registry Hives/ })).toBeVisible();

  // Real UI path 2: navigating directly to the Artifacts tab (not via the
  // drawer link) still shows the same real data -- proves the tab isn't
  // only reachable/populated via the drawer's hand-off state.
  await detail.openArtifactsTab();
  await expect(detail.page.getByText("Process", { exact: true })).toBeVisible({ timeout: 10000 });
});
