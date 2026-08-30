import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Real KAPE-shaped fixtures (tests/fixtures/samples/real/kape/NOTICE.md):
// a real zip container (4 real inner artifacts: EVTX, Prefetch, Chrome
// History, an IIS-style access log) and a real EWF/E01 disk image (FAT16,
// built with real `ewfacquirestream`) containing real EVTX + Prefetch
// content. Both already verified against the real dev stack end-to-end at
// the backend level (poc/kape_ingestion_test/, 631 real OpenSearch
// documents, zero flagged parsing errors) -- this spec is the first time
// either has ever been driven through a real BROWSER upload against the
// test-stack profile's own celery-worker-plaso (added in Milestone UUU),
// closing Milestone UUU's own recommendation #1 (archive/EWF routing was
// the one HEAVY-tier path still untested end-to-end through a real E2E
// browser flow).
const KAPE_ZIP = path.resolve(__dirname, "../../tests/fixtures/samples/real/kape/kape_triage.zip");
const KAPE_E01 = path.resolve(__dirname, "../../tests/fixtures/samples/real/kape/kape_triage.E01");

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.2), test-stack profile.
 * ZipArchiveParser is unconditionally HEAVY (q.parse.plaso) even though
 * every inner member it recursively dispatches here (evtx-rs, Chrome
 * History, Nginx) is itself FAST -- see that class's own docstring on why
 * "might ever need Plaso for any input" makes queue routing unconditional,
 * not per-file. Budgeted generously but not guessed: real backend-only
 * verification (poc/kape_ingestion_test/output.txt) showed the zip's own
 * dominant cost is one nested Plaso invocation for its Prefetch member
 * (Plaso's own real startup time, same order of magnitude as
 * evidence-upload-heavy-parser.spec.ts's single-.pf case) plus near-instant
 * evtx-rs/Chrome/Nginx member parsing.
 */
test("real HEAVY-tier (ZipArchiveParser) KAPE zip reaches COMPLETE live, via SSE", async ({
  casesPageAsCaseLead,
}) => {
  test.setTimeout(150000);
  const title = `E2E heavy-parser archive(zip) spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-HEAVY-ZIP-${Date.now()}`);

  await detail.uploadEvidence(KAPE_ZIP);

  const { seenStates, terminal } = await detail.watchEvidenceStateLive("kape_triage.zip", 120000);

  expect(seenStates.length, `observed state sequence: ${seenStates.join(" -> ")}`).toBeGreaterThan(0);
  expect(terminal, `observed state sequence: ${seenStates.join(" -> ")}`).toBe("Complete");
});

/**
 * PlasoParser's EWF/E01 magic-byte routing -- the whole image is handed to
 * `log2timeline`/`psort`, which auto-detects "storage media image" via
 * dfVFS and walks the FAT filesystem itself (no KronOS-side recursion, a
 * different code path from the zip case above even though both land on
 * q.parse.plaso). Real backend-only run produced 414 real events from this
 * exact fixture (poc/kape_ingestion_test/output.txt) -- a materially larger
 * single Plaso invocation than either the zip's nested Prefetch-only parse
 * or evidence-upload-heavy-parser.spec.ts's own single-file case, budgeted
 * accordingly rather than reusing the smaller specs' timeouts.
 */
test("real HEAVY-tier (PlasoParser EWF/E01) KAPE disk image reaches COMPLETE live, via SSE", async ({
  casesPageAsCaseLead,
}) => {
  test.setTimeout(180000);
  const title = `E2E heavy-parser archive(e01) spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-HEAVY-E01-${Date.now()}`);

  await detail.uploadEvidence(KAPE_E01);

  const { seenStates, terminal } = await detail.watchEvidenceStateLive("kape_triage.E01", 150000);

  expect(seenStates.length, `observed state sequence: ${seenStates.join(" -> ")}`).toBeGreaterThan(0);
  expect(terminal, `observed state sequence: ${seenStates.join(" -> ")}`).toBe("Complete");
});
