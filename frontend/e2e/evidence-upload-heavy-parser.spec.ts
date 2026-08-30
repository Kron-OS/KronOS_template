import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Real Windows 10 prefetch sample (tests/fixtures/samples/real/NOTICE.md),
// already used by real backend-only parser tests -- reused here rather
// than a synthetic fixture. Routes to PlasoParser (ParserType.HEAVY,
// q.parse.plaso), never evtx-rs's FAST path -- confirmed via
// src/external/parsers/plaso.py's own magic-byte table (MAM/SCCA) and
// src/application/validation.py's MagicByteValidator entry for it.
const PREFETCH_SAMPLE = path.resolve(
  __dirname,
  "../../tests/fixtures/samples/real/CMD.EXE-087B4001.pf",
);

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.2), test-stack profile.
 * Milestone UUU: closes a real, structural gap named by Milestone PPP's
 * own coverage-gap review and carried since -- every prior spec in this
 * profile only ever exercised FAST-path parsers (evtx-rs/CloudTrail/
 * nginx text formats via celery-worker's own q.parse.fast queue).
 * ParserType.HEAVY (Plaso, ArchiveParser/TarArchiveParser's EWF/ZIP
 * routing, VolatilityModule) always routes to q.parse.plaso -- a queue
 * `docker-compose.test.yml` had NO consumer for at all until this
 * milestone added celery-worker-plaso (mirroring
 * docker-compose.dev.yml's own service). Confirmed live before this fix
 * landed: exactly Milestone MMM's own q.intake gap, recurring for the
 * heavy-parser queue instead -- a real HEAVY upload would have sat in
 * RECEIVED/PARSING forever, silently, with zero error.
 */
test("real HEAVY-tier (Plaso) evidence upload reaches COMPLETE live, via SSE", async ({
  casesPageAsCaseLead,
}) => {
  // Plaso's own real startup + parse time for even a tiny single-file
  // prefetch sample is meaningfully slower than the FAST-path text
  // parsers every other upload spec in this profile uses -- budgeted
  // generously rather than guessed, matching this initiative's own
  // practice for other Celery-backed specs (evidence-retry.spec.ts,
  // evidence-parse-retry.spec.ts) of sizing real observed pipeline work
  // rather than reusing a smaller default.
  test.setTimeout(120000);
  const title = `E2E heavy-parser spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-HEAVY-${Date.now()}`);

  await detail.uploadEvidence(PREFETCH_SAMPLE);

  const { seenStates, terminal } = await detail.watchEvidenceStateLive("CMD.EXE-087B4001.pf", 90000);

  expect(seenStates.length, `observed state sequence: ${seenStates.join(" -> ")}`).toBeGreaterThan(0);
  expect(terminal, `observed state sequence: ${seenStates.join(" -> ")}`).toBe("Complete");
});
