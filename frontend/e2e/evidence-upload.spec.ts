import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLOUDTRAIL_SAMPLE = path.resolve(__dirname, "../../tests/fixtures/samples/cloudtrail.json");

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.2 / §5 item 2): the
 * platform's own core loop, and the exact shape of bug
 * (poc/evidence_sse_realtime/browser_verify.py's SSE fix -- named-event
 * listener + snake_case/camelCase field mismatch) this suite exists to
 * catch automatically instead of by hand next time. Uses the same real
 * fixture file every prior real-browser upload PoC in this repo used.
 */
test("real evidence upload reaches COMPLETE live, via SSE, without a page reload", async ({ casesPageAsCaseLead }) => {
  const title = `E2E upload spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-${Date.now()}`);

  await detail.uploadEvidence(CLOUDTRAIL_SAMPLE);

  const { seenStates, terminal } = await detail.watchEvidenceStateLive("cloudtrail.json");

  expect(seenStates.length, `observed state sequence: ${seenStates.join(" -> ")}`).toBeGreaterThan(0);
  expect(terminal, `observed state sequence: ${seenStates.join(" -> ")}`).toBe("Complete");
});
