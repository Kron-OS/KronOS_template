import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Gap Audit Milestone AAAA: was tests/fixtures/samples/cloudtrail.json, a
// hand-crafted synthetic fixture -- this spec's own docstring claimed it
// "uses the same real fixture file every prior real-browser upload PoC in
// this repo used," which was never actually true for this specific spec.
// Swapped for the genuinely real, already-committed
// tests/fixtures/samples/real/aws_cloudtrail.jsonl (sourced from Plaso's
// own test_data/, see that directory's NOTICE.md) -- confirmed it routes
// identically via CloudTrailParser.supports() (.jsonl accepted, real
// "CloudTrailEvent" field present in the header bytes) before swapping,
// not assumed.
const CLOUDTRAIL_SAMPLE = path.resolve(__dirname, "../../tests/fixtures/samples/real/aws_cloudtrail.jsonl");

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.2 / §5 item 2): the
 * platform's own core loop, and the exact shape of bug
 * (poc/evidence_sse_realtime/browser_verify.py's SSE fix -- named-event
 * listener + snake_case/camelCase field mismatch) this suite exists to
 * catch automatically instead of by hand next time.
 */
test("real evidence upload reaches COMPLETE live, via SSE, without a page reload", async ({ casesPageAsCaseLead }) => {
  const title = `E2E upload spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-${Date.now()}`);

  await detail.uploadEvidence(CLOUDTRAIL_SAMPLE);

  const { seenStates, terminal } = await detail.watchEvidenceStateLive("aws_cloudtrail.jsonl");

  expect(seenStates.length, `observed state sequence: ${seenStates.join(" -> ")}`).toBeGreaterThan(0);
  expect(terminal, `observed state sequence: ${seenStates.join(" -> ")}`).toBe("Complete");
});
