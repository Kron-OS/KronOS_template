import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REAL_DIR = path.resolve(__dirname, "../../tests/fixtures/samples/real");

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.2), real FAST-tier
 * (`ParserType.FAST`, `q.parse.fast`) parsers -- closes Gap Audit
 * Milestone XXX's own coverage-gap finding: three straight cycles
 * (UUU/VVV/WWW) built out real, dedicated E2E coverage for every
 * HEAVY-tier parser, but left the FAST tier -- the platform's actual
 * highest-volume real-world ingestion path -- as the comparatively
 * LEAST-verified tier. Before this spec, only CloudTrail
 * (`evidence-upload.spec.ts`, a synthetic fixture) had ever been driven
 * through a real top-level upload; evtx/nginx/suricata/chrome-history had
 * either never been uploaded standalone at all, or (nginx, chrome-history)
 * only ever been exercised indirectly as members recursively unpacked
 * from `kape_triage.zip` (Milestone VVV) -- never as their own evidence
 * item, going through their own independent `supports()`/magic-byte
 * detection at the top level.
 *
 * Every fixture here is real (not synthetic), already committed, and
 * already independently verified at the unit/parser level
 * (`tests/unit/parsers/test_real_world_samples.py` for evtx/nginx/suricata;
 * `poc/kape_ingestion_test/` for the chrome-history sample, which is the
 * exact same real file as `tests/fixtures/samples/real/kape/kape_triage.zip`'s
 * own Chrome History member, extracted standalone here -- see
 * `tests/fixtures/samples/real/chrome_history/NOTICE.md`).
 */

test("real evtx-rs (Windows EVTX) evidence upload reaches COMPLETE live, via SSE", async ({
  casesPageAsCaseLead,
}) => {
  const title = `E2E fast-parser evtx spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-FAST-EVTX-${Date.now()}`);

  await detail.uploadEvidence(path.join(REAL_DIR, "system.evtx"));

  const { seenStates, terminal } = await detail.watchEvidenceStateLive("system.evtx");

  expect(seenStates.length, `observed state sequence: ${seenStates.join(" -> ")}`).toBeGreaterThan(0);
  expect(terminal, `observed state sequence: ${seenStates.join(" -> ")}`).toBe("Complete");
});

test("real Nginx/Apache access-log evidence upload reaches COMPLETE live, via SSE", async ({
  casesPageAsCaseLead,
}) => {
  const title = `E2E fast-parser nginx spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-FAST-NGINX-${Date.now()}`);

  await detail.uploadEvidence(path.join(REAL_DIR, "apache_access.log"));

  const { seenStates, terminal } = await detail.watchEvidenceStateLive("apache_access.log");

  expect(seenStates.length, `observed state sequence: ${seenStates.join(" -> ")}`).toBeGreaterThan(0);
  expect(terminal, `observed state sequence: ${seenStates.join(" -> ")}`).toBe("Complete");
});

test("real Suricata EVE JSON evidence upload reaches COMPLETE live, via SSE", async ({
  casesPageAsCaseLead,
}) => {
  const title = `E2E fast-parser suricata spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-FAST-SURICATA-${Date.now()}`);

  await detail.uploadEvidence(path.join(REAL_DIR, "suricata", "eve.json"));

  const { seenStates, terminal } = await detail.watchEvidenceStateLive("eve.json");

  expect(seenStates.length, `observed state sequence: ${seenStates.join(" -> ")}`).toBeGreaterThan(0);
  expect(terminal, `observed state sequence: ${seenStates.join(" -> ")}`).toBe("Complete");
});

test("real Chrome History SQLite evidence upload reaches COMPLETE live, via SSE", async ({
  casesPageAsCaseLead,
}) => {
  const title = `E2E fast-parser chrome-history spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-FAST-CHROME-${Date.now()}`);

  await detail.uploadEvidence(path.join(REAL_DIR, "chrome_history", "History"));

  const { seenStates, terminal } = await detail.watchEvidenceStateLive("History");

  expect(seenStates.length, `observed state sequence: ${seenStates.join(" -> ")}`).toBeGreaterThan(0);
  expect(terminal, `observed state sequence: ${seenStates.join(" -> ")}`).toBe("Complete");
});
