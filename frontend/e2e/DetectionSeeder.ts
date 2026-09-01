import path from "node:path";
import { fileURLToPath } from "node:url";
import { runPythonFixture } from "./pythonFixture";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SEED_SCRIPT = path.resolve(__dirname, "fixtures/seed_detection.py");

export type SeededDetection = { detectionId: string; orgId: string; ruleName: string };

/**
 * Wraps frontend/e2e/fixtures/seed_detection.py rather than
 * reimplementing the insert in TypeScript -- that script goes through the
 * real PostgresDetectionRepository + DetectionRiskScorer domain code, so
 * it stays correct automatically if the `detections` schema ever changes,
 * instead of drifting out of sync with a second, hand-written INSERT.
 */
export class DetectionSeeder {
  // KRONOS_E2E_SEED_ORG_ALIAS override (Milestone NNN): the dev stack's
  // keycloak-init provisions "kronos-dev", but docker-compose.test.yml's
  // own keycloak-init provisions "kronos-test" instead -- login as
  // case-lead there gets that org's org_id, which would never match a
  // detection seeded under the wrong default. Callers targeting a non-dev
  // stack should still prefer passing orgAlias explicitly; this env
  // fallback exists so CI can point the whole suite at the right org
  // without editing every spec that omits the argument.
  seed(ruleName: string, orgAlias = process.env.KRONOS_E2E_SEED_ORG_ALIAS ?? "kronos-dev"): SeededDetection {
    return runPythonFixture<SeededDetection>(SEED_SCRIPT, ["--org-alias", orgAlias, "--rule-name", ruleName]);
  }

  /**
   * Milestone JJJJ: seeds a detection already sitting at a non-default
   * triage state -- `seed_detection.py --triage-state` is a real insert via
   * the real domain code, not a simulated FSM transition (see that
   * script's own comment for why that's fine at insert time). Used by
   * `visual-regression-pills.spec.ts` to get all 4 real `TriageStatePill`
   * colors on screen without needing to click through the UI's own
   * transition rules for every state.
   */
  seedAtTriageState(
    ruleName: string,
    triageState: "NEW" | "INVESTIGATING" | "TRUE_POSITIVE" | "FALSE_POSITIVE",
    orgAlias = process.env.KRONOS_E2E_SEED_ORG_ALIAS ?? "kronos-dev",
  ): SeededDetection {
    return runPythonFixture<SeededDetection>(SEED_SCRIPT, [
      "--org-alias",
      orgAlias,
      "--rule-name",
      ruleName,
      "--triage-state",
      triageState,
    ]);
  }
}
