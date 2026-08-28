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
  seed(ruleName: string, orgAlias = "kronos-dev"): SeededDetection {
    return runPythonFixture<SeededDetection>(SEED_SCRIPT, ["--org-alias", orgAlias, "--rule-name", ruleName]);
  }
}
