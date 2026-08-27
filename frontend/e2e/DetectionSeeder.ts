import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SEED_SCRIPT = path.resolve(__dirname, "fixtures/seed_detection.py");
const PYTHON = process.env.KRONOS_E2E_PYTHON ?? path.join(process.env.HOME ?? "", "venv/bin/python3");

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
    const stdout = execFileSync(
      PYTHON,
      [SEED_SCRIPT, "--org-alias", orgAlias, "--rule-name", ruleName],
      { stdio: ["ignore", "pipe", "inherit"] },
    ).toString();
    return JSON.parse(stdout.trim().split("\n").pop() ?? "{}") as SeededDetection;
  }
}
