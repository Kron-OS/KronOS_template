import { execFileSync } from "node:child_process";
import path from "node:path";

const PYTHON = process.env.KRONOS_E2E_PYTHON ?? path.join(process.env.HOME ?? "", "venv/bin/python3");

/**
 * Shared runner for the `frontend/e2e/fixtures/*.py` scripts (seed_detection.py,
 * seed_second_org.py, ...) -- consolidated here (Gap Audit
 * 2026-08-28_MILESTONE_EEE maintainability finding #2) instead of each
 * fixture wrapper re-implementing its own `execFileSync` call, so the
 * "Python not found" failure mode and the `KRONOS_E2E_PYTHON` override are
 * documented and handled in exactly one place. See frontend/e2e/README.md
 * for why a second interpreter is involved at all (reusing real backend
 * domain code to avoid schema drift, not a preference for Python per se).
 */
export function runPythonFixture<T>(scriptPath: string, args: string[] = []): T {
  let stdout: string;
  try {
    stdout = execFileSync(PYTHON, [scriptPath, ...args], { stdio: ["ignore", "pipe", "inherit"] }).toString();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(
        `Could not run Python fixture ${scriptPath} -- no interpreter at "${PYTHON}". ` +
          `Set KRONOS_E2E_PYTHON to a real Python 3 with this repo's backend deps installed. ` +
          `See frontend/e2e/README.md.`,
      );
    }
    throw err;
  }
  return JSON.parse(stdout.trim().split("\n").pop() ?? "{}") as T;
}
