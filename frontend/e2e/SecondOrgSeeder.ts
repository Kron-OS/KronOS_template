import path from "node:path";
import { fileURLToPath } from "node:url";
import { runPythonFixture } from "./pythonFixture";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SEED_SCRIPT = path.resolve(__dirname, "fixtures/seed_second_org.py");

export type SeededSecondOrg = { orgId: string; orgAlias: string; username: string; password: string };

/**
 * Wraps frontend/e2e/fixtures/seed_second_org.py: creates a fresh, real,
 * throwaway Keycloak Organization + member user (real org_id user
 * attribute + analyst realm role) for cross-tenant UI isolation specs
 * (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.5). A fresh org per test run, not
 * reused across runs -- simpler than idempotent lookup for a disposable
 * fixture and avoids any stale-state-from-a-prior-run class of bug.
 */
export class SecondOrgSeeder {
  seed(): SeededSecondOrg {
    return runPythonFixture<SeededSecondOrg>(SEED_SCRIPT);
  }
}
