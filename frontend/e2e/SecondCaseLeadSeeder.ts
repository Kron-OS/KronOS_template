import path from "node:path";
import { fileURLToPath } from "node:url";
import { runPythonFixture } from "./pythonFixture";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SEED_SCRIPT = path.resolve(__dirname, "fixtures/seed_second_case_lead.py");

export type SeededSecondCaseLead = { orgAlias: string; username: string; password: string };

/**
 * Wraps frontend/e2e/fixtures/seed_second_case_lead.py: creates a fresh,
 * real, throwaway user in the EXISTING target org (default `kronos-dev`)
 * with the real `case-lead` realm role -- for `assert_case_lead_or_admin`
 * ("of case"/"own") RBAC coverage (Gap Audit Milestone CCCC's own
 * recommendation #2). The single static `case-lead` dev user can't
 * exercise this alone -- whatever case it creates, it owns -- so a
 * genuinely second, distinct case-lead account is required.
 */
export class SecondCaseLeadSeeder {
  seed(): SeededSecondCaseLead {
    return runPythonFixture<SeededSecondCaseLead>(SEED_SCRIPT);
  }
}
