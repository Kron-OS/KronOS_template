import path from "node:path";
import { fileURLToPath } from "node:url";
import { runPythonFixture } from "./pythonFixture";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT = path.resolve(__dirname, "fixtures/update_user_realm_role.py");

export type RoleUpdateResult = { userId: string; removedRole: string; addedRole: string };

/**
 * Wraps `frontend/e2e/fixtures/update_user_realm_role.py`: swaps an
 * EXISTING user's real Keycloak realm role -- for Gap Audit Milestone
 * NNNN's mid-session role-change coverage. Unlike `SecondCaseLeadSeeder`/
 * `SecondOrgSeeder` (which provision a fresh throwaway user), this acts on
 * a user id that's already logged in, in a real browser session, so the
 * test can observe the real effect of a live demotion on that session's
 * still-valid access token vs. a freshly-refreshed one.
 */
export class UserRoleUpdater {
  swapRealmRole(userId: string, removeRole: string, addRole: string): RoleUpdateResult {
    return runPythonFixture<RoleUpdateResult>(SCRIPT, [
      "--user-id",
      userId,
      "--remove-role",
      removeRole,
      "--add-role",
      addRole,
    ]);
  }
}
