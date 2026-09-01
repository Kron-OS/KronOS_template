import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";

/**
 * RBAC/data-integrity tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md), closing
 * Gap Audit Milestone KKKK's own security finding: `add_case_member`
 * (`src/external/routes/cases.py`) used to accept ANY UUID as
 * `body.userId` with no existence/org check at all -- a case-lead who
 * owns a case could add a target id that isn't a real user in their org
 * (or any org), silently creating a dead membership row with no
 * feedback. Milestone QQQQ fixed this: `add_case_member` now validates
 * `body.userId` against the caller's own org via a real
 * `KeycloakAdminClient.is_org_member` call before accepting the mutation.
 *
 * This is a real, live proof of that fix against the actual dev stack's
 * real Keycloak, not the mocked unit-test coverage
 * (`TestAddCaseMemberOrgValidation` in `tests/unit/test_cases_routes.py`)
 * -- confirms the real `HttpxKeycloakAdminClient` wired at real startup
 * (`configure_keycloak_admin_client_from_settings()`) genuinely rejects a
 * random UUID, not just that a fake client in a unit test does.
 */
test("add_case_member rejects a real, syntactically valid UUID that is not a member of the caller's org", async ({
  page,
}) => {
  test.setTimeout(30000);

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  const cases = await login.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);

  await cases.createCase(
    `E2E UserId-Validation Case ${Date.now()}`,
    `E2E-USERID-VALID-${Date.now()}`,
  );
  const caseId = page.url().split("/cases/")[1];
  expect(caseId, `expected a real case id in the URL, got: ${page.url()}`).toBeTruthy();

  // A syntactically-valid but real-nowhere UUID -- not a member of any
  // org, confirmed by construction (a fresh random v4, vanishingly
  // unlikely to collide with any real Keycloak user id).
  const bogusUserId = crypto.randomUUID();
  const status = await cases.attemptAddMember(caseId, bogusUserId);
  expect(
    status,
    "a case-lead who owns this case must still be denied adding a userId that is not a real member of their org",
  ).toBe(403);
});
