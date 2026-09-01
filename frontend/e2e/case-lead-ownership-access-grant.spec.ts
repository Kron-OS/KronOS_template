import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";

/**
 * RBAC tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md), closing Gap Audit
 * Milestone KKKK's own coverage-gap finding: `assert_case_lead_or_admin`
 * (`src/external/middleware/rbac.py`) gates THREE call sites in
 * `src/external/routes/cases.py` -- `add_case_member`, `delete_case`, and
 * `list_case_audit_events`. Its DENY branch has real coverage
 * (`case-lead-ownership-access-denial.spec.ts`); its ALLOW branch is only
 * ever asserted as a side effect of `case-membership-access-grant.spec.ts`'s
 * own setup step -- that spec's real, named purpose is
 * `assert_case_access`'s separate ALLOW branch (does a granted member get
 * real read access), not this one. `list_case_audit_events` specifically
 * has never been exercised by any spec, on either branch, before this one
 * (confirmed via `grep -rl "auditlog\|Audit Log" frontend/e2e/` before
 * writing this).
 *
 * A freshly created case already has a real, non-empty audit trail --
 * `create_case` itself logs `AuditEventType.CASE_CREATED`
 * (`src/external/routes/cases.py`) -- so no extra setup is needed to prove
 * the Audit Log tab returns real content, not just an empty 200.
 */
test("a real case-lead who owns this case can read its audit log and perform a case-lead-gated mutation", async ({
  page,
}) => {
  test.setTimeout(45000);

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  const cases = await login.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);

  const caseTitle = `E2E Ownership-Allow Case ${Date.now()}`;
  const detail = await cases.createCase(caseTitle, `E2E-ALLOW-${Date.now()}`);
  const caseId = page.url().split("/cases/")[1];
  expect(caseId, `expected a real case id in the URL, got: ${page.url()}`).toBeTruthy();

  // list_case_audit_events's own assert_case_lead_or_admin ALLOW branch --
  // never exercised by any prior spec, on either branch.
  await detail.openAuditLogTab();
  await detail.waitForAuditEventRow("case.created");
  const totalAfterCreate = await detail.getAuditLogTotalText();
  expect(totalAfterCreate).toContain("1 total events");

  // add_case_member's own ALLOW branch, named explicitly as this spec's
  // own scenario this time (not just asserted as a side effect of a
  // differently-framed spec, per Milestone KKKK's finding). Real target
  // userId doesn't matter here -- this spec is about the ownership check
  // succeeding and being audited, not about the resulting member's own
  // access (case-membership-access-grant.spec.ts already covers that).
  const grantStatus = await cases.attemptAddMember(caseId, "00000000-0000-0000-0000-000000000002");
  expect(
    grantStatus,
    "case-lead adding a member to a case it owns must be a real, successful grant",
  ).toBe(200);

  // Confirm the mutation is genuinely reflected in a fresh read of the
  // same case-lead-gated audit endpoint, not just trusted from the POST's
  // own response.
  await page.reload();
  await detail.waitUntilReady();
  await detail.openAuditLogTab();
  await detail.waitForAuditEventRow("case.updated");
  const totalAfterGrant = await detail.getAuditLogTotalText();
  expect(totalAfterGrant).toContain("2 total events");
});
