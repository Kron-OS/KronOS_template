import { test, expect } from "./fixtures";

/**
 * RBAC/authz access-denial coverage (docs/PLAYWRIGHT_E2E_TEST_PLAN.md) --
 * carried unclosed across five straight milestones (Gap Audit
 * Milestones OOO through AAAA all named this as an open gap) before this
 * spec. Every prior spec in this suite only ever proves a PRIVILEGED
 * user succeeding; nothing had ever confirmed a real, deliberately
 * LESS-privileged user actually gets denied -- the only remaining named
 * gap that is a real security boundary (CLAUDE.md §A.6), not a UX/
 * resilience nicety.
 *
 * Real, confirmed premise (docker/keycloak/kronos-realm.json's own real
 * user->role assignments, not assumed): the dev-seeded "analyst" account
 * carries only Role.ANALYST, never Role.CASE_LEAD/Role.ORG_ADMIN.
 * `POST /api/cases` (src/external/routes/cases.py) is gated
 * `requires_role(Role.ORG_ADMIN, Role.CASE_LEAD)` -- an analyst is
 * therefore a real, deterministic 403 case, not a synthetic one.
 *
 * Real, previously-unverified frontend behaviour this also confirms:
 * `CasesPage.tsx` has NO frontend-side role gate on the "New Case"
 * button/modal at all (confirmed by reading the component before writing
 * this spec, not assumed) -- every authenticated user can open and
 * submit the form regardless of role. The real security boundary is
 * enforced entirely server-side; this spec is what actually proves that
 * boundary holds and that the frontend surfaces the resulting real 403
 * as a visible error rather than hanging or crashing.
 */
test("an analyst (lacking case-lead/org-admin) is denied case creation, and the UI surfaces it", async ({
  casesPageAsAnalyst,
}) => {
  // Real backend claim shape (src/external/middleware/keycloak_auth.py,
  // AUTH-006): roles are read from a FLAT top-level "roles" claim, not
  // Keycloak's default nested realm_access.roles -- OpenSearch Security's
  // roles_key can't walk nested paths, so the kronos-realm.json client
  // scope mapper emits this flat shape instead. Verified against the
  // backend source before asserting on it, not assumed from Keycloak's
  // own default token shape.
  const claims = await casesPageAsAnalyst.fetchDecodedAccessTokenClaims();
  const roles = (claims.roles as string[] | undefined) ?? [];
  expect(roles, "analyst token must carry only the analyst role, never case-lead/org-admin").toContain(
    "analyst",
  );
  expect(roles).not.toContain("case-lead");
  expect(roles).not.toContain("org-admin");

  const title = `E2E RBAC-denied case ${Date.now()}`;
  await casesPageAsAnalyst.attemptCreateCase(title, `E2E-RBAC-${Date.now()}`);

  const errorText = await casesPageAsAnalyst.waitForCreateCaseError();
  expect(errorText).toContain("Failed to create case");

  // Real confirmation nothing succeeded, not just that an error rendered:
  // the create modal is still open (CreateCaseModal never calls onClose()
  // outside its own onSuccess handler), and the case never appears in the
  // list once the modal is dismissed.
  await expect(
    casesPageAsAnalyst.page.locator("#case-title"),
    "the still-open create-case form -- a real success would have closed it",
  ).toBeVisible();
  await casesPageAsAnalyst.page.click("button:has-text('Cancel')");
  await expect(casesPageAsAnalyst.page.locator(`text=${title}`)).toHaveCount(0);
});
