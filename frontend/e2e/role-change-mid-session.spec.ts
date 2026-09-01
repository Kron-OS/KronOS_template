import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { SecondCaseLeadSeeder } from "./SecondCaseLeadSeeder";
import { UserRoleUpdater } from "./UserRoleUpdater";

/**
 * RBAC tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md), closing Gap Audit
 * Milestone KKKK's own coverage-gap finding: no spec had ever covered a
 * role changing while a session is already active.
 *
 * The real design question this spec answers (investigated by reading
 * `src/external/middleware/keycloak_auth.py` and `src/keycloak.ts` before
 * writing anything, not guessed): role authorization is 100% stateless --
 * `_extract_tenant()` reads `roles` directly off the JWT's own claims,
 * and `KeycloakTokenValidator` never re-checks them against Keycloak
 * per-request ("Token introspection is never used" -- the class's own
 * docstring). The frontend's own `keycloak.ts` compounds this: its
 * in-memory access token is only ever replaced reactively (a 401 from
 * `api/client.ts`'s interceptor) or on a fresh page load
 * (`initKeycloak()`'s own real `POST /auth/refresh` call, confirmed by
 * reading it before writing this) -- there is no proactive/periodic
 * silent refresh. Two real, live runs found two distinct real things
 * before this final version, neither guessed in advance: the FIRST run
 * (an earlier draft with no explicit "still privileged" step) accidentally
 * proved the core finding by tripping over it -- a case-creation attempt
 * placed AFTER a live Admin API demotion but BEFORE any reload still
 * succeeded, because the already-open browser session's own in-memory
 * token was untouched by the demotion. The SECOND run (this draft's first
 * attempt to assert that deliberately) then found a bug in the TEST
 * itself: navigating back to the cases list via `page.goto("/cases")`
 * between steps is a genuine browser navigation, which itself triggers
 * `initKeycloak()`'s real refresh and adopts the new (demoted) token
 * early -- silently invalidating the "still privileged" assertion it was
 * meant to set up for. Fixed by navigating via a real in-app link click
 * (client-side routing) instead, reserving an actual `page.reload()` for
 * the one step that's supposed to trigger the refresh. The real, verified
 * conclusion: a role change takes effect only once THIS app's own token
 * store is refreshed (a reload, here; in real use, whenever the token
 * naturally expires and the next request 401s), not the instant an
 * org-admin changes it in Keycloak.
 *
 * `UserRoleUpdater` (new) acts on an EXISTING user id via the Admin API --
 * unlike every other `seed_*` fixture, which provisions a fresh throwaway
 * account, this needs to target the exact account that's already logged
 * in for the "mid-session" scenario to be real. `SecondCaseLeadSeeder`
 * gained a real `userId` field (Milestone NNNN) for exactly this purpose.
 */
test("a role change takes effect on this session's next token refresh, not instantly", async ({
  page,
}) => {
  test.setTimeout(60000);

  const seeded = new SecondCaseLeadSeeder().seed();

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  const cases = await login.loginWithSso(seeded.username, seeded.password);

  // Baseline sanity: this freshly-seeded case-lead really can create a
  // case, before anything about its role changes -- otherwise a later
  // "denied" observation would be meaningless (could just be broken).
  await cases.createCase(
    `E2E Role-Change Baseline Case ${Date.now()}`,
    `E2E-ROLECHANGE-BASE-${Date.now()}`,
  );

  // Real org-admin action, live, via the Admin API -- demotes THIS same,
  // already-logged-in user from case-lead to analyst. No app-side action
  // taken yet.
  new UserRoleUpdater().swapRealmRole(seeded.userId, "case-lead", "analyst");

  // A separate, direct POST /auth/refresh round trip (bypassing the app's
  // own in-memory token store entirely) already reflects the new role --
  // confirms Keycloak 26.2's real refresh_token grant re-evaluates realm-
  // role mappings at redemption time, not just that our own code trusts
  // whatever it's handed (a claim about a pinned external dependency,
  // verified live per CLAUDE.md SS F rather than assumed from general
  // OIDC knowledge).
  const freshClaims = await cases.fetchDecodedAccessTokenClaims();
  const freshRoles = (freshClaims.roles as string[] | undefined) ?? [];
  expect(
    freshRoles,
    "a direct refresh redeemed after the Admin API demotion must reflect the real, current role",
  ).not.toContain("case-lead");
  expect(freshRoles).toContain("analyst");

  // createCase() navigates into the new case's own detail page -- back to
  // the /cases list via a real in-app link click (client-side routing,
  // NOT page.goto()/page.reload() -- either of those is a genuine browser
  // navigation that would itself trigger initKeycloak()'s real
  // /auth/refresh and adopt the new token early, defeating the entire
  // point of this step. Confirmed live: an earlier version of this spec
  // used page.goto("/cases") here and the "still-privileged" assertion
  // below failed for exactly this reason -- a real, found-live bug in the
  // TEST, not the app.
  await page.click("text=Cases");
  await page.waitForURL("**/cases", { timeout: 10000 });
  await cases.waitUntilReady();

  // The real, load-bearing "not instant" proof: THIS SAME browser
  // session, without a reload, still has its OWN in-memory token from
  // before the demotion -- api/client.ts only refreshes reactively on a
  // 401, and this token hasn't expired -- so a UI-driven case creation
  // still succeeds, using stale-but-still-cryptographically-valid
  // privileges.
  await cases.createCase(
    `E2E Role-Change Still-Privileged Case ${Date.now()}`,
    `E2E-ROLECHANGE-STALE-${Date.now()}`,
  );

  // Back to /cases via the same client-side nav (still on the OLD token),
  // then a real reload forces initKeycloak()'s own real POST /auth/refresh
  // (src/keycloak.ts), adopting a fresh, now-analyst token app-wide --
  // THIS is the real mechanism by which a role change actually takes
  // effect for an already-open session, not an arbitrary test-only action.
  await page.click("text=Cases");
  await page.waitForURL("**/cases", { timeout: 10000 });
  await page.reload();
  await cases.waitUntilReady();

  await cases.attemptCreateCase(
    `E2E Role-Change Post-Reload Case ${Date.now()}`,
    `E2E-ROLECHANGE-POST-${Date.now()}`,
  );
  const error = await cases.waitForCreateCaseError();
  expect(error).toContain("Failed to create case");
});
