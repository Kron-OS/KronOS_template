import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";
import { generateTotp } from "./totp";

/**
 * Milestone TTTT: `GET`/`PATCH /api/admin/org/quota`
 * (`src/external/routes/admin.py`, `docs/TENANT_USAGE_QUOTA.md`) had zero
 * frontend UI before this -- confirmed via `grep -rn "Quota\|quota"
 * frontend/src/pages/*.tsx` before writing anything: no matches. New
 * `QuotaSection` (`AdminPage.tsx`) shows real current usage vs. the
 * configured limit and lets an org-admin set or clear it.
 *
 * `PATCH .../quota` is `_assert_aal2`-gated (step-up MFA), same as
 * `inviteUser`/`updateUserRole` -- and this is the FIRST spec in this
 * whole suite to ever drive a real step-up flow through a real browser
 * (confirmed via `grep -rl "acr.*aal2\|acrValues\|step-up" frontend/e2e/*.spec.ts`
 * before writing this: no matches, despite those two other admin actions
 * having shipped with this same gating for a while). A real, live
 * investigation (not assumed from reading the code alone) found:
 *
 * 1. The dev-seeded `admin` account's own normal login is `acr=aal1`
 *    (confirmed live by decoding its real token) -- despite `admin`
 *    already requiring TOTP just to complete ordinary login
 *    (Milestone JJJJ), that is a DIFFERENT Keycloak flow from the
 *    conditional-OTP step-up flow this route needs; the two don't imply
 *    each other.
 * 2. `apiClient`'s global interceptor performs a real, full BROWSER
 *    REDIRECT to Keycloak for step-up (`keycloak.login({acrValues:
 *    'aal2', prompt: 'login'})`), not an in-page silent refresh --
 *    confirmed live: a full password + real TOTP re-authentication is
 *    required (`poc/admin_totp_enrollment/output.txt`'s captured secret,
 *    `frontend/e2e/totp.ts`'s existing RFC 6238 helper).
 * 3. A full page redirect cannot resume the original in-flight JS
 *    mutation Promise -- confirmed live: after completing step-up and
 *    landing back on `/admin/org`, the quota was still unchanged, AND
 *    the form's own local React state (the typed value) was gone (a full
 *    remount, not a resumed session). The user must re-enter the value
 *    and click Save a SECOND time; that second call then succeeds
 *    directly, with no further redirect (the token is now aal2 for the
 *    rest of the session). This is a real, pre-existing UX rough edge
 *    that equally affects the already-shipped `inviteUser`/
 *    `updateUserRole` step-up flows, not something new introduced by this
 *    UI -- named here rather than silently worked around, and NOT fixed
 *    in this pass (a real architectural question -- persisting pending
 *    form state across a redirect -- out of scope for a single new
 *    admin-settings section).
 */
const ADMIN_TOTP_SECRET = "JB3US4TBJNBEO32BOJJTSZCEI5WGYMKG";

const TOTP_STEP_MS = 30000;

/** Real ms remaining until the current 30s TOTP window rolls over. */
function msUntilNextTotpWindow(): number {
  return TOTP_STEP_MS - (Date.now() % TOTP_STEP_MS);
}

/**
 * A TOTP code is only valid for a real 30s window. The first retry
 * strategy tried here (wait a fixed 2s, then regenerate) was NOT
 * sufficient -- confirmed live, it still failed roughly as often as no
 * retry at all. Root cause, found by testing repeated quick successive
 * runs: `generateTotp()` is deterministic within a given 30s window, so
 * a 2s wait usually does NOT cross a window boundary, producing the
 * IDENTICAL code as the just-rejected one -- and Keycloak 26.2's default
 * OTP policy also rejects **reuse** of the same code within its replay
 * cache, which look identical to the user ("Invalid authenticator code")
 * but have a different real cause than a stale/skewed code. The fix that
 * actually eliminates the flakiness: wait out the REAL remaining time in
 * the current window (up to ~30s, not a fixed short guess) before
 * generating the retry code, guaranteeing a genuinely different one.
 */
async function completeStepUpReauth(page: import("@playwright/test").Page): Promise<void> {
  await page.waitForSelector("#password", { timeout: 10000 });
  await page.fill("#password", DEV_USERS.admin.password);
  await page.click("#kc-login");
  await page.waitForSelector("#otp", { timeout: 10000 });

  for (let attempt = 1; attempt <= 2; attempt++) {
    await page.fill("#otp", generateTotp(ADMIN_TOTP_SECRET));
    await page.click("#kc-login");
    const rejected = await page
      .getByText("Invalid authenticator code", { exact: false })
      .waitFor({ timeout: 4000 })
      .then(() => true)
      .catch(() => false);
    if (!rejected) return;
    if (attempt === 2) throw new Error("Step-up OTP rejected twice in a row -- not just window-boundary flakiness.");
    await page.waitForTimeout(msUntilNextTotpWindow() + 1000);
  }
}

test("an org-admin can set a real storage quota through the real Settings UI, completing a real step-up re-auth", async ({
  page,
}) => {
  // A retried OTP submission can wait up to ~30s for a fresh TOTP window
  // (completeStepUpReauth's own real fix for a demonstrated flakiness
  // cause) -- generous headroom above that plus the rest of the flow.
  test.setTimeout(90000);

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);

  await page.goto("/admin/org");
  await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });
  await page.waitForSelector("text=Storage Quota", { timeout: 10000 });

  // First attempt: triggers the real step-up redirect. The mutation
  // itself is abandoned by the page navigation -- confirmed live, see
  // this spec's own docstring -- so no assertion on quota state yet.
  await page.fill("#quota-gb-input", "5");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await completeStepUpReauth(page);

  // Real navigation back to the app on success.
  await page.waitForURL("**/admin/org", { timeout: 15000 });
  await page.waitForSelector("text=Storage Quota", { timeout: 10000 });

  // Retry, now with a fresh aal2 token -- succeeds directly, no further
  // redirect.
  await page.fill("#quota-gb-input", "5");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByText("used of 5.00 GB", { exact: false }).waitFor({ timeout: 10000 });

  // Clear it back to unlimited (leaves the shared dev-stack org in its
  // original state for other specs/manual use, and exercises the second
  // real mutation path).
  await page.getByRole("button", { name: "Clear (unlimited)", exact: true }).click();
  await page.getByText("(unlimited)", { exact: false }).waitFor({ timeout: 10000 });
});
