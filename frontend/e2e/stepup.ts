import type { Page } from "@playwright/test";
import { DEV_USERS } from "./fixtures";
import { generateTotp } from "./totp";

/**
 * Shared step-up (MFA) re-authentication helper, extracted from
 * `admin-quota-ui.spec.ts` (Milestone TTTT, the first spec to ever drive a
 * real step-up flow) so `admin-user-management-stepup.spec.ts` (Milestone
 * WWWW, Tier 1 item 4 of `docs/HANDOFF_AND_ORCHESTRATION.md`) reuses the
 * same, already-proven window-aligned-retry logic rather than duplicating
 * it. Specific to the dev-seeded `admin` account (the only dev user with
 * both `ORG_ADMIN` and real TOTP enrollment, `poc/admin_totp_enrollment/`)
 * -- not generalized to other accounts/secrets since no other real caller
 * exists yet.
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
 * cache, which looks identical to the user ("Invalid authenticator code")
 * but has a different real cause than a stale/skewed code. The fix that
 * actually eliminates the flakiness: wait out the REAL remaining time in
 * the current window (up to ~30s, not a fixed short guess) before
 * generating the retry code, guaranteeing a genuinely different one.
 */
export async function completeStepUpReauth(page: Page): Promise<void> {
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
