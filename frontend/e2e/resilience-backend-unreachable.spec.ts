import { test, expect } from "./fixtures";

/**
 * docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.7, scenario 1: "Backend temporarily
 * unreachable (block the `/api/*` route at the Playwright network-
 * interception layer) -> the UI shows a real, legible error state, not a
 * blank screen or an unhandled promise rejection in the console (assert on
 * `page.on("pageerror")` staying empty across the scenario)."
 *
 * Investigated the real frontend error-handling code before writing this
 * (per this milestone's own instructions): `src/api/client.ts`'s axios
 * response interceptor only special-cases 401s (token refresh); any other
 * failure -- including a `page.route()` abort, which surfaces to axios as
 * a plain network error with `error.response` undefined -- falls through
 * to a bare `Promise.reject(error)`. That rejection is caught by
 * react-query (`App.tsx`'s `QueryClient` has `retry: 1` for queries,
 * default `retry: 0` for mutations), which is why every page already
 * renders a real `ErrorBanner` off `error`/`mutation.isError` --
 * confirmed by reading `CasesPage.tsx` and `DetectionsPage.tsx` directly,
 * not assumed. So the real question this spec answers isn't "does an
 * error banner exist" (it does, already, for both the query and mutation
 * paths) but "does the *whole real flow* -- an authenticated user already
 * on a loaded page, hitting a genuinely unreachable backend -- actually
 * reach that banner live, with zero unhandled rejection along the way."
 */
test.describe("backend unreachable", () => {
  test("a mutation attempted after the backend goes unreachable surfaces a real, legible error banner", async ({
    casesPageAsCaseLead,
    page,
  }) => {
    const pageErrors: string[] = [];
    page.on("pageerror", (err) => pageErrors.push(err.message));

    // casesPageAsCaseLead is already logged in and rendering the real,
    // successfully-loaded /cases dashboard (the fixture's own
    // waitUntilReady() already confirmed this) -- i.e. genuinely "a page
    // that's already loaded/authenticated" before the backend goes down.
    await page.route("**/api/**", (route) => route.abort("failed"));

    await casesPageAsCaseLead.attemptCreateCase(
      `E2E unreachable-backend spec ${Date.now()}`,
      `E2E-UNREACH-${Date.now()}`,
    );
    const errorText = await casesPageAsCaseLead.waitForCreateCaseError();
    expect(errorText).toContain("Failed to create case");

    // Not a blank screen: the real app shell (header/nav) is still fully
    // rendered underneath the still-open, now-erroring modal.
    await expect(page.locator("header", { hasText: "KronOS" })).toBeVisible();

    expect(pageErrors, "no unhandled exception anywhere in the page while the backend was unreachable").toEqual([]);
  });

  test("a fresh query fired after the backend goes unreachable surfaces a real, legible error banner", async ({
    casesPageAsCaseLead,
    page,
  }) => {
    const pageErrors: string[] = [];
    page.on("pageerror", (err) => pageErrors.push(err.message));

    // Confirm the starting page is genuinely loaded (real case cards, not
    // a loading spinner) before cutting the backend off.
    await expect(page.locator("text=New Case")).toBeVisible();

    await page.route("**/api/**", (route) => route.abort("failed"));

    // Real, in-app, client-side navigation (no reload -- the same
    // authenticated session/DOM survives) to a page whose own useQuery
    // has never fetched before, forcing a genuinely fresh request against
    // the now-unreachable backend.
    await page.click("text=Detections");
    await page.waitForURL("**/detections", { timeout: 10000 });

    await expect(page.locator("text=Failed to load detections.")).toBeVisible({ timeout: 15000 });

    // Not a blank screen: the real app shell is still fully rendered.
    await expect(page.locator("header", { hasText: "KronOS" })).toBeVisible();

    expect(pageErrors, "no unhandled exception anywhere in the page while the backend was unreachable").toEqual([]);
  });
});
