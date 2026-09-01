import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";
import { test, expect, DEV_USERS } from "./fixtures";
import { LoginPage } from "./pages/LoginPage";
import { DetectionSeeder } from "./DetectionSeeder";
import { DetectionDetailPage } from "./pages/DetectionDetailPage";

/**
 * §3.8 (docs/PLAYWRIGHT_E2E_TEST_PLAN.md): a real, automated WCAG scan via
 * `@axe-core/playwright` on each of the app's 6 real pages (per
 * PLAYWRIGHT_E2E_TEST_PLAN.md §0's own "real pages that exist today" list --
 * LoginPage, CasesPage, CaseDetailPage, DetectionsPage, DetectionDetailPage,
 * AdminPage). This is a real, automated rule-set check (missing labels,
 * contrast, landmark/heading structure, ...), not a subjective pass --
 * assert on `results.violations` being empty. WCAG 2.0/2.1 A+AA is the
 * standard axe-core default tag set for this kind of scan.
 */
const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

async function scan(page: Page) {
  return new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
}

function formatViolations(results: Awaited<ReturnType<typeof scan>>): string {
  return results.violations
    .map((v) => `[${v.impact}] ${v.id}: ${v.help} (${v.nodes.length} node(s): ${v.nodes.map((n) => n.target.join(" ")).join(", ")})`)
    .join("\n");
}

test.describe("accessibility (@axe-core/playwright, real WCAG scan)", () => {
  test("login page has no real WCAG violations", async ({ page }) => {
    const login = await LoginPage.open(page);
    await login.waitUntilReady();
    const results = await scan(page);
    expect(results.violations, formatViolations(results)).toEqual([]);
  });

  test("cases page has no real WCAG violations", async ({ casesPageAsCaseLead, page }) => {
    await casesPageAsCaseLead.waitUntilReady();
    const results = await scan(page);
    expect(results.violations, formatViolations(results)).toEqual([]);
  });

  test("case detail page has no real WCAG violations", async ({ casesPageAsCaseLead, page }) => {
    const title = `E2E a11y case ${Date.now()}`;
    const detail = await casesPageAsCaseLead.createCase(title, `E2E-A11Y-${Date.now()}`);
    await detail.waitUntilReady();
    const results = await scan(page);
    expect(results.violations, formatViolations(results)).toEqual([]);
  });

  // Milestone RRRR: the case detail page's Settings tab gained real new
  // interactive UI (Case Members form, Danger Zone) -- the test above only
  // ever scans the default Evidence tab, so this is a genuinely separate
  // scan, not redundant with it.
  test("case detail page's Settings tab has no real WCAG violations", async ({
    casesPageAsCaseLead,
    page,
  }) => {
    const title = `E2E a11y settings case ${Date.now()}`;
    const detail = await casesPageAsCaseLead.createCase(title, `E2E-A11Y-SETTINGS-${Date.now()}`);
    await detail.waitUntilReady();
    await detail.openSettingsTab();
    const results = await scan(page);
    expect(results.violations, formatViolations(results)).toEqual([]);
  });

  test("detections page has no real WCAG violations", async ({ casesPageAsCaseLead, page }) => {
    // Seed a real detection first so the list renders real row content
    // (pills, tags, links), not just the empty-state copy -- a scan of an
    // empty list would miss real violations in DetectionRow/TriageStatePill.
    new DetectionSeeder().seed(`E2E a11y detection ${Date.now()}`);
    const detections = await casesPageAsCaseLead.goToDetections();
    await detections.waitUntilReady();
    const results = await scan(page);
    expect(results.violations, formatViolations(results)).toEqual([]);
  });

  test("detection detail page has no real WCAG violations", async ({ casesPageAsCaseLead, page }) => {
    const seeded = new DetectionSeeder().seed(`E2E a11y detection detail ${Date.now()}`);
    await DetectionDetailPage.openById(page, seeded.detectionId);
    const results = await scan(page);
    expect(results.violations, formatViolations(results)).toEqual([]);
  });

  test("admin org page has no real WCAG violations", async ({ page }) => {
    // Requires Role.ORG_ADMIN (RbacGuard requiredRole="org-admin" on
    // /admin/org, App.tsx) -- the shared casesPageAsCaseLead/casesPageAsAnalyst
    // fixtures don't cover this role, so this test logs in directly with
    // the real dev-seeded "admin" account.
    const login = await LoginPage.open(page);
    await login.waitUntilReady();
    await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);
    await page.goto("/admin/org");
    await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });
    const results = await scan(page);
    expect(results.violations, formatViolations(results)).toEqual([]);
  });
});
