// Throwaway PoC (CLAUDE.md §F): reproduces, in a real browser against the
// real dev-stack Keycloak SSO + OpenSearch Dashboards 2.11.1, the exact bug
// reported live: a KQL query for a field that only exists on Plaso-parsed
// records (event_identifier) returns 0 hits in the real Discover embed,
// even though the same field IS present and correctly indexed in the
// underlying OpenSearch index (confirmed separately via raw HTTP against
// the real kronos-*-201508 index -- see README.md).
//
// Run: node poc/opensearch_dashboards_stale_field_cache/verify_bug.mjs
import { chromium } from "../../frontend/node_modules/playwright/index.mjs";

const CASE_ID = "3033bc95-d03d-4ec3-ae1c-11b0d99bb8d6";
const BASE = "https://kronos.local";

async function loginAndOpenCase(page) {
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded", timeout: 60000 });
  await page.waitForSelector("text=Sign in with SSO", { timeout: 30000 });
  await page.click("text=Sign in with SSO");
  // Real Keycloak-hosted login form (selectors per frontend/e2e/pages/LoginPage.ts).
  await page.waitForSelector("#username", { timeout: 30000 });
  await page.fill("#username", "admin");
  await page.fill("#password", "DevAdmin#2026");
  await page.click("#kc-login");
  await page.waitForURL(/\/cases/, { timeout: 30000 });
  // A hard page.goto() to an internal route destroys keycloak-js's
  // in-memory access token, forcing a silent-SSO iframe refresh that this
  // environment's CSP (frame-ancestors 'self') blocks -- client-side
  // (SPA) navigation instead, exactly like a real user clicking a link.
  await page.evaluate((path) => {
    window.history.pushState(null, "", path);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, `/cases/${CASE_ID}`);
  await page.waitForTimeout(5000);
  await page.screenshot({ path: "poc/opensearch_dashboards_stale_field_cache/debug_casepage.png", fullPage: true });
  console.log("URL after nav:", page.url());
  console.log("BODY:", (await page.textContent("body")).slice(0, 1000));
  await page.getByRole("button", { name: "Timeline", exact: true }).click({ timeout: 30000 });
}

async function queryAndCountHits(page, kqlQuery) {
  const frame = page.frameLocator('iframe[title="Timeline Analysis"]');
  const queryBar = frame.getByTestId("osdQueryBar-language-switcher").locator("..").locator("textarea, input").first();
  // Fall back to the well-known Discover query input test id if the above
  // locator doesn't resolve cleanly.
  const input = frame.locator('[data-test-subj="queryInput"]').first();
  await input.waitFor({ timeout: 20000 }).catch(() => {});
  await input.click({ timeout: 20000 });
  await input.fill(kqlQuery);
  await input.press("Enter");
  await page.waitForTimeout(4000);
  const hitsText = await frame.getByText(/\d+\s+hits?/i).first().textContent({ timeout: 20000 }).catch(() => null);
  const noResults = await frame.getByText(/no results match your search criteria/i).first().isVisible().catch(() => false);
  return { hitsText, noResults };
}

const browser = await chromium.launch({ args: ["--ignore-certificate-errors"] });
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await context.newPage();
page.on("console", (msg) => console.log("CONSOLE:", msg.type(), msg.text().slice(0, 300)));
page.on("pageerror", (err) => console.log("PAGEERROR:", err.message));
page.on("requestfailed", (req) => console.log("REQFAILED:", req.url(), req.failure()?.errorText));
page.on("response", (res) => {
  if (res.status() >= 400) console.log("HTTP", res.status(), res.url());
});

try {
  await loginAndOpenCase(page);

  console.log("--- Query: event.code:1100 (zip/FastEvtxParser field, known to the cached index-pattern fields) ---");
  const r1 = await queryAndCountHits(page, "event.code:1100");
  console.log(JSON.stringify(r1));
  await page.screenshot({ path: "poc/opensearch_dashboards_stale_field_cache/1_event_code.png" });

  console.log("--- Query: event_identifier:1100 (Plaso-only field, NOT in the cached index-pattern fields) ---");
  const r2 = await queryAndCountHits(page, "event_identifier:1100");
  console.log(JSON.stringify(r2));
  await page.screenshot({ path: "poc/opensearch_dashboards_stale_field_cache/2_event_identifier.png" });

  console.log("--- Query: free text 1100 (unqualified) ---");
  const r3 = await queryAndCountHits(page, "1100");
  console.log(JSON.stringify(r3));
  await page.screenshot({ path: "poc/opensearch_dashboards_stale_field_cache/3_freetext.png" });

  console.log("--- Sidebar 'Available fields' list check: is event_identifier offered as a real filterable field? ---");
  const frame = page.frameLocator('iframe[title="Timeline Analysis"]');
  const sidebarText = await frame.locator("body").innerText({ timeout: 20000 });
  console.log("sidebar contains 'event_identifier':", sidebarText.includes("event_identifier"));
  console.log("sidebar contains 'message_identifier':", sidebarText.includes("message_identifier"));
  console.log("sidebar contains 'event.code':", sidebarText.includes("event.code"));
  await page.screenshot({ path: "poc/opensearch_dashboards_stale_field_cache/4_sidebar_full.png", fullPage: true });

  // Click "+ Add filter" and check the field-picker's own autocomplete list
  // -- the concrete UI affordance a real user relies on to "filter on
  // event identifier", as opposed to hand-typing raw KQL syntax.
  const addFilterBtn = frame.getByRole("button", { name: /\+ Add filter/i }).first();
  await addFilterBtn.click({ timeout: 15000 }).catch((e) => console.log("add filter click failed:", e.message));
  await page.waitForTimeout(1500);
  const fieldPicker = frame.locator('[data-test-subj="filterFieldSuggestionList"], [data-test-subj*="FieldSelect"], input[placeholder="Select a field first"]').first();
  await fieldPicker.click({ timeout: 10000 }).catch((e) => console.log("field picker click failed:", e.message));
  await fieldPicker.fill("event_identifier").catch((e) => console.log("field picker fill failed:", e.message));
  await page.waitForTimeout(1500);
  await page.screenshot({ path: "poc/opensearch_dashboards_stale_field_cache/5_add_filter_picker.png" });
  const pickerText = await frame.locator("body").innerText({ timeout: 10000 });
  console.log("field-picker dropdown offers 'event_identifier' as a real option:", pickerText.includes("event_identifier"));
} catch (err) {
  console.error("PoC error:", err);
  await page.screenshot({ path: "poc/opensearch_dashboards_stale_field_cache/error.png" }).catch(() => {});
} finally {
  await browser.close();
}
