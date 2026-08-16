// Throwaway PoC script (CLAUDE.md Section F.3) verifying the P2-W12
// dark-mode-toggle fix and the P2-W13 error boundary fallback UI by
// actually launching a real headless Chromium against the running Vite
// dev server (frontend/, `npm run dev` on 127.0.0.1:5199) and capturing
// screenshots -- not just reading source and assuming it renders right.
//
// Playwright + chromium pinned via `npm install -D playwright && npx
// playwright install chromium` (see final report for whether this was
// kept in package.json afterward).
//
// BOOT_TIMEOUT_MS is generous (25s) because in this sandbox
// main.tsx's bootstrap() awaits initKeycloak(), which tries a real
// keycloak.init() against https://kronos.local:8443 -- that TLS
// handshake is slow/fails here (no real Keycloak reachable), so the app
// doesn't mount into #root until that resolves. This is a sandbox network
// characteristic, not a bug in the code under test; a real deployment
// resolves kronos.local with a valid cert and this is fast.
const BOOT_TIMEOUT_MS = 25000

import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'

const BASE_URL = 'http://127.0.0.1:5199'
const OUT_DIR = process.env.POC_OUT_DIR ?? new URL('.', import.meta.url).pathname
mkdirSync(OUT_DIR, { recursive: true })

async function main() {
  const browser = await chromium.launch()
  const results = []

  // --- LoginPage: no auth required, reachable directly. ---
  {
    const context = await browser.newContext({ colorScheme: 'dark', viewport: { width: 1280, height: 800 } })
    const page = await context.newPage()
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'load' })
    await page.waitForSelector('text=Sign in with SSO', { timeout: BOOT_TIMEOUT_MS })
    const htmlClass = await page.evaluate(() => document.documentElement.className)
    const bodyBg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor)
    await page.screenshot({ path: `${OUT_DIR}/login_dark.png` })
    results.push({ page: 'login', mode: 'dark (system default, no localStorage)', htmlClass, bodyBg })
    await context.close()
  }

  {
    const context = await browser.newContext({ colorScheme: 'dark', viewport: { width: 1280, height: 800 } })
    const page = await context.newPage()
    // Seed localStorage the same way Layout's toggle button persists it
    // (kronos-theme=light) via an init script so it's present before the
    // very first script on the page runs -- matches a real "user toggled
    // light mode in a previous session, then reloaded" scenario.
    await page.addInitScript(() => localStorage.setItem('kronos-theme', 'light'))
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'load' })
    await page.waitForSelector('text=Sign in with SSO', { timeout: BOOT_TIMEOUT_MS })
    const htmlClass = await page.evaluate(() => document.documentElement.className)
    const bodyBg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor)
    await page.screenshot({ path: `${OUT_DIR}/login_light.png` })
    results.push({ page: 'login', mode: 'light (forced via localStorage)', htmlClass, bodyBg })
    await context.close()
  }

  // --- Authenticated harness: Layout + CasesPage, auth store pre-seeded
  // (see frontend/src/harness-authenticated.tsx) since a real Keycloak
  // login isn't reachable in this sandbox (kronos.local is the sole
  // authorized domain, docs/lan-dev-access.md). Mounts the real <App/>
  // unmodified, just with isAuthenticated pre-seeded true. The
  // GET /api/cases call CasesPage makes is intercepted with fake data
  // (there's no real backend running) so the real success-state markup
  // (CaseCard grid, badges) renders instead of an error banner. ---
  const fakeCasesResponse = {
    items: [
      {
        id: 'case-1',
        title: 'Q3 Payroll System Intrusion',
        reference: 'CASE-2026-014',
        description: 'Suspected lateral movement via compromised service account.',
        evidenceCount: 7,
        createdAt: '2026-07-01T12:00:00Z',
      },
      {
        id: 'case-2',
        title: 'Endpoint Ransomware Containment',
        reference: 'CASE-2026-021',
        description: '',
        evidenceCount: 2,
        createdAt: '2026-08-02T09:30:00Z',
      },
    ],
    total: 2,
  }

  for (const [mode, colorScheme, seedLight] of [
    ['dark', 'dark', false],
    ['light', 'dark', true],
  ]) {
    const context = await browser.newContext({ colorScheme, viewport: { width: 1280, height: 800 } })
    if (seedLight) {
      await context.addInitScript(() => localStorage.setItem('kronos-theme', 'light'))
    }
    const page = await context.newPage()
    await page.route('**/api/cases', (route) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fakeCasesResponse) }),
    )
    await page.goto(`${BASE_URL}/harness-authenticated.html`, { waitUntil: 'load' })
    await page.waitForSelector('text=Q3 Payroll System Intrusion', { timeout: BOOT_TIMEOUT_MS })
    await page.waitForTimeout(300)
    await page.screenshot({ path: `${OUT_DIR}/authenticated_harness_${mode}.png` })
    const htmlClass = await page.evaluate(() => document.documentElement.className)
    results.push({ page: 'authenticated harness (Layout+CasesPage, mocked API)', mode, htmlClass })
    await context.close()
  }

  // --- Error boundary fallback UI (frontend/src/harness-error-boundary.tsx) ---
  {
    const context = await browser.newContext({ colorScheme: 'dark', viewport: { width: 1280, height: 800 } })
    const page = await context.newPage()
    await page.goto(`${BASE_URL}/harness-error-boundary.html`, { waitUntil: 'load' })
    await page.waitForSelector('text=Something went wrong', { timeout: BOOT_TIMEOUT_MS })
    await page.screenshot({ path: `${OUT_DIR}/error_boundary_dark.png` })
    results.push({ page: 'error boundary fallback', mode: 'dark', status: 'captured' })
    await context.close()
  }
  {
    const context = await browser.newContext({ colorScheme: 'dark', viewport: { width: 1280, height: 800 } })
    const page = await context.newPage()
    await page.addInitScript(() => localStorage.setItem('kronos-theme', 'light'))
    await page.goto(`${BASE_URL}/harness-error-boundary.html`, { waitUntil: 'load' })
    await page.waitForSelector('text=Something went wrong', { timeout: BOOT_TIMEOUT_MS })
    await page.screenshot({ path: `${OUT_DIR}/error_boundary_light.png` })
    results.push({ page: 'error boundary fallback', mode: 'light', status: 'captured' })
    await context.close()
  }

  await browser.close()
  console.log(JSON.stringify(results, null, 2))
}

main().catch((err) => {
  console.error('POC FAILED:', err)
  process.exit(1)
})
