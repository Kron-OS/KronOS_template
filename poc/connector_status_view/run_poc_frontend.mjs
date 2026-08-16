// Throwaway PoC script (CLAUDE.md Section F.3) verifying the new
// /admin/connectors ConnectorStatusPage renders correctly in both light and
// dark mode, by actually launching a real headless Chromium against the
// running Vite dev server (frontend/, `npm run dev` on 127.0.0.1:5199) and
// capturing screenshots -- not just reading source and assuming it renders
// right. Mirrors poc/frontend_theme_fix/run_poc.mjs's own harness approach
// exactly (see that PoC's README for why a throwaway harness entry is
// needed instead of a real Keycloak login in this sandbox).
const BOOT_TIMEOUT_MS = 25000

import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'

const BASE_URL = 'http://127.0.0.1:5199'
const OUT_DIR = process.env.POC_OUT_DIR ?? new URL('.', import.meta.url).pathname
mkdirSync(OUT_DIR, { recursive: true })

// Covers every real status/mode combination the route can return: an
// active self-service push source, a never-used push source, a revoked
// push source, and the globally-configured (non-self-service) Defender
// poll entry in its "failing" state -- real field names/shapes matching
// src/external/routes/admin_connector_status.py's ConnectorStatusOut DTO.
const fakeConnectorStatusResponse = {
  items: [
    {
      sourceId: 'wazuh-hq-manager',
      sourceType: 'wazuh',
      mode: 'push',
      selfService: true,
      status: 'active',
      createdAt: '2026-07-01T12:00:00Z',
      revokedAt: null,
      lastIngestedAt: '2026-08-16T18:42:00Z',
      lastPolledAt: null,
      lastPollFailedAt: null,
      lastFailureReason: null,
      note: "Self-service: this org provisioned this connector's API key directly.",
    },
    {
      sourceId: 'zeek-branch-office',
      sourceType: 'zeek-json',
      mode: 'push',
      selfService: true,
      status: 'never_used',
      createdAt: '2026-08-15T09:00:00Z',
      revokedAt: null,
      lastIngestedAt: null,
      lastPolledAt: null,
      lastPollFailedAt: null,
      lastFailureReason: null,
      note: "Self-service: this org provisioned this connector's API key directly.",
    },
    {
      sourceId: 'legacy-generic-webhook',
      sourceType: 'generic-webhook',
      mode: 'push',
      selfService: true,
      status: 'revoked',
      createdAt: '2026-05-01T09:00:00Z',
      revokedAt: '2026-07-20T09:00:00Z',
      lastIngestedAt: '2026-06-15T09:00:00Z',
      lastPolledAt: null,
      lastPollFailedAt: null,
      lastFailureReason: null,
      note: "Self-service: this org provisioned this connector's API key directly.",
    },
    {
      sourceId: 'ms-defender-alerts',
      sourceType: 'ms-defender-alerts',
      mode: 'poll',
      selfService: false,
      status: 'failing',
      createdAt: null,
      revokedAt: null,
      lastIngestedAt: null,
      lastPolledAt: '2026-08-16T10:00:00Z',
      lastPollFailedAt: '2026-08-16T18:30:00Z',
      lastFailureReason: '401 Unauthorized from Microsoft Graph (token expired)',
      note: 'Configured for this org via platform settings — not self-service; contact your KronOS operator to change it.',
    },
  ],
}

async function main() {
  const browser = await chromium.launch()
  const results = []

  for (const [mode, seedLight] of [
    ['dark', false],
    ['light', true],
  ]) {
    const context = await browser.newContext({ colorScheme: 'dark', viewport: { width: 1400, height: 900 } })
    if (seedLight) {
      await context.addInitScript(() => localStorage.setItem('kronos-theme', 'light'))
    }
    const page = await context.newPage()
    await page.route('**/api/admin/connectors/status', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(fakeConnectorStatusResponse),
      }),
    )
    await page.goto(`${BASE_URL}/harness-authenticated.html`, { waitUntil: 'load' })
    await page.waitForSelector('text=Connector Status', { timeout: BOOT_TIMEOUT_MS })
    await page.waitForSelector('text=wazuh-hq-manager', { timeout: BOOT_TIMEOUT_MS })
    await page.waitForTimeout(300)
    await page.screenshot({ path: `${OUT_DIR}/connector_status_${mode}.png`, fullPage: true })
    const htmlClass = await page.evaluate(() => document.documentElement.className)
    const url = page.url()
    results.push({ page: 'ConnectorStatusPage (Layout + /admin/connectors, mocked API)', mode, htmlClass, url })
    await context.close()
  }

  await browser.close()
  console.log(JSON.stringify(results, null, 2))
}

main().catch((err) => {
  console.error('POC FAILED:', err)
  process.exit(1)
})
