import { describe, it, expect, afterEach, vi } from 'vitest'
import { isTrustedDashboardsUrl } from '../utils/dashboardsOrigin'

describe('isTrustedDashboardsUrl (FE-6)', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('rejects a malformed URL regardless of configuration', () => {
    expect(isTrustedDashboardsUrl('not a url')).toBe(false)
  })

  it('accepts any well-formed URL when no expected origin is configured', () => {
    expect(isTrustedDashboardsUrl('http://anywhere.example/app/discover')).toBe(true)
  })

  it('accepts a URL matching the configured expected origin', () => {
    vi.stubEnv('VITE_OPENSEARCH_DASHBOARDS_ORIGIN', 'http://localhost:5601')
    expect(isTrustedDashboardsUrl('http://localhost:5601/app/data-explorer/discover?embed=true')).toBe(true)
  })

  it('rejects a URL whose origin differs from the configured expected origin', () => {
    vi.stubEnv('VITE_OPENSEARCH_DASHBOARDS_ORIGIN', 'http://localhost:5601')
    expect(isTrustedDashboardsUrl('http://evil.example/app/discover')).toBe(false)
  })
})
