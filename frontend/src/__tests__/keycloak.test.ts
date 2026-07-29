import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useAuthStore } from '../store/auth'

function fakeToken(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }))
  const body = btoa(JSON.stringify(payload))
  return `${header}.${body}.`
}

const validAccessToken = fakeToken({
  sub: 'user-1',
  preferred_username: 'alice',
  roles: ['analyst'],
  organization: { acme: { id: 'org-1' } },
  exp: Math.floor(Date.now() / 1000) + 3600,
})

describe('keycloak.ts token handling (AUTH-002/FE-1/FE-2)', () => {
  beforeEach(() => {
    useAuthStore.getState().clearAuth()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('never writes any token to sessionStorage or localStorage', async () => {
    const setSpy = vi.spyOn(Storage.prototype, 'setItem')
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => ({ access_token: validAccessToken }),
    })

    const { initKeycloak } = await import('../keycloak')
    await initKeycloak()

    // The theme toggle (Layout.tsx) is the only legitimate localStorage user
    // in this app; assert no call ever wrote anything resembling a token.
    for (const call of setSpy.mock.calls) {
      expect(String(call[1])).not.toContain(validAccessToken)
      expect(call[0]).not.toMatch(/token/i)
    }
  })

  it('resumes a session from the backend cookie proxy and populates the auth store', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => ({ access_token: validAccessToken }),
    })

    const { initKeycloak } = await import('../keycloak')
    const result = await initKeycloak()

    expect(result).toBe(true)
    expect(useAuthStore.getState().isAuthenticated).toBe(true)
    expect(useAuthStore.getState().accessToken).toBe(validAccessToken)
    expect(useAuthStore.getState().user?.username).toBe('alice')

    // credentials: 'include' is what lets the browser attach the HttpOnly
    // cookie — without it the whole cookie-proxy scheme silently no-ops.
    const [, options] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(options).toMatchObject({ credentials: 'include' })
  })

  it('refreshAccessToken updates the store on success', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => ({ access_token: validAccessToken }),
    })

    const { refreshAccessToken } = await import('../keycloak')
    const ok = await refreshAccessToken()

    expect(ok).toBe(true)
    expect(useAuthStore.getState().accessToken).toBe(validAccessToken)
  })

  it('refreshAccessToken clears auth on failure (expired/revoked cookie)', async () => {
    useAuthStore.getState().setAuth('stale-token', {
      userId: 'user-1',
      username: 'alice',
      email: '',
      roles: [],
      orgId: 'org-1',
      orgAlias: 'acme',
      acr: 'aal1',
    })
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({ ok: false })

    const { keycloak, refreshAccessToken } = await import('../keycloak')
    const loginSpy = vi.spyOn(keycloak, 'login').mockResolvedValue(undefined)

    const ok = await refreshAccessToken()

    expect(ok).toBe(false)
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
    expect(useAuthStore.getState().accessToken).toBeNull()
    expect(loginSpy).toHaveBeenCalled()
  })
})
