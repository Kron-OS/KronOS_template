import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useAuthStore } from '../store/auth'

/**
 * Gap Audit Milestone SS: apiClient's 401-refresh interceptor had a real
 * bug -- the request that actually triggered a token refresh pushed its own
 * retry callback onto `pendingRequests` only AFTER the refresh's own
 * `pendingRequests.forEach(...)` flush already ran, so it queued behind an
 * already-emptied array and hung forever, even when the refresh succeeded.
 * Only OTHER requests that happened to be concurrently in flight at that
 * exact moment were ever actually retried. These tests exercise the real
 * apiClient instance and its real interceptor chain end-to-end, replacing
 * only the low-level HTTP transport (axios's `adapter`) so no real network
 * call is made.
 */

const loginMock = vi.fn()
const refreshAccessTokenMock = vi.fn()

vi.mock('../keycloak', () => ({
  keycloak: { login: (...args: unknown[]) => loginMock(...args) },
  refreshAccessToken: () => refreshAccessTokenMock(),
}))

function unauthorizedError(config: unknown, wwwAuthenticate = ''): unknown {
  return {
    isAxiosError: true,
    message: 'Request failed with status code 401',
    config,
    response: {
      status: 401,
      statusText: 'Unauthorized',
      headers: { 'www-authenticate': wwwAuthenticate },
      data: {},
      config,
    },
  }
}

describe('apiClient 401 refresh interceptor (Gap Audit Milestone SS)', () => {
  let originalAdapter: unknown

  beforeEach(async () => {
    loginMock.mockReset()
    refreshAccessTokenMock.mockReset()
    useAuthStore.getState().clearAuth()
    const { default: apiClient } = await import('../api/client')
    originalAdapter = apiClient.defaults.adapter
  })

  afterEach(async () => {
    const { default: apiClient } = await import('../api/client')
    apiClient.defaults.adapter = originalAdapter as typeof apiClient.defaults.adapter
  })

  it('retries the SAME request that triggered a successful refresh, not just later concurrent ones', async () => {
    const { default: apiClient } = await import('../api/client')

    let callCount = 0
    apiClient.defaults.adapter = vi.fn(async (config) => {
      callCount += 1
      if (callCount === 1) {
        throw unauthorizedError(config)
      }
      return { status: 200, statusText: 'OK', data: { ok: true }, headers: {}, config }
    }) as typeof apiClient.defaults.adapter

    refreshAccessTokenMock.mockImplementation(async () => {
      useAuthStore.setState({ accessToken: 'fresh-token' })
      return true
    })

    const result = await apiClient.get('/api/whatever')

    expect(result.data).toEqual({ ok: true })
    expect(callCount).toBe(2)
    expect(refreshAccessTokenMock).toHaveBeenCalledTimes(1)
  }, 2000)

  it('rejects (does not hang) when the refresh fails', async () => {
    const { default: apiClient } = await import('../api/client')

    apiClient.defaults.adapter = vi.fn(async (config) => {
      throw unauthorizedError(config)
    }) as typeof apiClient.defaults.adapter

    refreshAccessTokenMock.mockResolvedValue(false)

    await expect(apiClient.get('/api/whatever')).rejects.toBeTruthy()
    expect(refreshAccessTokenMock).toHaveBeenCalledTimes(1)
  }, 2000)

  it('redirects to step-up login on an aal2 challenge without attempting a token refresh', async () => {
    const { default: apiClient } = await import('../api/client')

    apiClient.defaults.adapter = vi.fn(async (config) => {
      throw unauthorizedError(config, 'Bearer error="insufficient_user_authentication", acr_values="aal2"')
    }) as typeof apiClient.defaults.adapter

    await expect(apiClient.get('/api/whatever')).rejects.toBeTruthy()
    expect(loginMock).toHaveBeenCalledWith({ acrValues: 'aal2', prompt: 'login' })
    expect(refreshAccessTokenMock).not.toHaveBeenCalled()
  }, 2000)

  it('queues a concurrent request behind an in-flight refresh and retries it once the refresh succeeds', async () => {
    const { default: apiClient } = await import('../api/client')

    let refreshResolve!: (value: boolean) => void
    let refreshCalledSignal!: () => void
    const refreshCalled = new Promise<void>((resolve) => {
      refreshCalledSignal = resolve
    })
    refreshAccessTokenMock.mockImplementation(() => {
      // Fires the moment the FIRST request's interceptor actually calls
      // refreshAccessToken() -- which happens synchronously right after
      // `isRefreshing = true` is set, so awaiting this signal (rather than
      // polling on a timer) deterministically guarantees the second
      // request below is issued only once the first has already claimed
      // the in-flight-refresh slot.
      refreshCalledSignal()
      return new Promise<boolean>((resolve) => {
        refreshResolve = resolve
      })
    })

    let attemptsByUrl: Record<string, number> = {}
    let secondDispatchedSignal!: () => void
    const secondDispatched = new Promise<void>((resolve) => {
      secondDispatchedSignal = resolve
    })
    apiClient.defaults.adapter = vi.fn(async (config) => {
      const url = config.url as string
      attemptsByUrl[url] = (attemptsByUrl[url] ?? 0) + 1
      if (attemptsByUrl[url] === 1) {
        if (url === '/api/second') secondDispatchedSignal()
        throw unauthorizedError(config)
      }
      return { status: 200, statusText: 'OK', data: { url }, headers: {}, config }
    }) as typeof apiClient.defaults.adapter

    const first = apiClient.get('/api/first')
    await refreshCalled
    const second = apiClient.get('/api/second')
    // Wait for the SECOND request's own adapter dispatch (its 401) to have
    // actually happened, then flush a few more microtask turns so its
    // rejection has propagated all the way through axios's real interceptor
    // chain and it has genuinely registered itself in pendingRequests --
    // otherwise resolving the refresh below races ahead of it.
    await secondDispatched
    for (let i = 0; i < 5; i++) await Promise.resolve()

    useAuthStore.setState({ accessToken: 'fresh-token' })
    refreshResolve(true)

    const [firstResult, secondResult] = await Promise.all([first, second])

    expect(firstResult.data).toEqual({ url: '/api/first' })
    expect(secondResult.data).toEqual({ url: '/api/second' })
    // Only ONE refresh cycle for both requests -- the whole point of the
    // isRefreshing guard.
    expect(refreshAccessTokenMock).toHaveBeenCalledTimes(1)
  }, 2000)
})
