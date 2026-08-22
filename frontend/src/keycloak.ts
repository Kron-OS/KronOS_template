import Keycloak from 'keycloak-js'
import { useAuthStore } from './store/auth'
import { parseTenantContext } from './utils/parseTenantContext'
import { decodeJwtPayload } from './utils/jwt'

// AUTH-002/FE-1/FE-2: tokens are never persisted to sessionStorage or
// localStorage — both are fully readable by any XSS. The access token lives
// only in the in-memory auth store (store/auth.ts, a plain zustand store
// with no persist middleware); the refresh token lives only in an
// HttpOnly + Secure + SameSite=Strict cookie set by the backend's
// POST /auth/refresh proxy (src/external/routes/auth.py). This module never
// reads that cookie's value — it just calls the endpoint with
// `credentials: 'include'` and lets the browser attach/store it.

const API_URL = (import.meta.env.VITE_API_URL as string | undefined) ?? ''

/**
 * Keycloak's browser-facing URL. NOT derived from window.location, on
 * purpose — a real, reproduced regression found while testing this: the
 * server pins ONE canonical KC_HOSTNAME (docker-compose.dev.yml), and
 * every URL Keycloak renders for the interactive login flow (the login
 * form's own POST target, "action=...") is that literal, single value —
 * regardless of which origin the browser used to reach the *first* page
 * of the flow. Cookies never cross domains, so a client starting the flow
 * on any origin other than that one pinned value arrives at the login
 * form's POST with no session cookie at all, and Keycloak rejects it
 * outright: "Restart login cookie not found." Confirmed directly
 * (poc/tls_lan_https/): a scripted login starting on a different origin
 * than KC_HOSTNAME got exactly this 400; the identical flow starting
 * directly on the canonical origin completed successfully end-to-end.
 *
 * The fix is not a smarter derivation — there isn't a client-side rule
 * that produces the right answer per-origin, because Keycloak's own
 * answer isn't per-origin either. Every client must start the flow at
 * the exact same KC_HOSTNAME value: https://kronos.local:8443, the sole
 * authorized domain for this app (docs/lan-dev-access.md) — no
 * localhost/127.0.0.1/bare-IP fallbacks. VITE_KEYCLOAK_URL is a real
 * build-time arg (docker-compose.dev.yml passes it to Dockerfile.frontend,
 * sourced from the same KRONOS_LAN_HOST the server side's KC_HOSTNAME/
 * tls-init SAN are built from) precisely because this has to be one fixed
 * value, not something recomputed per request. The bare fallback below
 * only matters when nothing else sets it at all (e.g. a plain `npm run
 * build`/`vite dev` with no frontend/.env present) — vite.config.ts
 * supplies the identical default so the two never disagree.
 */
function resolveKeycloakUrl(): string {
  return (import.meta.env.VITE_KEYCLOAK_URL as string | undefined) || 'https://kronos.local:8443'
}

export const keycloak = new Keycloak({
  url: resolveKeycloakUrl(),
  realm: import.meta.env.VITE_KEYCLOAK_REALM as string,
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID as string,
})

keycloak.onAuthLogout = () => useAuthStore.getState().clearAuth()

interface RefreshResponse {
  access_token: string
}

/**
 * Call the backend's HttpOnly-cookie refresh proxy.
 *
 * With no argument, relies solely on the browser sending the HttpOnly
 * `refresh_token` cookie (the steady-state path, and how a page reload
 * resumes a session). Passing `bootstrapRefreshToken` is only for the
 * one-time handoff right after a fresh keycloak-js login, before the
 * backend has ever had a chance to set that cookie.
 */
async function callRefreshEndpoint(bootstrapRefreshToken?: string): Promise<RefreshResponse | null> {
  try {
    const res = await fetch(`${API_URL}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: bootstrapRefreshToken ? { 'Content-Type': 'application/json' } : {},
      body: bootstrapRefreshToken ? JSON.stringify({ refresh_token: bootstrapRefreshToken }) : undefined,
    })
    if (!res.ok) return null
    return (await res.json()) as RefreshResponse
  } catch {
    return null
  }
}

let refreshTimer: ReturnType<typeof setTimeout> | undefined

/** Silent refresh (exp - now - 60s) ahead of expiry, per spec §6 SPA OIDC wiring. */
function scheduleSilentRefresh(accessToken: string): void {
  if (refreshTimer) clearTimeout(refreshTimer)
  const { exp } = decodeJwtPayload(accessToken) as { exp?: number }
  if (!exp) return
  const msUntilRefresh = Math.max((exp - Date.now() / 1000 - 60) * 1000, 0)
  refreshTimer = setTimeout(() => {
    void refreshAccessToken()
  }, msUntilRefresh)
}

function adoptAccessToken(accessToken: string): void {
  useAuthStore.getState().setAuth(accessToken, parseTenantContext(accessToken))
  scheduleSilentRefresh(accessToken)
}

/**
 * Refresh the access token via the backend's HttpOnly-cookie proxy.
 *
 * Deliberately never calls `keycloak.updateToken()` — that depends on
 * keycloak-js's own in-memory refresh token, which this module only uses
 * once (see `initKeycloak`) to hand off into the backend-owned cookie. On
 * failure (cookie missing/expired/revoked), falls back to a full Keycloak
 * login, preserving the current location as the post-login redirect target.
 */
export async function refreshAccessToken(): Promise<boolean> {
  const result = await callRefreshEndpoint()
  if (!result) {
    useAuthStore.getState().clearAuth()
    if (refreshTimer) clearTimeout(refreshTimer)
    keycloak.login({ redirectUri: window.location.href })
    return false
  }
  adoptAccessToken(result.access_token)
  return true
}

// Shared with the fast-path's own background call below — keycloak-js's
// `login()`/`logout()`/`register()` all read `pkceMethod`/`responseMode`/
// `scope`/etc back off the instance, so whichever branch of initKeycloak()
// runs, keycloak.init() must be called with the SAME options or a later
// keycloak.login() (e.g. apiClient's step-up-triggered call) would silently
// behave differently depending on which page loaded it first.
const KEYCLOAK_INIT_OPTIONS = {
  pkceMethod: 'S256' as const,
  responseMode: 'fragment' as const,
  useNonce: true,
  checkLoginIframe: false,
  // The backend requires the `organization` claim. Request the scope
  // explicitly so the minted token always carries it, independent of the
  // realm's default-scope configuration.
  scope: 'openid organization',
}

/**
 * A pending `code=`/`error=` fragment means this load is a direct return
 * from a real Keycloak redirect — either the initial login OR a step-up
 * re-authentication (apiClient's response interceptor calling
 * `keycloak.login({ acrValues: 'aal2', ... })`, ./api/client.ts). That
 * fragment carries the FRESHEST possible token (e.g. the one that now
 * actually satisfies acr=aal2); it must always be processed via
 * keycloak.init(), never skipped.
 */
function hasPendingRedirectCallback(): boolean {
  return /[#&](code|error)=/.test(window.location.hash)
}

/**
 * Establish (or resume) the SPA session without ever touching Web Storage.
 *
 * 1. If this load is NOT a return from a real Keycloak redirect (see
 *    `hasPendingRedirectCallback`), try resuming purely from the backend's
 *    HttpOnly refresh-token cookie — this is what survives a plain page
 *    reload, since no token is ever persisted client-side.
 * 2. Otherwise (first visit, cookie absent/expired, or a pending redirect
 *    callback that must win the race against an still-valid OLD cookie —
 *    see below), fall back to keycloak-js's own full `init()` — either
 *    processing the real callback in the URL, or a silent-SSO check (a
 *    hidden iframe against Keycloak's session cookie — blocked by
 *    third-party-cookie restrictions in some browsers, in which case the
 *    user just sees the login page). On success, hand its refresh token to
 *    the backend exactly once so the HttpOnly cookie is established, then
 *    this module never reads keycloak-js's copy again.
 *
 * Real, reproduced bug fixed here (found live while building the step-up
 * containment UI, poc/detection_containment_ui/README.md — the FIRST real
 * caller of `keycloak.login()` anywhere in this codebase other than the
 * very first login page): keycloak-js's `login()`/`logout()`/`register()`
 * all depend on private instance state (adapter, PKCE method, scope, …)
 * that ONLY `keycloak.init()` populates. The cookie fast path above never
 * called it, so on every page reached via that fast path (i.e. every page
 * after the very first login) `keycloak.login()` threw immediately on an
 * unset internal field — silently, since it happened inside an
 * unawaited/uncaught call inside apiClient's interceptor. A second, related
 * bug: even after fixing that, a page reached by returning from a step-up
 * redirect still has the OLD refresh-token cookie sitting there (not yet
 * expired) — resuming from it first would win the race against the fresh
 * `code=` in the URL and silently adopt the stale, pre-step-up (still
 * aal1) token, discarding the fragment unprocessed. `hasPendingRedirectCallback`
 * closes that race by always preferring the real callback when one exists.
 */
export async function initKeycloak(): Promise<boolean> {
  if (!hasPendingRedirectCallback()) {
    const resumed = await callRefreshEndpoint()
    if (resumed) {
      adoptAccessToken(resumed.access_token)
      // Fire-and-forget: populates keycloak-js's own private adapter/PKCE/
      // scope state so a LATER keycloak.login()/.logout() call on this
      // same page works. Real network cost (discovery + 3p-cookie iframe —
      // keycloak-js has no cheaper way to do just this part), so this must
      // not block the fast path's whole point (immediate render). Any
      // failure here just means login()/logout() would still be broken on
      // this page; the already-resumed session itself is unaffected.
      void keycloak.init(KEYCLOAK_INIT_OPTIONS).catch(() => {})
      return true
    }
  }

  let authenticated = false
  try {
    authenticated = await keycloak.init({
      ...KEYCLOAK_INIT_OPTIONS,
      onLoad: 'check-sso',
      silentCheckSsoRedirectUri: window.location.origin + '/silent-check-sso.html',
    })
  } catch {
    authenticated = false
  }

  if (authenticated && keycloak.token && keycloak.refreshToken) {
    await callRefreshEndpoint(keycloak.refreshToken)
    adoptAccessToken(keycloak.token)
  }
  return authenticated
}
