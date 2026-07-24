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
 * of the flow. If the SPA sent keycloak-js to a *different* origin per
 * client (e.g. http://localhost:8080 for local access, the LAN HTTPS
 * proxy for everyone else), the initial GET lands on that origin and sets
 * Keycloak's session-restart cookie there — but the rendered login form
 * then POSTs to the one-and-only KC_HOSTNAME origin instead. Cookies
 * never cross domains, so that POST arrives with no session cookie at
 * all, and Keycloak rejects it outright: "Restart login cookie not
 * found." Confirmed directly (poc/tls_lan_https/): a scripted login
 * starting on http://localhost:8080 got exactly this 400; the identical
 * flow starting directly on the canonical https://192.168.5.13:8443
 * origin completed successfully end-to-end.
 *
 * The fix is not a smarter derivation — there isn't a client-side rule
 * that produces the right answer per-origin, because Keycloak's own
 * answer isn't per-origin either. Every client must start the flow at
 * the exact same KC_HOSTNAME value. VITE_KEYCLOAK_URL is a real build-time
 * arg (docker-compose.dev.yml passes it to Dockerfile.frontend, sourced
 * from the same KRONOS_LAN_HOST the server side's KC_HOSTNAME/tls-init
 * SAN are built from) precisely because this has to be one fixed value,
 * not something recomputed per request. The bare fallback below only
 * matters for `npm run dev` against a separate, non-Docker local Keycloak
 * setup, where localhost:8080 is that setup's own (single, consistent)
 * KC_HOSTNAME too.
 */
function resolveKeycloakUrl(): string {
  return (import.meta.env.VITE_KEYCLOAK_URL as string | undefined) || 'http://localhost:8080'
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

/**
 * Establish (or resume) the SPA session without ever touching Web Storage.
 *
 * 1. Try resuming purely from the backend's HttpOnly refresh-token cookie —
 *    this is what survives a page reload, since no token is ever persisted
 *    client-side.
 * 2. If that fails (first visit, or the cookie is absent/expired), fall
 *    back to keycloak-js's own silent-SSO check (a hidden iframe against
 *    Keycloak's session cookie — blocked by third-party-cookie restrictions
 *    in some browsers, in which case the user just sees the login page). On
 *    success, hand its refresh token to the backend exactly once so the
 *    HttpOnly cookie is established, then this module never reads
 *    keycloak-js's copy again.
 */
export async function initKeycloak(): Promise<boolean> {
  const resumed = await callRefreshEndpoint()
  if (resumed) {
    adoptAccessToken(resumed.access_token)
    return true
  }

  let authenticated = false
  try {
    authenticated = await keycloak.init({
      pkceMethod: 'S256',
      responseMode: 'fragment',
      useNonce: true,
      checkLoginIframe: false,
      onLoad: 'check-sso',
      // The backend requires the `organization` claim. Request the scope
      // explicitly so the minted token always carries it, independent of the
      // realm's default-scope configuration.
      scope: 'openid organization',
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
