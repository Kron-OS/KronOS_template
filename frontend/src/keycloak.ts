import Keycloak from 'keycloak-js'

const TOKEN_STORAGE_KEY = 'kronos:kc-tokens'

interface StoredTokens {
  token: string
  refreshToken: string
  idToken: string
}

function loadStoredTokens(): StoredTokens | null {
  try {
    const raw = sessionStorage.getItem(TOKEN_STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Partial<StoredTokens>
    if (!parsed.token || !parsed.refreshToken || !parsed.idToken) return null
    return { token: parsed.token, refreshToken: parsed.refreshToken, idToken: parsed.idToken }
  } catch {
    return null
  }
}

function persistTokens(): void {
  if (keycloak.token && keycloak.refreshToken && keycloak.idToken) {
    const tokens: StoredTokens = {
      token: keycloak.token,
      refreshToken: keycloak.refreshToken,
      idToken: keycloak.idToken,
    }
    sessionStorage.setItem(TOKEN_STORAGE_KEY, JSON.stringify(tokens))
  }
}

function clearStoredTokens(): void {
  sessionStorage.removeItem(TOKEN_STORAGE_KEY)
}

export const keycloak = new Keycloak({
  url: import.meta.env.VITE_KEYCLOAK_URL as string,
  realm: import.meta.env.VITE_KEYCLOAK_REALM as string,
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID as string,
})

// Keep the sessionStorage copy in sync with the live session so the next
// full page reload (initKeycloak below) can restore it directly.
keycloak.onAuthSuccess = persistTokens
keycloak.onAuthRefreshSuccess = persistTokens
keycloak.onAuthLogout = clearStoredTokens
keycloak.onAuthRefreshError = clearStoredTokens

export async function initKeycloak(): Promise<boolean> {
  // onLoad: 'check-sso' alone silently fails to detect an existing Keycloak
  // session on every reload once the browser blocks third-party cookies
  // (default in current Chrome/Edge/Firefox): silent-check-sso.html runs in
  // a hidden iframe on the Keycloak origin, and that iframe can no longer
  // read the Keycloak session cookie from within our page's context —
  // without this, every refresh looked like a brand-new, logged-out visit.
  // Restoring the last known token/refreshToken lets keycloak-js validate
  // the session directly (a same-origin fetch to Keycloak's token endpoint)
  // instead, which doesn't depend on third-party cookies at all.
  const stored = loadStoredTokens()
  try {
    const authenticated = await keycloak.init({
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
      ...stored,
    })
    if (!authenticated) clearStoredTokens()
    return authenticated
  } catch {
    // The stored refresh token was rejected outright (e.g. expired, or the
    // dev Keycloak was restarted since it was issued) — fall back to a
    // normal logged-out state; the user signs in again via the login page.
    clearStoredTokens()
    return false
  }
}

export function scheduleTokenRefresh(): void {
  setInterval(
    async () => {
      try {
        await keycloak.updateToken(60)
      } catch {
        clearStoredTokens()
        keycloak.login()
      }
    },
    5 * 60 * 1000,
  )
}
