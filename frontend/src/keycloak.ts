import Keycloak from 'keycloak-js'

export const keycloak = new Keycloak({
  url: import.meta.env.VITE_KEYCLOAK_URL as string,
  realm: import.meta.env.VITE_KEYCLOAK_REALM as string,
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID as string,
})

export async function initKeycloak(): Promise<boolean> {
  return keycloak.init({
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
}

export function scheduleTokenRefresh(): void {
  setInterval(
    async () => {
      try {
        await keycloak.updateToken(60)
      } catch {
        keycloak.login()
      }
    },
    5 * 60 * 1000,
  )
}
