import type { TenantContext, Role } from '../types'
import { decodeJwtPayload } from './jwt'

/**
 * Derive the tenant context from a raw access-token JWT string.
 *
 * AUTH-002: takes the token itself rather than a `Keycloak` instance —
 * the SPA can now populate the auth store purely from a token minted by the
 * backend's `/auth/refresh` cookie proxy (see `keycloak.ts`), without ever
 * routing through `keycloak-js`'s own `tokenParsed`, so this must work
 * identically for both the keycloak-js login path and the cookie-resume path.
 */
export function parseTenantContext(token: string): TenantContext {
  const parsed = decodeJwtPayload(token)

  // organization is a map keyed by org alias, e.g. {"acme": {"id": "..."}}
  // (Project_Specifications.md §6) — v1 reads the first (only) entry.
  const organization = parsed['organization'] as Record<string, { id?: string }> | undefined
  const [orgAlias, orgInfo] = organization ? (Object.entries(organization)[0] ?? []) : []

  return {
    userId: (parsed['sub'] as string) ?? '',
    username: (parsed['preferred_username'] as string) ?? '',
    email: (parsed['email'] as string) ?? '',
    // AUTH-006/FE-4: roles is a flat top-level claim (the "kronos-roles"
    // client scope mapper), not Keycloak's default nested realm_access.roles
    // — read the flat shape so this matches the backend's _extract_tenant
    // and the OpenSearch roles_key contract (Project_Specifications.md §1/§6).
    roles: ((parsed['roles'] as string[] | undefined) ?? []) as Role[],
    orgId: orgInfo?.id ?? '',
    orgAlias: orgAlias ?? '',
    acr: ((parsed['acr'] as 'aal1' | 'aal2') ?? 'aal1'),
  }
}
