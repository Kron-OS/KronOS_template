import type Keycloak from 'keycloak-js'
import type { TenantContext, Role } from '../types'

export function parseTenantContext(kc: Keycloak): TenantContext {
  const parsed = kc.tokenParsed ?? {}
  return {
    userId: (parsed['sub'] as string) ?? '',
    username: (parsed['preferred_username'] as string) ?? '',
    email: (parsed['email'] as string) ?? '',
    roles: ((parsed['realm_access'] as { roles?: string[] })?.roles ?? []) as Role[],
    orgId: ((parsed['organization'] as { id?: string })?.id) ?? '',
    orgAlias: ((parsed['organization'] as { alias?: string })?.alias) ?? '',
    acr: ((parsed['acr'] as 'aal1' | 'aal2') ?? 'aal1'),
  }
}
