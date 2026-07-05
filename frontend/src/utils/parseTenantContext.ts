import type Keycloak from 'keycloak-js'
import type { TenantContext, Role } from '../types'

export function parseTenantContext(kc: Keycloak): TenantContext {
  const parsed = kc.tokenParsed ?? {}
  return {
    userId: (parsed['sub'] as string) ?? '',
    username: (parsed['preferred_username'] as string) ?? '',
    email: (parsed['email'] as string) ?? '',
    // AUTH-006/FE-4: roles is a flat top-level claim (the "kronos-roles"
    // client scope mapper), not Keycloak's default nested realm_access.roles
    // — read the flat shape so this matches the backend's _extract_tenant
    // and the OpenSearch roles_key contract (Project_Specifications.md §1/§6).
    roles: ((parsed['roles'] as string[] | undefined) ?? []) as Role[],
    orgId: ((parsed['organization'] as { id?: string })?.id) ?? '',
    orgAlias: ((parsed['organization'] as { alias?: string })?.alias) ?? '',
    acr: ((parsed['acr'] as 'aal1' | 'aal2') ?? 'aal1'),
  }
}
