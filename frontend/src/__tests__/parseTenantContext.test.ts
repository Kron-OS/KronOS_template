import { describe, it, expect } from 'vitest'
import type Keycloak from 'keycloak-js'
import { parseTenantContext } from '../utils/parseTenantContext'

function fakeKeycloak(tokenParsed: Record<string, unknown>): Keycloak {
  return { tokenParsed } as unknown as Keycloak
}

describe('parseTenantContext', () => {
  // AUTH-006/FE-4 regression: roles must come from the flat top-level
  // `roles` claim (what the backend's "kronos-roles" mapper actually emits),
  // never from Keycloak's default nested `realm_access.roles` — OpenSearch
  // Security's roles_key cannot walk that nested path.
  it('reads roles from the flat top-level claim', () => {
    const kc = fakeKeycloak({
      sub: 'user-1',
      preferred_username: 'alice',
      email: 'alice@acme.example',
      roles: ['org-admin', 'analyst'],
      organization: { acme: { id: 'org-1', alias: 'acme' } },
      acr: 'aal2',
    })
    const ctx = parseTenantContext(kc)
    expect(ctx.roles).toEqual(['org-admin', 'analyst'])
  })

  it('ignores a nested realm_access.roles decoy and does not fall back to it', () => {
    const kc = fakeKeycloak({
      sub: 'user-1',
      roles: ['read-only'],
      realm_access: { roles: ['org-admin'] },
    })
    const ctx = parseTenantContext(kc)
    expect(ctx.roles).toEqual(['read-only'])
  })

  it('defaults to an empty roles array when the flat claim is absent', () => {
    const kc = fakeKeycloak({ sub: 'user-1' })
    const ctx = parseTenantContext(kc)
    expect(ctx.roles).toEqual([])
  })
})
