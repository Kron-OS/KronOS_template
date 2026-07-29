import { describe, it, expect } from 'vitest'
import { parseTenantContext } from '../utils/parseTenantContext'

function fakeToken(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }))
  const body = btoa(JSON.stringify(payload))
  return `${header}.${body}.`
}

describe('parseTenantContext', () => {
  // AUTH-006/FE-4 regression: roles must come from the flat top-level
  // `roles` claim (what the backend's "kronos-roles" mapper actually emits),
  // never from Keycloak's default nested `realm_access.roles` — OpenSearch
  // Security's roles_key cannot walk that nested path.
  it('reads roles from the flat top-level claim', () => {
    const token = fakeToken({
      sub: 'user-1',
      preferred_username: 'alice',
      email: 'alice@acme.example',
      roles: ['org-admin', 'analyst'],
      organization: { acme: { id: 'org-1' } },
      acr: 'aal2',
    })
    const ctx = parseTenantContext(token)
    expect(ctx.roles).toEqual(['org-admin', 'analyst'])
    expect(ctx.orgId).toBe('org-1')
    expect(ctx.orgAlias).toBe('acme')
    expect(ctx.userId).toBe('user-1')
    expect(ctx.acr).toBe('aal2')
  })

  it('ignores a nested realm_access.roles decoy and does not fall back to it', () => {
    const token = fakeToken({
      sub: 'user-1',
      roles: ['read-only'],
      realm_access: { roles: ['org-admin'] },
    })
    const ctx = parseTenantContext(token)
    expect(ctx.roles).toEqual(['read-only'])
  })

  it('defaults to an empty roles array and empty org fields when absent', () => {
    const token = fakeToken({ sub: 'user-1' })
    const ctx = parseTenantContext(token)
    expect(ctx.roles).toEqual([])
    expect(ctx.orgId).toBe('')
    expect(ctx.orgAlias).toBe('')
    expect(ctx.acr).toBe('aal1')
  })

  it('returns empty context for a malformed token instead of throwing', () => {
    expect(() => parseTenantContext('not-a-jwt')).not.toThrow()
    const ctx = parseTenantContext('not-a-jwt')
    expect(ctx.userId).toBe('')
  })
})
