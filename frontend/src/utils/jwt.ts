/**
 * Decode a JWT's payload without verifying its signature.
 *
 * The SPA never verifies tokens itself — the backend/Keycloak already did
 * that before issuing them — this is purely for reading claims (sub, roles,
 * organization, exp, ...) out of a token already held in memory. Returns an
 * empty object for a malformed token instead of throwing, so callers can
 * treat a bad token the same as "no claims available".
 */
export function decodeJwtPayload(token: string): Record<string, unknown> {
  const segment = token.split('.')[1]
  if (!segment) return {}
  const base64 = segment.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
  try {
    return JSON.parse(atob(padded)) as Record<string, unknown>
  } catch {
    return {}
  }
}
