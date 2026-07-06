/**
 * FE-6: validate the backend-supplied OpenSearch Dashboards embed URL's
 * origin before it's ever assigned to an iframe's `src`.
 *
 * Defense-in-depth against a compromised/misconfigured backend response —
 * the real trust boundary is still the backend's own auth/org-scoping on
 * `GET /api/cases/{id}/dashboard-url`, but an iframe pointed at an
 * unexpected origin would otherwise happily load without any client-side
 * signal. `VITE_OPENSEARCH_DASHBOARDS_ORIGIN` is optional: when unset (an
 * environment where the Dashboards origin isn't fixed in advance), this
 * only rejects a malformed URL rather than every URL.
 */
export function isTrustedDashboardsUrl(url: string): boolean {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return false
  }

  const expectedOrigin = import.meta.env.VITE_OPENSEARCH_DASHBOARDS_ORIGIN as string | undefined
  if (expectedOrigin) {
    return parsed.origin === expectedOrigin
  }
  return true
}
