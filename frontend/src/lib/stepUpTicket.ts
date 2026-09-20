import apiClient from '../api/client'

/**
 * Mints a one-time step-up ticket (`POST /api/step-up/ticket`,
 * `src/external/routes/step_up.py`) for routes that require both aal2 AND
 * a single-use ticket -- a stronger bar than `admin.py`'s quota/invite/role
 * routes, which only ever check `acr` and never call this at all. Real gap
 * found live via Playwright (Task 12): `PushConnectorKeyPanel.tsx`/
 * `ConnectorConfigForm.tsx` called their mutation routes directly with no
 * ticket, which `admin_integration_sources.py`/`admin_connector_config.py`
 * both reject with a 401 that carries no `acr_values` challenge --
 * `apiClient`'s interceptor doesn't recognize that shape as a step-up
 * challenge, so it fell into the token-refresh branch and retried forever
 * instead of failing fast or redirecting.
 *
 * On a first call (acr still aal1), the ticket route itself 401s with the
 * standard `acr_values="aal2"` challenge -- `apiClient`'s interceptor
 * already handles that identically to any other aal2-gated route (full
 * Keycloak redirect, in-flight call abandoned). Once the user returns with
 * a real aal2 session, calling this again succeeds and the ticket can be
 * attached to the real mutation.
 *
 * Field names are intentionally snake_case (`operation`/`resource_id`) --
 * `StepUpTicketIn` is the one DTO in this codebase that does NOT follow
 * the camelCase route convention (verified against
 * `src/external/routes/step_up.py`, not assumed).
 */
export async function mintStepUpTicket(operation: string, resourceId: string): Promise<string> {
  const res = await apiClient.post<{ ticketId: string }>('/api/step-up/ticket', {
    operation,
    resource_id: resourceId,
  })
  return res.data.ticketId
}
