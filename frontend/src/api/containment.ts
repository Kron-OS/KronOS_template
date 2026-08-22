import apiClient from './client'
import type { PlaybookExecutionResult } from '../types'

/**
 * Mint a one-time step-up ticket (RFC 9470) via the real
 * `POST /api/step-up/ticket` route (`src/external/routes/step_up.py`).
 *
 * Requires the caller's JWT to already carry `acr=aal2`; if not, the shared
 * `apiClient` response interceptor (`./client.ts`) intercepts the resulting
 * 401 + `WWW-Authenticate: ...acr_values="aal2"` response globally and
 * redirects the browser to Keycloak for a real step-up re-authentication --
 * this function's own promise still rejects in that case (the redirect does
 * not resolve it), so callers should treat a rejected promise here as "the
 * user may have just been redirected away," not merely "request failed."
 *
 * `resourceId` MUST be the exact value the backend will later check the
 * ticket against for the guarded operation (e.g. the real Keycloak
 * `sessionId` about to be revoked) -- see
 * `RevokeKeycloakSessionAction._resource_id()` (Gap Audit Milestone JJ):
 * a ticket minted for the wrong resource is honestly rejected, not
 * silently allowed.
 */
export async function mintStepUpTicket(operation: string, resourceId: string): Promise<string> {
  const res = await apiClient.post<{ ticketId: string }>('/api/step-up/ticket', {
    operation,
    resource_id: resourceId,
  })
  return res.data.ticketId
}

/**
 * Fire `RevokeKeycloakSessionAction` for one Detection via
 * `POST /api/detections/{id}/contain/revoke-session`
 * (role-gated ORG_ADMIN/CASE_LEAD server-side).
 *
 * `approvalTicketId` should be a ticket minted via `mintStepUpTicket` with
 * `operation: 'revoke_keycloak_session'` and `resourceId: sessionId` (the
 * SAME `sessionId` passed here) -- omitting it is a valid request shape for
 * a deployment using a non-step-up `ApprovalGate`, but the gate's own
 * denial (an audited, non-exceptional outcome) is what a missing/invalid
 * ticket produces when step-up IS the configured gate.
 *
 * Always resolves on a well-formed request (backend never returns a
 * non-2xx here) -- the real outcome is `result.succeeded`/
 * `result.stepResults[0].error`. Rejects (with a 404 AxiosError) only when
 * no `RevokeKeycloakSessionAction` is registered in this deployment (no
 * Keycloak admin client configured) -- an honest "not configured" state.
 */
export async function revokeKeycloakSession(
  detectionId: string,
  userId: string,
  sessionId: string,
  approvalTicketId?: string,
): Promise<PlaybookExecutionResult> {
  const res = await apiClient.post<PlaybookExecutionResult>(
    `/api/detections/${detectionId}/contain/revoke-session`,
    {
      userId,
      sessionId,
      ...(approvalTicketId ? { approvalTicketId } : {}),
    },
  )
  return res.data
}

/**
 * Fire `SyncDetectionToSiemAction` for one Detection via
 * `POST /api/detections/{id}/sync-to-siem/{sink_name}`
 * (role-gated ORG_ADMIN/CASE_LEAD/ANALYST server-side).
 *
 * There is no backend endpoint to discover configured sink names (a known,
 * accepted gap) -- `sinkName` is one of this codebase's three real
 * configurable SIEM sink types ("splunk"/"cef"/"sentinel", verified against
 * the exact strings `configure_splunk_hec_sink_from_settings()` /
 * `configure_cef_syslog_sink_from_settings()` /
 * `configure_sentinel_sink_from_settings()` register in
 * `src/external/dependencies.py`'s `get_playbook_action_registry()`), or
 * any other name an operator knows to be configured.
 *
 * Always resolves on a well-formed request; rejects (with a 404
 * AxiosError) when no sink named `sinkName` is configured in this
 * deployment -- an honest "not configured" state, not a bug.
 */
export async function syncDetectionToSiem(
  detectionId: string,
  sinkName: string,
): Promise<PlaybookExecutionResult> {
  const res = await apiClient.post<PlaybookExecutionResult>(
    `/api/detections/${detectionId}/sync-to-siem/${sinkName}`,
  )
  return res.data
}
