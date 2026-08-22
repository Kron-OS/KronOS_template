import { useState } from 'react'
import axios from 'axios'
import { useMutation } from '@tanstack/react-query'
import { mintStepUpTicket, revokeKeycloakSession, syncDetectionToSiem } from '../api/containment'
import { Spinner } from './Spinner'
import { useAuthStore } from '../store/auth'
import type { PlaybookExecutionResult } from '../types'

// Deliberately narrower than SIEM_SYNC_ROLES, mirroring the backend's own
// stricter role gate on POST /detections/{id}/contain/revoke-session
// (src/external/routes/detections.py::revoke_session_for_detection --
// ORG_ADMIN/CASE_LEAD only, since revoking a real, live user session is a
// genuinely destructive action, unlike a read-mostly SIEM push).
const REVOKE_SESSION_ROLES = ['org-admin', 'case-lead']
const SIEM_SYNC_ROLES = ['org-admin', 'case-lead', 'analyst']

// This codebase's three real, configurable SIEM sink types (verified
// against the exact strings configure_splunk_hec_sink_from_settings()/
// configure_cef_syslog_sink_from_settings()/
// configure_sentinel_sink_from_settings() register in
// src/external/dependencies.py's get_playbook_action_registry()) -- there
// is no backend endpoint to discover which are actually configured in a
// given deployment (accepted gap), so the user just picks one and gets an
// honest "not configured" result if it isn't wired up here.
const KNOWN_SIEM_SINKS = ['splunk', 'cef', 'sentinel'] as const

function getErrorDetail(error: unknown, fallback: string): string {
  if (axios.isAxiosError(error)) {
    const detail: unknown = error.response?.data?.detail
    if (typeof detail === 'string') return detail
  }
  return fallback
}

function isNotFound(error: unknown): boolean {
  return axios.isAxiosError(error) && error.response?.status === 404
}

function ExecutionResultBanner({ result }: { result: PlaybookExecutionResult }) {
  const stepError = result.stepResults[0]?.error
  if (result.succeeded) {
    return (
      <p className="text-xs text-green-600 dark:text-green-400">
        Succeeded — outcome: {result.stepResults[0]?.outcome ?? 'unknown'}
      </p>
    )
  }
  return (
    <p className="text-xs text-red-600 dark:text-red-400">
      Not applied — {stepError ?? 'the action did not succeed (see audit log for details)'}
    </p>
  )
}

interface ContainmentPanelProps {
  detectionId: string
}

export function ContainmentPanel({ detectionId }: ContainmentPanelProps) {
  const roles = useAuthStore((s) => s.user?.roles) ?? []
  const canRevokeSession = roles.some((r) => REVOKE_SESSION_ROLES.includes(r))
  const canSyncToSiem = roles.some((r) => SIEM_SYNC_ROLES.includes(r))

  return (
    <div className="mb-6">
      <h2 className="mb-2 text-sm font-semibold text-gray-800 dark:text-gray-200">
        Containment
      </h2>
      <div className="flex flex-col gap-6 rounded-lg border border-gray-200 p-4 dark:border-gray-800">
        <SyncToSiemSection detectionId={detectionId} allowed={canSyncToSiem} />
        <div className="border-t border-gray-200 pt-4 dark:border-gray-800">
          <RevokeSessionSection detectionId={detectionId} allowed={canRevokeSession} />
        </div>
      </div>
    </div>
  )
}

function SyncToSiemSection({ detectionId, allowed }: { detectionId: string; allowed: boolean }) {
  const [sinkName, setSinkName] = useState<string>(KNOWN_SIEM_SINKS[0])

  const mutation = useMutation({
    mutationFn: () => syncDetectionToSiem(detectionId, sinkName),
  })

  return (
    <div>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">
        Sync to SIEM
      </h3>
      {!allowed && (
        <p className="text-xs text-gray-500">
          Your role does not permit syncing detections to a SIEM (org-admin, case-lead, or
          analyst required).
        </p>
      )}
      {allowed && (
        <>
          <div className="flex items-center gap-3">
            <select
              aria-label="SIEM sink"
              value={sinkName}
              onChange={(e) => setSinkName(e.target.value)}
              disabled={mutation.isPending}
              className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm text-gray-800 disabled:opacity-60 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200"
            >
              {KNOWN_SIEM_SINKS.map((sink) => (
                <option key={sink} value={sink}>
                  {sink}
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled={mutation.isPending}
              onClick={() => mutation.mutate()}
              className="flex items-center gap-2 rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
            >
              {mutation.isPending && <Spinner size="sm" />}
              Sync to SIEM
            </button>
          </div>
          <div className="mt-2">
            {mutation.isSuccess && <ExecutionResultBanner result={mutation.data} />}
            {mutation.isError && isNotFound(mutation.error) && (
              <p className="text-xs text-gray-500">
                SIEM sink &quot;{sinkName}&quot; is not configured in this deployment.
              </p>
            )}
            {mutation.isError && !isNotFound(mutation.error) && (
              <p className="text-xs text-red-600 dark:text-red-400">
                {getErrorDetail(mutation.error, 'Failed to sync this detection to the SIEM.')}
              </p>
            )}
          </div>
        </>
      )}
    </div>
  )
}

function RevokeSessionSection({ detectionId, allowed }: { detectionId: string; allowed: boolean }) {
  const [userId, setUserId] = useState('')
  const [sessionId, setSessionId] = useState('')
  const [ticketId, setTicketId] = useState<string | null>(null)

  const ticketMutation = useMutation({
    mutationFn: () => mintStepUpTicket('revoke_keycloak_session', sessionId),
    onSuccess: (newTicketId) => setTicketId(newTicketId),
  })

  const revokeMutation = useMutation({
    mutationFn: () => revokeKeycloakSession(detectionId, userId, sessionId, ticketId ?? undefined),
    onSuccess: () => setTicketId(null), // tickets are single-use; a fresh one is required to retry
  })

  const canRequestApproval = userId.trim().length > 0 && sessionId.trim().length > 0

  return (
    <div>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">
        Revoke Keycloak Session
      </h3>
      {!allowed && (
        <p className="text-xs text-gray-500">
          Your role does not permit revoking user sessions (org-admin or case-lead required).
        </p>
      )}
      {allowed && (
        <>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              type="text"
              placeholder="User ID (UUID)"
              aria-label="User ID"
              value={userId}
              onChange={(e) => {
                setUserId(e.target.value)
                setTicketId(null)
              }}
              disabled={ticketMutation.isPending || revokeMutation.isPending}
              className="flex-1 rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm text-gray-800 disabled:opacity-60 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200"
            />
            <input
              type="text"
              placeholder="Session ID"
              aria-label="Session ID"
              value={sessionId}
              onChange={(e) => {
                setSessionId(e.target.value)
                setTicketId(null)
              }}
              disabled={ticketMutation.isPending || revokeMutation.isPending}
              className="flex-1 rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm text-gray-800 disabled:opacity-60 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200"
            />
          </div>
          <div className="mt-3 flex items-center gap-3">
            <button
              type="button"
              disabled={!canRequestApproval || ticketMutation.isPending || ticketId !== null}
              onClick={() => ticketMutation.mutate()}
              className="flex items-center gap-2 rounded-md border border-indigo-600 px-4 py-2 text-sm font-medium text-indigo-600 hover:bg-indigo-50 disabled:opacity-60 dark:hover:bg-indigo-950"
            >
              {ticketMutation.isPending && <Spinner size="sm" />}
              {ticketId ? 'Approval granted' : 'Request Approval'}
            </button>
            <button
              type="button"
              disabled={ticketId === null || revokeMutation.isPending}
              onClick={() => revokeMutation.mutate()}
              className="flex items-center gap-2 rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-60"
            >
              {revokeMutation.isPending && <Spinner size="sm" />}
              Confirm Revoke
            </button>
          </div>
          <div className="mt-2">
            {ticketMutation.isError && (
              <p className="text-xs text-red-600 dark:text-red-400">
                {axios.isAxiosError(ticketMutation.error) &&
                ticketMutation.error.response?.status === 401
                  ? 'Step-up authentication required — you are being redirected to sign in again. Please retry once you return.'
                  : getErrorDetail(ticketMutation.error, 'Failed to request approval.')}
              </p>
            )}
            {revokeMutation.isSuccess && <ExecutionResultBanner result={revokeMutation.data} />}
            {revokeMutation.isError && isNotFound(revokeMutation.error) && (
              <p className="text-xs text-gray-500">
                Session revocation containment is not configured in this deployment.
              </p>
            )}
            {revokeMutation.isError && !isNotFound(revokeMutation.error) && (
              <p className="text-xs text-red-600 dark:text-red-400">
                {getErrorDetail(revokeMutation.error, 'Failed to revoke this session.')}
              </p>
            )}
          </div>
        </>
      )}
    </div>
  )
}
