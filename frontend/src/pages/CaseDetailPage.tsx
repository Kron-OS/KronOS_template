import { useState, useEffect } from 'react'
import { useParams, useNavigate } from '@tanstack/react-router'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getCase, addCaseMember, removeCaseMember, deleteCase } from '../api/cases'
import { getEvidence, getAuditLog, getDashboardUrl } from '../api/evidence'
import { getOrgSettings, updateOrgSettings } from '../api/admin'
import { StatusPill } from '../components/StatusPill'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import { UploadDrawer } from '../components/UploadDrawer'
import { EvidenceDetailDrawer } from '../components/EvidenceDetailDrawer'
import { useEvidenceSSE } from '../hooks/useEvidenceSSE'
import { useAuthStore } from '../store/auth'
import { isTrustedDashboardsUrl } from '../utils/dashboardsOrigin'
import type { Case, Evidence, AuditEvent, SSEStatusEvent } from '../types'

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function truncateHash(hash: string | null): string {
  if (!hash) return '—'
  return `${hash.slice(0, 8)}…`
}

function EvidenceTab({ caseId }: { caseId: string }) {
  const queryClient = useQueryClient()
  const [showUpload, setShowUpload] = useState(false)
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null)
  const { data, isLoading, error } = useQuery({
    queryKey: ['evidence', caseId],
    queryFn: () => getEvidence(caseId),
    staleTime: 15_000,
  })

  const handleSSEEvent = (event: SSEStatusEvent) => {
    // Optimistic patch for an instant status-pill flip, immediately
    // followed by a real refetch: the SSE payload only carries
    // evidenceId/state, so patching just `state` in place left
    // errorReason/retryAction/sha256/etc. stale until the next incidental
    // refetch (window refocus, remount, or a manual reload) -- which is
    // why status changes didn't seem to show up promptly. invalidateQueries
    // refetches the full row from the real API right away.
    queryClient.setQueryData<{ items: Evidence[] }>(['evidence', caseId], (old) => {
      if (!old) return old
      return {
        ...old,
        items: old.items.map((e) => (e.id === event.evidenceId ? { ...e, state: event.state } : e)),
      }
    })
    void queryClient.invalidateQueries({ queryKey: ['evidence', caseId] })
  }

  useEvidenceSSE(caseId, handleSSEEvent)

  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent<{ caseId: string }>).detail
      if (detail.caseId === caseId) {
        void queryClient.invalidateQueries({ queryKey: ['evidence', caseId] })
      }
    }
    window.addEventListener('kronos:sse-poll', handler)
    return () => window.removeEventListener('kronos:sse-poll', handler)
  }, [caseId, queryClient])

  return (
    <div>
      <div className="mb-4 flex justify-end">
        <button
          type="button"
          onClick={() => setShowUpload(true)}
          className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
        >
          Upload Evidence
        </button>
      </div>

      {isLoading && (
        <div className="flex justify-center py-12">
          <Spinner size="lg" />
        </div>
      )}
      {error && <ErrorBanner message="Failed to load evidence." />}

      {data && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-100/50 text-left text-xs text-gray-600 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-400">
                <th className="px-4 py-3 font-medium">Filename</th>
                <th className="px-4 py-3 font-medium">Size</th>
                <th className="px-4 py-3 font-medium">SHA-256</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Uploader</th>
                <th className="px-4 py-3 font-medium sr-only">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
              {data.items.map((ev) => (
                <tr
                  key={ev.id}
                  className="cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-900/40"
                  onClick={() => setSelectedEvidence(ev)}
                >
                  <td className="max-w-xs truncate px-4 py-3 font-mono text-gray-800 dark:text-gray-200">
                    {ev.filename}
                  </td>
                  <td className="px-4 py-3 text-gray-600 dark:text-gray-400">{formatBytes(ev.sizeBytes)}</td>
                  <td
                    className="px-4 py-3 font-mono text-xs text-gray-500"
                    title={ev.sha256 ?? undefined}
                  >
                    {truncateHash(ev.sha256)}
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill state={ev.state} />
                  </td>
                  <td className="px-4 py-3 text-gray-600 dark:text-gray-400">{ev.uploadedBy}</td>
                  <td className="px-4 py-3">
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); setSelectedEvidence(ev) }}
                      className="text-xs text-indigo-600 hover:underline dark:text-indigo-400"
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))}
              {data.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-10 text-center text-gray-500">
                    No evidence uploaded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <UploadDrawer
        caseId={caseId}
        open={showUpload}
        onClose={() => setShowUpload(false)}
      />

      <EvidenceDetailDrawer
        evidence={selectedEvidence}
        onClose={() => setSelectedEvidence(null)}
      />
    </div>
  )
}

function TimelineTab({ caseId }: { caseId: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboardUrl', caseId],
    queryFn: () => getDashboardUrl(caseId),
    staleTime: 300_000,
    retry: 1,
  })

  if (isLoading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner size="lg" />
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-gray-200 py-16 text-sm text-gray-500 dark:border-gray-800">
        <p>Timeline analysis unavailable — no parsed evidence yet.</p>
        <p className="text-xs text-gray-400 dark:text-gray-600">
          Upload and process evidence to view the forensic timeline.
        </p>
      </div>
    )
  }

  if (!isTrustedDashboardsUrl(data.url)) {
    return (
      <ErrorBanner message="Timeline analysis is unavailable: the Dashboards URL returned by the server did not match the expected origin." />
    )
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex justify-end">
        <a
          href={data.url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs text-indigo-600 hover:underline dark:text-indigo-400"
        >
          Open in new tab
        </a>
      </div>
      <iframe
        src={data.url}
        allow="fullscreen"
        sandbox="allow-same-origin allow-scripts allow-forms allow-popups"
        title="Timeline Analysis"
        className="w-full rounded-lg border border-gray-200 dark:border-gray-800"
        style={{ height: '70vh' }}
      />
    </div>
  )
}

function AuditLogTab({ caseId }: { caseId: string }) {
  const [page, setPage] = useState(1)
  const pageSize = 25

  const { data, isLoading, error } = useQuery({
    queryKey: ['auditlog', caseId, page],
    queryFn: () => getAuditLog(caseId, { page, pageSize }),
    staleTime: 30_000,
  })

  return (
    <div>
      {isLoading && (
        <div className="flex justify-center py-12">
          <Spinner size="lg" />
        </div>
      )}
      {error && <ErrorBanner message="Failed to load audit log." />}

      {data && (
        <>
          <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-800">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 bg-gray-100/50 text-left text-xs text-gray-600 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-400">
                  <th className="px-4 py-3 font-medium">Event</th>
                  <th className="px-4 py-3 font-medium">User</th>
                  <th className="px-4 py-3 font-medium">Timestamp</th>
                  <th className="px-4 py-3 font-medium">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
                {data.items.map((ev: AuditEvent) => (
                  <tr key={ev.id} className="hover:bg-gray-100 dark:hover:bg-gray-900/40">
                    <td className="px-4 py-3 font-mono text-xs text-indigo-600 dark:text-indigo-300">
                      {ev.eventType}
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-gray-400">{ev.userId}</td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {new Date(ev.occurredAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <details>
                        <summary className="cursor-pointer text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
                          view
                        </summary>
                        <pre className="mt-1 max-w-xs overflow-auto rounded bg-gray-100 p-2 text-xs text-gray-600 dark:bg-gray-950 dark:text-gray-400">
                          {JSON.stringify(ev.details, null, 2)}
                        </pre>
                      </details>
                    </td>
                  </tr>
                ))}
                {data.items.length === 0 && (
                  <tr>
                    <td colSpan={4} className="py-10 text-center text-gray-500">
                      No audit events.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="mt-4 flex items-center justify-between text-sm text-gray-500">
            <span>
              {data.total} total events
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="rounded px-3 py-1 hover:bg-gray-200 disabled:opacity-40 dark:hover:bg-gray-800"
              >
                Previous
              </button>
              <button
                type="button"
                onClick={() => setPage((p) => p + 1)}
                disabled={page * pageSize >= data.total}
                className="rounded px-3 py-1 hover:bg-gray-200 disabled:opacity-40 dark:hover:bg-gray-800"
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

/**
 * Case-lead-gated (assert_case_lead_or_admin) member management --
 * add_case_member/remove_case_member (Gap Audit Milestones CCCC-QQQQ)
 * were fully built, tested, and audited on the backend with no frontend
 * UI ever reaching them until now (Milestone RRRR). Adding a member
 * takes a raw Keycloak user id, not a name/email picker -- a case-lead
 * has no org-user-listing access today (GET /api/admin/users is
 * org-admin-only), so this deliberately matches what the API itself has
 * always required rather than opening a new RBAC boundary as part of a
 * UI pass. An org-admin can find a user's id on the Admin page.
 */
function CaseMembersSection({ caseId, memberUserIds }: { caseId: string; memberUserIds: string[] }) {
  const queryClient = useQueryClient()
  const [newMemberId, setNewMemberId] = useState('')

  const addMutation = useMutation({
    mutationFn: (userId: string) => addCaseMember(caseId, userId),
    onSuccess: async () => {
      setNewMemberId('')
      await queryClient.invalidateQueries({ queryKey: ['case', caseId] })
    },
  })

  const removeMutation = useMutation({
    mutationFn: (userId: string) => removeCaseMember(caseId, userId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['case', caseId] })
    },
  })

  return (
    <div className="mb-8 max-w-md">
      <h3 className="mb-4 text-sm font-semibold text-gray-800 dark:text-gray-200">Case Members</h3>
      {memberUserIds.length === 0 ? (
        <p className="mb-3 text-sm text-gray-500">No members added yet.</p>
      ) : (
        <ul className="mb-4 divide-y divide-gray-200 rounded border border-gray-200 dark:divide-gray-800 dark:border-gray-800">
          {memberUserIds.map((userId) => (
            <li key={userId} className="flex items-center justify-between px-3 py-2 text-sm">
              <span className="font-mono text-xs text-gray-600 dark:text-gray-400">{userId}</span>
              <button
                type="button"
                onClick={() => removeMutation.mutate(userId)}
                disabled={removeMutation.isPending}
                className="text-xs text-red-600 hover:underline disabled:opacity-50 dark:text-red-400"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (newMemberId.trim()) addMutation.mutate(newMemberId.trim())
        }}
        className="flex items-center gap-2"
      >
        <label htmlFor={`add-member-${caseId}`} className="sr-only">
          User ID to add
        </label>
        <input
          id={`add-member-${caseId}`}
          type="text"
          value={newMemberId}
          onChange={(e) => setNewMemberId(e.target.value)}
          placeholder="Keycloak user ID (see Admin > Org Users)"
          className="flex-1 rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
        />
        <button
          type="submit"
          disabled={addMutation.isPending || !newMemberId.trim()}
          className="flex items-center gap-2 rounded bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
        >
          {addMutation.isPending && <Spinner size="sm" />}
          Add
        </button>
      </form>
      {addMutation.isError && <ErrorBanner message="Failed to add member." />}
      {removeMutation.isError && <ErrorBanner message="Failed to remove member." />}
    </div>
  )
}

/** Case-lead-gated (assert_case_lead_or_admin) archive -- delete_case is a soft
 * archive (CaseStatus.ARCHIVED), not a row deletion; evidence/audit history
 * both survive it untouched. */
function DeleteCaseSection({ caseId, status }: { caseId: string; status: Case['status'] }) {
  const navigate = useNavigate()
  const [confirming, setConfirming] = useState(false)
  const mutation = useMutation({
    mutationFn: () => deleteCase(caseId),
    onSuccess: () => {
      void navigate({ to: '/cases' })
    },
  })

  if (status === 'archived') {
    return (
      <div className="mb-8 max-w-md">
        <h3 className="mb-2 text-sm font-semibold text-gray-800 dark:text-gray-200">Case Status</h3>
        <p className="text-sm text-gray-500">This case has been archived.</p>
      </div>
    )
  }

  return (
    <div className="mb-8 max-w-md">
      <h3 className="mb-2 text-sm font-semibold text-red-700 dark:text-red-400">Danger Zone</h3>
      {!confirming ? (
        <button
          type="button"
          onClick={() => setConfirming(true)}
          className="rounded border border-red-300 px-4 py-2 text-sm font-medium text-red-700 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
        >
          Delete / Archive Case
        </button>
      ) : (
        <div className="space-y-2">
          <p className="text-sm text-gray-700 dark:text-gray-300">
            Are you sure? This archives the case; evidence and audit history are preserved.
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => mutation.mutate()}
              disabled={mutation.isPending}
              className="flex items-center gap-2 rounded bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-60"
            >
              {mutation.isPending && <Spinner size="sm" />}
              Confirm Delete
            </button>
            <button
              type="button"
              onClick={() => setConfirming(false)}
              className="rounded px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-800"
            >
              Cancel
            </button>
          </div>
          {mutation.isError && <ErrorBanner message="Failed to delete case." />}
        </div>
      )}
    </div>
  )
}

function SettingsTab({ caseData }: { caseData: Case }) {
  const caseId = caseData.id
  const user = useAuthStore((s) => s.user)
  const isAdmin = user?.roles.includes('org-admin') ?? false
  const isOwner = user?.userId === caseData.createdBy
  const canManageCase = isAdmin || isOwner
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['orgSettings'],
    queryFn: getOrgSettings,
    enabled: isAdmin === true,
    staleTime: 60_000,
  })

  const mutation = useMutation({
    mutationFn: updateOrgSettings,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['orgSettings'] })
    },
  })

  if (!canManageCase) {
    return (
      <p className="py-8 text-center text-sm text-gray-500">
        Only this case's lead or an org-admin can manage its settings.
      </p>
    )
  }

  return (
    <div>
      <CaseMembersSection caseId={caseId} memberUserIds={caseData.memberUserIds} />
      <DeleteCaseSection caseId={caseId} status={caseData.status} />
      {isAdmin && (
        <div className="max-w-md">
          {isLoading ? (
            <Spinner className="mt-4" />
          ) : (
            <>
              <h3 className="mb-4 text-sm font-semibold text-gray-800 dark:text-gray-200">Retention Settings</h3>
      {data && (
        <form
          onSubmit={(e) => {
            e.preventDefault()
            const fd = new FormData(e.currentTarget)
            mutation.mutate({
              retentionDays: Number(fd.get('retentionDays')),
              legalHoldDefault: fd.get('legalHoldDefault') === 'on',
            })
          }}
          className="space-y-4"
        >
          <div>
            <label
              className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400"
              htmlFor={`retention-${caseId}`}
            >
              Retention (days)
            </label>
            <input
              id={`retention-${caseId}`}
              name="retentionDays"
              type="number"
              min={1}
              defaultValue={data.retentionDays}
              className="rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
            />
          </div>
          <div className="flex items-center gap-2">
            <input
              id={`legal-hold-${caseId}`}
              name="legalHoldDefault"
              type="checkbox"
              defaultChecked={data.legalHoldDefault}
              className="rounded border-gray-300 bg-white dark:border-gray-600 dark:bg-gray-800"
            />
            <label htmlFor={`legal-hold-${caseId}`} className="text-sm text-gray-700 dark:text-gray-300">
              Legal hold by default
            </label>
          </div>
          <button
            type="submit"
            disabled={mutation.isPending}
            className="flex items-center gap-2 rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
          >
            {mutation.isPending && <Spinner size="sm" />}
            Save
          </button>
          {mutation.isSuccess && (
            <p className="text-xs text-green-600 dark:text-green-400">Saved.</p>
          )}
          {mutation.isError && (
            <ErrorBanner message="Failed to save settings." />
          )}
        </form>
      )}
            </>
          )}
        </div>
      )}
    </div>
  )
}

type Tab = 'evidence' | 'timeline' | 'auditlog' | 'settings'

const tabs: { id: Tab; label: string }[] = [
  { id: 'evidence', label: 'Evidence' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'auditlog', label: 'Audit Log' },
  { id: 'settings', label: 'Settings' },
]

export function CaseDetailPage() {
  const { caseId } = useParams({ from: '/cases/$caseId' })
  const [activeTab, setActiveTab] = useState<Tab>('evidence')

  const { data: caseData, isLoading, error } = useQuery({
    queryKey: ['case', caseId],
    queryFn: () => getCase(caseId),
    staleTime: 30_000,
  })

  if (isLoading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner size="lg" />
      </div>
    )
  }

  if (error || !caseData) {
    return <ErrorBanner message="Failed to load case." />
  }

  return (
    <div>
      <div className="mb-6">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">{caseData.title}</h1>
            {caseData.status === 'archived' && (
              <span className="rounded bg-red-100 px-2 py-0.5 text-xs font-medium text-red-700 dark:bg-red-950 dark:text-red-400">
                Archived
              </span>
            )}
          </div>
          <span className="rounded bg-gray-200 px-2 py-1 font-mono text-xs text-gray-600 dark:bg-gray-800 dark:text-gray-400">
            {caseData.reference}
          </span>
        </div>
        {caseData.description && (
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">{caseData.description}</p>
        )}
      </div>

      <div className="mb-6 border-b border-gray-200 dark:border-gray-800">
        <nav className="flex gap-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'border-b-2 border-indigo-500 text-indigo-600 dark:text-indigo-400'
                  : 'text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {activeTab === 'evidence' && <EvidenceTab caseId={caseId} />}
      {activeTab === 'timeline' && <TimelineTab caseId={caseId} />}
      {activeTab === 'auditlog' && <AuditLogTab caseId={caseId} />}
      {activeTab === 'settings' && <SettingsTab caseData={caseData} />}
    </div>
  )
}
