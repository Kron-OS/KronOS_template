import { useState, useEffect } from 'react'
import { useParams } from '@tanstack/react-router'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getCase } from '../api/cases'
import { getEvidence, getAuditLog } from '../api/evidence'
import { getOrgSettings, updateOrgSettings } from '../api/admin'
import { StatusPill } from '../components/StatusPill'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import { UploadDrawer } from '../components/UploadDrawer'
import { useEvidenceSSE } from '../hooks/useEvidenceSSE'
import { useAuthStore } from '../store/auth'
import type { Evidence, AuditEvent, SSEStatusEvent, SSEErrorEvent } from '../types'

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
  const { data, isLoading, error } = useQuery({
    queryKey: ['evidence', caseId],
    queryFn: () => getEvidence(caseId),
    staleTime: 15_000,
  })

  const handleSSEEvent = (event: SSEStatusEvent | SSEErrorEvent) => {
    if ('status' in event) {
      queryClient.setQueryData<{ items: Evidence[] }>(
        ['evidence', caseId],
        (old) => {
          if (!old) return old
          return {
            ...old,
            items: old.items.map((e) =>
              e.id === event.evidenceId ? { ...e, state: event.status } : e,
            ),
          }
        },
      )
    }
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
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 bg-gray-900/50 text-left text-xs text-gray-400">
                <th className="px-4 py-3 font-medium">Filename</th>
                <th className="px-4 py-3 font-medium">Size</th>
                <th className="px-4 py-3 font-medium">SHA-256</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Uploader</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {data.items.map((ev) => (
                <tr key={ev.id} className="hover:bg-gray-900/40">
                  <td className="max-w-xs truncate px-4 py-3 font-mono text-gray-200">
                    {ev.filename}
                  </td>
                  <td className="px-4 py-3 text-gray-400">{formatBytes(ev.sizeBytes)}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-500">
                    {truncateHash(ev.sha256)}
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill state={ev.state} />
                  </td>
                  <td className="px-4 py-3 text-gray-400">{ev.uploadedBy}</td>
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
    </div>
  )
}

function TimelineTab() {
  return (
    <div className="flex h-64 items-center justify-center rounded-lg border border-gray-800 text-sm text-gray-500">
      Configure OpenSearch Dashboards URL in settings to embed the timeline view.
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
          <div className="overflow-x-auto rounded-lg border border-gray-800">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 bg-gray-900/50 text-left text-xs text-gray-400">
                  <th className="px-4 py-3 font-medium">Event</th>
                  <th className="px-4 py-3 font-medium">User</th>
                  <th className="px-4 py-3 font-medium">Timestamp</th>
                  <th className="px-4 py-3 font-medium">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {data.items.map((ev: AuditEvent) => (
                  <tr key={ev.id} className="hover:bg-gray-900/40">
                    <td className="px-4 py-3 font-mono text-xs text-indigo-300">{ev.eventType}</td>
                    <td className="px-4 py-3 text-gray-400">{ev.userId}</td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {new Date(ev.occurredAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <details>
                        <summary className="cursor-pointer text-xs text-gray-500 hover:text-gray-300">
                          view
                        </summary>
                        <pre className="mt-1 max-w-xs overflow-auto rounded bg-gray-950 p-2 text-xs text-gray-400">
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
                className="rounded px-3 py-1 hover:bg-gray-800 disabled:opacity-40"
              >
                Previous
              </button>
              <button
                type="button"
                onClick={() => setPage((p) => p + 1)}
                disabled={page * pageSize >= data.total}
                className="rounded px-3 py-1 hover:bg-gray-800 disabled:opacity-40"
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

function SettingsTab({ caseId }: { caseId: string }) {
  const user = useAuthStore((s) => s.user)
  const isAdmin = user?.roles.includes('org-admin')
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

  if (!isAdmin) {
    return (
      <p className="py-8 text-center text-sm text-gray-500">
        Only org-admins can view settings.
      </p>
    )
  }

  if (isLoading) return <Spinner className="mx-auto mt-8" />

  return (
    <div className="max-w-md">
      <h3 className="mb-4 text-sm font-semibold text-gray-200">Retention Settings</h3>
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
            <label className="mb-1 block text-xs font-medium text-gray-400" htmlFor={`retention-${caseId}`}>
              Retention (days)
            </label>
            <input
              id={`retention-${caseId}`}
              name="retentionDays"
              type="number"
              min={1}
              defaultValue={data.retentionDays}
              className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-2">
            <input
              id={`legal-hold-${caseId}`}
              name="legalHoldDefault"
              type="checkbox"
              defaultChecked={data.legalHoldDefault}
              className="rounded border-gray-600 bg-gray-800"
            />
            <label htmlFor={`legal-hold-${caseId}`} className="text-sm text-gray-300">
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
            <p className="text-xs text-green-400">Saved.</p>
          )}
          {mutation.isError && (
            <ErrorBanner message="Failed to save settings." />
          )}
        </form>
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
          <h1 className="text-xl font-bold text-gray-100">{caseData.title}</h1>
          <span className="rounded bg-gray-800 px-2 py-1 font-mono text-xs text-gray-400">
            {caseData.reference}
          </span>
        </div>
        {caseData.description && (
          <p className="mt-1 text-sm text-gray-400">{caseData.description}</p>
        )}
      </div>

      <div className="mb-6 border-b border-gray-800">
        <nav className="flex gap-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'border-b-2 border-indigo-500 text-indigo-400'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {activeTab === 'evidence' && <EvidenceTab caseId={caseId} />}
      {activeTab === 'timeline' && <TimelineTab />}
      {activeTab === 'auditlog' && <AuditLogTab caseId={caseId} />}
      {activeTab === 'settings' && <SettingsTab caseId={caseId} />}
    </div>
  )
}
