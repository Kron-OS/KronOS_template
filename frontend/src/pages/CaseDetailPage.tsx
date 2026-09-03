import { useState, useEffect } from 'react'
import { useParams, useNavigate } from '@tanstack/react-router'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getCase,
  addCaseMember,
  removeCaseMember,
  deleteCase,
  searchCaseMemberCandidates,
  getCaseArtifacts,
} from '../api/cases'
import { getEvidence, getAuditLog, getDashboardUrl } from '../api/evidence'
import { getOrgSettings, updateOrgSettings } from '../api/admin'
import { StatusPill } from '../components/StatusPill'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import { UploadDrawer } from '../components/UploadDrawer'
import { EvidenceDetailDrawer } from '../components/EvidenceDetailDrawer'
import { ArtifactContent } from '../components/ArtifactViews'
import { MEMORY_DUMP_EXTENSIONS } from '../utils/validateFileMagic'
import { useEvidenceSSE } from '../hooks/useEvidenceSSE'
import { useAuthStore } from '../store/auth'
import { isTrustedDashboardsUrl } from '../utils/dashboardsOrigin'
import type { Case, CaseMemberCandidate, Evidence, AuditEvent, SSEStatusEvent } from '../types'

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

function EvidenceTab({
  caseId,
  onViewArtifacts,
}: {
  caseId: string
  onViewArtifacts: (evidenceId: string) => void
}) {
  const queryClient = useQueryClient()
  const [showUpload, setShowUpload] = useState(false)
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null)
  const { data, isLoading, error } = useQuery({
    queryKey: ['evidence', caseId],
    queryFn: () => getEvidence(caseId),
    staleTime: 15_000,
  })
  // Same query key ArtifactsTab uses -- a real cache hit there (or here,
  // whichever mounts/refetches first), not a second independent fetch.
  const { data: artifacts } = useQuery({
    queryKey: ['artifacts', caseId],
    queryFn: () => getCaseArtifacts(caseId),
    staleTime: 15_000,
  })
  const selectedEvidenceArtifactCount = selectedEvidence
    ? (artifacts ?? []).filter((a) => a.evidenceId === selectedEvidence.id).length
    : 0

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
    // Gap Audit Milestone AAAAA: the artifacts query has its own 15s
    // staleTime -- without this, a user who already had the Evidence tab
    // open before a memory-dump's parse finished would see a stale,
    // artifact-free drawer/tab for up to 15s after the real pipeline
    // actually finished (found live: a fast, compressed real E2E run hit
    // this exact window). Any SSE event for this case is a real signal
    // evidence state changed, cheap enough to invalidate on every one
    // rather than trying to detect "this one specifically produced new
    // artifacts."
    void queryClient.invalidateQueries({ queryKey: ['artifacts', caseId] })
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
        artifactCount={selectedEvidenceArtifactCount}
        onViewArtifacts={() => {
          if (!selectedEvidence) return
          onViewArtifacts(selectedEvidence.id)
          setSelectedEvidence(null)
        }}
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

// Gap Audit Milestone DDDDD: human-readable labels for the real `kind`
// strings VolatilityModule emits (src/external/parsers/volatility.py's own
// `_plugin_to_kind`) -- an unrecognized kind (a future non-Volatility
// module's own) falls back to the raw kind string itself, never blank.
const KIND_LABELS: Record<string, string> = {
  'volatility.pstree': 'Process Tree',
  'volatility.psscan': 'Process List (scan)',
  'volatility.dlllist': 'Loaded DLLs',
  'volatility.cmdline': 'Command Lines',
  'volatility.malfind': 'Suspicious Regions',
  'volatility.filescan': 'Files in Memory',
  'volatility.registry.hivelist': 'Registry Hives',
}

// Clustered the way an analyst actually works a case, not alphabetically --
// "is anything suspicious here" is a different question from "what DLLs did
// this process load," and both are different from "what processes ran."
const KIND_CLUSTERS: { label: string; kinds: string[] }[] = [
  { label: 'Process', kinds: ['volatility.pstree', 'volatility.psscan', 'volatility.cmdline', 'volatility.dlllist'] },
  { label: 'Suspicious', kinds: ['volatility.malfind'] },
  { label: 'Files & Registry', kinds: ['volatility.filescan', 'volatility.registry.hivelist'] },
]

/** Second-level nav within a selected evidence file: a clustered pill strip
 * across the real artifact kinds that file actually produced -- a kind
 * this platform doesn't yet have a cluster entry for (a future module)
 * still renders, grouped under "Other" so it's never silently hidden. */
function ArtifactKindNav({
  kindsPresent,
  selectedKind,
  onSelectKind,
}: {
  kindsPresent: string[]
  selectedKind: string | null
  onSelectKind: (kind: string) => void
}) {
  const clustered = new Set(KIND_CLUSTERS.flatMap((c) => c.kinds))
  const otherKinds = kindsPresent.filter((k) => !clustered.has(k))
  const clusters = [...KIND_CLUSTERS, ...(otherKinds.length > 0 ? [{ label: 'Other', kinds: otherKinds }] : [])]

  return (
    <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2">
      {clusters.map((cluster) => {
        const present = cluster.kinds.filter((k) => kindsPresent.includes(k))
        if (present.length === 0) return null
        return (
          <div key={cluster.label} className="flex items-center gap-1.5">
            <span className="text-[10px] font-medium uppercase tracking-wide text-gray-600 dark:text-gray-400">
              {cluster.label}
            </span>
            {present.map((kind) => (
              <button
                key={kind}
                type="button"
                onClick={() => onSelectKind(kind)}
                className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                  selectedKind === kind
                    ? 'bg-indigo-600 text-white'
                    : 'text-gray-600 hover:bg-gray-200 dark:text-gray-400 dark:hover:bg-gray-800'
                }`}
              >
                {KIND_LABELS[kind] ?? kind}
              </button>
            ))}
          </div>
        )
      })}
    </div>
  )
}

/**
 * Gap Audit Milestone AAAAA: case-level Artifacts view ("scenario 4" of
 * the Volatility-UI design conversation). Groups real StructuredArtifacts
 * by evidence file first (a real, distinct memory dump per evidence_id --
 * never flattened together, see ArtifactRepository.list_by_case's own
 * docstring on why this is case-scoped, not per-evidence), then by kind
 * within a file (e.g. a real pstree tree next to a real psscan table).
 * `focusEvidenceId` (set by EvidenceDetailDrawer's "Open full analysis"
 * link) pre-selects that evidence file's group on arrival. Gap Audit
 * Milestone DDDDD: kind selection is a real second nav level now (see
 * `ArtifactKindNav`), since one file can produce 7+ real kinds.
 */
function ArtifactsTab({
  caseId,
  focusEvidenceId,
}: {
  caseId: string
  focusEvidenceId: string | null
}) {
  const { data: artifacts, isLoading, error } = useQuery({
    queryKey: ['artifacts', caseId],
    queryFn: () => getCaseArtifacts(caseId),
    staleTime: 15_000,
  })
  const { data: evidenceData } = useQuery({
    queryKey: ['evidence', caseId],
    queryFn: () => getEvidence(caseId),
    staleTime: 15_000,
  })

  const evidenceIdsWithArtifacts = Array.from(new Set((artifacts ?? []).map((a) => a.evidenceId)))
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null)

  // Real, live re-selection whenever the drawer's link sends a new focus
  // target -- not just on first mount (a user can open the drawer for a
  // second file, jump again, without leaving this tab in between).
  useEffect(() => {
    if (focusEvidenceId && evidenceIdsWithArtifacts.includes(focusEvidenceId)) {
      setSelectedEvidenceId(focusEvidenceId)
    } else if (!selectedEvidenceId && evidenceIdsWithArtifacts.length > 0) {
      setSelectedEvidenceId(evidenceIdsWithArtifacts[0])
    }
    // Deliberately keyed on focusEvidenceId/artifacts only, not
    // selectedEvidenceId -- this should run once per real focus-target or
    // data change, not fight a user's own manual re-selection below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusEvidenceId, artifacts])

  // Gap Audit Milestone DDDDD: a single evidence file can now produce 7+
  // real artifact kinds (Milestone CCCCC's eager multi-plugin set) instead
  // of the original 1-2 -- stacking every kind's full content vertically
  // (the pre-DDDDD behavior) would push a real "suspicious regions" card
  // off-screen below a 2500-row DLL table. Second nav level: cluster kinds
  // the way an analyst actually works a case (Process / Suspicious /
  // Files & Registry), select one at a time. Computed here (not after the
  // early-return checks below) -- hooks must run unconditionally on every
  // render, and `artifacts` is already safely optional via `?? []`.
  const selectedArtifacts = (artifacts ?? []).filter((a) => a.evidenceId === selectedEvidenceId)
  const kindsPresent = Array.from(new Set(selectedArtifacts.map((a) => a.kind)))
  const [selectedKind, setSelectedKind] = useState<string | null>(null)

  useEffect(() => {
    if (selectedKind && kindsPresent.includes(selectedKind)) return
    setSelectedKind(kindsPresent[0] ?? null)
    // Deliberately keyed on the evidence selection, not kindsPresent's own
    // array identity (recomputed every render) -- only re-pick a default
    // kind when the user actually switches evidence files.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedEvidenceId])

  if (isLoading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner size="lg" />
      </div>
    )
  }
  if (error) return <ErrorBanner message="Failed to load artifacts." />

  if (evidenceIdsWithArtifacts.length === 0) {
    // Gap Audit follow-up (Milestones AAAAA/BBBBB): a real user report --
    // "the volatility analysis result is not available" -- traced to this
    // generic empty state being shown even for a memory dump that DID
    // finish processing (state COMPLETE) but produced zero artifacts,
    // e.g. because volatility3 couldn't identify the image's OS/kernel at
    // all (a real, honest "unsupported/unrecognized memory image" outcome,
    // not a bug in the upload or the tab). Distinguish that case from
    // "nothing uploaded yet" and "still processing" instead of implying
    // the user forgot to upload anything.
    const memoryDumpEvidence = (evidenceData?.items ?? []).filter((e) =>
      MEMORY_DUMP_EXTENSIONS.has(e.filename.split('.').pop()?.toLowerCase() ?? ''),
    )
    const completedWithNoArtifacts = memoryDumpEvidence.filter((e) => e.state === 'COMPLETE')
    const stillProcessing = memoryDumpEvidence.filter(
      (e) => e.state !== 'COMPLETE' && e.state !== 'ERROR',
    )

    if (completedWithNoArtifacts.length > 0) {
      return (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-gray-200 py-16 text-sm text-gray-500 dark:border-gray-800">
          <p>No process data could be recovered from the uploaded memory dump.</p>
          <p className="max-w-md text-center text-xs text-gray-400 dark:text-gray-600">
            {completedWithNoArtifacts.map((e) => e.filename).join(', ')} finished processing, but
            memory analysis found nothing usable -- the image's OS/kernel structures may be
            unrecognized or unsupported. Check the Audit tab for this evidence for the real
            underlying error.
          </p>
        </div>
      )
    }
    if (stillProcessing.length > 0) {
      return (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-gray-200 py-16 text-sm text-gray-500 dark:border-gray-800">
          <p>Memory analysis is still in progress.</p>
          <p className="text-xs text-gray-400 dark:text-gray-600">
            {stillProcessing.map((e) => e.filename).join(', ')} hasn't finished parsing yet.
          </p>
        </div>
      )
    }
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-gray-200 py-16 text-sm text-gray-500 dark:border-gray-800">
        <p>No forensic artifacts yet.</p>
        <p className="text-xs text-gray-400 dark:text-gray-600">
          Upload a memory dump (.vmem/.mem/.raw/.dmp/.lime) to see process analysis here.
        </p>
      </div>
    )
  }

  const filenameFor = (evidenceId: string): string =>
    evidenceData?.items.find((e) => e.id === evidenceId)?.filename ?? evidenceId

  const selectedKindArtifacts = selectedArtifacts.filter((a) => a.kind === selectedKind)
  // Multiple StructuredArtifact rows can share one kind (ArtifactIngestService's
  // own size-cap-driven batching, src/application/artifact_ingest.py) --
  // that's a storage implementation detail, not something the UI should
  // expose as separate sections. Merge their rows into one view.
  const mergedArtifact =
    selectedKindArtifacts.length > 0
      ? {
          ...selectedKindArtifacts[0],
          content: {
            ...selectedKindArtifacts[0].content,
            rows: selectedKindArtifacts.flatMap((a) =>
              Array.isArray(a.content.rows) ? a.content.rows : [],
            ),
          } as Record<string, unknown>,
        }
      : null

  return (
    <div className="flex gap-6">
      <nav className="w-56 shrink-0">
        <ul className="flex flex-col gap-1">
          {evidenceIdsWithArtifacts.map((evidenceId) => (
            <li key={evidenceId}>
              <button
                type="button"
                onClick={() => setSelectedEvidenceId(evidenceId)}
                className={`w-full truncate rounded px-3 py-2 text-left text-sm ${
                  selectedEvidenceId === evidenceId
                    ? 'bg-indigo-100 font-medium text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300'
                    : 'text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800'
                }`}
                title={filenameFor(evidenceId)}
              >
                {filenameFor(evidenceId)}
              </button>
            </li>
          ))}
        </ul>
      </nav>
      <div className="min-w-0 flex-1">
        <ArtifactKindNav
          kindsPresent={kindsPresent}
          selectedKind={selectedKind}
          onSelectKind={setSelectedKind}
        />
        {mergedArtifact && (
          <div>
            <h3 className="mb-2 text-sm font-semibold text-gray-800 dark:text-gray-200">
              {KIND_LABELS[mergedArtifact.kind] ?? mergedArtifact.kind}
              {typeof mergedArtifact.content.plugin === 'string' && (
                <span className="ml-2 font-mono text-xs font-normal text-gray-500">
                  ({mergedArtifact.content.plugin})
                </span>
              )}
            </h3>
            <ArtifactContent artifact={mergedArtifact} />
          </div>
        )}
      </div>
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
 * UI ever reaching them until Milestone RRRR, which shipped with a
 * deliberate v1 gap: adding a member took a raw Keycloak user id, since a
 * case-lead had no org-user-listing access at all (GET /api/admin/users
 * is org-admin-only).
 *
 * Gap Audit Milestone ZZZZ: closes that gap with a genuinely new, narrow
 * RBAC surface rather than widening the existing org-admin-only listing
 * -- GET /{case_id}/member-candidates (src/external/routes/cases.py) is
 * gated by the exact same assert_case_lead_or_admin check this section's
 * own Add/Remove actions already use, so a case-lead only ever sees this
 * slice of the org directory for a case they actually lead.
 */
function CaseMembersSection({ caseId, memberUserIds }: { caseId: string; memberUserIds: string[] }) {
  const queryClient = useQueryClient()
  const [searchInput, setSearchInput] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(searchInput.trim()), 300)
    return () => clearTimeout(timer)
  }, [searchInput])

  const { data: candidates, isFetching: isSearching } = useQuery({
    queryKey: ['caseMemberCandidates', caseId, debouncedQuery],
    queryFn: () => searchCaseMemberCandidates(caseId, debouncedQuery),
    enabled: debouncedQuery.length > 0,
  })

  const addMutation = useMutation({
    mutationFn: (userId: string) => addCaseMember(caseId, userId),
    onSuccess: async () => {
      setSearchInput('')
      setDebouncedQuery('')
      await queryClient.invalidateQueries({ queryKey: ['case', caseId] })
    },
  })

  const removeMutation = useMutation({
    mutationFn: (userId: string) => removeCaseMember(caseId, userId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['case', caseId] })
    },
  })

  // Already-added members don't need to be offered again -- the backend
  // treats a re-add as a harmless no-op, but hiding them keeps the
  // picker's own list meaningfully "who's left to add."
  const suggestions: CaseMemberCandidate[] = (candidates ?? []).filter(
    (c) => !memberUserIds.includes(c.userId),
  )

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
      <label htmlFor={`add-member-search-${caseId}`} className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">
        Add a member -- search by name or email
      </label>
      <div className="relative">
        <input
          id={`add-member-search-${caseId}`}
          type="text"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder="Start typing a name or email..."
          className="w-full rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
        />
        {isSearching && (
          <div className="absolute right-3 top-1/2 -translate-y-1/2">
            <Spinner size="sm" />
          </div>
        )}
        {debouncedQuery.length > 0 && !isSearching && (
          <ul className="mt-1 max-h-48 divide-y divide-gray-200 overflow-y-auto rounded border border-gray-200 bg-white shadow-sm dark:divide-gray-800 dark:border-gray-800 dark:bg-gray-900">
            {suggestions.length === 0 && (
              <li className="px-3 py-2 text-sm text-gray-500">No matching org members found.</li>
            )}
            {suggestions.map((candidate) => (
              <li key={candidate.userId} className="flex items-center justify-between px-3 py-2 text-sm">
                <span>
                  <span className="text-gray-800 dark:text-gray-200">{candidate.username}</span>{' '}
                  <span className="text-xs text-gray-500">{candidate.email}</span>
                </span>
                <button
                  type="button"
                  onClick={() => addMutation.mutate(candidate.userId)}
                  disabled={addMutation.isPending}
                  className="rounded bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
                >
                  Add
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
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
  const queryClient = useQueryClient()
  const [confirming, setConfirming] = useState(false)
  const mutation = useMutation({
    mutationFn: () => deleteCase(caseId),
    onSuccess: async () => {
      // Real, found-live bug (Milestone SSSS): the cases list's own
      // useQuery has a 30s staleTime, so without this the /cases page
      // this navigate() lands on kept serving its pre-archive cached
      // data -- the real archive succeeded server-side, but the list a
      // user actually saw right after confirming didn't reflect it.
      await queryClient.invalidateQueries({ queryKey: ['cases'] })
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

type Tab = 'evidence' | 'artifacts' | 'timeline' | 'auditlog' | 'settings'

const tabs: { id: Tab; label: string }[] = [
  { id: 'evidence', label: 'Evidence' },
  { id: 'artifacts', label: 'Artifacts' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'auditlog', label: 'Audit Log' },
  { id: 'settings', label: 'Settings' },
]

export function CaseDetailPage() {
  const { caseId } = useParams({ from: '/cases/$caseId' })
  const [activeTab, setActiveTab] = useState<Tab>('evidence')
  // Gap Audit Milestone AAAAA: set by EvidenceDetailDrawer's "Open full
  // analysis" link (via EvidenceTab's onViewArtifacts callback) so
  // ArtifactsTab arrives pre-selected to that evidence file.
  const [artifactsFocusEvidenceId, setArtifactsFocusEvidenceId] = useState<string | null>(null)

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

      {activeTab === 'evidence' && (
        <EvidenceTab
          caseId={caseId}
          onViewArtifacts={(evidenceId) => {
            setArtifactsFocusEvidenceId(evidenceId)
            setActiveTab('artifacts')
          }}
        />
      )}
      {activeTab === 'artifacts' && (
        <ArtifactsTab caseId={caseId} focusEvidenceId={artifactsFocusEvidenceId} />
      )}
      {activeTab === 'timeline' && <TimelineTab caseId={caseId} />}
      {activeTab === 'auditlog' && <AuditLogTab caseId={caseId} />}
      {activeTab === 'settings' && <SettingsTab caseData={caseData} />}
    </div>
  )
}
