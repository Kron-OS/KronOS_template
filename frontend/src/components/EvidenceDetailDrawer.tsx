import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { Evidence } from '../types'
import { downloadEvidence, retryIntake, retryParse } from '../api/evidence'
import { ErrorCatalogueChip } from './ErrorCatalogue'
import { Spinner } from './Spinner'
import { StatusPill } from './StatusPill'
import { MEMORY_DUMP_EXTENSIONS } from '../utils/validateFileMagic'

// Mirrors the backend's own "not yet promoted" check
// (src/external/routes/cases.py::download_evidence -- 404s when
// evidence.minio_evidence_key is None): the object is only ever promoted
// to the real evidence bucket once hashing has completed.
const DOWNLOAD_NOT_YET_AVAILABLE_STATES: ReadonlySet<Evidence['state']> = new Set([
  'UPLOADING',
  'SCANNING',
  'HASHING',
])

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

interface FieldRowProps {
  label: string
  value: React.ReactNode
}

function FieldRow({ label, value }: FieldRowProps) {
  return (
    <div className="flex flex-col gap-0.5 border-b border-gray-200 py-2.5 last:border-0 dark:border-gray-800">
      <span className="text-xs font-medium uppercase tracking-wide text-gray-500">{label}</span>
      <span className="text-sm text-gray-800 break-all dark:text-gray-200">{value}</span>
    </div>
  )
}

interface EvidenceDetailDrawerProps {
  evidence: Evidence | null
  onClose: () => void
  // Gap Audit Milestone AAAAA: the "hybrid" scenario -- a compact summary
  // here, a link to the full case-level Artifacts tab (pre-filtered to
  // this evidence file) rather than trying to render a real process
  // tree/table inside this narrow (max-w-md) drawer. Both optional so
  // every existing caller (none currently pass them) keeps working.
  artifactCount?: number
  onViewArtifacts?: () => void
}

export function EvidenceDetailDrawer({
  evidence,
  onClose,
  artifactCount = 0,
  onViewArtifacts,
}: EvidenceDetailDrawerProps) {
  const [copied, setCopied] = useState(false)
  const queryClient = useQueryClient()

  const retryMutation = useMutation({
    mutationFn: (evidenceId: string) =>
      evidence?.retryAction === 'parse' ? retryParse(evidenceId) : retryIntake(evidenceId),
    onSuccess: (_result, _evidenceId) => {
      if (evidence) {
        void queryClient.invalidateQueries({ queryKey: ['evidence', evidence.caseId] })
        // Real bug found via frontend/e2e/evidence-retry.spec.ts (Gap Audit
        // 2026-08-28): useEvidenceSSE closes its stream once evidence first
        // reaches a terminal state (ERROR included) and never reopens it --
        // a successful retry un-terminates evidence server-side with no
        // client-side signal to reconnect, so the UI froze on the stale
        // ERROR state even though the backend genuinely completed. This
        // reuses the same CustomEvent bridge the polling fallback already
        // established (`kronos:sse-poll`) to tell useEvidenceSSE to
        // reconnect with a fresh ticket.
        window.dispatchEvent(new CustomEvent('kronos:sse-reconnect', { detail: { caseId: evidence.caseId } }))
      }
    },
  })

  const downloadMutation = useMutation({
    mutationFn: () => {
      if (!evidence) return Promise.resolve()
      return downloadEvidence(evidence.caseId, evidence.id, evidence.filename)
    },
  })

  useEffect(() => {
    if (!evidence) return
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [evidence, onClose])

  if (!evidence) return null

  async function copyHash() {
    if (!evidence?.sha256) return
    await navigator.clipboard.writeText(evidence.sha256)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-black/50"
        onClick={onClose}
        aria-hidden="true"
      />
      <aside
        className="fixed right-0 top-0 z-50 flex h-full w-full max-w-md flex-col bg-white shadow-2xl dark:bg-gray-900"
        role="dialog"
        aria-label="Evidence details"
      >
        <div className="flex items-center justify-between border-b border-gray-200 px-5 py-4 dark:border-gray-800">
          <h2 className="text-sm font-semibold text-gray-900 dark:text-gray-100">Evidence Details</h2>
          <button
            type="button"
            onClick={onClose}
            className="text-lg leading-none text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4">
          <FieldRow label="Filename" value={evidence.filename} />
          <FieldRow label="Size" value={formatBytes(evidence.sizeBytes)} />
          <FieldRow
            label="Status"
            value={
              <div className="flex items-center gap-2">
                <StatusPill state={evidence.state} />
                {!DOWNLOAD_NOT_YET_AVAILABLE_STATES.has(evidence.state) && (
                  <button
                    type="button"
                    onClick={() => downloadMutation.mutate()}
                    disabled={downloadMutation.isPending}
                    className="flex items-center gap-1.5 rounded px-2 py-1 text-xs font-medium text-indigo-600 hover:bg-gray-200 disabled:opacity-60 dark:text-indigo-400 dark:hover:bg-gray-800"
                  >
                    {downloadMutation.isPending && <Spinner size="sm" />}
                    Download
                  </button>
                )}
              </div>
            }
          />
          {downloadMutation.isError && (
            <p className="pb-2 text-xs text-red-600 dark:text-red-400">
              Download failed — the original file may not be available yet.
            </p>
          )}
          <FieldRow label="Uploaded by" value={evidence.uploadedBy} />
          <FieldRow
            label="Uploaded at"
            value={new Date(evidence.uploadedAt).toLocaleString()}
          />

          <div className="flex flex-col gap-0.5 border-b border-gray-200 py-2.5 dark:border-gray-800">
            <span className="text-xs font-medium uppercase tracking-wide text-gray-500">
              SHA-256
            </span>
            <div className="flex items-start gap-2">
              <span className="flex-1 break-all font-mono text-xs text-gray-700 dark:text-gray-300">
                {evidence.sha256 ?? 'not yet computed'}
              </span>
              {evidence.sha256 && (
                <button
                  type="button"
                  onClick={() => void copyHash()}
                  className="shrink-0 rounded px-2 py-1 text-xs text-indigo-600 hover:bg-gray-200 dark:text-indigo-400 dark:hover:bg-gray-800"
                >
                  {copied ? 'Copied' : 'Copy'}
                </button>
              )}
            </div>
          </div>

          <FieldRow
            label="RFC 3161 timestamp"
            value={
              evidence.rfc3161Token ? (
                <span className="text-green-600 dark:text-green-400">Present</span>
              ) : (
                <span className="text-gray-500">Not anchored yet</span>
              )
            }
          />

          {artifactCount > 0 && onViewArtifacts && (
            <FieldRow
              label="Forensic artifacts"
              value={
                <div className="flex items-center justify-between gap-2">
                  <span>
                    {artifactCount} artifact{artifactCount === 1 ? '' : 's'} found
                  </span>
                  <button
                    type="button"
                    onClick={onViewArtifacts}
                    className="shrink-0 text-xs font-medium text-indigo-600 hover:underline dark:text-indigo-400"
                  >
                    Open full analysis →
                  </button>
                </div>
              }
            />
          )}
          {artifactCount === 0 &&
            evidence.state === 'COMPLETE' &&
            MEMORY_DUMP_EXTENSIONS.has(evidence.filename.split('.').pop()?.toLowerCase() ?? '') && (
              // Real user report, Gap Audit Milestone BBBBB follow-up: this
              // row was previously hidden entirely whenever artifactCount
              // was 0 -- indistinguishable here from "not a memory dump at
              // all," even though this evidence file genuinely finished
              // memory analysis and found nothing. The Artifacts tab
              // itself already got an honest message for this same case
              // (CaseDetailPage.tsx's ArtifactsTab); this drawer -- the
              // first place a user actually looks -- still showed nothing.
              <FieldRow
                label="Forensic artifacts"
                value={
                  <span className="text-gray-500">
                    No process data could be recovered from this memory image.
                  </span>
                }
              />
            )}

          {evidence.errorReason && (
            <div className="mt-4 flex flex-col gap-2">
              <ErrorCatalogueChip reasonCode={evidence.errorReason} />
              {evidence.retryAction && (
                <button
                  type="button"
                  onClick={() => retryMutation.mutate(evidence.id)}
                  disabled={retryMutation.isPending}
                  className="flex w-fit items-center gap-2 rounded bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
                >
                  {retryMutation.isPending && <Spinner size="sm" />}
                  Retry
                </button>
              )}
              {retryMutation.isError && (
                <span className="text-xs text-red-600 dark:text-red-400">
                  Retry failed — please try again.
                </span>
              )}
            </div>
          )}
        </div>
      </aside>
    </>
  )
}
