import { useEffect, useState } from 'react'
import type { Evidence } from '../types'
import { ErrorCatalogueChip } from './ErrorCatalogue'
import { StatusPill } from './StatusPill'

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
    <div className="flex flex-col gap-0.5 py-2.5 border-b border-gray-800 last:border-0">
      <span className="text-xs font-medium uppercase tracking-wide text-gray-500">{label}</span>
      <span className="text-sm text-gray-200 break-all">{value}</span>
    </div>
  )
}

interface EvidenceDetailDrawerProps {
  evidence: Evidence | null
  onClose: () => void
}

export function EvidenceDetailDrawer({ evidence, onClose }: EvidenceDetailDrawerProps) {
  const [copied, setCopied] = useState(false)

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
        className="fixed right-0 top-0 z-50 flex h-full w-full max-w-md flex-col bg-gray-900 shadow-2xl"
        role="dialog"
        aria-label="Evidence details"
      >
        <div className="flex items-center justify-between border-b border-gray-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-gray-100">Evidence Details</h2>
          <button
            type="button"
            onClick={onClose}
            className="text-lg leading-none text-gray-400 hover:text-gray-200"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4">
          <FieldRow label="Filename" value={evidence.filename} />
          <FieldRow label="Size" value={formatBytes(evidence.sizeBytes)} />
          <FieldRow label="Status" value={<StatusPill state={evidence.state} />} />
          <FieldRow label="Uploaded by" value={evidence.uploadedBy} />
          <FieldRow
            label="Uploaded at"
            value={new Date(evidence.uploadedAt).toLocaleString()}
          />

          <div className="flex flex-col gap-0.5 py-2.5 border-b border-gray-800">
            <span className="text-xs font-medium uppercase tracking-wide text-gray-500">
              SHA-256
            </span>
            <div className="flex items-start gap-2">
              <span className="flex-1 break-all font-mono text-xs text-gray-300">
                {evidence.sha256 ?? 'not yet computed'}
              </span>
              {evidence.sha256 && (
                <button
                  type="button"
                  onClick={() => void copyHash()}
                  className="shrink-0 rounded px-2 py-1 text-xs text-indigo-400 hover:bg-gray-800"
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
                <span className="text-green-400">Present</span>
              ) : (
                <span className="text-gray-500">Not anchored yet</span>
              )
            }
          />

          {evidence.errorReason && (
            <div className="mt-4">
              <ErrorCatalogueChip reasonCode={evidence.errorReason} />
            </div>
          )}
        </div>
      </aside>
    </>
  )
}
