import { useState } from 'react'
import { useUploadsStore } from '../store/uploads'
import { BLOCKED_EXTENSIONS } from '../utils/validateFileMagic'
import { Spinner } from './Spinner'
import { ErrorBanner } from './ErrorBanner'

// Milestone: minimizable uploads. This drawer no longer owns any upload
// progress state itself (moved to store/uploads.ts, which keeps driving
// the real upload regardless of whether this component is mounted) --
// it's a thin, globally-mounted view over that store (see Layout.tsx).
// Local state remains only for files staged before "Upload" is clicked,
// which is inherently transient and doesn't need to survive minimize.
export function UploadDrawer() {
  const activeCaseId = useUploadsStore((s) => s.activeCaseId)
  const drawerOpen = useUploadsStore((s) => s.drawerOpen)
  const minimized = useUploadsStore((s) => s.minimized)
  const jobs = useUploadsStore((s) => s.jobs)
  const minimize = useUploadsStore((s) => s.minimize)
  const closeDrawer = useUploadsStore((s) => s.closeDrawer)
  const enqueueFiles = useUploadsStore((s) => s.enqueueFiles)

  const [stagedFiles, setStagedFiles] = useState<File[]>([])
  const [globalError, setGlobalError] = useState<string | null>(null)

  // Real, hard E2E constraint (frontend/e2e/pages/CaseDetailPage.ts's
  // uploadEvidence() asserts #evidence-file-input fully detaches from the
  // DOM once closed) -- minimized must unmount exactly like closed does,
  // not just hide visually.
  if (!drawerOpen || minimized || !activeCaseId) return null

  const caseJobs = jobs.filter((j) => j.caseId === activeCaseId)
  const uploading = caseJobs.some((j) => j.status === 'uploading')
  // Newly staged (not-yet-uploaded) files take priority over a PRIOR
  // batch's finished/errored jobs for this case -- otherwise picking a new
  // batch after one finishes would keep silently showing the old one until
  // Upload is clicked again.
  const displayItems =
    stagedFiles.length > 0 && !uploading
      ? stagedFiles.map((f) => ({ key: f.name, name: f.name, progress: 0, error: null, done: false }))
      : caseJobs.map((j) => ({
          key: j.id,
          name: j.filename,
          progress: j.progress,
          error: j.error,
          done: j.status === 'done',
        }))

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = Array.from(e.target.files ?? [])
    const blocked = selected.filter((f) => {
      const ext = f.name.split('.').pop()?.toLowerCase() ?? ''
      return BLOCKED_EXTENSIONS.has(ext)
    })
    if (blocked.length > 0) {
      setGlobalError(`Blocked file type(s): ${blocked.map((f) => f.name).join(', ')}`)
      e.target.value = ''
      return
    }
    setGlobalError(null)
    setStagedFiles(selected)
  }

  async function handleUpload() {
    if (stagedFiles.length === 0 || !activeCaseId) return
    setGlobalError(null)
    const files = stagedFiles
    setStagedFiles([])
    await enqueueFiles(activeCaseId, files)
  }

  return (
    <div className="fixed inset-0 z-40 flex items-end justify-center bg-black/60 sm:items-center">
      <div className="w-full max-w-lg rounded-t-lg border border-gray-300 bg-white p-5 dark:border-gray-700 dark:bg-gray-900 sm:rounded-lg">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-900 dark:text-gray-100">Upload Evidence</h2>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={minimize}
              className="text-lg leading-none text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200"
              aria-label="Minimize"
              title="Minimize (upload keeps running)"
            >
              &#9472;
            </button>
            <button
              type="button"
              onClick={closeDrawer}
              disabled={uploading}
              className="text-lg text-gray-600 hover:text-gray-900 disabled:opacity-40 dark:text-gray-400 dark:hover:text-gray-200"
              aria-label="Close"
            >
              ×
            </button>
          </div>
        </div>

        <label
          className="mb-4 flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed border-gray-300 bg-gray-100/60 p-8 text-sm text-gray-600 hover:border-indigo-600 hover:text-gray-900 dark:border-gray-700 dark:bg-gray-800/40 dark:text-gray-400 dark:hover:text-gray-200"
          htmlFor="evidence-file-input"
        >
          <span>Click to select files</span>
          <span className="text-xs text-gray-500 dark:text-gray-600">
            evtx, json, jsonl, csv, log, txt, gz, zip, sqlite, dat, hve, hiv, pf, E01
          </span>
          <input
            id="evidence-file-input"
            type="file"
            multiple
            className="sr-only"
            onChange={handleFileChange}
          />
        </label>

        {globalError && (
          <div className="mb-4">
            <ErrorBanner message={globalError} />
          </div>
        )}

        {displayItems.length > 0 && (
          <ul className="mb-4 space-y-2">
            {displayItems.map((f) => (
              <li key={f.key} className="text-xs">
                <div className="mb-1 flex justify-between text-gray-700 dark:text-gray-300">
                  <span className="max-w-xs truncate">{f.name}</span>
                  <span className="ml-2 shrink-0">
                    {f.error ? (
                      <span className="text-red-600 dark:text-red-400">{f.error}</span>
                    ) : f.done ? (
                      <span className="text-green-600 dark:text-green-400">Done</span>
                    ) : (
                      <span className="text-gray-500">{f.progress}%</span>
                    )}
                  </span>
                </div>
                <div className="h-1 w-full overflow-hidden rounded-full bg-gray-300 dark:bg-gray-700">
                  <div
                    className={`h-1 rounded-full transition-all ${f.error ? 'bg-red-500' : f.done ? 'bg-green-500' : 'bg-indigo-500'}`}
                    style={{ width: `${f.progress}%` }}
                  />
                </div>
              </li>
            ))}
          </ul>
        )}

        <div className="flex justify-end gap-3">
          <button
            type="button"
            onClick={closeDrawer}
            disabled={uploading}
            className="rounded px-4 py-2 text-sm text-gray-600 hover:bg-gray-200 disabled:opacity-40 dark:text-gray-400 dark:hover:bg-gray-800"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleUpload}
            disabled={uploading || stagedFiles.length === 0}
            className="flex items-center gap-2 rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
          >
            {uploading && <Spinner size="sm" />}
            Upload
          </button>
        </div>
      </div>
    </div>
  )
}
