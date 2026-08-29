import { useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { requestUpload, finalizeUploadWithHash } from '../api/evidence'
import { validateFileMagic, BLOCKED_EXTENSIONS } from '../utils/validateFileMagic'
import { Spinner } from './Spinner'
import { ErrorBanner } from './ErrorBanner'

async function computeSHA256(file: File): Promise<string> {
  const buffer = await file.arrayBuffer()
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

interface FileProgress {
  name: string
  progress: number
  error: string | null
  done: boolean
}

interface UploadDrawerProps {
  caseId: string
  open: boolean
  onClose: () => void
}

async function uploadFile(
  caseId: string,
  file: File,
  onProgress: (pct: number) => void,
): Promise<void> {
  const validation = await validateFileMagic(file)
  if (!validation.ok) {
    throw new Error(validation.reason ?? 'File rejected by pre-check')
  }

  const sha256 = await computeSHA256(file)

  const upload = await requestUpload(
    caseId,
    file.name,
    file.type || 'application/octet-stream',
    file.size,
  )

  await new Promise<void>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('PUT', upload.presignedUrl)
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100))
    }
    xhr.onload = () => (xhr.status < 400 ? resolve() : reject(new Error(`HTTP ${xhr.status}`)))
    xhr.onerror = () => reject(new Error('Network error'))
    xhr.send(file)
  })

  await finalizeUploadWithHash(upload.evidenceId, sha256)
  // Parsing is auto-triggered by the backend pipeline after finalization.
  // No client-side parse/start call needed.
}

export function UploadDrawer({ caseId, open, onClose }: UploadDrawerProps) {
  const queryClient = useQueryClient()
  const inputRef = useRef<HTMLInputElement>(null)
  const [files, setFiles] = useState<FileProgress[]>([])
  const [uploading, setUploading] = useState(false)
  const [globalError, setGlobalError] = useState<string | null>(null)

  function handleClose() {
    if (!uploading) {
      setFiles([])
      setGlobalError(null)
      onClose()
    }
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = Array.from(e.target.files ?? [])
    const blocked = selected.filter((f) => {
      const ext = f.name.split('.').pop()?.toLowerCase() ?? ''
      return BLOCKED_EXTENSIONS.has(ext)
    })
    if (blocked.length > 0) {
      setGlobalError(
        `Blocked file type(s): ${blocked.map((f) => f.name).join(', ')}`,
      )
      e.target.value = ''
      return
    }
    setGlobalError(null)
    setFiles(selected.map((f) => ({ name: f.name, progress: 0, error: null, done: false })))
  }

  async function handleUpload() {
    const selected = Array.from(inputRef.current?.files ?? [])
    if (selected.length === 0) return

    setUploading(true)
    setGlobalError(null)
    setFiles((prev) => prev.map((f) => ({ ...f, error: null })))

    await Promise.allSettled(
      selected.map(async (file, i) => {
        try {
          await uploadFile(caseId, file, (pct) => {
            setFiles((prev) =>
              prev.map((f, j) => (j === i ? { ...f, progress: pct, error: null } : f)),
            )
          })
          setFiles((prev) =>
            prev.map((f, j) => (j === i ? { ...f, progress: 100, done: true, error: null } : f)),
          )
        } catch (err) {
          const msg = err instanceof Error ? err.message : 'Upload failed'
          setFiles((prev) =>
            prev.map((f, j) => (j === i ? { ...f, error: msg, done: false } : f)),
          )
        }
      }),
    )

    await queryClient.invalidateQueries({ queryKey: ['evidence', caseId] })
    setUploading(false)
  }

  if (!open) return null

  return (
    <div className="fixed inset-0 z-40 flex items-end justify-center bg-black/60 sm:items-center">
      <div className="w-full max-w-lg rounded-t-lg border border-gray-300 bg-white p-5 dark:border-gray-700 dark:bg-gray-900 sm:rounded-lg">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-900 dark:text-gray-100">Upload Evidence</h2>
          <button
            type="button"
            onClick={handleClose}
            disabled={uploading}
            className="text-lg text-gray-600 hover:text-gray-900 disabled:opacity-40 dark:text-gray-400 dark:hover:text-gray-200"
            aria-label="Close"
          >
            ×
          </button>
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
            ref={inputRef}
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

        {files.length > 0 && (
          <ul className="mb-4 space-y-2">
            {files.map((f, i) => (
              <li key={i} className="text-xs">
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
            onClick={handleClose}
            disabled={uploading}
            className="rounded px-4 py-2 text-sm text-gray-600 hover:bg-gray-200 disabled:opacity-40 dark:text-gray-400 dark:hover:bg-gray-800"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleUpload}
            disabled={uploading || files.length === 0}
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
