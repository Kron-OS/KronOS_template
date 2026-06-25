import { useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { requestUpload, finalizeUploadWithHash } from '../api/evidence'
import { Spinner } from './Spinner'
import { ErrorBanner } from './ErrorBanner'

const ALLOWED_EXTENSIONS = new Set([
  'evtx', 'json', 'jsonl', 'csv', 'log', 'gz', 'zip', 'sqlite', 'db',
])

const BLOCKED_EXTENSIONS = new Set([
  'exe', 'dll', 'scr', 'bat', 'cmd', 'ps1', 'js', 'vbs', 'jar', 'msi', 'com',
])

async function computeSHA256(file: File): Promise<string> {
  const buffer = await file.arrayBuffer()
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

async function validateFileMagic(file: File): Promise<{ ok: boolean; reason?: string }> {
  const ext = file.name.split('.').pop()?.toLowerCase() ?? ''

  if (BLOCKED_EXTENSIONS.has(ext)) {
    return { ok: false, reason: `Blocked file type: .${ext}` }
  }

  // Read first 262 bytes for magic byte check
  const slice = file.slice(0, 262)
  const buf = await slice.arrayBuffer()
  const bytes = new Uint8Array(buf)

  // EVTX: ElfFile\x00
  if (
    bytes[0] === 0x45 && bytes[1] === 0x6c && bytes[2] === 0x66 &&
    bytes[3] === 0x46 && bytes[4] === 0x69 && bytes[5] === 0x6c &&
    bytes[6] === 0x65 && bytes[7] === 0x00
  ) {
    return { ok: true }
  }

  // GZIP: \x1f\x8b
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) return { ok: true }

  // ZIP / .zip: PK\x03\x04
  if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
    return { ok: true }
  }

  // SQLite: "SQLite format 3\x00"
  const sqliteMagic = [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00]
  if (sqliteMagic.every((b, i) => bytes[i] === b)) return { ok: true }

  // Prefetch: MAM\x04
  if (bytes[0] === 0x4d && bytes[1] === 0x41 && bytes[2] === 0x4d && bytes[3] === 0x04) {
    return { ok: true }
  }

  // Text-based formats (json, jsonl, csv, log) — check for printable ASCII start
  if (['json', 'jsonl', 'csv', 'log'].includes(ext)) {
    const isText = bytes.slice(0, 8).every((b) => b >= 0x09 && b <= 0x7e)
    if (isText) return { ok: true }
  }

  // MZ header (Windows PE) — always reject
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
    return { ok: false, reason: 'Windows executable files are not accepted' }
  }

  if (!ALLOWED_EXTENSIONS.has(ext)) {
    return { ok: false, reason: `Unsupported extension: .${ext}` }
  }

  return { ok: true }
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

    await Promise.allSettled(
      selected.map(async (file, i) => {
        try {
          await uploadFile(caseId, file, (pct) => {
            setFiles((prev) =>
              prev.map((f, j) => (j === i ? { ...f, progress: pct } : f)),
            )
          })
          setFiles((prev) =>
            prev.map((f, j) => (j === i ? { ...f, progress: 100, done: true } : f)),
          )
        } catch (err) {
          const msg = err instanceof Error ? err.message : 'Upload failed'
          setFiles((prev) =>
            prev.map((f, j) => (j === i ? { ...f, error: msg } : f)),
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
      <div className="w-full max-w-lg rounded-t-lg border border-gray-700 bg-gray-900 p-5 sm:rounded-lg">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-100">Upload Evidence</h2>
          <button
            type="button"
            onClick={handleClose}
            disabled={uploading}
            className="text-lg text-gray-400 hover:text-gray-200 disabled:opacity-40"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <label
          className="mb-4 flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed border-gray-700 bg-gray-800/40 p-8 text-sm text-gray-400 hover:border-indigo-600 hover:text-gray-200"
          htmlFor="evidence-file-input"
        >
          <span>Click to select files</span>
          <span className="text-xs text-gray-600">evtx, json, jsonl, csv, log, gz, zip, sqlite</span>
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
                <div className="mb-1 flex justify-between text-gray-300">
                  <span className="max-w-xs truncate">{f.name}</span>
                  <span className="ml-2 shrink-0">
                    {f.error ? (
                      <span className="text-red-400">{f.error}</span>
                    ) : f.done ? (
                      <span className="text-green-400">Done</span>
                    ) : (
                      <span className="text-gray-500">{f.progress}%</span>
                    )}
                  </span>
                </div>
                <div className="h-1 w-full overflow-hidden rounded-full bg-gray-700">
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
            className="rounded px-4 py-2 text-sm text-gray-400 hover:bg-gray-800 disabled:opacity-40"
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
