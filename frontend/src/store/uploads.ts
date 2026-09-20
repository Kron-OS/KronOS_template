import { sha256 } from '@noble/hashes/sha2.js'
import { create } from 'zustand'
import { requestUpload, finalizeUploadWithHash } from '../api/evidence'
import { validateFileMagic } from '../utils/validateFileMagic'
import { queryClient } from '../lib/queryClient'

export interface UploadJob {
  id: string
  caseId: string
  filename: string
  progress: number
  status: 'uploading' | 'done' | 'error'
  error: string | null
}

interface UploadsState {
  activeCaseId: string | null
  drawerOpen: boolean
  minimized: boolean
  jobs: UploadJob[]
  openDrawer: (caseId: string) => void
  minimize: () => void
  closeDrawer: () => void
  enqueueFiles: (
    caseId: string,
    files: File[],
    declaredFormat?: 'memory_dump',
  ) => Promise<void>
}

// Real bug this replaced: `crypto.subtle.digest()` over a single
// `file.arrayBuffer()` call needs the ENTIRE file materialized as one
// in-memory ArrayBuffer -- for a multi-GB memory dump (this platform's
// own memory-forensics use case) that silently produces a hash over
// truncated/corrupted bytes well before any browser OOM error surfaces,
// while the actual PUT below (`xhr.send(file)`) streams the real, full
// file straight from disk without ever going through that buffer. The
// two diverge, and the server's real streamed-from-storage hash
// (`_run_hash`, src/application/evidence_intake.py) never matches the
// declared one -- a real, reproduced `hash_mismatch` on every large-file
// upload, not an intermittent fluke. Fixed by hashing in fixed-size
// chunks via an incremental hasher (`@noble/hashes` -- Web Crypto's
// SubtleCrypto has no chunked/streaming digest API) so peak memory stays
// bounded regardless of file size.
const _HASH_CHUNK_BYTES = 32 * 1024 * 1024

// Exported so a test can exercise chunk-boundary correctness directly
// against a large file without driving the whole upload store.
export async function computeSHA256(file: File): Promise<string> {
  const hasher = sha256.create()
  for (let offset = 0; offset < file.size; offset += _HASH_CHUNK_BYTES) {
    const chunk = file.slice(offset, offset + _HASH_CHUNK_BYTES)
    hasher.update(new Uint8Array(await chunk.arrayBuffer()))
  }
  return Array.from(hasher.digest())
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// Same real upload sequence UploadDrawer always used (client-side hash,
// presigned PUT with progress, finalize) -- relocated here so it's driven
// by the store rather than a component effect, and keeps running correctly
// regardless of which component (if any) is mounted to watch it. Parsing
// is auto-triggered by the backend pipeline after finalization -- no
// client-side parse/start call needed (CLAUDE.md SS E.2).
async function runUpload(
  caseId: string,
  file: File,
  onProgress: (pct: number) => void,
  declaredFormat?: 'memory_dump',
): Promise<void> {
  const validation = await validateFileMagic(file, declaredFormat)
  if (!validation.ok) {
    throw new Error(validation.reason ?? 'File rejected by pre-check')
  }

  const sha256 = await computeSHA256(file)

  const upload = await requestUpload(
    caseId,
    file.name,
    file.type || 'application/octet-stream',
    file.size,
    declaredFormat,
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

export const useUploadsStore = create<UploadsState>((set) => ({
  activeCaseId: null,
  drawerOpen: false,
  minimized: false,
  jobs: [],

  openDrawer: (caseId) => set({ activeCaseId: caseId, drawerOpen: true, minimized: false }),

  minimize: () => set({ minimized: true }),

  // Mirrors the pre-refactor UploadDrawer.handleClose exactly: a no-op
  // while anything for the active case is still uploading (the UI also
  // disables the Close button for that case, but the store enforces the
  // same rule independently rather than trusting the button alone).
  // Otherwise clears finished/error jobs for that case and hides the
  // drawer/badge.
  closeDrawer: () =>
    set((state) => {
      const stillUploading = state.jobs.some(
        (j) => j.caseId === state.activeCaseId && j.status === 'uploading',
      )
      if (stillUploading) return state
      return {
        drawerOpen: false,
        minimized: false,
        jobs: state.jobs.filter((j) => j.caseId !== state.activeCaseId),
      }
    }),

  enqueueFiles: async (caseId, files, declaredFormat) => {
    const newJobs: UploadJob[] = files.map((f) => ({
      id: `${caseId}:${f.name}:${Date.now()}:${Math.random().toString(36).slice(2)}`,
      caseId,
      filename: f.name,
      progress: 0,
      status: 'uploading',
      error: null,
    }))
    set((state) => ({ jobs: [...state.jobs, ...newJobs] }))

    await Promise.allSettled(
      files.map(async (file, i) => {
        const jobId = newJobs[i].id
        try {
          await runUpload(
            caseId,
            file,
            (pct) => {
              set((state) => ({
                jobs: state.jobs.map((j) => (j.id === jobId ? { ...j, progress: pct } : j)),
              }))
            },
            declaredFormat,
          )
          set((state) => ({
            jobs: state.jobs.map((j) =>
              j.id === jobId ? { ...j, progress: 100, status: 'done', error: null } : j,
            ),
          }))
          // Invalidated here, not by a component effect -- the whole point
          // of a background/minimizable upload is that the page it started
          // on may not be mounted when it finishes.
          await queryClient.invalidateQueries({ queryKey: ['evidence', caseId] })
        } catch (err) {
          const msg = err instanceof Error ? err.message : 'Upload failed'
          set((state) => ({
            jobs: state.jobs.map((j) =>
              j.id === jobId ? { ...j, status: 'error', error: msg } : j,
            ),
          }))
        }
      }),
    )
  },
}))

export function hasActiveJobs(): boolean {
  return useUploadsStore.getState().jobs.some((j) => j.status === 'uploading')
}

// Real, native "leave site?" warning for an actual tab close/refresh/typed-
// URL navigation while a job is running -- registered once at module scope
// (ES modules are singletons), not inside a React effect, so there's no
// mount/unmount churn to reason about. Modern browsers (Chrome/Firefox/
// Safari/Edge) do not render custom text here for security reasons (anti-
// phishing) -- only a generic native prompt is possible; this does not
// fire for TanStack Router's own client-side navigation (that's the whole
// point of minimizing), only for real document unload.
window.addEventListener('beforeunload', (event) => {
  if (hasActiveJobs()) {
    event.preventDefault()
    event.returnValue = ''
  }
})
