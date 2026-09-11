import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useUploadsStore, hasActiveJobs } from '../store/uploads'

const requestUploadMock = vi.fn()
const finalizeUploadWithHashMock = vi.fn()
const validateFileMagicMock = vi.fn().mockResolvedValue({ ok: true })

vi.mock('../api/evidence', () => ({
  requestUpload: (...args: unknown[]) => requestUploadMock(...args),
  finalizeUploadWithHash: (...args: unknown[]) => finalizeUploadWithHashMock(...args),
}))

vi.mock('../utils/validateFileMagic', () => ({
  validateFileMagic: (...args: unknown[]) => validateFileMagicMock(...args),
  BLOCKED_EXTENSIONS: new Set(['exe']),
}))

// Fake XHR standing in for the real presigned-URL PUT (mirrors the real
// interface store/uploads.ts's runUpload() actually drives: open/send,
// upload.onprogress, onload, onerror, status) -- this exact flow is
// exercised for real against the real dev stack by
// frontend/e2e/evidence-upload*.spec.ts; this unit test is about the
// store's own job-lifecycle bookkeeping, not re-proving the network path.
class FakeXHR {
  static instances: FakeXHR[] = []
  upload = { onprogress: null as ((e: ProgressEvent) => void) | null }
  onload: (() => void) | null = null
  onerror: (() => void) | null = null
  status = 200
  open = vi.fn()
  send = vi.fn(() => {
    FakeXHR.instances.push(this)
  })
}

beforeEach(() => {
  useUploadsStore.setState({ activeCaseId: null, drawerOpen: false, minimized: false, jobs: [] })
  requestUploadMock.mockReset()
  finalizeUploadWithHashMock.mockReset()
  validateFileMagicMock.mockReset().mockResolvedValue({ ok: true })
  FakeXHR.instances = []
  vi.stubGlobal('XMLHttpRequest', FakeXHR)
  vi.stubGlobal('crypto', {
    subtle: { digest: vi.fn().mockResolvedValue(new ArrayBuffer(32)) },
  })
})

function makeFile(name: string): File {
  return new File(['content'], name, { type: 'text/plain' })
}

describe('useUploadsStore drawer state', () => {
  it('openDrawer sets the active case and opens un-minimized', () => {
    useUploadsStore.getState().openDrawer('case-1')
    const state = useUploadsStore.getState()
    expect(state.activeCaseId).toBe('case-1')
    expect(state.drawerOpen).toBe(true)
    expect(state.minimized).toBe(false)
  })

  it('minimize hides the drawer without touching jobs', () => {
    useUploadsStore.getState().openDrawer('case-1')
    useUploadsStore.setState({ jobs: [{ id: 'j1', caseId: 'case-1', filename: 'a.log', progress: 40, status: 'uploading', error: null }] })

    useUploadsStore.getState().minimize()

    const state = useUploadsStore.getState()
    expect(state.minimized).toBe(true)
    expect(state.drawerOpen).toBe(true)
    expect(state.jobs).toHaveLength(1)
  })

  it('closeDrawer is a no-op while a job for the active case is still uploading', () => {
    useUploadsStore.setState({
      activeCaseId: 'case-1',
      drawerOpen: true,
      minimized: false,
      jobs: [{ id: 'j1', caseId: 'case-1', filename: 'a.log', progress: 40, status: 'uploading', error: null }],
    })

    useUploadsStore.getState().closeDrawer()

    const state = useUploadsStore.getState()
    expect(state.drawerOpen).toBe(true)
    expect(state.jobs).toHaveLength(1)
  })

  it('closeDrawer clears finished/error jobs for the active case and hides once nothing is uploading', () => {
    useUploadsStore.setState({
      activeCaseId: 'case-1',
      drawerOpen: true,
      minimized: true,
      jobs: [
        { id: 'j1', caseId: 'case-1', filename: 'a.log', progress: 100, status: 'done', error: null },
        { id: 'j2', caseId: 'case-1', filename: 'b.log', progress: 0, status: 'error', error: 'boom' },
        { id: 'j3', caseId: 'case-2', filename: 'c.log', progress: 100, status: 'done', error: null },
      ],
    })

    useUploadsStore.getState().closeDrawer()

    const state = useUploadsStore.getState()
    expect(state.drawerOpen).toBe(false)
    expect(state.minimized).toBe(false)
    // Case-1's jobs are gone; a different case's finished job is untouched.
    expect(state.jobs).toEqual([
      { id: 'j3', caseId: 'case-2', filename: 'c.log', progress: 100, status: 'done', error: null },
    ])
  })
})

describe('useUploadsStore.enqueueFiles', () => {
  it('creates an uploading job per file, then marks it done and invalidates evidence on success', async () => {
    requestUploadMock.mockResolvedValue({ evidenceId: 'ev-1', presignedUrl: 'https://minio/x' })
    finalizeUploadWithHashMock.mockResolvedValue({})

    const promise = useUploadsStore.getState().enqueueFiles('case-1', [makeFile('a.log')])

    // Job exists synchronously (before the async chain resolves) so a
    // badge/drawer watching the store sees it immediately.
    expect(useUploadsStore.getState().jobs).toHaveLength(1)
    expect(useUploadsStore.getState().jobs[0]).toMatchObject({
      caseId: 'case-1',
      filename: 'a.log',
      status: 'uploading',
    })
    expect(hasActiveJobs()).toBe(true)

    // Resolve the fake XHR's PUT once runUpload's own async chain
    // (validateFileMagic -> computeSHA256 -> requestUpload) reaches it.
    await vi.waitFor(() => expect(FakeXHR.instances).toHaveLength(1))
    const xhr = FakeXHR.instances[0]
    xhr.onload?.()

    await promise

    const job = useUploadsStore.getState().jobs[0]
    expect(job.status).toBe('done')
    expect(job.progress).toBe(100)
    expect(hasActiveJobs()).toBe(false)
    expect(finalizeUploadWithHashMock).toHaveBeenCalledWith('ev-1', expect.any(String))
  })

  it('marks the job as error (not the whole batch) when the PUT fails, without aborting other jobs', async () => {
    requestUploadMock.mockResolvedValue({ evidenceId: 'ev-1', presignedUrl: 'https://minio/x' })

    const promise = useUploadsStore.getState().enqueueFiles('case-1', [makeFile('bad.log')])
    await vi.waitFor(() => expect(FakeXHR.instances).toHaveLength(1))
    const xhr = FakeXHR.instances[0]
    xhr.onerror?.()

    await promise

    const job = useUploadsStore.getState().jobs[0]
    expect(job.status).toBe('error')
    expect(job.error).toBe('Network error')
    expect(hasActiveJobs()).toBe(false)
  })

  it('threads declaredFormat through to validateFileMagic and requestUpload', async () => {
    // Real diagnosis fix (case 43097ab0-aae3-4968-915b-8f0229ac3865): the
    // "This is a memory image" checkbox in UploadDrawer must reach both
    // the client-side pre-check and the real backend request, not just one.
    requestUploadMock.mockResolvedValue({ evidenceId: 'ev-1', presignedUrl: 'https://minio/x' })
    finalizeUploadWithHashMock.mockResolvedValue({})

    const promise = useUploadsStore
      .getState()
      .enqueueFiles('case-1', [makeFile('ch2.dat')], 'memory_dump')

    await vi.waitFor(() => expect(FakeXHR.instances).toHaveLength(1))
    FakeXHR.instances[0].onload?.()
    await promise

    expect(validateFileMagicMock).toHaveBeenCalledWith(expect.anything(), 'memory_dump')
    expect(requestUploadMock).toHaveBeenCalledWith(
      'case-1',
      'ch2.dat',
      expect.any(String),
      expect.any(Number),
      'memory_dump',
    )
  })
})
