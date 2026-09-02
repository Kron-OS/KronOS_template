import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { EvidenceDetailDrawer } from '../components/EvidenceDetailDrawer'
import type { Evidence, EvidenceState } from '../types'

const downloadEvidenceMock = vi.fn().mockResolvedValue(undefined)
const retryIntakeMock = vi.fn().mockResolvedValue(undefined)
const retryParseMock = vi.fn().mockResolvedValue(undefined)

vi.mock('../api/evidence', () => ({
  downloadEvidence: (...args: unknown[]) => downloadEvidenceMock(...args),
  retryIntake: (...args: unknown[]) => retryIntakeMock(...args),
  retryParse: (...args: unknown[]) => retryParseMock(...args),
}))

function makeEvidence(
  state: EvidenceState,
  retryAction: Evidence['retryAction'] = null,
  filename = 'sample.log',
): Evidence {
  return {
    id: 'ev-1',
    caseId: 'case-1',
    filename,
    contentType: 'text/plain',
    sizeBytes: 1024,
    sha256: 'abc123',
    md5: 'def456',
    state,
    // Real markup constraint (EvidenceDetailDrawer.tsx): the Retry button
    // only renders when BOTH errorReason and retryAction are truthy --
    // must set a real reason whenever a caller wants Retry visible.
    errorReason: retryAction ? 'ingest_failed' : null,
    retryAction,
    uploadedBy: 'analyst',
    uploadedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    rfc3161Token: null,
  }
}

function renderDrawer(
  state: EvidenceState,
  retryAction: Evidence['retryAction'] = null,
  options: { filename?: string; artifactCount?: number } = {},
) {
  const queryClient = new QueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      <EvidenceDetailDrawer
        evidence={makeEvidence(state, retryAction, options.filename)}
        onClose={() => {}}
        artifactCount={options.artifactCount ?? 0}
        onViewArtifacts={() => {}}
      />
    </QueryClientProvider>,
  )
}

describe('EvidenceDetailDrawer download affordance', () => {
  beforeEach(() => {
    downloadEvidenceMock.mockClear()
  })

  it.each<EvidenceState>(['UPLOADING', 'SCANNING', 'HASHING'])(
    'hides the Download button while %s (not yet promoted to the evidence bucket)',
    (state) => {
      renderDrawer(state)
      expect(screen.queryByRole('button', { name: /download/i })).not.toBeInTheDocument()
    },
  )

  it.each<EvidenceState>(['RECEIVED', 'PARSING', 'INGESTING', 'COMPLETE', 'ERROR'])(
    'shows the Download button once %s',
    (state) => {
      renderDrawer(state)
      expect(screen.getByRole('button', { name: /download/i })).toBeInTheDocument()
    },
  )

  it('calls downloadEvidence with the real case/evidence id and filename on click', async () => {
    const user = userEvent.setup()
    renderDrawer('COMPLETE')

    await user.click(screen.getByRole('button', { name: /download/i }))

    await waitFor(() => {
      expect(downloadEvidenceMock).toHaveBeenCalledWith('case-1', 'ev-1', 'sample.log')
    })
  })
})

/**
 * Real user report follow-up (Gap Audit Milestone BBBBB): the "Forensic
 * artifacts" row used to be hidden entirely whenever artifactCount was 0
 * -- indistinguishable from "not a memory dump at all," even for a real
 * memory dump that genuinely finished analysis and found nothing. This
 * drawer is the first place a user actually looks (before the separate
 * Artifacts tab), so it needs its own honest message, not just a silent
 * empty state.
 */
describe('EvidenceDetailDrawer forensic-artifacts honesty', () => {
  it('shows the honest no-artifacts message for a COMPLETE memory dump with zero artifacts', () => {
    renderDrawer('COMPLETE', null, { filename: 'ch2.dmp', artifactCount: 0 })
    expect(
      screen.getByText('No process data could be recovered from this memory image.'),
    ).toBeInTheDocument()
  })

  it('does not show the no-artifacts message while still processing', () => {
    renderDrawer('PARSING', null, { filename: 'ch2.dmp', artifactCount: 0 })
    expect(
      screen.queryByText('No process data could be recovered from this memory image.'),
    ).not.toBeInTheDocument()
  })

  it('does not show the no-artifacts message for a non-memory-dump file', () => {
    renderDrawer('COMPLETE', null, { filename: 'sample.log', artifactCount: 0 })
    expect(
      screen.queryByText('No process data could be recovered from this memory image.'),
    ).not.toBeInTheDocument()
  })

  it('shows the real artifact count (not the honest-zero message) once artifacts exist', () => {
    renderDrawer('COMPLETE', null, { filename: 'ch2.dmp', artifactCount: 3 })
    expect(screen.getByText('3 artifacts found')).toBeInTheDocument()
    expect(
      screen.queryByText('No process data could be recovered from this memory image.'),
    ).not.toBeInTheDocument()
  })
})

describe('EvidenceDetailDrawer retry recovery', () => {
  beforeEach(() => {
    retryIntakeMock.mockClear()
    retryParseMock.mockClear()
  })

  it('calls retryParse (not retryIntake) when retryAction is "parse"', async () => {
    const user = userEvent.setup()
    renderDrawer('ERROR', 'parse')

    await user.click(screen.getByRole('button', { name: /retry/i }))

    await waitFor(() => expect(retryParseMock).toHaveBeenCalledWith('ev-1'))
    expect(retryIntakeMock).not.toHaveBeenCalled()
  })

  it(
    // Real, reproduced bug (frontend/e2e/evidence-retry.spec.ts, Gap
    // Audit 2026-08-28): useEvidenceSSE closes its SSE stream permanently
    // once evidence first reaches a terminal state and never reopens it,
    // so a successful retry recovered on the backend but never showed up
    // live in the UI. Fixed by dispatching this event on retry success so
    // useEvidenceSSE can reconnect -- this test guards the dispatch side
    // of that fix (the reconnect side itself is only realistically
    // provable against a real EventSource/backend, which the E2E spec
    // covers).
    'dispatches kronos:sse-reconnect with the real caseId on a successful retry',
    async () => {
      const user = userEvent.setup()
      const seen: CustomEvent<{ caseId: string }>[] = []
      const listener = (e: Event) => seen.push(e as CustomEvent<{ caseId: string }>)
      window.addEventListener('kronos:sse-reconnect', listener)

      try {
        renderDrawer('ERROR', 'intake')
        await user.click(screen.getByRole('button', { name: /retry/i }))

        await waitFor(() => expect(seen).toHaveLength(1))
        expect(seen[0].detail).toEqual({ caseId: 'case-1' })
      } finally {
        window.removeEventListener('kronos:sse-reconnect', listener)
      }
    },
  )
})
