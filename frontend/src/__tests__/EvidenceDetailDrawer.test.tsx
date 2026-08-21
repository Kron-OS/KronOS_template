import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { EvidenceDetailDrawer } from '../components/EvidenceDetailDrawer'
import type { Evidence, EvidenceState } from '../types'

const downloadEvidenceMock = vi.fn().mockResolvedValue(undefined)

vi.mock('../api/evidence', () => ({
  downloadEvidence: (...args: unknown[]) => downloadEvidenceMock(...args),
  retryIntake: vi.fn(),
  retryParse: vi.fn(),
}))

function makeEvidence(state: EvidenceState): Evidence {
  return {
    id: 'ev-1',
    caseId: 'case-1',
    filename: 'sample.log',
    contentType: 'text/plain',
    sizeBytes: 1024,
    sha256: 'abc123',
    md5: 'def456',
    state,
    errorReason: null,
    retryAction: null,
    uploadedBy: 'analyst',
    uploadedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    rfc3161Token: null,
  }
}

function renderDrawer(state: EvidenceState) {
  const queryClient = new QueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      <EvidenceDetailDrawer evidence={makeEvidence(state)} onClose={() => {}} />
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
