import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, beforeEach } from 'vitest'
import { UploadStatusBadge } from '../components/UploadStatusBadge'
import { useUploadsStore } from '../store/uploads'

beforeEach(() => {
  useUploadsStore.setState({ activeCaseId: null, drawerOpen: false, minimized: false, jobs: [] })
})

describe('UploadStatusBadge', () => {
  it('renders nothing when there are no jobs', () => {
    render(<UploadStatusBadge />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('renders nothing when not minimized, even with active jobs', () => {
    useUploadsStore.setState({
      activeCaseId: 'case-1',
      drawerOpen: true,
      minimized: false,
      jobs: [{ id: 'j1', caseId: 'case-1', filename: 'a.log', progress: 40, status: 'uploading', error: null }],
    })
    render(<UploadStatusBadge />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('shows live average progress across active jobs while minimized', () => {
    useUploadsStore.setState({
      activeCaseId: 'case-1',
      drawerOpen: true,
      minimized: true,
      jobs: [
        { id: 'j1', caseId: 'case-1', filename: 'a.log', progress: 20, status: 'uploading', error: null },
        { id: 'j2', caseId: 'case-1', filename: 'b.log', progress: 60, status: 'uploading', error: null },
      ],
    })
    render(<UploadStatusBadge />)
    expect(screen.getByText(/Uploading 2 files… 40%/)).toBeInTheDocument()
  })

  it('shows a completion summary once all jobs are done', () => {
    useUploadsStore.setState({
      activeCaseId: 'case-1',
      drawerOpen: true,
      minimized: true,
      jobs: [
        { id: 'j1', caseId: 'case-1', filename: 'a.log', progress: 100, status: 'done', error: null },
        { id: 'j2', caseId: 'case-1', filename: 'b.log', progress: 100, status: 'done', error: null },
      ],
    })
    render(<UploadStatusBadge />)
    expect(screen.getByText('2 files uploaded')).toBeInTheDocument()
  })

  it('clicking the badge un-minimizes and reopens the drawer for the active case', async () => {
    const user = userEvent.setup()
    useUploadsStore.setState({
      activeCaseId: 'case-1',
      drawerOpen: true,
      minimized: true,
      jobs: [{ id: 'j1', caseId: 'case-1', filename: 'a.log', progress: 40, status: 'uploading', error: null }],
    })
    render(<UploadStatusBadge />)

    await user.click(screen.getByRole('button'))

    const state = useUploadsStore.getState()
    expect(state.minimized).toBe(false)
    expect(state.drawerOpen).toBe(true)
    expect(state.activeCaseId).toBe('case-1')
  })
})
