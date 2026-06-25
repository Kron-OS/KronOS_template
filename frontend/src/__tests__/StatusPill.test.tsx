import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { StatusPill } from '../components/StatusPill'
import type { EvidenceState } from '../types'

const stateLabels: Array<[EvidenceState, string]> = [
  ['UPLOADING', 'Uploading'],
  ['SCANNING', 'Scanning'],
  ['HASHING', 'Hashing'],
  ['RECEIVED', 'Received'],
  ['PARSING', 'Parsing'],
  ['INGESTING', 'Ingesting'],
  ['COMPLETE', 'Complete'],
  ['ERROR', 'Error'],
  ['PURGED', 'Purged'],
]

describe('StatusPill', () => {
  it.each(stateLabels)('renders label for state %s', (state, label) => {
    render(<StatusPill state={state} />)
    expect(screen.getByText(label)).toBeInTheDocument()
  })

  it('applies green class for COMPLETE', () => {
    const { container } = render(<StatusPill state="COMPLETE" />)
    const pill = container.firstChild as HTMLElement
    expect(pill.className).toMatch(/green/)
  })

  it('applies red class for ERROR', () => {
    const { container } = render(<StatusPill state="ERROR" />)
    const pill = container.firstChild as HTMLElement
    expect(pill.className).toMatch(/red/)
  })
})
