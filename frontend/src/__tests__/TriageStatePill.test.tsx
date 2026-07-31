import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { TriageStatePill } from '../components/TriageStatePill'
import type { DetectionTriageState } from '../types'

const stateLabels: Array<[DetectionTriageState, string]> = [
  ['NEW', 'New'],
  ['INVESTIGATING', 'Investigating'],
  ['TRUE_POSITIVE', 'True Positive'],
  ['FALSE_POSITIVE', 'False Positive'],
]

describe('TriageStatePill', () => {
  it.each(stateLabels)('renders label for state %s', (state, label) => {
    render(<TriageStatePill state={state} />)
    expect(screen.getByText(label)).toBeInTheDocument()
  })

  it('applies red class for TRUE_POSITIVE', () => {
    const { container } = render(<TriageStatePill state="TRUE_POSITIVE" />)
    const pill = container.firstChild as HTMLElement
    expect(pill.className).toMatch(/red/)
  })

  it('applies purple class for NEW', () => {
    const { container } = render(<TriageStatePill state="NEW" />)
    const pill = container.firstChild as HTMLElement
    expect(pill.className).toMatch(/purple/)
  })
})
