import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ConnectorStatusPill } from '../components/ConnectorStatusPill'
import type { ConnectorStatusState } from '../types'

const stateLabels: Array<[ConnectorStatusState, string]> = [
  ['never_used', 'Never used'],
  ['active', 'Active'],
  ['failing', 'Failing'],
  ['revoked', 'Revoked'],
]

describe('ConnectorStatusPill', () => {
  it.each(stateLabels)('renders label for state %s', (state, label) => {
    render(<ConnectorStatusPill state={state} />)
    expect(screen.getByText(label)).toBeInTheDocument()
  })

  it('applies green class for active', () => {
    const { container } = render(<ConnectorStatusPill state="active" />)
    const pill = container.firstChild as HTMLElement
    expect(pill.className).toMatch(/green/)
  })

  it('applies red class for failing', () => {
    const { container } = render(<ConnectorStatusPill state="failing" />)
    const pill = container.firstChild as HTMLElement
    expect(pill.className).toMatch(/red/)
  })
})
