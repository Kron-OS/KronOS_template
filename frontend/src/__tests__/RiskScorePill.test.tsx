import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { RiskScorePill } from '../components/RiskScorePill'

describe('RiskScorePill', () => {
  it('shows "Not scored" for a null score', () => {
    render(<RiskScorePill score={null} />)
    expect(screen.getByText('Not scored')).toBeInTheDocument()
  })

  it('labels 0-24 as Low', () => {
    render(<RiskScorePill score={10} />)
    expect(screen.getByText('Low · 10')).toBeInTheDocument()
  })

  it('labels 25-49 as Medium', () => {
    render(<RiskScorePill score={30} />)
    expect(screen.getByText('Medium · 30')).toBeInTheDocument()
  })

  it('labels 50-74 as High', () => {
    render(<RiskScorePill score={60} />)
    expect(screen.getByText('High · 60')).toBeInTheDocument()
  })

  it('labels 75-100 as Critical', () => {
    render(<RiskScorePill score={90} />)
    expect(screen.getByText('Critical · 90')).toBeInTheDocument()
  })

  it('rounds a fractional score for display', () => {
    render(<RiskScorePill score={74.6} />)
    expect(screen.getByText('High · 75')).toBeInTheDocument()
  })

  it('applies the red band class at the critical boundary', () => {
    const { container } = render(<RiskScorePill score={75} />)
    const pill = container.firstChild as HTMLElement
    expect(pill.className).toMatch(/red/)
  })

  it('applies the gray band class for a null score', () => {
    const { container } = render(<RiskScorePill score={null} />)
    const pill = container.firstChild as HTMLElement
    expect(pill.className).toMatch(/gray/)
  })
})
