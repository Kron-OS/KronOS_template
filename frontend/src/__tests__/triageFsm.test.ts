import { describe, it, expect } from 'vitest'
import { nextTriageStates, triageActionLabel } from '../utils/triageFsm'

describe('triageFsm', () => {
  it('NEW can only advance to INVESTIGATING', () => {
    expect(nextTriageStates('NEW')).toEqual(['INVESTIGATING'])
  })

  it('INVESTIGATING can advance to TRUE_POSITIVE or FALSE_POSITIVE', () => {
    expect(nextTriageStates('INVESTIGATING')).toEqual(['TRUE_POSITIVE', 'FALSE_POSITIVE'])
  })

  it('TRUE_POSITIVE and FALSE_POSITIVE are terminal', () => {
    expect(nextTriageStates('TRUE_POSITIVE')).toEqual([])
    expect(nextTriageStates('FALSE_POSITIVE')).toEqual([])
  })

  it('provides a human label for every target state', () => {
    expect(triageActionLabel('INVESTIGATING')).toMatch(/investigat/i)
    expect(triageActionLabel('TRUE_POSITIVE')).toMatch(/true positive/i)
    expect(triageActionLabel('FALSE_POSITIVE')).toMatch(/false positive/i)
  })
})
