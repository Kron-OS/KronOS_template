import { describe, expect, it, beforeEach } from 'vitest'
import {
  stashPendingStepUpForm,
  takePendingStepUpForm,
  clearPendingStepUpForm,
} from '../lib/stepUpFormPersistence'

describe('stepUpFormPersistence', () => {
  beforeEach(() => {
    sessionStorage.clear()
  })

  it('round-trips a stashed value through take (single read)', () => {
    stashPendingStepUpForm('quota', { gbInput: '5' })
    expect(takePendingStepUpForm('quota')).toEqual({ gbInput: '5' })
  })

  it('take clears the value -- a second read returns null', () => {
    stashPendingStepUpForm('quota', { gbInput: '5' })
    takePendingStepUpForm('quota')
    expect(takePendingStepUpForm('quota')).toBeNull()
  })

  it('take returns null when nothing was ever stashed', () => {
    expect(takePendingStepUpForm('never-stashed')).toBeNull()
  })

  it('keys are independent -- stashing one does not clobber another', () => {
    stashPendingStepUpForm('quota', { gbInput: '5' })
    stashPendingStepUpForm('invite', { email: 'a@example.invalid' })
    expect(takePendingStepUpForm('invite')).toEqual({ email: 'a@example.invalid' })
    expect(takePendingStepUpForm('quota')).toEqual({ gbInput: '5' })
  })

  it('a later stash overwrites an earlier one under the same key', () => {
    stashPendingStepUpForm('quota', { gbInput: '5' })
    stashPendingStepUpForm('quota', { gbInput: '10' })
    expect(takePendingStepUpForm('quota')).toEqual({ gbInput: '10' })
  })

  it('clearPendingStepUpForm removes a stash without reading it', () => {
    stashPendingStepUpForm('quota', { gbInput: '5' })
    clearPendingStepUpForm('quota')
    expect(takePendingStepUpForm('quota')).toBeNull()
  })
})
