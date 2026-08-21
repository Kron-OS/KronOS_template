import { describe, it, expect } from 'vitest'
import { filenameFromContentDisposition } from '../api/evidence'

describe('filenameFromContentDisposition', () => {
  it('extracts a quoted filename', () => {
    expect(
      filenameFromContentDisposition('attachment; filename="evidence.log"', 'fallback.bin'),
    ).toBe('evidence.log')
  })

  it('extracts an unquoted filename', () => {
    expect(filenameFromContentDisposition('attachment; filename=evidence.log', 'fallback.bin')).toBe(
      'evidence.log',
    )
  })

  it('falls back when the header is missing', () => {
    expect(filenameFromContentDisposition(undefined, 'fallback.bin')).toBe('fallback.bin')
  })

  it('falls back when the header has no filename directive', () => {
    expect(filenameFromContentDisposition('attachment', 'fallback.bin')).toBe('fallback.bin')
  })
})
