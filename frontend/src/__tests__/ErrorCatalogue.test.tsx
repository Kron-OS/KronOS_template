import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ErrorCatalogueChip, lookupError } from '../components/ErrorCatalogue'

/**
 * Gap Audit Milestone XX: every reason code exercised here is a real,
 * literal string confirmed via `grep -rn "with_error(" src/` -- previously
 * this catalogue used plausible-sounding but wrong keys
 * (invalid_magic_bytes/file_too_large/ingest_count_mismatch instead of the
 * real no_parser_found/size_limit_exceeded/ingest_failed) and had two
 * retryable flags inverted relative to src/domain/evidence.py's own
 * is_retryable_error_reason() (hash_mismatch is backend-TERMINAL,
 * parse_timeout is backend-retryable) -- these tests assert the corrected,
 * backend-consistent values.
 */

describe('lookupError', () => {
  it('returns known entry for upload_timeout', () => {
    expect(lookupError('upload_timeout').title).toBe('Upload timed out')
    expect(lookupError('upload_timeout').retryable).toBe(true)
  })

  it('returns code as title for unknown reason', () => {
    expect(lookupError('completely_unknown').title).toBe('completely_unknown')
  })

  it('marks hash_mismatch as non-retryable (backend TERMINAL, src/domain/evidence.py)', () => {
    expect(lookupError('hash_mismatch').retryable).toBe(false)
  })

  it('marks parse_timeout as retryable (backend does not treat it as terminal)', () => {
    expect(lookupError('parse_timeout').retryable).toBe(true)
  })

  it('marks validation_failed as non-retryable', () => {
    expect(lookupError('validation_failed').retryable).toBe(false)
  })

  it('marks size_limit_exceeded as non-retryable with the real reason string', () => {
    const entry = lookupError('size_limit_exceeded')
    expect(entry.retryable).toBe(false)
    expect(entry.title).toBe('File too large')
  })

  it('marks no_parser_found as non-retryable with the real reason string', () => {
    const entry = lookupError('no_parser_found')
    expect(entry.retryable).toBe(false)
    expect(entry.title).toBe('Unsupported file format')
  })

  it('marks ingest_failed as retryable with the real reason string', () => {
    const entry = lookupError('ingest_failed')
    expect(entry.retryable).toBe(true)
    expect(entry.title).toBe('Indexing incomplete')
  })

  it('marks intake_timeout as retryable', () => {
    expect(lookupError('intake_timeout').retryable).toBe(true)
  })

  it('marks parse_failed as retryable', () => {
    expect(lookupError('parse_failed').retryable).toBe(true)
  })

  it('matches the dynamic infected: prefix and surfaces the threat name, non-retryable', () => {
    const entry = lookupError('infected:Win32.Trojan')
    expect(entry.title).toBe('Malware detected')
    expect(entry.hint).toContain('Win32.Trojan')
    expect(entry.retryable).toBe(false)
  })

  it('matches the dynamic intake_failed: prefix and surfaces the exception type, retryable', () => {
    const entry = lookupError('intake_failed:ConnectionError')
    expect(entry.title).toBe('Intake failed')
    expect(entry.hint).toContain('ConnectionError')
    expect(entry.retryable).toBe(true)
  })
})

describe('ErrorCatalogueChip', () => {
  it('shows title for known error code', () => {
    render(<ErrorCatalogueChip reasonCode="upload_timeout" />)
    expect(screen.getByText('Upload timed out')).toBeInTheDocument()
  })

  it('shows hint text', () => {
    render(<ErrorCatalogueChip reasonCode="infected:Win32.Trojan" />)
    expect(screen.getByText(/ClamAV/)).toBeInTheDocument()
  })

  it('shows code as title for unknown error code', () => {
    render(<ErrorCatalogueChip reasonCode="some_unknown_code" />)
    expect(screen.getByText('some_unknown_code')).toBeInTheDocument()
  })

  it('shows diagnostic ID when provided', () => {
    render(<ErrorCatalogueChip reasonCode="hash_mismatch" diagnosticId="abc-123" />)
    expect(screen.getByText(/abc-123/)).toBeInTheDocument()
  })

  it('shows retryable badge for retryable errors', () => {
    render(<ErrorCatalogueChip reasonCode="upload_timeout" />)
    expect(screen.getByText('retryable')).toBeInTheDocument()
  })

  it('does not show retryable badge for non-retryable errors', () => {
    render(<ErrorCatalogueChip reasonCode="hash_mismatch" />)
    expect(screen.queryByText('retryable')).not.toBeInTheDocument()
  })
})
