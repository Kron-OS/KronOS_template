import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ErrorCatalogueChip, lookupError } from '../components/ErrorCatalogue'

describe('lookupError', () => {
  it('returns known entry for upload_timeout', () => {
    expect(lookupError('upload_timeout').title).toBe('Upload timed out')
  })

  it('returns code as title for unknown reason', () => {
    expect(lookupError('completely_unknown').title).toBe('completely_unknown')
  })

  it('marks virus_detected as non-retryable', () => {
    expect(lookupError('virus_detected').retryable).toBe(false)
  })

  it('marks tsa_unreachable as retryable', () => {
    expect(lookupError('tsa_unreachable').retryable).toBe(true)
  })
})

describe('ErrorCatalogueChip', () => {
  it('shows title for known error code', () => {
    render(<ErrorCatalogueChip reasonCode="upload_timeout" />)
    expect(screen.getByText('Upload timed out')).toBeInTheDocument()
  })

  it('shows hint text', () => {
    render(<ErrorCatalogueChip reasonCode="virus_detected" />)
    expect(screen.getByText(/ClamAV/)).toBeInTheDocument()
  })

  it('shows code as title for unknown error code', () => {
    render(<ErrorCatalogueChip reasonCode="some_unknown_code" />)
    expect(screen.getByText('some_unknown_code')).toBeInTheDocument()
  })

  it('shows diagnostic ID when provided', () => {
    render(<ErrorCatalogueChip reasonCode="storage_error" diagnosticId="abc-123" />)
    expect(screen.getByText(/abc-123/)).toBeInTheDocument()
  })

  it('shows retryable badge for retryable errors', () => {
    render(<ErrorCatalogueChip reasonCode="upload_timeout" />)
    expect(screen.getByText('retryable')).toBeInTheDocument()
  })

  it('does not show retryable badge for non-retryable errors', () => {
    render(<ErrorCatalogueChip reasonCode="virus_detected" />)
    expect(screen.queryByText('retryable')).not.toBeInTheDocument()
  })
})
