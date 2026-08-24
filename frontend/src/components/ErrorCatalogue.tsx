interface CatalogueEntry {
  title: string
  hint: string
  retryable: boolean
}

/**
 * Gap Audit Milestone XX: every key here used to drift from the real
 * backend reason strings -- some entries used a plausible-sounding but
 * wrong key that could never match anything `Evidence.with_error()`
 * actually sets (`invalid_magic_bytes` vs. the real `no_parser_found`,
 * `file_too_large` vs. `size_limit_exceeded`, `ingest_count_mismatch` vs.
 * `ingest_failed`), silently falling back to the raw machine code as the
 * title; two entries had their `retryable` flag inverted relative to the
 * backend's own authoritative classification
 * (`is_retryable_error_reason`/`_TERMINAL_ERROR_REASONS`,
 * src/domain/evidence.py) -- `hash_mismatch` is backend-TERMINAL but this
 * said `retryable: true`, `parse_timeout` is backend-retryable but this
 * said `retryable: false`; and three entries (`tsa_unreachable`,
 * `parser_oom`, `storage_error`) never corresponded to any real
 * `error_reason` the backend has ever set (confirmed via repo-wide grep
 * of every `with_error(...)` call site) and have been removed. This does
 * NOT affect the real Retry button in EvidenceDetailDrawer.tsx -- that is
 * gated by the server-computed `evidence.retryAction` field
 * (`_retry_action_for`, src/external/routes/evidence.py), which already
 * used the real backend classification correctly. This `retryable` field
 * only drives the cosmetic badge/wording shown alongside the error
 * title, but a wrong cosmetic label on a forensics platform is still a
 * real, misleading defect, not merely cosmetic noise.
 *
 * Every key below is a literal reason string confirmed via
 * `grep -rn "with_error(" src/` against
 * src/application/evidence_intake.py, src/application/
 * parsing_orchestration.py, and src/external/celery_app.py; every
 * `retryable` value mirrors `is_retryable_error_reason()`
 * (src/domain/evidence.py) exactly, not re-derived independently.
 */
const ERROR_CATALOGUE: Record<string, CatalogueEntry> = {
  upload_timeout: {
    title: 'Upload timed out',
    hint: 'The upload did not complete within 24 hours. Re-upload the file.',
    retryable: true,
  },
  intake_timeout: {
    title: 'Intake timed out',
    hint: 'Validation/scanning/hashing did not complete in time. Retrying re-attempts these steps.',
    retryable: true,
  },
  parse_timeout: {
    title: 'Parse timed out',
    hint: 'Evidence parsing did not complete in time for this attempt. Retrying will try again.',
    retryable: true,
  },
  validation_failed: {
    title: 'Validation failed',
    hint: 'The file failed format/size validation. This cannot be retried as-is.',
    retryable: false,
  },
  size_limit_exceeded: {
    title: 'File too large',
    hint: 'Maximum file size is 1 GB.',
    retryable: false,
  },
  hash_mismatch: {
    title: 'Integrity check failed',
    hint: 'The uploaded file SHA-256 does not match the declared hash. This cannot be retried as-is.',
    retryable: false,
  },
  no_parser_found: {
    title: 'Unsupported file format',
    hint: 'The file header does not match any supported forensic format.',
    retryable: false,
  },
  ingest_failed: {
    title: 'Indexing incomplete',
    hint: 'Not all parsed records were indexed. Retry to re-index.',
    retryable: true,
  },
  parse_failed: {
    title: 'Parsing failed',
    hint: 'The parser encountered an unexpected error. Retrying will try again.',
    retryable: true,
  },
}

/**
 * with_error() templates two reasons with real runtime detail
 * (`infected:{threat_name}`, `intake_failed:{exception type}`) that can
 * never appear as a fixed ERROR_CATALOGUE key -- matched by prefix
 * instead. `infected:` mirrors the one real entry in
 * `_TERMINAL_ERROR_PREFIXES` (src/domain/evidence.py); `intake_failed:`
 * has no such entry there, so it falls through to that function's own
 * documented default ("presumed transient and retryable"), matched here.
 */
const PREFIX_CATALOGUE: ReadonlyArray<{
  prefix: string
  entry: (detail: string) => CatalogueEntry
}> = [
  {
    prefix: 'infected:',
    entry: (detail) => ({
      title: 'Malware detected',
      hint: `ClamAV detected a known malware signature (${detail}). The file has been quarantined. This cannot be retried as-is.`,
      retryable: false,
    }),
  },
  {
    prefix: 'intake_failed:',
    entry: (detail) => ({
      title: 'Intake failed',
      hint: `An unexpected error occurred during validation/scanning/hashing (${detail}). Retrying will try again.`,
      retryable: true,
    }),
  },
]

export function lookupError(reasonCode: string): CatalogueEntry {
  const exact = ERROR_CATALOGUE[reasonCode]
  if (exact) return exact
  for (const { prefix, entry } of PREFIX_CATALOGUE) {
    if (reasonCode.startsWith(prefix)) {
      return entry(reasonCode.slice(prefix.length))
    }
  }
  return {
    title: reasonCode,
    hint: 'Unknown error. Contact support.',
    retryable: false,
  }
}

interface ErrorCatalogueChipProps {
  reasonCode: string
  diagnosticId?: string
}

export function ErrorCatalogueChip({ reasonCode, diagnosticId }: ErrorCatalogueChipProps) {
  const entry = lookupError(reasonCode)
  return (
    <div className="rounded-md border border-red-300 bg-red-50 p-3 text-sm dark:border-red-900/50 dark:bg-red-950/30">
      <div className="flex items-start justify-between gap-2">
        <p className="font-medium text-red-700 dark:text-red-300">{entry.title}</p>
        {entry.retryable && (
          <span className="shrink-0 rounded bg-amber-100 px-1.5 py-0.5 text-xs text-amber-700 dark:bg-amber-900/40 dark:text-amber-400">
            retryable
          </span>
        )}
      </div>
      <p className="mt-1 text-red-600/80 dark:text-red-400/80">{entry.hint}</p>
      {diagnosticId && (
        <p className="mt-2 font-mono text-xs text-gray-500 dark:text-gray-600">
          ID: {diagnosticId}
        </p>
      )}
    </div>
  )
}
