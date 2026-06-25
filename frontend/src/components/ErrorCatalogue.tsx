interface CatalogueEntry {
  title: string
  hint: string
  retryable: boolean
}

const ERROR_CATALOGUE: Record<string, CatalogueEntry> = {
  upload_timeout: {
    title: 'Upload timed out',
    hint: 'The upload did not complete within 24 hours. Re-upload the file.',
    retryable: true,
  },
  parse_timeout: {
    title: 'Parse timed out',
    hint: 'Evidence parsing exceeded the 6-hour limit. Contact support for large files.',
    retryable: false,
  },
  invalid_magic_bytes: {
    title: 'Unsupported file format',
    hint: 'The file header does not match any supported forensic format.',
    retryable: false,
  },
  file_too_large: {
    title: 'File too large',
    hint: 'Maximum file size is 1 GB.',
    retryable: false,
  },
  virus_detected: {
    title: 'Malware detected',
    hint: 'ClamAV detected a known malware signature. The file has been quarantined.',
    retryable: false,
  },
  hash_mismatch: {
    title: 'Integrity check failed',
    hint: 'The uploaded file SHA-256 does not match the declared hash.',
    retryable: true,
  },
  tsa_unreachable: {
    title: 'Timestamp service unavailable',
    hint: 'The RFC 3161 TSA is temporarily down. A retry will be attempted automatically.',
    retryable: true,
  },
  ingest_count_mismatch: {
    title: 'Indexing incomplete',
    hint: 'Not all parsed records were indexed. Retry to re-index.',
    retryable: true,
  },
  parser_oom: {
    title: 'Parser out of memory',
    hint: 'The file exceeded parser memory limits. Contact support.',
    retryable: false,
  },
  storage_error: {
    title: 'Storage error',
    hint: 'Unable to access evidence storage. Contact support.',
    retryable: true,
  },
}

export function lookupError(reasonCode: string): CatalogueEntry {
  return (
    ERROR_CATALOGUE[reasonCode] ?? {
      title: reasonCode,
      hint: 'Unknown error. Contact support.',
      retryable: false,
    }
  )
}

interface ErrorCatalogueChipProps {
  reasonCode: string
  diagnosticId?: string
}

export function ErrorCatalogueChip({ reasonCode, diagnosticId }: ErrorCatalogueChipProps) {
  const entry = lookupError(reasonCode)
  return (
    <div className="rounded-md border border-red-900/50 bg-red-950/30 p-3 text-sm">
      <div className="flex items-start justify-between gap-2">
        <p className="font-medium text-red-300">{entry.title}</p>
        {entry.retryable && (
          <span className="shrink-0 rounded bg-amber-900/40 px-1.5 py-0.5 text-xs text-amber-400">
            retryable
          </span>
        )}
      </div>
      <p className="mt-1 text-red-400/80">{entry.hint}</p>
      {diagnosticId && (
        <p className="mt-2 font-mono text-xs text-gray-600">ID: {diagnosticId}</p>
      )}
    </div>
  )
}
