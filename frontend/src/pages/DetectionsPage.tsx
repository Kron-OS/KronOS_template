import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { getDetections } from '../api/detections'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import { TriageStatePill } from '../components/TriageStatePill'
import { RiskScorePill } from '../components/RiskScorePill'
import type { Detection, DetectionTriageState } from '../types'

const FILTERS: Array<{ id: DetectionTriageState | 'ALL'; label: string }> = [
  { id: 'ALL', label: 'All' },
  { id: 'NEW', label: 'New' },
  { id: 'INVESTIGATING', label: 'Investigating' },
  { id: 'TRUE_POSITIVE', label: 'True Positive' },
  { id: 'FALSE_POSITIVE', label: 'False Positive' },
]

// Matches SIGMA_SEVERITY_LEVELS (src/domain/detection.py) exactly -- the
// real Sigma `level:` vocabulary, not a made-up UI-only list.
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

function DetectionRow({ d }: { d: Detection }) {
  return (
    <Link
      to="/detections/$detectionId"
      params={{ detectionId: d.id }}
      className="grid grid-cols-[1fr_auto_auto_auto] items-center gap-4 border-b border-gray-200 px-4 py-3 hover:bg-gray-100 dark:border-gray-800 dark:hover:bg-gray-900/40"
    >
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-gray-900 dark:text-gray-100">
          {d.ruleMatches[0]?.ruleName ?? d.ruleMatches[0]?.ruleId ?? d.detectorName}
        </p>
        <p className="mt-0.5 truncate text-xs text-gray-500">
          {d.detectorName} · {formatDateTime(d.findingTimestamp)}
        </p>
        {d.attackTags.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-1">
            {d.attackTags.map((tag) => (
              <span
                key={tag}
                className="rounded bg-gray-200 px-1.5 py-0.5 font-mono text-[10px] text-gray-600 dark:bg-gray-800 dark:text-gray-400"
              >
                {tag}
              </span>
            ))}
          </div>
        )}
      </div>
      <span className="shrink-0 text-xs text-gray-500">
        {d.ruleMatches.length} rule{d.ruleMatches.length !== 1 ? 's' : ''}
      </span>
      <RiskScorePill score={d.riskScore} className="shrink-0" />
      <TriageStatePill state={d.triageState} className="shrink-0" />
    </Link>
  )
}

export function DetectionsPage() {
  const [filter, setFilter] = useState<DetectionTriageState | 'ALL'>('ALL')
  const [severity, setSeverity] = useState<string>('ALL')
  const [searchInput, setSearchInput] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [page, setPage] = useState(1)
  const pageSize = 25

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(searchInput.trim()), 300)
    return () => clearTimeout(timer)
  }, [searchInput])

  const { data, isLoading, error } = useQuery({
    queryKey: ['detections', filter, severity, debouncedQuery, page],
    queryFn: () =>
      getDetections({
        triageState: filter === 'ALL' ? undefined : filter,
        severity: severity === 'ALL' ? undefined : severity,
        q: debouncedQuery || undefined,
        page,
        pageSize,
      }),
    staleTime: 15_000,
  })

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">Detections</h1>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex gap-1">
          {FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => { setFilter(f.id); setPage(1) }}
              className={`rounded px-3 py-1.5 text-xs font-medium transition-colors ${
                filter === f.id
                  ? 'bg-indigo-600 text-white'
                  : 'text-gray-600 hover:bg-gray-200 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-200'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        <select
          aria-label="Filter by severity"
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); setPage(1) }}
          className="rounded border border-gray-300 bg-white px-2 py-1.5 text-xs text-gray-700 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300"
        >
          <option value="ALL">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>

        <input
          type="search"
          aria-label="Search detections"
          placeholder="Search rule or detector name…"
          value={searchInput}
          onChange={(e) => { setSearchInput(e.target.value); setPage(1) }}
          className="w-64 rounded border border-gray-300 bg-white px-2 py-1.5 text-xs text-gray-700 placeholder:text-gray-400 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300"
        />
      </div>

      {isLoading && (
        <div className="flex justify-center py-16">
          <Spinner size="lg" />
        </div>
      )}

      {error && <ErrorBanner message="Failed to load detections." />}

      {data && (
        <>
          <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-800">
            {data.items.map((d) => (
              <DetectionRow key={d.id} d={d} />
            ))}
            {data.items.length === 0 && (
              <p className="py-12 text-center text-sm text-gray-500">
                {filter === 'ALL' && severity === 'ALL' && !debouncedQuery
                  ? 'No detections yet. Detections appear here once Security Analytics findings are synced for your organization.'
                  : 'No detections match the current filters.'}
              </p>
            )}
          </div>
          {data.total > pageSize && (
            <div className="mt-4 flex items-center justify-between text-sm text-gray-500">
              <span>{data.total} total</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="rounded px-3 py-1 hover:bg-gray-200 disabled:opacity-40 dark:hover:bg-gray-800"
                >
                  Previous
                </button>
                <button
                  type="button"
                  onClick={() => setPage((p) => p + 1)}
                  disabled={page * pageSize >= data.total}
                  className="rounded px-3 py-1 hover:bg-gray-200 disabled:opacity-40 dark:hover:bg-gray-800"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
