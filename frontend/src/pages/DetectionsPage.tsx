import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { bulkTriageDetections, getDetections } from '../api/detections'
import { getCases } from '../api/cases'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import { TriageStatePill } from '../components/TriageStatePill'
import { RiskScorePill } from '../components/RiskScorePill'
import type { Detection, DetectionTriageState } from '../types'
import type { DetectionsSearch } from '../App'

const ALL_TRIAGE_STATES: DetectionTriageState[] = [
  'NEW', 'INVESTIGATING', 'TRUE_POSITIVE', 'FALSE_POSITIVE',
]

const TRIAGE_LABELS: Record<DetectionTriageState, string> = {
  NEW: 'New',
  INVESTIGATING: 'Investigating',
  TRUE_POSITIVE: 'True Positive',
  FALSE_POSITIVE: 'False Positive',
}

// Matches SIGMA_SEVERITY_LEVELS (src/domain/detection.py) exactly -- the
// real Sigma `level:` vocabulary, not a made-up UI-only list.
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const

// Mirrors DetectionTriageState._VALID_TRANSITIONS (src/domain/detection.py)
// -- used to only offer bulk-action buttons that are reachable from at
// least one currently-selected row's own state, so a bulk action never
// leads with a target every selected row is guaranteed to reject.
const NEXT_STATES: Record<DetectionTriageState, DetectionTriageState[]> = {
  NEW: ['INVESTIGATING'],
  INVESTIGATING: ['TRUE_POSITIVE', 'FALSE_POSITIVE'],
  TRUE_POSITIVE: [],
  FALSE_POSITIVE: [],
}

const PAGE_SIZE = 25

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

function toggleValue<T>(arr: T[], value: T): T[] {
  return arr.includes(value) ? arr.filter((v) => v !== value) : [...arr, value]
}

// YYYY-MM-DD (from <input type="date">) -> a full ISO datetime with an
// explicit UTC offset. The backend accepts a bare date fine via pydantic,
// but parses it as a naive datetime -- sending an explicit 'Z' here avoids
// relying on server-side naive-datetime normalization for a value this
// page fully controls the shape of.
function dateInputToIso(value: string, boundary: 'start' | 'end'): string | undefined {
  if (!value) return undefined
  return boundary === 'start' ? `${value}T00:00:00Z` : `${value}T23:59:59Z`
}

function isoToDateInput(iso: string | undefined): string {
  return iso ? iso.slice(0, 10) : ''
}

function PillToggle({
  active, label, onClick,
}: { active: boolean; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={`rounded px-3 py-1.5 text-xs font-medium transition-colors ${
        active
          ? 'bg-indigo-600 text-white'
          : 'text-gray-600 hover:bg-gray-200 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-200'
      }`}
    >
      {label}
    </button>
  )
}

function DetectionRow({
  d, selected, onToggleSelect,
}: { d: Detection; selected: boolean; onToggleSelect: () => void }) {
  return (
    <div
      data-testid="detection-row"
      className="flex items-center gap-3 border-b border-gray-200 px-4 py-3 hover:bg-gray-100 dark:border-gray-800 dark:hover:bg-gray-900/40"
    >
      <input
        type="checkbox"
        aria-label={`Select detection ${d.ruleMatches[0]?.ruleName ?? d.detectorName}`}
        checked={selected}
        onChange={onToggleSelect}
        className="h-4 w-4 shrink-0 rounded border-gray-300"
      />
      <Link
        to="/detections/$detectionId"
        params={{ detectionId: d.id }}
        className="grid min-w-0 flex-1 grid-cols-[1fr_auto_auto_auto] items-center gap-4"
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
    </div>
  )
}

export function DetectionsPage() {
  const navigate = useNavigate({ from: '/detections' })
  const search = useSearch({ from: '/detections' })
  const queryClient = useQueryClient()

  // Default view (no explicit `triageState` in the URL at all): NEW only.
  // An explicit selection -- including all four states, or none -- is a
  // real, distinguishable-from-absent value once the analyst has touched
  // the filter, so it is never silently overridden back to this default.
  const selectedTriageStates = search.triageState ?? ['NEW']
  const selectedSeverities = search.severity ?? []
  const caseId = search.caseId
  const page = search.page ?? 1

  const [searchInput, setSearchInput] = useState(search.q ?? '')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkMessage, setBulkMessage] = useState<string | null>(null)

  useEffect(() => {
    const timer = setTimeout(() => {
      const trimmed = searchInput.trim()
      if (trimmed !== (search.q ?? '')) {
        void navigate({ search: (prev) => ({ ...prev, q: trimmed || undefined, page: undefined }) })
      }
    }, 300)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchInput])

  function updateSearch(patch: Partial<DetectionsSearch>) {
    void navigate({ search: (prev) => ({ ...prev, page: undefined, ...patch }) })
  }

  const { data, isLoading, error } = useQuery({
    queryKey: [
      'detections', selectedTriageStates, selectedSeverities, caseId,
      search.q, search.dateFrom, search.dateTo, page,
    ],
    queryFn: () =>
      getDetections({
        triageState: selectedTriageStates.length > 0 ? selectedTriageStates : undefined,
        severity: selectedSeverities.length > 0 ? selectedSeverities : undefined,
        caseId,
        q: search.q,
        dateFrom: search.dateFrom,
        dateTo: search.dateTo,
        page,
        pageSize: PAGE_SIZE,
      }),
    staleTime: 15_000,
  })

  const { data: casesForFilter } = useQuery({
    queryKey: ['cases-for-filter'],
    queryFn: () => getCases({ pageSize: 200 }),
    staleTime: 60_000,
  })

  // Selection is page-scoped -- switching filters/page while rows are
  // selected would otherwise silently retain ids that are no longer even
  // visible.
  const triageStateKey = selectedTriageStates.join(',')
  const severityKey = selectedSeverities.join(',')
  useEffect(() => {
    setSelectedIds(new Set())
  }, [triageStateKey, severityKey, caseId, search.q, search.dateFrom, search.dateTo, page])

  const selectedRows = useMemo(
    () => (data?.items ?? []).filter((d) => selectedIds.has(d.id)),
    [data, selectedIds],
  )
  const possibleTargets = useMemo(() => {
    const targets = new Set<DetectionTriageState>()
    for (const row of selectedRows) {
      for (const t of NEXT_STATES[row.triageState]) targets.add(t)
    }
    return Array.from(targets)
  }, [selectedRows])

  const bulkMutation = useMutation({
    mutationFn: (targetState: DetectionTriageState) =>
      bulkTriageDetections(Array.from(selectedIds), targetState),
    onSuccess: async (results) => {
      const okCount = results.filter((r) => r.status === 'ok').length
      const errorCount = results.length - okCount
      setBulkMessage(
        errorCount === 0
          ? `${okCount} detection${okCount !== 1 ? 's' : ''} updated.`
          : `${okCount} updated, ${errorCount} skipped (not a valid transition for their current state).`,
      )
      setSelectedIds(new Set())
      await queryClient.invalidateQueries({ queryKey: ['detections'] })
    },
  })

  function toggleRow(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleSelectAllOnPage() {
    if (!data) return
    setSelectedIds((prev) =>
      prev.size === data.items.length ? new Set() : new Set(data.items.map((d) => d.id)),
    )
  }

  const isDefaultView = selectedTriageStates.length === 1 && selectedTriageStates[0] === 'NEW'
    && selectedSeverities.length === 0 && !caseId && !search.q && !search.dateFrom && !search.dateTo

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">Detections</h1>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1" data-testid="triage-state-filters">
          {ALL_TRIAGE_STATES.map((state) => (
            <PillToggle
              key={state}
              label={TRIAGE_LABELS[state]}
              active={selectedTriageStates.includes(state)}
              onClick={() => updateSearch({ triageState: toggleValue(selectedTriageStates, state) })}
            />
          ))}
          <PillToggle
            label="All"
            active={selectedTriageStates.length === ALL_TRIAGE_STATES.length}
            onClick={() => updateSearch({ triageState: [...ALL_TRIAGE_STATES] })}
          />
        </div>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1" data-testid="severity-filters">
          {SEVERITIES.map((s) => (
            <PillToggle
              key={s}
              label={s.charAt(0).toUpperCase() + s.slice(1)}
              active={selectedSeverities.includes(s)}
              onClick={() => updateSearch({ severity: toggleValue(selectedSeverities, s) })}
            />
          ))}
        </div>

        <select
          aria-label="Filter by case"
          value={caseId ?? ''}
          onChange={(e) => updateSearch({ caseId: e.target.value || undefined })}
          className="rounded border border-gray-300 bg-white px-2 py-1.5 text-xs text-gray-700 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300"
        >
          <option value="">All cases</option>
          {casesForFilter?.items.map((c) => (
            <option key={c.id} value={c.id}>
              {c.title}
            </option>
          ))}
        </select>

        <div className="flex items-center gap-1 text-xs text-gray-500">
          <label htmlFor="date-from" className="sr-only">From date</label>
          <input
            id="date-from"
            type="date"
            value={isoToDateInput(search.dateFrom)}
            onChange={(e) => updateSearch({ dateFrom: dateInputToIso(e.target.value, 'start') })}
            className="rounded border border-gray-300 bg-white px-2 py-1.5 text-xs text-gray-700 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300"
          />
          <span>to</span>
          <label htmlFor="date-to" className="sr-only">To date</label>
          <input
            id="date-to"
            type="date"
            value={isoToDateInput(search.dateTo)}
            onChange={(e) => updateSearch({ dateTo: dateInputToIso(e.target.value, 'end') })}
            className="rounded border border-gray-300 bg-white px-2 py-1.5 text-xs text-gray-700 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300"
          />
        </div>

        <input
          type="search"
          aria-label="Search detections"
          placeholder="Search rule or detector name…"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          className="w-64 rounded border border-gray-300 bg-white px-2 py-1.5 text-xs text-gray-700 placeholder:text-gray-400 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300"
        />
      </div>

      {selectedIds.size > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-3 rounded-lg border border-indigo-300 bg-indigo-50 px-4 py-2 text-sm dark:border-indigo-800 dark:bg-indigo-950">
          <span className="font-medium text-indigo-900 dark:text-indigo-200">
            {selectedIds.size} selected
          </span>
          {possibleTargets.length === 0 ? (
            <span className="text-xs text-indigo-700 dark:text-indigo-300">
              No valid triage transition for the selected alerts.
            </span>
          ) : (
            <div className="flex gap-2">
              {possibleTargets.map((t) => (
                <button
                  key={t}
                  type="button"
                  disabled={bulkMutation.isPending}
                  onClick={() => bulkMutation.mutate(t)}
                  className="rounded bg-indigo-600 px-3 py-1 text-xs font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
                >
                  Mark {TRIAGE_LABELS[t]}
                </button>
              ))}
            </div>
          )}
          <button
            type="button"
            onClick={() => setSelectedIds(new Set())}
            className="ml-auto text-xs text-indigo-700 hover:underline dark:text-indigo-300"
          >
            Clear selection
          </button>
        </div>
      )}

      {bulkMessage && (
        <div className="mb-3 flex items-center justify-between rounded-lg border border-gray-200 bg-gray-100 px-4 py-2 text-xs text-gray-700 dark:border-gray-800 dark:bg-gray-900 dark:text-gray-300">
          <span>{bulkMessage}</span>
          <button type="button" onClick={() => setBulkMessage(null)} className="text-gray-500 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {isLoading && (
        <div className="flex justify-center py-16">
          <Spinner size="lg" />
        </div>
      )}

      {error && <ErrorBanner message="Failed to load detections." />}

      {data && (
        <>
          <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-800">
            {data.items.length > 0 && (
              <div className="flex items-center gap-3 border-b border-gray-200 bg-gray-50 px-4 py-2 dark:border-gray-800 dark:bg-gray-900/40">
                <input
                  type="checkbox"
                  aria-label="Select all detections on this page"
                  checked={selectedIds.size === data.items.length}
                  onChange={toggleSelectAllOnPage}
                  className="h-4 w-4 rounded border-gray-300"
                />
                <span className="text-xs text-gray-500">Select all on this page</span>
              </div>
            )}
            {data.items.map((d) => (
              <DetectionRow
                key={d.id}
                d={d}
                selected={selectedIds.has(d.id)}
                onToggleSelect={() => toggleRow(d.id)}
              />
            ))}
            {data.items.length === 0 && (
              <p className="py-12 text-center text-sm text-gray-500">
                {isDefaultView
                  ? 'No new detections. Detections appear here once Security Analytics findings are synced for your organization.'
                  : 'No detections match the current filters.'}
              </p>
            )}
          </div>
          {data.total > PAGE_SIZE && (
            <div className="mt-4 flex items-center justify-between text-sm text-gray-500">
              <span>{data.total} total</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => updateSearch({ page: Math.max(1, page - 1) })}
                  disabled={page === 1}
                  className="rounded px-3 py-1 hover:bg-gray-200 disabled:opacity-40 dark:hover:bg-gray-800"
                >
                  Previous
                </button>
                <button
                  type="button"
                  onClick={() => updateSearch({ page: page + 1 })}
                  disabled={page * PAGE_SIZE >= data.total}
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
