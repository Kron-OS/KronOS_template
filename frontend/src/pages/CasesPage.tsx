import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { getCases, createCase, type ListCasesParams } from '../api/cases'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import type { Case, CaseStatus } from '../types'
import type { CasesSearch } from '../App'

const STATUS_FILTERS: Array<{ id: CaseStatus | 'ALL'; label: string }> = [
  { id: 'ALL', label: 'All' },
  { id: 'open', label: 'Open' },
  { id: 'closed', label: 'Closed' },
  { id: 'archived', label: 'Archived' },
]

const SORT_OPTIONS: Array<{ value: string; label: string; sortBy: ListCasesParams['sortBy']; sortOrder: ListCasesParams['sortOrder'] }> = [
  { value: 'createdAt-desc', label: 'Newest first', sortBy: 'createdAt', sortOrder: 'desc' },
  { value: 'createdAt-asc', label: 'Oldest first', sortBy: 'createdAt', sortOrder: 'asc' },
  { value: 'title-asc', label: 'Title (A-Z)', sortBy: 'title', sortOrder: 'asc' },
]

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  })
}

function CaseCard({ c }: { c: Case }) {
  return (
    <Link
      to="/cases/$caseId"
      params={{ caseId: c.id }}
      className="block rounded-lg border border-gray-200 bg-white p-5 transition-colors hover:border-indigo-300 hover:bg-gray-100 dark:border-gray-800 dark:bg-gray-900 dark:hover:border-indigo-700 dark:hover:bg-gray-800/60"
    >
      <div className="mb-1 flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold leading-tight text-gray-900 dark:text-gray-100">
            {c.title}
          </h3>
          {c.status === 'archived' && (
            <span className="shrink-0 rounded bg-red-100 px-2 py-0.5 text-xs font-medium text-red-700 dark:bg-red-950 dark:text-red-400">
              Archived
            </span>
          )}
        </div>
        <span className="shrink-0 rounded bg-gray-200 px-2 py-0.5 font-mono text-xs text-gray-600 dark:bg-gray-800 dark:text-gray-400">
          {c.reference}
        </span>
      </div>
      {c.description && (
        <p className="mb-3 text-xs text-gray-500 line-clamp-2">{c.description}</p>
      )}
      <div className="flex items-center justify-between text-xs text-gray-500">
        <span>{c.evidenceCount} item{c.evidenceCount !== 1 ? 's' : ''}</span>
        <span className="flex items-center gap-2">
          {c.classification && c.classification !== 'UNCLASSIFIED' && (
            <span className="rounded bg-amber-100 px-1.5 py-0.5 font-mono text-[10px] text-amber-800 dark:bg-amber-950 dark:text-amber-400">
              {c.classification}
            </span>
          )}
          {formatDate(c.createdAt)}
        </span>
      </div>
    </Link>
  )
}

interface CreateCaseModalProps {
  open: boolean
  onClose: () => void
}

function CreateCaseModal({ open, onClose }: CreateCaseModalProps) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState({ title: '', reference: '', description: '' })
  const mutation = useMutation({
    mutationFn: createCase,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['cases'] })
      setForm({ title: '', reference: '', description: '' })
      onClose()
    },
  })

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-md rounded-lg border border-gray-300 bg-white p-6 shadow-xl dark:border-gray-700 dark:bg-gray-900">
        <h2 className="mb-4 text-base font-semibold text-gray-900 dark:text-gray-100">New Case</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            mutation.mutate(form)
          }}
          className="space-y-4"
        >
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400" htmlFor="case-title">
              Title
            </label>
            <input
              id="case-title"
              required
              value={form.title}
              onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))}
              className="w-full rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder-gray-500 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
              placeholder="Investigation title"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400" htmlFor="case-ref">
              Reference
            </label>
            <input
              id="case-ref"
              required
              value={form.reference}
              onChange={(e) => setForm((f) => ({ ...f, reference: e.target.value }))}
              className="w-full rounded border border-gray-300 bg-white px-3 py-2 font-mono text-sm text-gray-900 placeholder-gray-500 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
              placeholder="CASE-2026-001"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400" htmlFor="case-desc">
              Description
            </label>
            <textarea
              id="case-desc"
              rows={3}
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
              className="w-full rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder-gray-500 focus:border-indigo-500 focus:outline-none resize-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
              placeholder="Brief description (optional)"
            />
          </div>
          {mutation.isError && (
            <ErrorBanner message="Failed to create case. Please try again." />
          )}
          <div className="flex justify-end gap-3 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="rounded px-4 py-2 text-sm text-gray-600 hover:bg-gray-200 dark:text-gray-400 dark:hover:bg-gray-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={mutation.isPending}
              className="flex items-center gap-2 rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
            >
              {mutation.isPending && <Spinner size="sm" />}
              Create
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

const PAGE_SIZE = 24

export function CasesPage() {
  const [showCreate, setShowCreate] = useState(false)
  const navigate = useNavigate({ from: '/cases' })
  const search = useSearch({ from: '/cases' })
  const [searchInput, setSearchInput] = useState(search.q ?? '')

  const status = search.status ?? 'ALL'
  const classification = search.classification ?? ''
  const sortBy = search.sortBy ?? 'createdAt'
  const sortOrder = search.sortOrder ?? 'desc'
  const page = search.page ?? 1
  const sortValue = `${sortBy}-${sortOrder}`

  // Keep the free-text input debounced before it lands in the URL, mirroring
  // DetectionsPage's own search-input pattern.
  useEffect(() => {
    const timer = setTimeout(() => {
      const trimmed = searchInput.trim()
      if (trimmed !== (search.q ?? '')) {
        void navigate({
          search: (prev) => ({ ...prev, q: trimmed || undefined, page: undefined }),
        })
      }
    }, 300)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchInput])

  // Changing a filter resets to page 1 (via `page: undefined`) unless the
  // patch itself explicitly sets `page` (the Previous/Next buttons below) --
  // patch is spread last so it always wins.
  function updateSearch(patch: Partial<CasesSearch>) {
    void navigate({
      search: (prev) => ({ ...prev, page: undefined, ...patch }),
    })
  }

  const { data, isLoading, error } = useQuery({
    queryKey: ['cases', search.q, status, classification, sortBy, sortOrder, page],
    queryFn: () =>
      getCases({
        q: search.q,
        status: status === 'ALL' ? undefined : (status as ListCasesParams['status']),
        classification: classification || undefined,
        sortBy: sortBy as ListCasesParams['sortBy'],
        sortOrder: sortOrder as ListCasesParams['sortOrder'],
        page,
        pageSize: PAGE_SIZE,
      }),
    staleTime: 30_000,
  })

  const isFiltered = Boolean(search.q) || status !== 'ALL' || Boolean(classification)

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">Cases</h1>
        <button
          type="button"
          onClick={() => setShowCreate(true)}
          className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
        >
          New Case
        </button>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex gap-1">
          {STATUS_FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => updateSearch({ status: f.id === 'ALL' ? undefined : f.id })}
              className={`rounded px-3 py-1.5 text-xs font-medium transition-colors ${
                status === f.id
                  ? 'bg-indigo-600 text-white'
                  : 'text-gray-600 hover:bg-gray-200 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-200'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        <input
          type="text"
          aria-label="Filter by classification"
          placeholder="Classification…"
          value={classification}
          onChange={(e) => updateSearch({ classification: e.target.value || undefined })}
          className="w-40 rounded border border-gray-300 bg-white px-2 py-1.5 text-xs text-gray-700 placeholder:text-gray-400 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300"
        />

        <select
          aria-label="Sort cases"
          value={sortValue}
          onChange={(e) => {
            const opt = SORT_OPTIONS.find((o) => o.value === e.target.value)
            if (opt) updateSearch({ sortBy: opt.sortBy, sortOrder: opt.sortOrder })
          }}
          className="rounded border border-gray-300 bg-white px-2 py-1.5 text-xs text-gray-700 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300"
        >
          {SORT_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>

        <input
          type="search"
          aria-label="Search cases"
          placeholder="Search title, description, or reference…"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          className="w-72 rounded border border-gray-300 bg-white px-2 py-1.5 text-xs text-gray-700 placeholder:text-gray-400 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300"
        />
      </div>

      {isLoading && (
        <div className="flex justify-center py-16">
          <Spinner size="lg" />
        </div>
      )}

      {error && (
        <ErrorBanner message="Failed to load cases." />
      )}

      {data && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {data.items.map((c) => (
              <CaseCard key={c.id} c={c} />
            ))}
            {data.items.length === 0 && (
              <p className="col-span-full py-12 text-center text-sm text-gray-500">
                {isFiltered ? 'No cases match the current filters.' : 'No cases yet. Create one to get started.'}
              </p>
            )}
          </div>
          {data.total > PAGE_SIZE && (
            <div className="mt-4 flex items-center justify-between text-sm text-gray-500">
              <span>{data.total} total</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => updateSearch({ page: Math.max(1, page - 1) || undefined })}
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

      <CreateCaseModal open={showCreate} onClose={() => setShowCreate(false)} />
    </div>
  )
}
