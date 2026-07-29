import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { getCases, createCase } from '../api/cases'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import type { Case } from '../types'

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
      className="block rounded-lg border border-gray-800 bg-gray-900 p-5 hover:border-indigo-700 hover:bg-gray-800/60 transition-colors"
    >
      <div className="mb-1 flex items-start justify-between gap-2">
        <h3 className="text-sm font-semibold text-gray-100 leading-tight">{c.title}</h3>
        <span className="shrink-0 rounded bg-gray-800 px-2 py-0.5 font-mono text-xs text-gray-400">
          {c.reference}
        </span>
      </div>
      {c.description && (
        <p className="mb-3 text-xs text-gray-500 line-clamp-2">{c.description}</p>
      )}
      <div className="flex items-center justify-between text-xs text-gray-500">
        <span>{c.evidenceCount} item{c.evidenceCount !== 1 ? 's' : ''}</span>
        <span>{formatDate(c.createdAt)}</span>
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
      <div className="w-full max-w-md rounded-lg border border-gray-700 bg-gray-900 p-6 shadow-xl">
        <h2 className="mb-4 text-base font-semibold text-gray-100">New Case</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            mutation.mutate(form)
          }}
          className="space-y-4"
        >
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-400" htmlFor="case-title">
              Title
            </label>
            <input
              id="case-title"
              required
              value={form.title}
              onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-indigo-500 focus:outline-none"
              placeholder="Investigation title"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-400" htmlFor="case-ref">
              Reference
            </label>
            <input
              id="case-ref"
              required
              value={form.reference}
              onChange={(e) => setForm((f) => ({ ...f, reference: e.target.value }))}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 font-mono text-sm text-gray-100 placeholder-gray-500 focus:border-indigo-500 focus:outline-none"
              placeholder="CASE-2026-001"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-400" htmlFor="case-desc">
              Description
            </label>
            <textarea
              id="case-desc"
              rows={3}
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-indigo-500 focus:outline-none resize-none"
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
              className="rounded px-4 py-2 text-sm text-gray-400 hover:bg-gray-800"
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

export function CasesPage() {
  const [showCreate, setShowCreate] = useState(false)
  const { data, isLoading, error } = useQuery({
    queryKey: ['cases'],
    queryFn: getCases,
    staleTime: 30_000,
  })

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-100">Cases</h1>
        <button
          type="button"
          onClick={() => setShowCreate(true)}
          className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
        >
          New Case
        </button>
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
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {data.items.map((c) => (
            <CaseCard key={c.id} c={c} />
          ))}
          {data.items.length === 0 && (
            <p className="col-span-full py-12 text-center text-sm text-gray-500">
              No cases yet. Create one to get started.
            </p>
          )}
        </div>
      )}

      <CreateCaseModal open={showCreate} onClose={() => setShowCreate(false)} />
    </div>
  )
}
