import { useState } from 'react'
import { useParams, Link } from '@tanstack/react-router'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getDetection, triageDetection } from '../api/detections'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import { TriageStatePill } from '../components/TriageStatePill'
import { nextTriageStates, triageActionLabel } from '../utils/triageFsm'
import { useAuthStore } from '../store/auth'
import type { DetectionTriageState } from '../types'

const TRIAGE_ROLES = ['org-admin', 'case-lead', 'analyst']

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

export function DetectionDetailPage() {
  const { detectionId } = useParams({ from: '/detections/$detectionId' })
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const canTriage = user?.roles.some((r) => TRIAGE_ROLES.includes(r)) ?? false
  const [pendingTarget, setPendingTarget] = useState<DetectionTriageState | null>(null)

  const { data, isLoading, error } = useQuery({
    queryKey: ['detection', detectionId],
    queryFn: () => getDetection(detectionId),
    staleTime: 15_000,
  })

  const mutation = useMutation({
    mutationFn: (target: DetectionTriageState) => triageDetection(detectionId, target),
    onSuccess: async (updated) => {
      queryClient.setQueryData(['detection', detectionId], updated)
      await queryClient.invalidateQueries({ queryKey: ['detections'] })
      setPendingTarget(null)
    },
    onError: () => setPendingTarget(null),
  })

  if (isLoading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner size="lg" />
      </div>
    )
  }

  if (error || !data) {
    return <ErrorBanner message="Failed to load detection. It may not exist, or belong to another organization." />
  }

  const actions = nextTriageStates(data.triageState)

  return (
    <div>
      <Link
        to="/detections"
        className="mb-4 inline-block text-xs text-indigo-600 hover:underline dark:text-indigo-400"
      >
        &larr; Back to Detections
      </Link>

      <div className="mb-6 flex items-start justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">
            {data.ruleMatches[0]?.ruleName ?? data.ruleMatches[0]?.ruleId ?? data.detectorName}
          </h1>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
            Detected {formatDateTime(data.findingTimestamp)} by {data.detectorName}
          </p>
        </div>
        <TriageStatePill state={data.triageState} />
      </div>

      {data.attackTags.length > 0 && (
        <div className="mb-6 flex flex-wrap gap-1.5">
          {data.attackTags.map((tag) => (
            <span
              key={tag}
              className="rounded bg-gray-200 px-2 py-1 font-mono text-xs text-gray-600 dark:bg-gray-800 dark:text-gray-400"
            >
              {tag}
            </span>
          ))}
        </div>
      )}

      <div className="mb-6 grid grid-cols-1 gap-4 rounded-lg border border-gray-200 p-4 dark:border-gray-800 sm:grid-cols-2">
        <div>
          <p className="text-xs font-medium text-gray-500">Finding ID</p>
          <p className="mt-0.5 font-mono text-xs text-gray-700 dark:text-gray-300">{data.findingId}</p>
        </div>
        <div>
          <p className="text-xs font-medium text-gray-500">Source Index</p>
          <p
            className="mt-0.5 truncate font-mono text-xs text-gray-700 dark:text-gray-300"
            title={data.sourceIndex}
          >
            {data.sourceIndex}
          </p>
        </div>
        <div>
          <p className="text-xs font-medium text-gray-500">Case</p>
          <p className="mt-0.5 text-xs text-gray-700 dark:text-gray-300">
            {data.caseId ? (
              <Link
                to="/cases/$caseId"
                params={{ caseId: data.caseId }}
                className="text-indigo-600 hover:underline dark:text-indigo-400"
              >
                {data.caseId}
              </Link>
            ) : (
              '—'
            )}
          </p>
        </div>
        <div>
          <p className="text-xs font-medium text-gray-500">Matched Documents</p>
          <p className="mt-0.5 text-xs text-gray-700 dark:text-gray-300">{data.matchedDocumentIds.length}</p>
        </div>
      </div>

      <div className="mb-6">
        <h2 className="mb-2 text-sm font-semibold text-gray-800 dark:text-gray-200">Matched Rules</h2>
        <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-800">
          {data.ruleMatches.map((m) => (
            <div
              key={m.ruleId}
              className="border-b border-gray-200 px-4 py-3 last:border-b-0 dark:border-gray-800"
            >
              <p className="text-sm text-gray-800 dark:text-gray-200">{m.ruleName ?? m.ruleId}</p>
              <p className="mt-0.5 font-mono text-xs text-gray-500">{m.ruleId}</p>
              {m.tags.length > 0 && (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {m.tags.map((tag) => (
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
          ))}
        </div>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold text-gray-800 dark:text-gray-200">Triage</h2>
        {!canTriage && (
          <p className="text-xs text-gray-500">
            Your role does not permit triaging detections (org-admin, case-lead, or analyst required).
          </p>
        )}
        {canTriage && actions.length === 0 && (
          <p className="text-xs text-gray-500">
            This detection's triage verdict is final — no further transitions are permitted.
          </p>
        )}
        {canTriage && actions.length > 0 && (
          <div className="flex gap-3">
            {actions.map((target) => (
              <button
                key={target}
                type="button"
                disabled={mutation.isPending}
                onClick={() => { setPendingTarget(target); mutation.mutate(target) }}
                className="flex items-center gap-2 rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
              >
                {mutation.isPending && pendingTarget === target && <Spinner size="sm" />}
                {triageActionLabel(target)}
              </button>
            ))}
          </div>
        )}
        {mutation.isError && (
          <div className="mt-3">
            <ErrorBanner message="Failed to update triage state. It may have already been transitioned." />
          </div>
        )}
      </div>
    </div>
  )
}
