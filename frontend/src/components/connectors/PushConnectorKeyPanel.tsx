import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  listIntegrationSourceKeys,
  provisionIntegrationSourceKey,
  revokeIntegrationSourceKey,
} from '../../api/integrationSources'
import {
  stashPendingStepUpForm,
  takePendingStepUpForm,
  clearPendingStepUpForm,
} from '../../lib/stepUpFormPersistence'
import { Spinner } from '../Spinner'
import { ErrorBanner } from '../ErrorBanner'
import { ConfirmDialog } from '../ConfirmDialog'
import type { ConnectorDefinition } from '../../types'

interface PushConnectorKeyPanelProps {
  definition: ConnectorDefinition
  onClose: () => void
}

/**
 * PUSH connector (Wazuh/Suricata/Zeek) self-service API-key management.
 * Wraps the existing, already-working `admin_integration_sources.py`
 * routes -- POST .../provision (step-up gated), GET "" (list, org-scoped),
 * DELETE .../{source_type}/{source_id} (step-up gated). No backend
 * changes needed; this UI simply never existed before this pass.
 *
 * An org can have more than one instance of the same source_type (e.g.
 * two independent Wazuh managers), each identified by its own `sourceId`
 * -- so this panel lists every instance for this connector, not just one.
 */
export function PushConnectorKeyPanel({ definition, onClose }: PushConnectorKeyPanelProps) {
  const queryClient = useQueryClient()
  const stepUpKey = `push-key-${definition.sourceType}`

  const { data: allKeys, isLoading } = useQuery({
    queryKey: ['integrationSourceKeys'],
    queryFn: listIntegrationSourceKeys,
  })
  const keys = (allKeys ?? []).filter((k) => k.sourceType === definition.sourceType)

  const [newSourceId, setNewSourceId] = useState(
    () => takePendingStepUpForm<{ sourceId: string }>(stepUpKey)?.sourceId ?? '',
  )
  const [revealedKey, setRevealedKey] = useState<{ sourceId: string; apiKey: string } | null>(null)
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const provisionMutation = useMutation({
    mutationFn: (sourceId: string) => provisionIntegrationSourceKey(definition.sourceType, sourceId),
    onSuccess: (result) => {
      clearPendingStepUpForm(stepUpKey)
      setNewSourceId('')
      setRevealedKey({ sourceId: result.sourceId, apiKey: result.apiKey })
      queryClient.invalidateQueries({ queryKey: ['integrationSourceKeys'] })
    },
  })
  const revokeMutation = useMutation({
    mutationFn: (sourceId: string) => revokeIntegrationSourceKey(definition.sourceType, sourceId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['integrationSourceKeys'] }),
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-lg border border-gray-300 bg-white p-6 shadow-xl dark:border-gray-700 dark:bg-gray-900">
        <h2 className="mb-4 text-base font-semibold text-gray-900 dark:text-gray-100">
          {definition.displayName} — API Keys
        </h2>

        {definition.assetSetupNotes && (
          <div className="mb-4 rounded border border-blue-200 bg-blue-50 p-3 text-xs text-blue-900 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-200">
            <p className="mb-1 font-semibold">On your side, you'll need to:</p>
            <p>{definition.assetSetupNotes}</p>
          </div>
        )}

        {revealedKey && (
          <div className="mb-4 rounded border border-amber-300 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-950">
            <p className="mb-2 text-xs font-medium text-amber-800 dark:text-amber-300">
              Copy this key now — it will not be shown again.
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 overflow-x-auto rounded bg-white px-2 py-1 text-xs text-gray-900 dark:bg-gray-950 dark:text-gray-100">
                {revealedKey.apiKey}
              </code>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(revealedKey.apiKey)
                  setCopied(true)
                  setTimeout(() => setCopied(false), 2000)
                }}
                className="rounded border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
              >
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <p className="mt-2 text-xs text-amber-800 dark:text-amber-300">
              Send it in the <code>X-KronOS-Source-Key</code> header on requests to{' '}
              <code>POST /api/integrations/push/{definition.sourceType}</code>.
            </p>
            <button
              type="button"
              onClick={() => setRevealedKey(null)}
              className="mt-2 text-xs text-gray-600 underline dark:text-gray-400"
            >
              Dismiss
            </button>
          </div>
        )}

        {provisionMutation.isError && <ErrorBanner message="Failed to provision API key." />}

        {isLoading ? (
          <Spinner className="my-4" />
        ) : (
          <div className="mb-4 divide-y divide-gray-200 rounded border border-gray-200 dark:divide-gray-800 dark:border-gray-800">
            {keys.length === 0 && (
              <p className="p-3 text-sm text-gray-500">No API keys provisioned yet.</p>
            )}
            {keys.map((k) => (
              <div key={k.sourceId} className="flex items-center justify-between p-3 text-sm">
                <div>
                  <p className="font-medium text-gray-900 dark:text-gray-100">{k.sourceId}</p>
                  <p className="text-xs text-gray-500">
                    {k.revokedAt ? `Revoked ${new Date(k.revokedAt).toLocaleDateString()}` : 'Active'}
                  </p>
                </div>
                {!k.revokedAt && (
                  <button
                    type="button"
                    onClick={() => setConfirmRevoke(k.sourceId)}
                    className="rounded border border-red-300 px-2 py-1 text-xs text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                  >
                    Revoke
                  </button>
                )}
              </div>
            ))}
          </div>
        )}

        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (!newSourceId.trim()) return
            stashPendingStepUpForm(stepUpKey, { sourceId: newSourceId })
            provisionMutation.mutate(newSourceId.trim())
          }}
          className="flex items-end gap-2"
        >
          <div className="flex-1">
            <label htmlFor="new-source-id" className="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">
              New instance name (e.g. "{definition.sourceType}-manager-1")
            </label>
            <input
              id="new-source-id"
              type="text"
              value={newSourceId}
              onChange={(e) => setNewSourceId(e.target.value)}
              className="w-full rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
            />
          </div>
          <button
            type="submit"
            disabled={provisionMutation.isPending || !newSourceId.trim()}
            className="flex items-center gap-2 rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
          >
            {provisionMutation.isPending && <Spinner size="sm" />}
            Generate key
          </button>
        </form>

        <div className="mt-6 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded px-4 py-2 text-sm text-gray-700 hover:bg-gray-200 dark:text-gray-300 dark:hover:bg-gray-800"
          >
            Close
          </button>
        </div>

        <ConfirmDialog
          open={confirmRevoke != null}
          title="Revoke this API key?"
          message="Any system still using this key will immediately stop being able to push events. This cannot be undone."
          confirmLabel="Revoke"
          onConfirm={() => {
            if (confirmRevoke) revokeMutation.mutate(confirmRevoke)
            setConfirmRevoke(null)
          }}
          onCancel={() => setConfirmRevoke(null)}
        />
      </div>
    </div>
  )
}
