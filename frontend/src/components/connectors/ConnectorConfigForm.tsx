import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  deleteConnectorConfig,
  disableConnectorConfig,
  enableConnectorConfig,
  getConnectorConfig,
  putConnectorConfig,
} from '../../api/connectors'
import {
  stashPendingStepUpForm,
  takePendingStepUpForm,
  clearPendingStepUpForm,
} from '../../lib/stepUpFormPersistence'
import { Spinner } from '../Spinner'
import { ErrorBanner } from '../ErrorBanner'
import { ConfirmDialog } from '../ConfirmDialog'
import type { ConnectorDefinition } from '../../types'

interface ConnectorConfigFormProps {
  definition: ConnectorDefinition
  onClose: () => void
}

/**
 * Dynamic form generated from `ConnectorDefinition.parameters` -- one input
 * per parameter, secret fields as `type="password"` and never pre-filled
 * from `GET config` (that endpoint structurally never returns secret
 * values, see `ConnectorConfigSummary`'s own docstring on the backend).
 *
 * Step-up: `apiClient`'s global axios interceptor already transparently
 * handles the 401 + aal2 challenge and replays the request -- this only
 * needs to preserve in-progress form state across that redirect, same
 * idiom as `AdminPage.tsx`'s `QuotaSection`, keyed per source_type since
 * more than one connector's form could be mid-edit across a redirect.
 */
export function ConnectorConfigForm({ definition, onClose }: ConnectorConfigFormProps) {
  const queryClient = useQueryClient()
  const stepUpKey = `connector-config-${definition.sourceType}`

  const { data: existing, isLoading } = useQuery({
    queryKey: ['connectorConfig', definition.sourceType],
    queryFn: () => getConnectorConfig(definition.sourceType),
  })

  const [values, setValues] = useState<Record<string, string>>(() => {
    const pending = takePendingStepUpForm<Record<string, string>>(stepUpKey)
    if (pending) return pending
    const seed: Record<string, string> = {}
    for (const p of definition.parameters) {
      if (!p.secret && p.default) seed[p.name] = p.default
    }
    return seed
  })
  const [confirmDelete, setConfirmDelete] = useState(false)

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['connectorConfig', definition.sourceType] })
    queryClient.invalidateQueries({ queryKey: ['connectorConfigs'] })
    queryClient.invalidateQueries({ queryKey: ['connectorStatus'] })
  }

  const saveMutation = useMutation({
    mutationFn: (v: Record<string, string>) => putConnectorConfig(definition.sourceType, v),
    onSuccess: () => {
      clearPendingStepUpForm(stepUpKey)
      invalidate()
    },
  })
  const deleteMutation = useMutation({
    mutationFn: () => deleteConnectorConfig(definition.sourceType),
    onSuccess: () => {
      invalidate()
      onClose()
    },
  })
  const disableMutation = useMutation({
    mutationFn: () => disableConnectorConfig(definition.sourceType),
    onSuccess: invalidate,
  })
  const enableMutation = useMutation({
    mutationFn: () => enableConnectorConfig(definition.sourceType),
    onSuccess: invalidate,
  })

  if (isLoading) return <Spinner className="my-4" />

  const missingRequired = definition.parameters
    .filter((p) => p.required && !existing?.nonSecretFields[p.name] && !p.secret)
    .some((p) => !values[p.name])
  const secretsMissingOnFirstSave = definition.parameters
    .filter((p) => p.secret && p.required)
    .some((p) => !existing?.secretFieldNames.includes(p.name) && !values[p.name])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-lg border border-gray-300 bg-white p-6 shadow-xl dark:border-gray-700 dark:bg-gray-900">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">
            Configure {definition.displayName}
          </h2>
          {existing && (
            <span
              className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                existing.enabled
                  ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'
                  : 'bg-gray-200 text-gray-600 dark:bg-gray-800 dark:text-gray-400'
              }`}
            >
              {existing.enabled ? 'Enabled' : existing.autoDisabledAt ? 'Auto-disabled' : 'Disabled'}
            </span>
          )}
        </div>

        {definition.assetSetupNotes && (
          <div className="mb-4 rounded border border-blue-200 bg-blue-50 p-3 text-xs text-blue-900 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-200">
            <p className="mb-1 font-semibold">On your side, you'll need to:</p>
            <p>{definition.assetSetupNotes}</p>
          </div>
        )}

        {saveMutation.isError && <ErrorBanner message="Failed to save connector config." />}

        <form
          onSubmit={(e) => {
            e.preventDefault()
            stashPendingStepUpForm(stepUpKey, values)
            saveMutation.mutate(values)
          }}
          className="space-y-4"
        >
          {definition.parameters.map((p) => (
            <div key={p.name}>
              <label
                htmlFor={`param-${p.name}`}
                className="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300"
              >
                {p.label}
                {p.required && <span className="text-red-500"> *</span>}
                {p.secret && existing?.secretFieldNames.includes(p.name) && (
                  <span className="ml-2 text-gray-500">(configured — leave blank to keep)</span>
                )}
              </label>
              <input
                id={`param-${p.name}`}
                type={p.secret ? 'password' : 'text'}
                value={values[p.name] ?? ''}
                onChange={(e) => setValues((v) => ({ ...v, [p.name]: e.target.value }))}
                placeholder={p.default ?? undefined}
                className="w-full rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
              />
            </div>
          ))}

          {definition.parameters.length === 0 && (
            <p className="text-sm text-gray-500">
              This connector has no configurable parameters — see the status table for its
              self-service API key.
            </p>
          )}

          <div className="flex items-center justify-between pt-2">
            <div className="flex gap-2">
              {existing && (
                <button
                  type="button"
                  onClick={() => setConfirmDelete(true)}
                  className="rounded border border-red-300 px-3 py-1.5 text-sm text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                >
                  Remove
                </button>
              )}
              {existing?.enabled && (
                <button
                  type="button"
                  onClick={() => disableMutation.mutate()}
                  disabled={disableMutation.isPending}
                  className="rounded border border-gray-300 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
                >
                  Disable
                </button>
              )}
              {existing && !existing.enabled && (
                <button
                  type="button"
                  onClick={() => enableMutation.mutate()}
                  disabled={enableMutation.isPending}
                  className="rounded border border-green-300 px-3 py-1.5 text-sm text-green-700 hover:bg-green-50 dark:border-green-800 dark:text-green-400 dark:hover:bg-green-950"
                >
                  Enable
                </button>
              )}
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={onClose}
                className="rounded px-4 py-2 text-sm text-gray-700 hover:bg-gray-200 dark:text-gray-300 dark:hover:bg-gray-800"
              >
                Close
              </button>
              <button
                type="submit"
                disabled={
                  saveMutation.isPending ||
                  (!existing && (missingRequired || secretsMissingOnFirstSave))
                }
                className="flex items-center gap-2 rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
              >
                {saveMutation.isPending && <Spinner size="sm" />}
                Save
              </button>
            </div>
          </div>
        </form>

        <ConfirmDialog
          open={confirmDelete}
          title={`Remove ${definition.displayName}?`}
          message="This permanently deletes this connector's stored configuration and secrets for your organization. This cannot be undone."
          confirmLabel="Remove"
          onConfirm={() => {
            setConfirmDelete(false)
            deleteMutation.mutate()
          }}
          onCancel={() => setConfirmDelete(false)}
        />
      </div>
    </div>
  )
}
