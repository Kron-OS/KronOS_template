import { useQuery, useQueryClient } from '@tanstack/react-query'
import { getConnectorStatus } from '../api/connectors'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import { ConnectorStatusPill } from '../components/ConnectorStatusPill'
import type { ConnectorStatus } from '../types'

function formatDateTime(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

// The one place in this page that has to say, out loud, "you can't change
// this from here" for POLL connectors -- see admin_connector_status.py's
// own module docstring for why this can never say "self-service" for a
// poll-mode entry (only Microsoft Defender today, globally configured via
// Settings.defender_poll_org_id, not per-org).
function ConfigScopeBadge({ connector }: { connector: ConnectorStatus }) {
  if (connector.selfService) {
    return (
      <span className="inline-flex items-center rounded-full border border-indigo-300 bg-indigo-100 px-2.5 py-0.5 text-xs font-medium text-indigo-700 dark:border-indigo-700 dark:bg-indigo-900 dark:text-indigo-300">
        Self-service (this org)
      </span>
    )
  }
  return (
    <span className="inline-flex items-center rounded-full border border-gray-300 bg-gray-200 px-2.5 py-0.5 text-xs font-medium text-gray-600 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-400">
      Platform-configured (global)
    </span>
  )
}

function ConnectorRow({ connector }: { connector: ConnectorStatus }) {
  const lastActivity = connector.mode === 'push' ? connector.lastIngestedAt : connector.lastPolledAt
  return (
    <tr className="hover:bg-gray-100 dark:hover:bg-gray-900/40">
      <td className="px-4 py-3">
        <p className="font-medium text-gray-900 dark:text-gray-100">{connector.sourceId}</p>
        <p className="text-xs text-gray-500">{connector.sourceType}</p>
      </td>
      <td className="px-4 py-3">
        <ConfigScopeBadge connector={connector} />
      </td>
      <td className="px-4 py-3">
        <ConnectorStatusPill state={connector.status} />
      </td>
      <td className="px-4 py-3 text-xs text-gray-600 dark:text-gray-400">
        {formatDateTime(lastActivity)}
      </td>
      <td className="px-4 py-3 text-xs text-gray-600 dark:text-gray-400">
        {connector.lastPollFailedAt ? (
          <span className="text-red-600 dark:text-red-400">
            {formatDateTime(connector.lastPollFailedAt)}
            {connector.lastFailureReason && (
              <span className="block text-gray-500 dark:text-gray-500">
                {connector.lastFailureReason}
              </span>
            )}
          </span>
        ) : (
          '—'
        )}
      </td>
      <td className="max-w-xs px-4 py-3 text-xs text-gray-500 dark:text-gray-500">
        {connector.note}
      </td>
    </tr>
  )
}

export function ConnectorStatusPage() {
  const queryClient = useQueryClient()
  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ['connectorStatus'],
    queryFn: getConnectorStatus,
    staleTime: 30_000,
  })

  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">Connector Status</h1>
        <button
          type="button"
          onClick={() => queryClient.invalidateQueries({ queryKey: ['connectorStatus'] })}
          disabled={isFetching}
          className="flex items-center gap-2 rounded-md border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-200 disabled:opacity-60 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
        >
          {isFetching && <Spinner size="sm" />}
          Refresh
        </button>
      </div>
      <p className="mb-6 max-w-3xl text-sm text-gray-600 dark:text-gray-400">
        Inbound EDR/SIEM connectors for this organization. PUSH connectors (Wazuh, Suricata/Zeek,
        generic webhooks) are self-service — provision or revoke an API key from Integration
        Source Keys. POLL connectors (currently only Microsoft Defender) are configured
        platform-wide by a KronOS operator, not per-org — this view is read-only for those.
      </p>

      {isLoading && <div className="flex justify-center py-12"><Spinner size="lg" /></div>}
      {error && <ErrorBanner message="Failed to load connector status." />}

      {data && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-100/50 text-left text-xs text-gray-600 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-400">
                <th className="px-4 py-3 font-medium">Connector</th>
                <th className="px-4 py-3 font-medium">Configuration</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Last Activity</th>
                <th className="px-4 py-3 font-medium">Last Failure</th>
                <th className="px-4 py-3 font-medium">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
              {data.map((c) => (
                <ConnectorRow key={`${c.mode}:${c.sourceType}:${c.sourceId}`} connector={c} />
              ))}
              {data.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-gray-500">
                    No connectors configured for this organization yet. Provision a PUSH source
                    API key from Integration Source Keys to get started.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
