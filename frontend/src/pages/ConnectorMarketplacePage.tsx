import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { getConnectorCatalog, getConnectorStatus, listConnectorConfigs } from '../api/connectors'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import { ConnectorStatusPill } from '../components/ConnectorStatusPill'
import { ConnectorCatalogCard } from '../components/connectors/ConnectorCatalogCard'
import { ConnectorConfigForm } from '../components/connectors/ConnectorConfigForm'
import { PushConnectorKeyPanel } from '../components/connectors/PushConnectorKeyPanel'
import type { ConnectorDefinition, ConnectorStatus } from '../types'

function formatDateTime(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

// Unchanged from the previous ConnectorStatusPage.tsx -- this table stays
// exactly as it was, just relocated onto this page's second section.
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

export function ConnectorMarketplacePage() {
  const queryClient = useQueryClient()
  const [configuring, setConfiguring] = useState<ConnectorDefinition | null>(null)

  const catalogQuery = useQuery({ queryKey: ['connectorCatalog'], queryFn: getConnectorCatalog })
  const configsQuery = useQuery({ queryKey: ['connectorConfigs'], queryFn: listConnectorConfigs })
  const statusQuery = useQuery({
    queryKey: ['connectorStatus'],
    queryFn: getConnectorStatus,
    staleTime: 30_000,
  })

  const configBySourceType = new Map((configsQuery.data ?? []).map((c) => [c.sourceType, c]))

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">Connectors</h1>
        <button
          type="button"
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ['connectorCatalog'] })
            queryClient.invalidateQueries({ queryKey: ['connectorConfigs'] })
            queryClient.invalidateQueries({ queryKey: ['connectorStatus'] })
          }}
          className="flex items-center gap-2 rounded-md border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-200 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
        >
          Refresh
        </button>
      </div>

      <section className="mb-10">
        <h2 className="mb-2 text-sm font-semibold text-gray-800 dark:text-gray-200">Marketplace</h2>
        <p className="mb-4 max-w-3xl text-sm text-gray-600 dark:text-gray-400">
          Browse available connectors and configure one for this organization. Push connectors
          (Wazuh, Suricata, Zeek) are self-service via an API key. Poll/egress connectors (Microsoft
          Defender, Sentinel, Splunk HEC, CEF syslog) are configured per-org here — each
          organization's credentials are stored independently and never shared across tenants.
        </p>

        {catalogQuery.isLoading && (
          <div className="flex justify-center py-8">
            <Spinner size="lg" />
          </div>
        )}
        {catalogQuery.error && <ErrorBanner message="Failed to load connector catalog." />}

        {catalogQuery.data && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {catalogQuery.data.map((definition) => (
              <ConnectorCatalogCard
                key={definition.sourceType}
                definition={definition}
                config={configBySourceType.get(definition.sourceType)}
                onConfigure={() => setConfiguring(definition)}
              />
            ))}
          </div>
        )}
      </section>

      <section>
        <h2 className="mb-2 text-sm font-semibold text-gray-800 dark:text-gray-200">
          Connected sources
        </h2>
        {statusQuery.isLoading && (
          <div className="flex justify-center py-8">
            <Spinner size="lg" />
          </div>
        )}
        {statusQuery.error && <ErrorBanner message="Failed to load connector status." />}

        {statusQuery.data && (
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
                {statusQuery.data.map((c) => (
                  <ConnectorRow key={`${c.mode}:${c.sourceType}:${c.sourceId}`} connector={c} />
                ))}
                {statusQuery.data.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-10 text-center text-gray-500">
                      No connectors configured for this organization yet. Configure one from the
                      marketplace above to get started.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {configuring && configuring.mode === 'push' && (
        <PushConnectorKeyPanel definition={configuring} onClose={() => setConfiguring(null)} />
      )}
      {configuring && configuring.mode !== 'push' && (
        <ConnectorConfigForm definition={configuring} onClose={() => setConfiguring(null)} />
      )}
    </div>
  )
}
