import type { ConnectorConfig, ConnectorDefinition } from '../../types'

function ModeBadge({ mode }: { mode: ConnectorDefinition['mode'] }) {
  const labels: Record<ConnectorDefinition['mode'], string> = {
    push: 'Push',
    poll: 'Poll',
    sink: 'Egress sink',
  }
  return (
    <span className="inline-flex items-center rounded-full border border-gray-300 bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-600 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-400">
      {labels[mode]}
    </span>
  )
}

interface ConnectorCatalogCardProps {
  definition: ConnectorDefinition
  config: ConnectorConfig | undefined
  onConfigure: () => void
}

export function ConnectorCatalogCard({ definition, config, onConfigure }: ConnectorCatalogCardProps) {
  const isPush = definition.mode === 'push'
  const isConfigured = config != null

  return (
    <div className="flex flex-col justify-between rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-800 dark:bg-gray-900">
      <div>
        <div className="mb-1 flex items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100">
            {definition.displayName}
          </h3>
          <ModeBadge mode={definition.mode} />
        </div>
        <p className="mb-3 text-xs text-gray-600 dark:text-gray-400">{definition.description}</p>
        {isConfigured && (
          <span
            className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
              config.enabled
                ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'
                : 'bg-gray-200 text-gray-600 dark:bg-gray-800 dark:text-gray-400'
            }`}
          >
            {config.enabled ? 'Configured' : config.autoDisabledAt ? 'Auto-disabled' : 'Disabled'}
          </span>
        )}
      </div>
      <button
        type="button"
        onClick={onConfigure}
        className="mt-3 rounded border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
      >
        {isPush ? 'Manage API key' : isConfigured ? 'Edit configuration' : 'Configure'}
      </button>
    </div>
  )
}
