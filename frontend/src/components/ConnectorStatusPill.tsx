import type { ConnectorStatusState } from '../types'
import { cn } from '../utils/cn'

// Same light/dark badge-mirroring approach as StatusPill/TriageStatePill.
const stateConfig: Record<ConnectorStatusState, { label: string; classes: string }> = {
  never_used: {
    label: 'Never used',
    classes: 'bg-gray-200 text-gray-600 border-gray-300 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600',
  },
  active: {
    label: 'Active',
    classes: 'bg-green-100 text-green-700 border-green-300 dark:bg-green-900 dark:text-green-300 dark:border-green-700',
  },
  failing: {
    label: 'Failing',
    classes: 'bg-red-100 text-red-700 border-red-300 dark:bg-red-900 dark:text-red-300 dark:border-red-700',
  },
  revoked: {
    label: 'Revoked',
    classes: 'bg-yellow-100 text-yellow-700 border-yellow-300 dark:bg-yellow-900 dark:text-yellow-300 dark:border-yellow-700',
  },
}

interface ConnectorStatusPillProps {
  state: ConnectorStatusState
  className?: string
}

export function ConnectorStatusPill({ state, className }: ConnectorStatusPillProps) {
  const config = stateConfig[state] ?? stateConfig.never_used
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium',
        config.classes,
        className,
      )}
    >
      {config.label}
    </span>
  )
}
