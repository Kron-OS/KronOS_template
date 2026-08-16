import type { DetectionTriageState } from '../types'
import { cn } from '../utils/cn'

// Same light/dark badge-mirroring approach as StatusPill.
const stateConfig: Record<DetectionTriageState, { label: string; classes: string }> = {
  NEW: {
    label: 'New',
    classes: 'bg-purple-100 text-purple-700 border-purple-300 dark:bg-purple-900 dark:text-purple-300 dark:border-purple-700',
  },
  INVESTIGATING: {
    label: 'Investigating',
    classes: 'bg-yellow-100 text-yellow-700 border-yellow-300 dark:bg-yellow-900 dark:text-yellow-300 dark:border-yellow-700',
  },
  TRUE_POSITIVE: {
    label: 'True Positive',
    classes: 'bg-red-100 text-red-700 border-red-300 dark:bg-red-900 dark:text-red-300 dark:border-red-700',
  },
  FALSE_POSITIVE: {
    label: 'False Positive',
    classes: 'bg-gray-200 text-gray-600 border-gray-300 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600',
  },
}

interface TriageStatePillProps {
  state: DetectionTriageState
  className?: string
}

export function TriageStatePill({ state, className }: TriageStatePillProps) {
  const config = stateConfig[state] ?? stateConfig.NEW
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
