import type { DetectionTriageState } from '../types'
import { cn } from '../utils/cn'

const stateConfig: Record<DetectionTriageState, { label: string; classes: string }> = {
  NEW: { label: 'New', classes: 'bg-purple-900 text-purple-300 border-purple-700' },
  INVESTIGATING: { label: 'Investigating', classes: 'bg-yellow-900 text-yellow-300 border-yellow-700' },
  TRUE_POSITIVE: { label: 'True Positive', classes: 'bg-red-900 text-red-300 border-red-700' },
  FALSE_POSITIVE: { label: 'False Positive', classes: 'bg-gray-800 text-gray-400 border-gray-600' },
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
