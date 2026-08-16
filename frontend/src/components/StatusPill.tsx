import type { EvidenceState } from '../types'
import { cn } from '../utils/cn'

// Each entry pairs a light-mode badge (light bg, dark-tinted text/border)
// with a dark-mode `dark:` variant using the original dark-bg/light-text
// badge colors -- same hue per state, just mirrored for contrast.
const stateConfig: Record<EvidenceState, { label: string; classes: string }> = {
  UPLOADING: {
    label: 'Uploading',
    classes: 'bg-blue-100 text-blue-700 border-blue-300 dark:bg-blue-900 dark:text-blue-300 dark:border-blue-700',
  },
  SCANNING: {
    label: 'Scanning',
    classes: 'bg-yellow-100 text-yellow-700 border-yellow-300 dark:bg-yellow-900 dark:text-yellow-300 dark:border-yellow-700',
  },
  HASHING: {
    label: 'Hashing',
    classes: 'bg-yellow-100 text-yellow-700 border-yellow-300 dark:bg-yellow-900 dark:text-yellow-300 dark:border-yellow-700',
  },
  RECEIVED: {
    label: 'Received',
    classes: 'bg-purple-100 text-purple-700 border-purple-300 dark:bg-purple-900 dark:text-purple-300 dark:border-purple-700',
  },
  PARSING: {
    label: 'Parsing',
    classes: 'bg-orange-100 text-orange-700 border-orange-300 dark:bg-orange-900 dark:text-orange-300 dark:border-orange-700',
  },
  INGESTING: {
    label: 'Ingesting',
    classes: 'bg-orange-100 text-orange-700 border-orange-300 dark:bg-orange-900 dark:text-orange-300 dark:border-orange-700',
  },
  COMPLETE: {
    label: 'Complete',
    classes: 'bg-green-100 text-green-700 border-green-300 dark:bg-green-900 dark:text-green-300 dark:border-green-700',
  },
  ERROR: {
    label: 'Error',
    classes: 'bg-red-100 text-red-700 border-red-300 dark:bg-red-900 dark:text-red-300 dark:border-red-700',
  },
  PURGED: {
    label: 'Purged',
    classes: 'bg-gray-200 text-gray-600 border-gray-300 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600',
  },
}

interface StatusPillProps {
  state: EvidenceState
  className?: string
}

export function StatusPill({ state, className }: StatusPillProps) {
  const config = stateConfig[state] ?? stateConfig.ERROR
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
