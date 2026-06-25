import type { EvidenceState } from '../types'
import { cn } from '../utils/cn'

const stateConfig: Record<EvidenceState, { label: string; classes: string }> = {
  UPLOADING: { label: 'Uploading', classes: 'bg-blue-900 text-blue-300 border-blue-700' },
  SCANNING: { label: 'Scanning', classes: 'bg-yellow-900 text-yellow-300 border-yellow-700' },
  HASHING: { label: 'Hashing', classes: 'bg-yellow-900 text-yellow-300 border-yellow-700' },
  RECEIVED: { label: 'Received', classes: 'bg-purple-900 text-purple-300 border-purple-700' },
  PARSING: { label: 'Parsing', classes: 'bg-orange-900 text-orange-300 border-orange-700' },
  INGESTING: { label: 'Ingesting', classes: 'bg-orange-900 text-orange-300 border-orange-700' },
  COMPLETE: { label: 'Complete', classes: 'bg-green-900 text-green-300 border-green-700' },
  ERROR: { label: 'Error', classes: 'bg-red-900 text-red-300 border-red-700' },
  PURGED: { label: 'Purged', classes: 'bg-gray-800 text-gray-400 border-gray-600' },
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
