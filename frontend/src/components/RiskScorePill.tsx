import { cn } from '../utils/cn'

// Bands mirror src/application/risk_scoring.py's own SEVERITY_NORMALIZED_LEVELS
// spacing (0/0.25/0.5/0.75/1.0 over the 5-value Sigma severity vocabulary) --
// Detection.risk_score itself is a 0-100 weighted average (src/domain/risk.py's
// RiskScoreBreakdown docstring), not a rule severity, so these are visual
// bands over that same scale, not a re-derivation of the Sigma vocabulary.
function bandFor(score: number): { label: string; classes: string } {
  if (score >= 75) {
    return {
      label: 'Critical',
      classes: 'bg-red-100 text-red-700 border-red-300 dark:bg-red-900 dark:text-red-300 dark:border-red-700',
    }
  }
  if (score >= 50) {
    return {
      label: 'High',
      classes:
        'bg-orange-100 text-orange-700 border-orange-300 dark:bg-orange-900 dark:text-orange-300 dark:border-orange-700',
    }
  }
  if (score >= 25) {
    return {
      label: 'Medium',
      classes:
        'bg-yellow-100 text-yellow-700 border-yellow-300 dark:bg-yellow-900 dark:text-yellow-300 dark:border-yellow-700',
    }
  }
  return {
    label: 'Low',
    classes: 'bg-gray-200 text-gray-600 border-gray-300 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600',
  }
}

interface RiskScorePillProps {
  score: number | null
  className?: string
}

export function RiskScorePill({ score, className }: RiskScorePillProps) {
  if (score === null) {
    return (
      <span
        className={cn(
          'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium',
          'bg-gray-100 text-gray-500 border-gray-300 dark:bg-gray-900 dark:text-gray-500 dark:border-gray-700',
          className,
        )}
        title="No matched rule/enrichment data carried a recognized value for any risk factor"
      >
        Not scored
      </span>
    )
  }

  const band = bandFor(score)
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium',
        band.classes,
        className,
      )}
    >
      {band.label} · {Math.round(score)}
    </span>
  )
}
