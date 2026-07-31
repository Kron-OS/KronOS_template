import type { DetectionTriageState } from '../types'

// Mirrors src/domain/detection.py's _VALID_TRANSITIONS exactly -- the
// backend is the sole enforcement point (POST /triage rejects anything not
// listed here with a real 409), this is UI-only so the triage action only
// ever offers a legal next step instead of round-tripping a doomed request.
const VALID_TRANSITIONS: Record<DetectionTriageState, DetectionTriageState[]> = {
  NEW: ['INVESTIGATING'],
  INVESTIGATING: ['TRUE_POSITIVE', 'FALSE_POSITIVE'],
  TRUE_POSITIVE: [],
  FALSE_POSITIVE: [],
}

export function nextTriageStates(current: DetectionTriageState): DetectionTriageState[] {
  return VALID_TRANSITIONS[current] ?? []
}

const ACTION_LABELS: Record<DetectionTriageState, string> = {
  NEW: 'Mark New',
  INVESTIGATING: 'Start Investigating',
  TRUE_POSITIVE: 'Confirm True Positive',
  FALSE_POSITIVE: 'Mark False Positive',
}

export function triageActionLabel(target: DetectionTriageState): string {
  return ACTION_LABELS[target] ?? target
}
