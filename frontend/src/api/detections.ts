import apiClient from './client'
import type { Detection, DetectionTriageState, MatchedEvent, PaginatedResponse } from '../types'

interface ListDetectionsParams {
  // Milestone IIIII: repeatable -- e.g. NEW + INVESTIGATING together for a
  // "not yet resolved" view.
  triageState?: DetectionTriageState[]
  caseId?: string
  // Matches Detection.rule_severity exactly (real Sigma `level:`
  // vocabulary) -- not a substring match, unlike `q` below. Repeatable.
  severity?: string[]
  // Case-insensitive free-text match against detector name or any matched
  // rule's name/id (src/external/routes/detections.py's _detection_matches_query).
  q?: string
  // ISO 8601 date-time strings, filtering Detection.finding_timestamp.
  dateFrom?: string
  dateTo?: string
  page?: number
  pageSize?: number
}

export async function getDetections(
  params: ListDetectionsParams = {},
): Promise<PaginatedResponse<Detection>> {
  // indexes: null -- FastAPI's repeatable Query() params expect
  // `severity=a&severity=b`, not axios's default `severity[]=a&severity[]=b`
  // bracket notation (verified live against a real buildURL() call).
  const res = await apiClient.get<PaginatedResponse<Detection>>('/api/detections', {
    params,
    paramsSerializer: { indexes: null },
  })
  return res.data
}

export async function getDetection(id: string): Promise<Detection> {
  const res = await apiClient.get<Detection>(`/api/detections/${id}`)
  return res.data
}

interface MatchedEventsResponse {
  items: MatchedEvent[]
  truncatedFrom: number | null
}

export async function getMatchedEvents(id: string): Promise<MatchedEventsResponse> {
  const res = await apiClient.get<MatchedEventsResponse>(`/api/detections/${id}/matched-events`)
  return res.data
}

export async function triageDetection(
  id: string,
  targetState: DetectionTriageState,
): Promise<Detection> {
  const res = await apiClient.post<Detection>(`/api/detections/${id}/triage`, { targetState })
  return res.data
}

export interface BulkTriageResult {
  detectionId: string
  status: 'ok' | 'error'
  detail: string | null
}

// Milestone IIIII: the analyst-facing "select several alerts, change them
// all at once" action. A bulk request over an FSM is expected to partially
// fail (e.g. one row already terminal) -- always 200, per-item results.
export async function bulkTriageDetections(
  detectionIds: string[],
  targetState: DetectionTriageState,
): Promise<BulkTriageResult[]> {
  const res = await apiClient.post<{ results: BulkTriageResult[] }>(
    '/api/detections/bulk-triage',
    { detectionIds, targetState },
  )
  return res.data.results
}
