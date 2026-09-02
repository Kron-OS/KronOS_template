import apiClient from './client'
import type { Detection, DetectionTriageState, MatchedEvent, PaginatedResponse } from '../types'

interface ListDetectionsParams {
  triageState?: DetectionTriageState
  caseId?: string
  // Matches Detection.rule_severity exactly (real Sigma `level:`
  // vocabulary) -- not a substring match, unlike `q` below.
  severity?: string
  // Case-insensitive free-text match against detector name or any matched
  // rule's name/id (src/external/routes/detections.py's _detection_matches_query).
  q?: string
  page?: number
  pageSize?: number
}

export async function getDetections(
  params: ListDetectionsParams = {},
): Promise<PaginatedResponse<Detection>> {
  const res = await apiClient.get<PaginatedResponse<Detection>>('/api/detections', { params })
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
