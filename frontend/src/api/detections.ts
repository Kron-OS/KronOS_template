import apiClient from './client'
import type { Detection, DetectionTriageState, PaginatedResponse } from '../types'

interface ListDetectionsParams {
  triageState?: DetectionTriageState
  caseId?: string
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

export async function triageDetection(
  id: string,
  targetState: DetectionTriageState,
): Promise<Detection> {
  const res = await apiClient.post<Detection>(`/api/detections/${id}/triage`, { targetState })
  return res.data
}
