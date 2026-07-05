import apiClient from './client'
import type { Evidence, AuditEvent, PaginatedResponse, UploadRequest, SSETicket } from '../types'

interface ListParams {
  page?: number
  pageSize?: number
}

export async function getEvidence(
  caseId: string,
  params: ListParams = {},
): Promise<PaginatedResponse<Evidence>> {
  const res = await apiClient.get<PaginatedResponse<Evidence>>(
    `/api/cases/${caseId}/evidence`,
    { params },
  )
  return res.data
}

export async function requestUpload(
  caseId: string,
  filename: string,
  contentType: string,
  sizeBytes: number,
): Promise<UploadRequest> {
  const res = await apiClient.post<UploadRequest>('/api/evidence/upload/request', {
    caseId,
    filename,
    contentType,
    sizeBytes,
  })
  return res.data
}

export async function finalizeUpload(evidenceId: string): Promise<Evidence> {
  const res = await apiClient.post<Evidence>(
    `/api/evidence/upload/finalize/${evidenceId}`,
  )
  return res.data
}

export async function getAuditLog(
  caseId: string,
  params: ListParams = {},
): Promise<PaginatedResponse<AuditEvent>> {
  const res = await apiClient.get<PaginatedResponse<AuditEvent>>(
    `/api/cases/${caseId}/audit`,
    { params },
  )
  return res.data
}

export async function getSSETicket(caseId: string): Promise<SSETicket> {
  const res = await apiClient.post<SSETicket>('/api/sse/ticket', { caseId })
  return res.data
}

export async function finalizeUploadWithHash(
  evidenceId: string,
  clientSha256: string,
): Promise<Evidence> {
  const res = await apiClient.post<Evidence>(
    `/api/evidence/upload/finalize/${evidenceId}`,
    { client_sha256: clientSha256 },
  )
  return res.data
}

export async function getDashboardUrl(caseId: string): Promise<{ url: string }> {
  const res = await apiClient.get<{ url: string }>(`/api/cases/${caseId}/dashboard-url`)
  return res.data
}

export async function deleteEvidence(id: string): Promise<void> {
  await apiClient.delete(`/api/evidence/${id}`)
}
