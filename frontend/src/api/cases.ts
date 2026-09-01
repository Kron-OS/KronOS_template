import apiClient from './client'
import type { Case, PaginatedResponse } from '../types'

export async function getCases(): Promise<PaginatedResponse<Case>> {
  const res = await apiClient.get<PaginatedResponse<Case>>('/api/cases')
  return res.data
}

export async function getCase(id: string): Promise<Case> {
  const res = await apiClient.get<Case>(`/api/cases/${id}`)
  return res.data
}

export async function createCase(data: {
  title: string
  reference: string
  description: string
}): Promise<Case> {
  const res = await apiClient.post<Case>('/api/cases', data)
  return res.data
}

export async function addCaseMember(caseId: string, userId: string): Promise<Case> {
  const res = await apiClient.post<Case>(`/api/cases/${caseId}/members`, { userId })
  return res.data
}

export async function removeCaseMember(caseId: string, userId: string): Promise<Case> {
  const res = await apiClient.delete<Case>(`/api/cases/${caseId}/members/${userId}`)
  return res.data
}

export async function deleteCase(caseId: string): Promise<void> {
  await apiClient.delete(`/api/cases/${caseId}`)
}
