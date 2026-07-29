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
