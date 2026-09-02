import apiClient from './client'
import type { Artifact, Case, CaseMemberCandidate, PaginatedResponse } from '../types'

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

// Gap Audit Milestone ZZZZ: backs CaseMembersSection's search-as-you-type
// "Add Member" picker. `q` is required by the backend (min_length=1) --
// callers must not invoke this with an empty/whitespace-only query.
export async function searchCaseMemberCandidates(
  caseId: string,
  q: string,
): Promise<CaseMemberCandidate[]> {
  const res = await apiClient.get<{ items: CaseMemberCandidate[] }>(
    `/api/cases/${caseId}/member-candidates`,
    { params: { q } },
  )
  return res.data.items
}

export async function deleteCase(caseId: string): Promise<void> {
  await apiClient.delete(`/api/cases/${caseId}`)
}

// Gap Audit Milestone AAAAA: every real StructuredArtifact across the
// whole case (all evidence files) -- not paginated, see the backend
// route's own docstring for why. The Artifacts tab groups these
// client-side by evidenceId, then by kind.
export async function getCaseArtifacts(caseId: string): Promise<Artifact[]> {
  const res = await apiClient.get<{ items: Artifact[] }>(`/api/cases/${caseId}/artifacts`)
  return res.data.items
}
