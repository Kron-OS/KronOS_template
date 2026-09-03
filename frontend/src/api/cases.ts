import apiClient from './client'
import { filenameFromContentDisposition } from './evidence'
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

// Milestone EEEEE/FFFFF: on-demand, analyst-triggered extractions. Both
// return 202 + a Celery taskId immediately -- the real result lands as a
// new StructuredArtifact a short while later (real-verified sub-few-second
// turnaround for both actions, poc/volatility_dumpfiles/ and
// poc/volatility_registry_printkey/); the caller (ArtifactsTab) polls
// getCaseArtifacts for the new kind rather than a dedicated SSE channel --
// see docs/GAP_AUDIT_2026-09-03_MILESTONE_EEEEE.md for why (the existing
// SSE mechanism is hardcoded to Evidence.state, which a derived artifact
// never changes).
export async function requestVolatilityDumpFile(
  caseId: string,
  evidenceId: string,
  physaddr: number,
): Promise<{ taskId: string }> {
  const res = await apiClient.post<{ taskId: string }>(
    `/api/cases/${caseId}/evidence/${evidenceId}/volatility/dump-file`,
    { physaddr },
  )
  return res.data
}

export async function requestVolatilityRegistryKey(
  caseId: string,
  evidenceId: string,
  hiveOffset: number,
  key: string | null,
): Promise<{ taskId: string }> {
  const res = await apiClient.post<{ taskId: string }>(
    `/api/cases/${caseId}/evidence/${evidenceId}/volatility/registry-key`,
    { hiveOffset, key },
  )
  return res.data
}

// Mirrors downloadEvidence's real Content-Disposition-aware blob download.
export async function downloadDerivedArtifact(
  caseId: string,
  artifactId: string,
  fallbackFilename: string,
): Promise<void> {
  const res = await apiClient.get<Blob>(`/api/cases/${caseId}/artifacts/${artifactId}/download`, {
    responseType: 'blob',
  })
  const filename = filenameFromContentDisposition(
    res.headers['content-disposition'] as string | undefined,
    fallbackFilename,
  )
  const url = URL.createObjectURL(res.data)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}
