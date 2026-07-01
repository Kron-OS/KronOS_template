import apiClient from './client'
import type { OrgUser, OrgSettings, Role, InviteUserInput, InviteUserResult } from '../types'

export async function getOrgUsers(): Promise<OrgUser[]> {
  const res = await apiClient.get<{ items: OrgUser[]; total: number }>('/api/admin/org/users')
  return res.data.items
}

export async function inviteUser(input: InviteUserInput): Promise<InviteUserResult> {
  const res = await apiClient.post<InviteUserResult>('/api/admin/org/users/invite', input)
  return res.data
}

export async function updateUserRole(userId: string, role: Role): Promise<OrgUser> {
  const res = await apiClient.patch<OrgUser>(`/api/admin/org/users/${userId}/role`, { role })
  return res.data
}

export async function removeUser(userId: string): Promise<void> {
  await apiClient.delete(`/api/admin/org/users/${userId}`)
}

export async function getOrgSettings(): Promise<OrgSettings> {
  const res = await apiClient.get<OrgSettings>('/api/admin/org/settings')
  return res.data
}

export async function updateOrgSettings(settings: Partial<OrgSettings>): Promise<OrgSettings> {
  const res = await apiClient.patch<OrgSettings>('/api/admin/org/settings', settings)
  return res.data
}
