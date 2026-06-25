import apiClient from './client'
import type { OrgUser, OrgSettings, Role } from '../types'

export async function getOrgUsers(): Promise<OrgUser[]> {
  const res = await apiClient.get<OrgUser[]>('/api/admin/org/users')
  return res.data
}

export async function inviteUser(email: string, role: Role): Promise<OrgUser> {
  const res = await apiClient.post<OrgUser>('/api/admin/org/users/invite', { email, role })
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
