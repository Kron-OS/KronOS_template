import apiClient from './client'
import { mintStepUpTicket } from '../lib/stepUpTicket'

// Field names match src/external/routes/admin_integration_sources.py's DTOs
// exactly (PUSH connector self-service API-key provisioning: Wazuh/
// Suricata/Zeek). Distinct from connectors.ts (per-org POLL/SINK config)
// since this is a different backend route module (admin_integration_sources.py,
// not admin_connector_config.py) with its own key-based identity model.
export interface IntegrationSourceKey {
  sourceId: string
  sourceType: string
  apiKey: string
  createdAt: string
}

export interface IntegrationSourceKeySummary {
  sourceId: string
  sourceType: string
  createdAt: string
  revokedAt: string | null
}

export async function listIntegrationSourceKeys(): Promise<IntegrationSourceKeySummary[]> {
  const res = await apiClient.get<{ items: IntegrationSourceKeySummary[]; total: number }>(
    '/api/admin/integration-sources',
  )
  return res.data.items
}

export async function provisionIntegrationSourceKey(
  sourceType: string,
  sourceId: string,
): Promise<IntegrationSourceKey> {
  // Credential issuance -- requires a one-time step-up ticket, not just
  // aal2 (see admin_integration_sources.py's own docstring). Minted fresh
  // per call: tickets are single-use.
  const ticket = await mintStepUpTicket(
    'integration_source_key.provision',
    `${sourceType}:${sourceId}`,
  )
  const res = await apiClient.post<IntegrationSourceKey>(
    `/api/admin/integration-sources/${sourceType}/provision`,
    { sourceId },
    { headers: { 'X-Step-Up-Ticket': ticket } },
  )
  return res.data
}

export async function revokeIntegrationSourceKey(sourceType: string, sourceId: string): Promise<void> {
  const ticket = await mintStepUpTicket('integration_source_key.revoke', `${sourceType}:${sourceId}`)
  await apiClient.delete(`/api/admin/integration-sources/${sourceType}/${sourceId}`, {
    headers: { 'X-Step-Up-Ticket': ticket },
  })
}
