import apiClient from './client'
import { mintStepUpTicket } from '../lib/stepUpTicket'
import type { ConnectorConfig, ConnectorDefinition, ConnectorStatus } from '../types'

export async function getConnectorStatus(): Promise<ConnectorStatus[]> {
  const res = await apiClient.get<{ items: ConnectorStatus[] }>('/api/admin/connectors/status')
  return res.data.items
}

export async function getConnectorCatalog(): Promise<ConnectorDefinition[]> {
  const res = await apiClient.get<{ items: ConnectorDefinition[] }>('/api/admin/connectors/catalog')
  return res.data.items
}

export async function listConnectorConfigs(): Promise<ConnectorConfig[]> {
  const res = await apiClient.get<{ items: ConnectorConfig[] }>('/api/admin/connectors')
  return res.data.items
}

export async function getConnectorConfig(sourceType: string): Promise<ConnectorConfig | null> {
  try {
    const res = await apiClient.get<ConnectorConfig>(`/api/admin/connectors/${sourceType}/config`)
    return res.data
  } catch (err) {
    // 404 -- an honest "not configured", not an error the UI needs to surface.
    if (
      typeof err === 'object' &&
      err !== null &&
      'response' in err &&
      (err as { response?: { status?: number } }).response?.status === 404
    ) {
      return null
    }
    throw err
  }
}

// All four mutations below are credential-bearing (POLL/SINK secrets) and
// require a one-time step-up ticket, not just aal2 -- see
// admin_connector_config.py's own module docstring. Minted fresh per call
// since tickets are single-use.

export async function putConnectorConfig(
  sourceType: string,
  values: Record<string, string>,
): Promise<ConnectorConfig> {
  const ticket = await mintStepUpTicket('connector_config.set', sourceType)
  const res = await apiClient.put<ConnectorConfig>(
    `/api/admin/connectors/${sourceType}/config`,
    { values },
    { headers: { 'X-Step-Up-Ticket': ticket } },
  )
  return res.data
}

export async function deleteConnectorConfig(sourceType: string): Promise<void> {
  const ticket = await mintStepUpTicket('connector_config.delete', sourceType)
  await apiClient.delete(`/api/admin/connectors/${sourceType}/config`, {
    headers: { 'X-Step-Up-Ticket': ticket },
  })
}

export async function disableConnectorConfig(sourceType: string): Promise<ConnectorConfig> {
  const ticket = await mintStepUpTicket('connector_config.disable', sourceType)
  const res = await apiClient.post<ConnectorConfig>(
    `/api/admin/connectors/${sourceType}/config/disable`,
    undefined,
    { headers: { 'X-Step-Up-Ticket': ticket } },
  )
  return res.data
}

export async function enableConnectorConfig(sourceType: string): Promise<ConnectorConfig> {
  const ticket = await mintStepUpTicket('connector_config.enable', sourceType)
  const res = await apiClient.post<ConnectorConfig>(
    `/api/admin/connectors/${sourceType}/config/enable`,
    undefined,
    { headers: { 'X-Step-Up-Ticket': ticket } },
  )
  return res.data
}
