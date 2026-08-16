import apiClient from './client'
import type { ConnectorStatus } from '../types'

export async function getConnectorStatus(): Promise<ConnectorStatus[]> {
  const res = await apiClient.get<{ items: ConnectorStatus[] }>('/api/admin/connectors/status')
  return res.data.items
}
