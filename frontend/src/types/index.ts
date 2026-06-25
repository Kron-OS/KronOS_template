export type EvidenceState =
  | 'UPLOADING'
  | 'SCANNING'
  | 'HASHING'
  | 'RECEIVED'
  | 'PARSING'
  | 'INGESTING'
  | 'COMPLETE'
  | 'ERROR'
  | 'PURGED'

export type Role = 'org-admin' | 'case-lead' | 'analyst' | 'read-only'

export interface TenantContext {
  userId: string
  username: string
  email: string
  roles: Role[]
  orgId: string
  orgAlias: string
  acr: 'aal1' | 'aal2'
}

export interface Case {
  id: string
  title: string
  description: string
  reference: string
  createdAt: string
  updatedAt: string
  createdBy: string
  orgId: string
  evidenceCount: number
}

export interface Evidence {
  id: string
  caseId: string
  filename: string
  contentType: string
  sizeBytes: number
  sha256: string | null
  md5: string | null
  state: EvidenceState
  errorReason: string | null
  uploadedBy: string
  uploadedAt: string
  updatedAt: string
  rfc3161Token: string | null
}

export interface AuditEvent {
  id: string
  eventType: string
  evidenceId: string | null
  caseId: string | null
  orgId: string
  userId: string
  occurredAt: string
  details: Record<string, unknown>
  rowHash: string
  sequenceNumber: number
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

export interface UploadRequest {
  evidenceId: string
  presignedUrl: string
  objectKey: string
  expiresInSeconds: number
}

export interface OrgUser {
  userId: string
  username: string
  email: string
  roles: Role[]
  joinedAt: string
}

export interface OrgSettings {
  retentionDays: number
  legalHoldDefault: boolean
}

export interface SSETicket {
  ticket: string
  expiresIn: number
}

export interface SSEStatusEvent {
  evidenceId: string
  status: EvidenceState
  progress?: {
    kind: 'bytes' | 'records'
    done: number
    total: number
  }
}

export interface SSEErrorEvent {
  evidenceId: string
  reasonCode: string
  retryable: boolean
}

export interface DashboardUrl {
  url: string
}
