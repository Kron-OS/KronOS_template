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
  retryAction: 'intake' | 'parse' | null
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

export interface InviteUserInput {
  email: string
  firstName: string
  lastName: string
  password: string
  role: Role
}

export interface InviteUserResult {
  detail: string
  userId: string
  created: boolean
}

export interface OrgSettings {
  retentionDays: number
  legalHoldDefault: boolean
}

export interface SSETicket {
  ticket: string
  expiresIn: number
}

// Field names match the real payload src/external/routes/sse.py's
// event_generator() actually emits (evidenceId/state) -- verified against
// the real backend source, not assumed from a shorthand naming.
export interface SSEStatusEvent {
  evidenceId: string
  state: EvidenceState
}

export interface DashboardUrl {
  url: string
}

export type DetectionTriageState = 'NEW' | 'INVESTIGATING' | 'TRUE_POSITIVE' | 'FALSE_POSITIVE'

export interface DetectionRuleMatch {
  ruleId: string
  ruleName: string | null
  tags: string[]
}

// Field names match src/external/routes/detections.py's DetectionOut DTO --
// the only tenant-facing surface over SA finding data (roadmap A3 gate).
export interface Detection {
  id: string
  orgId: string
  caseId: string | null
  findingId: string
  detectorName: string
  sourceIndex: string
  ruleMatches: DetectionRuleMatch[]
  matchedDocumentIds: string[]
  attackTags: string[]
  findingTimestamp: string
  triageState: DetectionTriageState
  syncedAt: string
  updatedAt: string
}
