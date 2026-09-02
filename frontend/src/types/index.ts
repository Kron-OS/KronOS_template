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

export type CaseStatus = 'open' | 'closed' | 'archived'

export interface Case {
  id: string
  title: string
  description: string
  reference: string
  status: CaseStatus
  createdAt: string
  updatedAt: string
  createdBy: string
  orgId: string
  evidenceCount: number
  memberUserIds: string[]
}

// Gap Audit Milestone AAAAA: a non-timeline forensic artifact (e.g. a
// Volatility pstree/psscan snapshot) -- `content` is intentionally opaque
// (matches src/domain/artifact.py's own docstring, no per-kind schema
// exists), kind-aware components (ProcessTreeView/ProcessTableView) give
// it shape client-side.
export interface Artifact {
  id: string
  kind: string
  content: Record<string, unknown>
  evidenceId: string
  caseId: string
  parser: string
  parserVersion: string
  sourcePath: string | null
  createdAt: string
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

// Gap Audit Milestone ZZZZ: deliberately narrower than OrgUser -- no
// roles, matching the backend's own CaseMemberCandidateOut (a case-lead
// searching for someone to add to their own case has no legitimate need
// to see another member's org role).
export interface CaseMemberCandidate {
  userId: string
  username: string
  email: string
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

export interface OrgQuota {
  storageQuotaBytes: number | null
  currentUsageBytes: number
  updatedAt: string | null
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

export type ConnectorMode = 'push' | 'poll'
export type ConnectorStatusState = 'never_used' | 'active' | 'failing' | 'revoked'

// Field names match src/external/routes/admin_connector_status.py's
// ConnectorStatusOut DTO exactly (Milestone W14). selfService/note exist
// specifically to keep the real PUSH (self-service) vs POLL (global,
// platform-configured) asymmetry honest in the UI -- see that route's own
// module docstring.
export interface ConnectorStatus {
  sourceId: string
  sourceType: string
  mode: ConnectorMode
  selfService: boolean
  status: ConnectorStatusState
  createdAt: string | null
  revokedAt: string | null
  lastIngestedAt: string | null
  lastPolledAt: string | null
  lastPollFailedAt: string | null
  lastFailureReason: string | null
  note: string
}

export type DetectionTriageState = 'NEW' | 'INVESTIGATING' | 'TRUE_POSITIVE' | 'FALSE_POSITIVE'

export interface DetectionRuleMatch {
  ruleId: string
  ruleName: string | null
  tags: string[]
  // The real, compiled OpenSearch query string SA evaluated to fire this
  // rule -- null for a Detection synced before this field existed (see
  // DetectionRuleMatch.query's own docstring, src/domain/detection.py).
  query: string | null
}

// Field names match src/external/routes/detections.py's MatchedEventOut DTO.
export interface MatchedEvent {
  id: string
  source: Record<string, unknown>
}

export interface RiskFactor {
  name: string
  weight: number
  normalizedValue: number | null
  detail: string
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
  riskScore: number | null
  riskFactors: RiskFactor[]
}

// Field names match src/external/routes/detections.py's PlaybookStepResultOut/
// PlaybookExecutionResultOut DTOs exactly (roadmap M7/H1, Gap Audit
// Milestone EE1/MM) -- the shared response shape for both
// POST /detections/{id}/contain/revoke-session and
// POST /detections/{id}/sync-to-siem/{sink_name}. Always a 200 on a
// well-formed request; the real outcome lives in succeeded/stepResults,
// never a second, competing HTTP status (see both routes' own docstrings).
export interface PlaybookStepResult {
  stepId: string
  actionName: string
  outcome: string
  output: Record<string, unknown> | null
  error: string | null
}

export interface PlaybookExecutionResult {
  executionId: string
  playbookName: string
  succeeded: boolean
  haltedEarly: boolean
  stepResults: PlaybookStepResult[]
}
