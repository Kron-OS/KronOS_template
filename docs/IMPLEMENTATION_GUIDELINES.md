# KronOS Implementation Guidelines

Derived from six design reviews (2026-04-20 → 2026-06-16) and the Project Specifications.
Every rule here traces to a concrete architectural decision; the source section is noted.

---

## Table of Contents

1. [Python / FastAPI Backend](#1-python--fastapi-backend)
2. [Domain Layer (DDD)](#2-domain-layer-ddd)
3. [Application Services](#3-application-services)
4. [Adapter Layer — Repositories](#4-adapter-layer--repositories)
5. [Adapter Layer — Storage (MinIO)](#5-adapter-layer--storage-minio)
6. [Adapter Layer — Task Queue (Celery)](#6-adapter-layer--task-queue-celery)
7. [Adapter Layer — OpenSearch](#7-adapter-layer--opensearch)
8. [External — Auth Middleware (Keycloak)](#8-external--auth-middleware-keycloak)
9. [External — Parsers](#9-external--parsers)
10. [Audit Log](#10-audit-log)
11. [Frontend (React / TypeScript)](#11-frontend-react--typescript)
12. [Database Schema (PostgreSQL / Alembic)](#12-database-schema-postgresql--alembic)
13. [Container & Security Baseline](#13-container--security-baseline)
14. [CI / CD Pipeline](#14-ci--cd-pipeline)
15. [Compliance Checklist (ISO 27001:2022)](#15-compliance-checklist-iso-270012022)

---

## 1. Python / FastAPI Backend

### 1.1 Async-first

All FastAPI route handlers **must** be `async def`. No synchronous blocking on the FastAPI thread.

```python
# CORRECT
@router.post("/cases/{case_id}/evidence")
async def request_upload(
    case_id: UUID,
    payload: EvidenceUploadRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    intake: EvidenceIntakeService = Depends(get_intake_service),
) -> EvidenceUploadResponse:
    return await intake.request_upload(ctx, case_id, payload)

# WRONG — blocks the event loop
@router.get("/cases")
def list_cases(...):   # missing async
    ...
```

### 1.2 Dependency Injection

All collaborators are injected via FastAPI's `Depends` or constructor DI. No service instantiation inside route handlers.

```python
# src/external/dependencies.py — the only singleton allowed
class _DIContainer:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._db_pool: asyncpg.Pool | None = None

    async def get_audit_repo(self) -> AuditLogRepository:
        return PostgresAuditLogRepository(await self._get_pool())

_container: _DIContainer | None = None

def get_audit_repo() -> AuditLogRepository:
    return _container.get_audit_repo()   # type: ignore[union-attr]
```

### 1.3 Domain isolation

Files under `src/domain/` and `src/application/` must have **zero** imports of FastAPI, Celery, asyncpg, boto3, or opensearch-py. Verify with:

```bash
ruff check --select=INP001 src/domain/ src/application/
python -c "
import ast, sys, pathlib
forbidden = {'fastapi','celery','asyncpg','boto3','opensearchpy','opensearch_py'}
for p in pathlib.Path('src/domain').rglob('*.py'):
    tree = ast.parse(p.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in getattr(node,'names',[])] + [node.module or '']
            for name in names:
                root = name.split('.')[0].replace('-','_')
                if root in forbidden:
                    print(f'{p}:{node.lineno} forbidden import {name}')
                    sys.exit(1)
"
```

### 1.4 Configuration

All tunable values come from `pydantic.BaseSettings`. No hardcoded strings, IPs, or timeouts.

```python
# src/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    postgres_dsn: str
    minio_endpoint: str
    minio_access_key: str
    minio_secret_key: str
    keycloak_issuer: str
    keycloak_audience: str = "kronos-backend"
    opensearch_url: str
    celery_broker_url: str
    tsa_url: str
    evidence_retention_days: int = 365
    evidence_max_size_bytes: int = 1_073_741_824  # 1 GB
```

Vault-sourced secrets are injected as env vars by Vault Agent; the `Settings` class reads them identically to file-based env vars. No secret must appear in git or container images.

### 1.5 Error handling

Every exception must be caught and re-raised as a domain exception with context:

```python
try:
    await storage.promote(evidence_id, object_key)
except Exception as exc:
    raise StorageError(f"promote failed for {evidence_id}") from exc
```

All `KronOSException` subclasses are translated at the FastAPI exception-handler layer to structured JSON responses. Stack traces are **never** sent to clients; they are logged with a correlation ID.

### 1.6 Structured logging

```python
import structlog

logger = structlog.get_logger()

# Correct — JSON-serialisable values, no PII
logger.info("evidence_intake_complete",
            evidence_id=str(evidence.id),
            org_id=str(ctx.org_id),
            size_bytes=evidence.size_bytes)

# Wrong — don't log file content, user IP, or stack traces at INFO
logger.info(f"file contents: {raw_bytes}")   # NEVER
```

---

## 2. Domain Layer (DDD)

**Source:** CLAUDE.md §A.3; reviews/Part_1_Review.md §5.2; reviews/Part_2_Review.md §5.6-5.7

### 2.1 Evidence model and FSM

```python
# src/domain/evidence.py
from __future__ import annotations
from enum import StrEnum
from typing import ClassVar
from uuid import UUID
import datetime

from pydantic import BaseModel, ConfigDict

class EvidenceState(StrEnum):
    UPLOADING  = "UPLOADING"
    SCANNING   = "SCANNING"
    HASHING    = "HASHING"
    RECEIVED   = "RECEIVED"
    PARSING    = "PARSING"
    INGESTING  = "INGESTING"
    COMPLETE   = "COMPLETE"
    ERROR      = "ERROR"
    PURGED     = "PURGED"

# Allowed transitions — source of truth for the FSM
ALLOWED_TRANSITIONS: dict[EvidenceState, frozenset[EvidenceState]] = {
    EvidenceState.UPLOADING:  frozenset({EvidenceState.SCANNING}),
    EvidenceState.SCANNING:   frozenset({EvidenceState.HASHING, EvidenceState.ERROR}),
    EvidenceState.HASHING:    frozenset({EvidenceState.RECEIVED, EvidenceState.ERROR}),
    EvidenceState.RECEIVED:   frozenset({EvidenceState.PARSING}),
    EvidenceState.PARSING:    frozenset({EvidenceState.INGESTING, EvidenceState.ERROR}),
    EvidenceState.INGESTING:  frozenset({EvidenceState.COMPLETE, EvidenceState.ERROR}),
    EvidenceState.COMPLETE:   frozenset(),
    EvidenceState.ERROR:      frozenset({EvidenceState.SCANNING, EvidenceState.PARSING}),
    EvidenceState.PURGED:     frozenset(),
}

class Evidence(BaseModel):
    """Core evidence domain model — no ORM, no framework imports."""

    model_config = ConfigDict(frozen=True)

    id: UUID
    case_id: UUID
    org_id: UUID
    filename: str
    size_bytes: int
    sha256: bytes | None = None          # BYTEA(32)
    mime_detected: str | None = None
    artefact_type: str | None = None
    status: EvidenceState = EvidenceState.UPLOADING
    bucket: str
    object_key: str
    object_lock_until: datetime.datetime | None = None
    legal_hold: bool = False
    rfc3161_token: bytes | None = None
    uploaded_by: UUID
    uploaded_at: datetime.datetime
    error_reason: str | None = None

    def transition(self, new_state: EvidenceState) -> "Evidence":
        """Return a new Evidence with the updated state; raise if transition is invalid."""
        if new_state not in ALLOWED_TRANSITIONS[self.status]:
            raise ValidationError(
                f"Invalid transition {self.status} → {new_state}"
            )
        return self.model_copy(update={"status": new_state})
```

Rules:
- All domain models use `ConfigDict(frozen=True)` — they are **immutable value objects**.
- Transitions always return a new copy; they never mutate in place.
- `sha256` is `bytes` (BYTEA in Postgres), not a hex string.
- Zero ORM imports.

### 2.2 TimelineRecord (ECS + kronos.*)

```python
# src/domain/timeline.py
from pydantic import BaseModel, ConfigDict

class KronosProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant_id: str           # org_id
    org_alias: str
    case_id: str
    evidence_id: str
    evidence_sha256: str     # hex
    tz_fold: int = 0         # 0 or 1; -1 = ambiguous DST
    parser_version: str
    ingest_id: str
    original_object_key: str | None = None   # when event.original > 32 KB

class TimelineRecord(BaseModel):
    """One normalised event ready for OpenSearch ingestion."""

    model_config = ConfigDict(frozen=True)

    # ECS mandatory fields
    timestamp: str           # @timestamp — ISO-8601 UTC with Z suffix
    event_kind: str          # "event" | "alert" | "metric" …
    event_category: list[str]
    event_action: str | None = None
    event_module: str        # parser name
    event_dataset: str
    event_original: str | None = None    # raw record, max 32 KB
    event_timezone: str | None = None    # IANA TZ, when known

    # Provenance
    kronos: KronosProvenance

    # Parsed fields (partial — each parser adds more)
    host_name: str | None = None
    user_name: str | None = None
    process_name: str | None = None
    message: str | None = None
```

Rules:
- `@timestamp` is **always UTC** with trailing `Z` — no local-time in the index.
- `event.original` is truncated to 32 KB; oversized originals go to MinIO (`kronos.original_object_key`).
- `kronos.*` block is **mandatory** on every event.

### 2.3 AuditEvent

```python
# src/domain/audit.py
import hashlib, json
from enum import StrEnum
from uuid import UUID
import datetime
from pydantic import BaseModel, ConfigDict

class AuditEventType(StrEnum):
    # Access decisions
    ACCESS_ALLOW = "access.allow"
    ACCESS_DENY  = "access.deny"
    # Evidence custody
    EVIDENCE_UPLOAD_START    = "evidence.upload.start"
    EVIDENCE_UPLOAD_COMPLETE = "evidence.upload.complete"
    EVIDENCE_SCAN_CLEAN      = "evidence.scan.clean"
    EVIDENCE_SCAN_INFECTED   = "evidence.scan.infected"
    EVIDENCE_HASH_VERIFIED   = "evidence.hash.verified"
    EVIDENCE_HASH_MISMATCH   = "evidence.hash.mismatch"
    EVIDENCE_PROMOTED        = "evidence.promoted"
    EVIDENCE_LEGAL_HOLD_SET  = "evidence.legal_hold.set"
    EVIDENCE_LEGAL_HOLD_CLEARED = "evidence.legal_hold.cleared"
    EVIDENCE_DOWNLOAD        = "evidence.download"
    EVIDENCE_DELETE          = "evidence.delete"
    EVIDENCE_PARSE_START     = "evidence.parse.start"
    EVIDENCE_PARSE_SUCCESS   = "evidence.parse.success"
    EVIDENCE_PARSE_ERROR     = "evidence.parse.error"
    EVIDENCE_INGEST_SUCCESS  = "evidence.ingest.success"
    EVIDENCE_INGEST_ERROR    = "evidence.ingest.error"
    EVIDENCE_TSA_ANCHORED    = "evidence.tsa.anchored"

class AuditEvent(BaseModel):
    """Immutable audit event — one per state transition."""

    model_config = ConfigDict(frozen=True)

    id: UUID
    ts: datetime.datetime
    org_id: UUID
    actor_user_id: UUID | None   # None for Celery tasks
    action: AuditEventType
    resource_type: str
    resource_id: UUID
    decision: str                # "allow" | "deny" | "error" | "ok"
    ip: str | None = None
    extra: dict = {}
    prev_row_hash: bytes         # BYTEA(32) — SHA-256 of previous row
    row_hash: bytes              # BYTEA(32) — SHA-256(prev_row_hash || canonical_json(self))

    @staticmethod
    def compute_row_hash(prev_row_hash: bytes, event_without_hash: dict) -> bytes:
        """Produces the per-row hash for tamper detection."""
        canonical = json.dumps(event_without_hash, sort_keys=True, ensure_ascii=True)
        payload = prev_row_hash + canonical.encode()
        return hashlib.sha256(payload).digest()
```

Rules:
- `row_hash = SHA256(prev_row_hash || canonical_json(event))` — this is the tamper-detection chain.
- `AuditEvent` is **immutable**; once written it is never updated.
- `actor_user_id` may be `None` for machine tasks; the Celery worker identity is in `extra`.
- Audit events must **never** contain passwords, raw file bytes, user IPs beyond the `ip` field, or PII beyond `preferred_username`.

### 2.4 User and TenantContext

```python
# src/domain/user.py
from uuid import UUID
from pydantic import BaseModel, ConfigDict

class Role(StrEnum):
    ORG_ADMIN  = "org-admin"
    CASE_LEAD  = "case-lead"
    ANALYST    = "analyst"
    READ_ONLY  = "read-only"

class TenantContext(BaseModel):
    """Extracted from the JWT on each request; immutable for its lifetime."""

    model_config = ConfigDict(frozen=True)

    org_id: UUID
    org_alias: str
    user_id: UUID
    preferred_username: str   # for audit rows
    roles: list[Role]
    acr: str                  # "aal1" | "aal2"
```

---

## 3. Application Services

**Source:** CLAUDE.md §A.1-A.6; reviews/Part_2_Review.md §5; reviews/Part_3_Review.md §5

### 3.1 AuditLogService

```python
# src/application/audit_log.py
from contextlib import asynccontextmanager

class AuditLogService:
    """Append-only audit log with per-row hash chain."""

    def __init__(self, repo: AuditLogRepository) -> None:
        self._repo = repo

    @asynccontextmanager
    async def audit_context(
        self,
        ctx: TenantContext,
        action: AuditEventType,
        resource_type: str,
        resource_id: UUID,
        ip: str | None = None,
        extra: dict | None = None,
    ):
        """Logs success on normal exit; logs error event if exception escapes."""
        try:
            yield
            await self.log(ctx, action, resource_type, resource_id, "ok", ip, extra)
        except Exception as exc:
            await self.log(
                ctx, action, resource_type, resource_id, "error",
                ip, {**(extra or {}), "error": str(exc)},
            )
            raise

    async def log(self, ...) -> AuditEvent:
        prev = await self._repo.latest_row_hash(ctx.org_id)
        event = AuditEvent(
            ...,
            prev_row_hash=prev,
            row_hash=AuditEvent.compute_row_hash(prev, ...),
        )
        await self._repo.append(event)
        return event
```

Every service method that mutates state **must** be wrapped in `audit_context` or call `log` explicitly. No silent mutations.

### 3.2 EvidenceIntakeService

```python
# src/application/evidence_intake.py

class EvidenceIntakeService:
    def __init__(
        self,
        storage: EvidenceStorage,
        evidence_repo: EvidenceRepository,
        audit_log: AuditLogService,
        hash_service: HashService,
        scanner: ClamAVScanner,
        validator_chain: ValidatorChain,
        tsa: RFCTimestampService,
    ) -> None: ...

    async def request_upload(
        self, ctx: TenantContext, case_id: UUID, payload: EvidenceUploadRequest
    ) -> EvidenceUploadResponse:
        async with self._audit_log.audit_context(ctx, EVIDENCE_UPLOAD_START, ...):
            # 1. Create evidence row in UPLOADING state
            # 2. Mint presigned multipart URLs
            # 3. Return URLs — client uploads directly to MinIO quarantine bucket
            ...

    async def finalize_upload(
        self, ctx: TenantContext, evidence_id: UUID, client_sha256: bytes
    ) -> Evidence:
        # Triggers SCANNING → HASHING → RECEIVED pipeline via Celery
        ...
```

### 3.3 ValidatorChain

```python
# src/application/validation.py
from abc import ABC, abstractmethod

class EvidenceValidator(ABC):
    """Abstract base for evidence validators."""

    @abstractmethod
    async def validate(self, evidence: Evidence, file_header: bytes) -> None:
        """Raise ValidationError if invalid."""

class MagicByteValidator(EvidenceValidator):
    """Validates against the §2 review §5.4 allowlist."""

    MAGIC_TABLE: ClassVar[dict[str, tuple[int, bytes]]] = {
        "evtx":    (0,  b"ElfFile\x00"),
        "prefetch":(4,  b"SCCA"),
        "regf":    (0,  b"regf"),
        "sqlite":  (0,  b"SQLite format 3\x00"),
        "journal": (0,  b"LPKSHHRH"),
    }

    async def validate(self, evidence: Evidence, file_header: bytes) -> None:
        if evidence.artefact_type not in self.MAGIC_TABLE:
            return  # Text formats handled by FileSizeValidator + libmagic only
        offset, magic = self.MAGIC_TABLE[evidence.artefact_type]
        if file_header[offset : offset + len(magic)] != magic:
            raise ValidationError(
                f"magic byte mismatch for {evidence.artefact_type}"
            )

class ValidatorChain(EvidenceValidator):
    """Runs validators in order; first failure stops the chain."""

    def __init__(self, validators: list[EvidenceValidator]) -> None:
        self._validators = validators

    async def validate(self, evidence: Evidence, file_header: bytes) -> None:
        for v in self._validators:
            await v.validate(evidence, file_header)
```

### 3.4 HashService

```python
# src/application/hashing.py
import hashlib

class HashService:
    """Computes and verifies whole-file SHA-256."""

    async def compute_from_stream(
        self, stream: AsyncIterator[bytes]
    ) -> bytes:
        """Returns raw 32-byte SHA-256 digest (not hex)."""
        h = hashlib.sha256()
        async for chunk in stream:
            h.update(chunk)
        return h.digest()

    def verify(self, computed: bytes, expected: bytes) -> None:
        if computed != expected:
            raise ValidationError("SHA-256 mismatch — file corrupted in transit")
```

Rule: **SHA-256 is stored as raw `bytes` (BYTEA), not hex.** The S3 multipart ETag is never used as the forensic fingerprint.

---

## 4. Adapter Layer — Repositories

**Source:** CLAUDE.md §A.3; reviews/Part_1_Review.md §5.2; reviews/Part_2_Review.md §5.7

### 4.1 Abstract interfaces

```python
# src/adapter/repository/audit_log.py
from abc import ABC, abstractmethod

class AuditLogRepository(ABC):
    """Append-only. Never exposes update/delete methods."""

    @abstractmethod
    async def append(self, event: AuditEvent) -> None: ...

    @abstractmethod
    async def latest_row_hash(self, org_id: UUID) -> bytes: ...

    @abstractmethod
    def paginate(
        self, org_id: UUID, *, cursor: UUID | None, limit: int
    ) -> AsyncIterator[AuditEvent]: ...
```

```python
# src/adapter/repository/evidence.py
class EvidenceRepository(ABC):
    @abstractmethod
    async def create(self, evidence: Evidence) -> None: ...

    @abstractmethod
    async def get(self, org_id: UUID, evidence_id: UUID) -> Evidence: ...

    @abstractmethod
    async def update_state(
        self, org_id: UUID, evidence_id: UUID,
        new_state: EvidenceState, error_reason: str | None = None
    ) -> Evidence: ...
```

### 4.2 PostgreSQL implementation

```python
# src/adapter/repository/postgres_evidence.py

class PostgresEvidenceRepository(EvidenceRepository):
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def get(self, org_id: UUID, evidence_id: UUID) -> Evidence:
        async with self._pool.acquire() as conn:
            # org_id filter is mandatory — never query without it
            row = await conn.fetchrow(
                "SELECT * FROM evidence WHERE id = $1 AND org_id = $2",
                evidence_id, org_id,
            )
        if row is None:
            raise NotFoundError(f"evidence {evidence_id} not found")
        return Evidence(**dict(row))
```

Rules:
- **Every query must include `org_id`** — this is the multi-tenancy enforcement.
- Set `SET app.current_org = :org_id` at connection time to prepare for future Row-Level Security.
- Never pass ORM objects upward; always convert to domain models at the repository boundary.

---

## 5. Adapter Layer — Storage (MinIO)

**Source:** reviews/Part_2_Review.md §5.1-5.2; reviews/Part_5_Review.md §5.3

### 5.1 Bucket layout

| Bucket pattern | Object Lock | SSE-KMS | Purpose |
|---|---|---|---|
| `kronos-evidence-{org_alias}-quarantine` | None (versioning on) | Yes | Post-upload, pre-scan |
| `kronos-evidence-{org_alias}` | Compliance mode | Yes | Verified, WORM evidence |
| `kronos-siem-archive` | Compliance 7y | Yes | Write-once Wazuh alerts |

Both buckets must have SSE-KMS enabled **at creation time** — it cannot be retro-fitted.

### 5.2 Abstract interface

```python
# src/adapter/storage/storage.py
from abc import ABC, abstractmethod

class EvidenceStorage(ABC):
    @abstractmethod
    async def create_multipart_upload(
        self, org_alias: str, evidence_id: UUID, filename: str
    ) -> list[PresignedPart]: ...

    @abstractmethod
    async def complete_multipart_upload(
        self, org_alias: str, evidence_id: UUID, parts: list[UploadedPart]
    ) -> str: ...   # returns object_key

    @abstractmethod
    async def promote_to_evidence_bucket(
        self,
        org_alias: str,
        quarantine_key: str,
        evidence_id: UUID,
        sha256: bytes,
        retain_until: datetime.datetime,
    ) -> str: ...

    @abstractmethod
    async def get_streaming_url(
        self, bucket: str, object_key: str, expires_in: int = 300
    ) -> str: ...   # presigned GET URL (one-shot for parsers)
```

### 5.3 S3 implementation rules

```python
# src/adapter/storage/s3.py
class S3EvidenceStorage(EvidenceStorage):

    async def promote_to_evidence_bucket(self, ...) -> str:
        # CopyObject with Object Lock headers
        await self._client.copy_object(
            CopySource={"Bucket": quarantine_bucket, "Key": quarantine_key},
            Bucket=evidence_bucket,
            Key=object_key,
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until.isoformat(),
            ServerSideEncryption="aws:kms",
            Metadata={"x-amz-meta-sha256": sha256.hex()},
        )
```

Rules:
- Presigned URLs expire in **15 minutes** (upload) or **5 minutes** (single-use GET for parsers).
- After promotion, **delete the quarantine copy**.
- Legal Hold is a separate API call after promotion.
- The whole-file SHA-256 is stored as MinIO user metadata `x-amz-meta-sha256` in addition to the Postgres column.

---

## 6. Adapter Layer — Task Queue (Celery)

**Source:** reviews/Part_3_Review.md §5.5; reviews/Part_5_Review.md §5.4; Project_Specifications.md §3

### 6.1 Queue definitions

```python
# src/external/celery_app.py
from celery import Celery

app = Celery("kronos")
app.conf.task_queues = {
    "q.parse.fast":         {"exchange": "parse", "routing_key": "parse.fast"},
    "q.parse.plaso":        {"exchange": "parse", "routing_key": "parse.plaso"},
    "q.parse.plaso.heavy":  {"exchange": "parse", "routing_key": "parse.plaso.heavy"},
    "q.index":              {"exchange": "index",  "routing_key": "index"},
}
```

| Queue | Sandbox | RAM cap | Workers |
|---|---|---|---|
| `q.parse.fast` | gVisor (`runsc`) | 1 GB | CPU count |
| `q.parse.plaso` | Firecracker microVM | 2 GB | max(1, CPU/4) |
| `q.parse.plaso.heavy` | Firecracker microVM | 4 GB | 1–2 |
| `q.index` | none | — | tuned to OS cluster |

### 6.2 Celery DAG

```python
# src/external/celery_tasks.py
from celery import chain, chord, group

def submit_parse_pipeline(evidence: Evidence) -> None:
    pipeline = chain(
        dispatch_parse.s(str(evidence.id)),
        parse_artefact.s(),
        chord(
            group(index_chunk.s(i) for i in range(expected_chunks)),
            finalize_evidence.s(str(evidence.id)),
        ),
    )
    pipeline.apply_async()
```

### 6.3 Retry policy

```python
@app.task(
    bind=True,
    max_retries=5,
    default_retry_delay=30,                 # 30 s base
    retry_backoff=True,
    retry_backoff_max=480,                  # cap at 8 min
    retry_jitter=True,
)
def index_chunk(self, chunk_path: str, evidence_id: str, chunk_index: int) -> int:
    try:
        return _do_index(chunk_path, evidence_id, chunk_index)
    except OpenSearchTransportError as exc:
        raise self.retry(exc=exc)   # transient — retry
    except ParsingError as exc:
        # deterministic — do NOT retry, go straight to ERROR
        mark_evidence_error(evidence_id, "parser_format_error")
        raise
```

### 6.4 Idempotent OpenSearch document IDs

```python
import hashlib

def deterministic_doc_id(evidence_id: str, parser: str, record_index: int) -> str:
    """SHA-1 of (evidence_id:parser:record_index) — idempotent upserts on retry."""
    payload = f"{evidence_id}:{parser}:{record_index}".encode()
    return hashlib.sha1(payload).hexdigest()
```

This prevents duplicate documents when an `index_chunk` task is retried.

---

## 7. Adapter Layer — OpenSearch

**Source:** reviews/Part_1_Review.md §5.4; reviews/Part_3_Review.md §5.3-5.4; reviews/Part_4_Review.md §5.3

### 7.1 Index naming convention

```
kronos-{org_alias}-case-{case_id}-{yyyymm}
```

Each case also has a **write alias** `kronos-{org_alias}-case-{case_id}` that rolls over via ISM when the index reaches 30 GB or 30 days.

### 7.2 ECS index template (critical fields)

```json
{
  "index_patterns": ["kronos-*-case-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "codec": "best_compression",
      "refresh_interval": "30s"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "event": {
          "properties": {
            "kind":     { "type": "keyword" },
            "category": { "type": "keyword" },
            "action":   { "type": "keyword" },
            "module":   { "type": "keyword" },
            "dataset":  { "type": "keyword" },
            "original": { "type": "text", "index": false }
          }
        },
        "kronos": {
          "properties": {
            "tenant_id":       { "type": "keyword" },
            "org_alias":       { "type": "keyword" },
            "case_id":         { "type": "keyword" },
            "evidence_id":     { "type": "keyword" },
            "evidence_sha256": { "type": "keyword" },
            "tz_fold":         { "type": "byte" },
            "parser_version":  { "type": "keyword" },
            "ingest_id":       { "type": "keyword" }
          }
        }
      }
    }
  }
}
```

### 7.3 Bulk ingestion

```python
# src/adapter/opensearch/client.py

class OpenSearchClient:
    BATCH_SIZE = 500

    async def bulk_index(
        self,
        index: str,
        records: AsyncIterator[TimelineRecord],
    ) -> int:
        batch: list[dict] = []
        indexed = 0
        async for record in records:
            doc_id = deterministic_doc_id(
                record.kronos.evidence_id,
                record.event_module,
                indexed,
            )
            batch.append({"index": {"_index": index, "_id": doc_id}})
            batch.append(record.model_dump(by_alias=True))
            indexed += 1
            if len(batch) // 2 >= self.BATCH_SIZE:
                await self._flush(batch)
                batch = []
        if batch:
            await self._flush(batch)
        return indexed
```

### 7.4 Document-Level Security

Every OpenSearch index has a DLS filter on `tenant_id`. The OpenSearch Security `roles.yml` must define:

```yaml
kronos_analyst:
  index_permissions:
    - index_patterns: ["kronos-*"]
      dls: '{"term": {"kronos.tenant_id": "${user.name}"}}'
      allowed_actions: ["read"]
```

This is a belt-and-braces defence; the primary isolation is the index-naming scheme.

### 7.5 ISM Rollover Policy

```json
{
  "policy": {
    "description": "Rollover at 30 GB or 30 days",
    "states": [{
      "name": "active",
      "actions": [{
        "rollover": {
          "min_size": "30gb",
          "min_index_age": "30d"
        }
      }]
    }]
  }
}
```

---

## 8. External — Auth Middleware (Keycloak)

**Source:** reviews/Part_6_Review.md §5.4-5.5; Project_Specifications.md §6

### 8.1 JWT validation pipeline

```python
# src/external/middleware/keycloak_auth.py
from jose import JWTError, jwt as jose_jwt

ALLOWED_ALGORITHMS = {"RS256", "PS256"}   # NEVER allow "none"

class KeycloakTokenValidator:
    def __init__(self, settings: Settings) -> None:
        self._issuer   = settings.keycloak_issuer
        self._audience = settings.keycloak_audience
        self._jwks_cache: dict[str, dict] = {}

    async def validate(self, token: str) -> TenantContext:
        header = jose_jwt.get_unverified_header(token)
        alg = header.get("alg", "none")
        if alg not in ALLOWED_ALGORITHMS:
            raise AuthenticationError(f"Algorithm {alg!r} is not allowed")
        kid = header["kid"]
        key = await self._get_key(kid)
        try:
            claims = jose_jwt.decode(
                token, key,
                algorithms=list(ALLOWED_ALGORITHMS),
                audience=self._audience,
                issuer=self._issuer,
            )
        except JWTError as exc:
            raise AuthenticationError("JWT validation failed") from exc
        return self._extract_context(claims)

    def _extract_context(self, claims: dict) -> TenantContext:
        org_map: dict = claims.get("organization", {})
        if not org_map:
            raise AuthenticationError("Missing organization claim")
        org_alias, org_attrs = next(iter(org_map.items()))
        return TenantContext(
            org_id=UUID(org_attrs["id"]),
            org_alias=org_alias,
            user_id=UUID(claims["sub"]),
            preferred_username=claims["preferred_username"],
            roles=[Role(r) for r in claims.get("roles", [])],
            acr=claims.get("acr", "aal1"),
        )
```

Rules:
- `alg=none` is rejected unconditionally — checked **before** attempting verification.
- On `kid` miss: re-fetch JWKS **once**, then fail.
- JWKS cache TTL ≤ 10 minutes.
- Token introspection is NOT used per-request (too slow).
- `typ` must be `Bearer`, not `ID` (reject ID tokens from being used as access tokens).

### 8.2 RBAC permission matrix

```python
# src/external/middleware/rbac.py
from functools import wraps

# (action, resource) → (minimum role, minimum ACR)
PERMISSION_MATRIX: dict[str, tuple[Role, str]] = {
    "case.create":           (Role.CASE_LEAD,  "aal1"),
    "evidence.upload":       (Role.ANALYST,    "aal1"),
    "evidence.download":     (Role.ANALYST,    "aal1"),
    "evidence.delete":       (Role.CASE_LEAD,  "aal2"),   # step-up required
    "evidence.legal_hold":   (Role.CASE_LEAD,  "aal2"),   # step-up required
    "org.manage_users":      (Role.ORG_ADMIN,  "aal2"),   # step-up required
    "audit_log.view":        (Role.CASE_LEAD,  "aal1"),
}

def requires_permission(action: str):
    """FastAPI dependency factory for RBAC enforcement."""
    def dependency(ctx: TenantContext = Depends(get_tenant_context)) -> None:
        min_role, min_acr = PERMISSION_MATRIX[action]
        if min_role not in ctx.roles and Role.ORG_ADMIN not in ctx.roles:
            raise ForbiddenError(f"Role insufficient for {action}")
        if ctx.acr < min_acr:
            raise InsufficientACRError(required_acr=min_acr)
    return Depends(dependency)
```

When `InsufficientACRError` is raised, the exception handler must return HTTP 401 with:

```
WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="aal2"
```

The SPA then calls `keycloak.login({ acrValues: 'aal2', prompt: 'login' })`.

### 8.3 OpenSearch Security YAML (normative)

```yaml
# opensearch-security/config.yml
authc:
  openid_auth_domain:
    order: 0              # MUST be first
    http_authenticator:
      type: openid
      challenge: false    # MUST be false for iframe SSO
      config:
        openid_connect_url: https://idp.kronos.example/realms/kronos/.well-known/openid-configuration
        subject_key: preferred_username   # human-readable for audit
        roles_key: roles                  # flat claim from kronos-roles scope
        jwt_clock_skew_tolerance_seconds: 30
    authentication_backend:
      type: noop
  basic_internal_auth_domain:
    order: 1              # after OIDC
    http_authenticator:
      type: basic
      challenge: true
    authentication_backend:
      type: internal
```

Rules:
- `openid_auth_domain` **must** be `order: 0`.
- `roles_key: roles` (flat, multivalued) — never `realm_access.roles` (nested path not supported).
- `subject_key: preferred_username` — not `sub` (UUID is useless for audit correlation).

---

## 9. External — Parsers

**Source:** CLAUDE.md §A.4; reviews/Part_3_Review.md §5.1-5.8

### 9.1 Abstract base

```python
# src/application/parsing.py
from abc import ABC, abstractmethod
from enum import StrEnum
from typing import AsyncIterator

class ParserType(StrEnum):
    FAST  = "fast"
    PLASO = "plaso"
    TEXT  = "text"

class ForensicParser(ABC):
    """Abstract base for all forensic parsers. Subclasses implement format logic."""

    @abstractmethod
    def supports(self, artefact_type: str) -> bool:
        """Return True if this parser handles the given artefact type."""

    @abstractmethod
    def parser_type(self) -> ParserType:
        """Return the queue slot this parser targets."""

    @abstractmethod
    async def validate(self, object_url: str) -> None:
        """Raise ParsingError if the file cannot be parsed by this implementation."""

    @abstractmethod
    async def parse(
        self, object_url: str, provenance: KronosProvenance
    ) -> AsyncIterator[TimelineRecord]:
        """Yield TimelineRecord one at a time. Never load the whole file into memory."""
```

Rules:
- Parsers **yield** records one at a time — no `list[TimelineRecord]` returns.
- Every yielded record carries the full `kronos.*` provenance block.
- `event.original` is truncated to 32 KB; overflow goes to MinIO.
- All timestamps in `@timestamp` are UTC with trailing `Z`. Use `dateutil.tz`, not `pytz`.

### 9.2 ParserRegistry

```python
# src/application/parser_registry.py

class ParserRegistry:
    """Auto-discovery registry. No if/elif chains allowed."""

    def __init__(self) -> None:
        self._parsers: list[ForensicParser] = []

    def register(self, parser: ForensicParser) -> None:
        self._parsers.append(parser)

    def resolve(self, artefact_type: str) -> ForensicParser:
        for parser in self._parsers:
            if parser.supports(artefact_type):
                return parser
        raise ParsingError(f"No parser registered for {artefact_type!r}")
```

Parsers are registered at application startup; the registry is then immutable.

### 9.3 DST / UTC normalisation

```python
from dateutil import tz as dateutil_tz

def to_utc_iso(
    dt: datetime.datetime,
    source_tz_name: str | None,
) -> tuple[str, int]:
    """Returns (iso8601_utc_z, tz_fold) where tz_fold ∈ {0, 1, -1}."""
    if source_tz_name:
        local_tz = dateutil_tz.gettz(source_tz_name)
        dt = dt.replace(tzinfo=local_tz)
        fold = 0
        if dateutil_tz.datetime_ambiguous(dt):
            fold = -1   # ambiguous — store both candidates
        elif not dateutil_tz.datetime_exists(dt):
            raise ParsingError(f"Non-existent local time: {dt}")
    utc = dt.astimezone(dateutil_tz.UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z", fold
```

- Never use `pytz` — deprecated fold semantics.
- DST ambiguity → set `kronos.tz_fold = -1`, store early candidate in `@timestamp`, late candidate in `kronos.alt_timestamp`.

### 9.4 Supported artefact types (v1)

| Artefact | `artefact_type` value | Parser slot | Notes |
|---|---|---|---|
| Windows EVTX | `evtx` | `fast` | evtx-rs; Plaso fallback for corrupt files |
| Prefetch (.pf) | `prefetch` | `plaso` | Plaso `prefetch` |
| Registry hive | `regf` | `plaso` | Plaso `winreg/*` plugins |
| SRUM | `srum` | `plaso.heavy` | 4 GB RAM cap — heavy queue |
| Shimcache | `shimcache` | `plaso` | via SYSTEM hive |
| Amcache | `amcache` | `plaso` | |
| Browser SQLite | `browser_sqlite` | `plaso` | Chrome / Firefox |
| journald | `journal` | `plaso` | |
| syslog | `syslog` | `plaso` | |
| Apache / Nginx logs | `nginx`, `apache` | `text` | Custom parser |
| AWS CloudTrail | `cloudtrail` | `text` | JSON-lines, ECS `aws.cloudtrail.*` |
| GCP audit / Azure | `gcp_audit`, `azure_activity` | `text` | Custom |
| EML / MBOX | `eml` | `plaso` | |
| CSV | `csv` | `text` | Header-aware chunker |
| JSON / NDJSON | `ndjson` | `text` | |

Large text logs (> 1 000 000 lines) are split into ≤ 500 k-line chunks; the CSV header is re-emitted on every chunk. Binary formats are **never** split mid-file.

---

## 10. Audit Log

**Source:** CLAUDE.md §A.2; reviews/Part_1_Review.md §5.6; reviews/Part_2_Review.md §5.7-5.8; reviews/Part_5_Review.md §5.5

### 10.1 Hash chain invariant

```
row_hash_N = SHA256(row_hash_{N-1} || canonical_json(event_N_without_hash))
```

- `canonical_json` means `json.dumps(sort_keys=True, ensure_ascii=True)`.
- `row_hash_0` (genesis) is `SHA256(b"\x00" * 32)` — a known constant.
- Silent deletion of any row makes the chain invalid; `kronos-attest verify --day` detects it.

### 10.2 Daily Merkle anchor

```python
# Celery beat task — runs at 00:05 UTC every day
@app.task
async def audit_merkle_anchor(date: str) -> None:
    rows = await audit_repo.rows_for_day(date)
    root = compute_merkle_root([r.row_hash for r in rows])
    tst  = await tsa_client.timestamp(root)
    await anchor_repo.insert(AuditAnchor(date=date, root_hash=root, tsa_token=tst))
```

### 10.3 kronos-attest verify CLI

The verifier is **read-only** — no write paths. It must be runnable by a third-party auditor given only:
- Read-only Postgres credentials.
- Read-only MinIO presigned access.
- The Sigstore TSA public certificate chain.

```bash
kronos-attest verify --day 2026-06-16
kronos-attest verify --case b2a9...
kronos-attest verify --audit-only --day 2026-06-16
```

---

## 11. Frontend (React / TypeScript)

**Source:** reviews/Part_4_Review.md §5; reviews/Part_6_Review.md §5.6; Project_Specifications.md §4

### 11.1 Auth wiring

```typescript
// Access token: in-memory ONLY. Never localStorage.
// Refresh token: HttpOnly + Secure + SameSite=Strict cookie, proxied via /auth/refresh.

const keycloak = new Keycloak({
  url: "https://idp.kronos.example",
  realm: "kronos",
  clientId: "kronos-spa",
});

await keycloak.init({
  onLoad: "check-sso",
  pkceMethod: "S256",
  responseMode: "fragment",
  useNonce: true,
  checkLoginIframe: false,
});
```

On `401 insufficient_user_authentication`:

```typescript
await keycloak.login({ acrValues: "aal2", prompt: "login" });
// Replay original request after re-authentication
```

### 11.2 Uppy upload configuration

```typescript
import Uppy from "@uppy/core";
import AwsS3Multipart from "@uppy/aws-s3-multipart";
import Tus from "@uppy/tus";

const uppy = new Uppy({ restrictions: { maxFileSize: 1_073_741_824 } })
  .use(AwsS3Multipart, {
    createMultipartUpload: (file) =>
      api.post("/cases/{caseId}/evidence", { filename: file.name }),
    signPart: (file, { uploadId, partNumber }) =>
      api.get(`/evidence/${file.meta.evidenceId}/parts/${partNumber}`, { uploadId }),
    completeMultipartUpload: (file, { uploadId, parts }) =>
      api.post(`/evidence/${file.meta.evidenceId}/complete`, {
        uploadId, parts, sha256: file.meta.clientSha256,
      }),
  })
  .use(Tus, { endpoint: "/tus", headers: { Authorization: `Bearer ${keycloak.token}` } });
```

Client-side magic-byte check via `file-type` npm package before requesting upload URLs — saves a round-trip on obviously wrong files. Server-side validation is the authority.

### 11.3 SSE status channel

```typescript
// Short-lived one-shot ticket (not Bearer JWT — EventSource cannot set headers)
const { ticket } = await api.post("/sse/ticket");
const source = new EventSource(`/sse/cases/${caseId}/evidence?ticket=${ticket}`);

// Fall back to polling if SSE does not open within 10 s
const fallback = setTimeout(() => startPolling(caseId), 10_000);
source.addEventListener("open", () => clearTimeout(fallback));
source.addEventListener("status", (e) => updateEvidenceRow(JSON.parse(e.data)));
```

### 11.4 OpenSearch Dashboards iframe

```html
<!-- CSP frame-ancestors is set by NGINX, NOT by the SPA -->
<iframe
  src={`https://dashboards.kronos.example/app/data-explorer/discover#/?embed=true&...`}
  sandbox="allow-scripts allow-same-origin allow-forms"
  loading="lazy"
/>
```

NGINX config (mandatory before day 1):

```nginx
add_header Content-Security-Policy
  "frame-ancestors 'self' https://app.kronos.example" always;
add_header X-Frame-Options "SAMEORIGIN" always;
```

---

## 12. Database Schema (PostgreSQL / Alembic)

**Source:** reviews/Part_1_Review.md §5.2; reviews/Part_2_Review.md §5.7

### 12.1 Core tables

```sql
-- Enable CITEXT for case-insensitive email lookups
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE org (
  id            UUID PRIMARY KEY,          -- matches Keycloak Organization.id
  alias         TEXT UNIQUE NOT NULL,      -- used in index names
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  retention_days INT NOT NULL DEFAULT 365
);

CREATE TABLE app_user (
  id          UUID PRIMARY KEY,            -- matches Keycloak sub
  org_id      UUID NOT NULL REFERENCES org(id),
  email       CITEXT UNIQUE NOT NULL,
  role        TEXT NOT NULL CHECK (role IN ('org-admin','case-lead','analyst','read-only')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE case_ (
  id            UUID PRIMARY KEY,
  org_id        UUID NOT NULL REFERENCES org(id),
  name          TEXT NOT NULL,
  lead_user_id  UUID REFERENCES app_user(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  retention_days INT,                      -- NULL = inherit from org
  UNIQUE(org_id, name)
);

CREATE TABLE case_member (
  case_id   UUID REFERENCES case_(id) ON DELETE CASCADE,
  user_id   UUID REFERENCES app_user(id) ON DELETE CASCADE,
  role      TEXT NOT NULL CHECK (role IN ('case-lead','analyst','read-only')),
  PRIMARY KEY (case_id, user_id)
);

CREATE TABLE evidence (
  id                UUID PRIMARY KEY,
  case_id           UUID NOT NULL REFERENCES case_(id),
  org_id            UUID NOT NULL REFERENCES org(id),
  filename          TEXT NOT NULL,
  size_bytes        BIGINT NOT NULL,
  sha256            BYTEA,                 -- 32 bytes; set on HASHING→RECEIVED
  mime_detected     TEXT,
  artefact_type     TEXT,
  status            TEXT NOT NULL CHECK (status IN (
                      'UPLOADING','SCANNING','HASHING','RECEIVED',
                      'PARSING','INGESTING','COMPLETE','ERROR','PURGED')),
  bucket            TEXT NOT NULL,
  object_key        TEXT NOT NULL,
  object_lock_until TIMESTAMPTZ,
  legal_hold        BOOLEAN NOT NULL DEFAULT false,
  rfc3161_token     BYTEA,
  uploaded_by       UUID NOT NULL REFERENCES app_user(id),
  uploaded_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  error_reason      TEXT,
  UNIQUE (org_id, case_id, sha256)        -- deduplication within a case
);
CREATE INDEX evidence_case_status_idx ON evidence(case_id, status);
CREATE INDEX evidence_org_uploaded_idx ON evidence(org_id, uploaded_at DESC);

CREATE TABLE audit_log (
  id              UUID PRIMARY KEY,
  ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
  org_id          UUID NOT NULL REFERENCES org(id),
  actor_user_id   UUID REFERENCES app_user(id),
  action          TEXT NOT NULL,
  resource_type   TEXT NOT NULL,
  resource_id     UUID NOT NULL,
  decision        TEXT NOT NULL,
  ip              INET,
  extra           JSONB NOT NULL DEFAULT '{}',
  prev_row_hash   BYTEA NOT NULL,          -- 32 bytes
  row_hash        BYTEA NOT NULL           -- 32 bytes
);
CREATE INDEX audit_log_org_ts_idx ON audit_log(org_id, ts DESC);
CREATE INDEX audit_log_resource_idx ON audit_log(resource_id);

CREATE TABLE audit_anchor (
  date        DATE PRIMARY KEY,
  root_hash   BYTEA NOT NULL,             -- Merkle root of day's audit_log rows
  tsa_token   BYTEA NOT NULL              -- RFC 3161 TimeStampToken
);
```

### 12.2 Alembic conventions

- One migration per logical change; descriptive names: `add_evidence_table`, not `v003`.
- Every migration is reversible (always implement `downgrade`).
- Tested against a real Postgres container in CI.
- `org_id` columns must have a foreign-key constraint **and** a check index.

### 12.3 Multi-tenancy via session variable (v1)

```python
async with pool.acquire() as conn:
    await conn.execute("SET app.current_org = $1", str(ctx.org_id))
    # All queries in this connection are now scoped to the org
```

When RLS is enabled (v2), this variable feeds the policy. In v1 the application layer enforces it.

---

## 13. Container & Security Baseline

**Source:** reviews/Part_5_Review.md §3.1, §3.7, §5.2-5.4

### 13.1 Base images

All containers use **Chainguard / Wolfi** base images:

```dockerfile
FROM cgr.dev/chainguard/python:latest-dev AS build
...
FROM cgr.dev/chainguard/python:latest
COPY --from=build /app /app
USER nonroot
```

No `apt-get`, no `pip install` at runtime.

### 13.2 Parser sandbox requirements

| Requirement | gVisor (`q.parse.fast`) | Firecracker (`q.parse.plaso`) |
|---|---|---|
| Runtime | `--runtime=runsc` on Docker/K8s | Firecracker VMM, 1 VM per task |
| Network | `--network=none` | No network device attached |
| RAM cap | 1 GB cgroup | 2 GB (4 GB heavy queue) |
| Filesystem | Read-only rootfs + writable tmpfs | Read-only rootfs + writable tmpfs |
| MinIO access | One-shot presigned GET URL injected at boot | Same |

OOM (exit 137) → `error_reason = "parser_oom"`. No retry.

### 13.3 Trivy CI gate

```yaml
# .github/workflows/build.yml
- name: Scan image for CVEs
  run: |
    trivy image \
      --severity HIGH,CRITICAL \
      --exit-code 1 \
      kronos/backend:${GITHUB_SHA}
```

A PR with a HIGH or CRITICAL CVE in any container **must not merge**.

### 13.4 SBOM and signing

```bash
syft kronos/backend:${TAG} -o spdx-json > sbom.spdx.json
cosign attest --type spdx \
  --predicate sbom.spdx.json \
  kronos/backend:${TAG}
```

---

## 14. CI / CD Pipeline

**Source:** reviews/Part_5_Review.md §5.7-5.8; CLAUDE.md §D

### 14.1 Required checks (every PR)

```bash
# Type checking
mypy src/ --strict

# Linting
ruff check src/ tests/

# Formatting
black --check src/ tests/

# Unit tests (must finish in < 5 s)
pytest tests/unit/ -v --timeout=5

# Domain isolation check
python scripts/check_domain_imports.py

# CVE scan
trivy image --severity HIGH,CRITICAL --exit-code 1 kronos/backend:${SHA}
```

All five must pass before merge.

### 14.2 Integration tests

```bash
# Requires testcontainers (Postgres, MinIO, OpenSearch, Redis, Keycloak)
pytest tests/integration/ -v --timeout=30
```

Run on merge to `main` and nightly.

### 14.3 Secret scanning

Pre-commit hook:

```yaml
- repo: https://github.com/gitleaks/gitleaks
  rev: v8.24.0
  hooks:
    - id: gitleaks
```

No secrets (API keys, passwords, tokens) are committed. Vault Agent renders them at runtime.

---

## 15. Compliance Checklist (ISO 27001:2022)

**Source:** reviews/Part_5_Review.md §5.7; Project_Specifications.md §5

| Control | KronOS implementation | Owner |
|---|---|---|
| **A.5.15** Access control | RBAC matrix in §8.2; Keycloak Organizations; OpenSearch DLS | Backend / Infra |
| **A.5.17** Authentication information | PKCE + HttpOnly refresh cookie; 15-min access tokens; rotation | Backend / Frontend |
| **A.5.24** Incident management | Wazuh alerts; NIST SP 800-86 runbook | Ops |
| **A.5.25** Assessment | Wazuh alert tiering; detection rules in §8.3 | Ops / Security |
| **A.5.26** Response | Chain-of-custody on every incident artefact | Ops / Dev |
| **A.5.28** Collection of evidence | **The product itself** — §2 FSM + RFC 3161 + Merkle root + `kronos-attest verify` | Dev |
| **A.5.30** ICT readiness | MinIO active-active; Vault HA; OpenSearch snapshots; RPO 5 min / RTO 15 min | Infra |
| **A.5.33** Protection of records | Object Lock Compliance; Legal Hold; SSE-KMS | Infra |
| **A.8.5** Secure authentication | PKCE; mandatory WebAuthn for org-admin | Dev / Keycloak |
| **A.8.7** Protection against malware | ClamAV post-store scan; Falco runtime; Trivy CI | Dev / Ops |
| **A.8.13** Information backup | MinIO replication; Postgres WAL; Vault snapshots | Infra |
| **A.8.15** Logging | `audit_log` hash chain; Wazuh; daily Merkle anchor | Dev |
| **A.8.16** Monitoring | Wazuh dashboards; Falco eBPF; OS Security Audit Log | Ops |
| **A.8.20** Network security | Four-zone trust boundary; mTLS everywhere; egress allowlist | Infra |
| **A.8.24** Use of cryptography | TLS 1.3; SSE-KMS; RFC 3161; Cosign | Dev / Infra |
| **A.8.25** Secure SDLC | Trivy + Cosign + SBOM + Semgrep + CodeQL in CI | Dev / Ops |
| **A.8.28** Secure coding | SAST in CI; dependency review; pre-commit secret scan | Dev |

---

## Quick Reference — Non-Negotiables

The following must **never** be violated:

| # | Rule | Source |
|---|---|---|
| 1 | `alg=none` in JWT → immediate rejection | Part_6_Review §3.3 |
| 2 | Every query includes `org_id` filter | Part_1_Review §5.2 |
| 3 | `@timestamp` always UTC with trailing `Z` | Part_3_Review §5.7 |
| 4 | `pytz` is never used (use `dateutil.tz`) | Part_3_Review §5.7 |
| 5 | SHA-256 is stored as BYTEA(32), not hex | Part_2_Review §5.3 |
| 6 | SSE-KMS set at bucket creation time — never retro-fitted | Part_5_Review §5.3 |
| 7 | Parsers yield records one at a time — no `list[TimelineRecord]` | CLAUDE.md §A.5 |
| 8 | Audit log is append-only — no update/delete methods on `AuditLogRepository` | Part_1_Review §5.6 |
| 9 | `kronos.*` block mandatory on every OpenSearch document | Part_3_Review §5.3 |
| 10 | `openid_auth_domain` must be `order: 0` in OpenSearch Security config | Part_6_Review §3.2 |
| 11 | Refresh token lives in HttpOnly cookie — never in localStorage | Part_6_Review §3.4 |
| 12 | No secrets in env vars, ConfigMaps, or git — Vault only | Part_5_Review §5.11 |
| 13 | No blocking operations on FastAPI thread | CLAUDE.md §A.5 |
| 14 | `roles_key: roles` (flat claim) — never `realm_access.roles` | Part_1_Review §5.4 |
| 15 | Evidence deletion requires `aal2` step-up auth | Part_6_Review §5.9 |
