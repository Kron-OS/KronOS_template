# KronOS Backend: Implementation Guidelines

**Project:** KronOS — Forensically sound, multi-tenant evidence management and forensic timeline analysis platform  
**Status:** Backend complete (Phases 1–5, 89% coverage). Frontend & infrastructure roadmap in [`roadmap.md`](./roadmap.md).  
**Design authority:** `Project_Specifications.md` + `reviews/Part_*.md`  
**Branch:** Work on designated feature branches; follow git workflow below.

---

## 🚀 Quick Start for All Agents

### For Backend Tasks (Phase 1–5 — ✅ COMPLETE)
This document contains the complete Phase 1–5 backend implementation guidelines. The backend core is finished; these sections are reference only.

### For All Other Tasks (Frontend, Infra, Security, etc.)
⭐ **Go to [`roadmap.md`](./roadmap.md)** — it contains:
- 9 main implementation sections (Frontend SPA, Advanced Parsing, Chain of Custody, Security, Observability, Infrastructure, CI/CD, v2 features)
- Self-contained **agent prompts** for each step (one per section, sometimes multiple per substep)
- All prompts reference `Project_Specifications.md` and `reviews/Part_*.md` — no prior conversation assumed
- Progress checklist per section

**Workflow:**
1. Find your section in `roadmap.md` (e.g., "2. Frontend SPA")
2. Read the agent prompt(s) for that section
3. Execute the prompt as a new agent task
4. Check off completion in the progress tracking (see below)
5. Next agent starts immediately on the next unchecked step

---

## Progress Tracking

See [`PROGRESS.md`](./PROGRESS.md) for a live checklist of all roadmap items. Update it after each section completes.

---

## Project Context

### What KronOS Does
- **Evidence Intake:** Upload files (EVTX, logs, cloud audit trails) with chain-of-custody
- **Forensic Parsing:** Extract timelines using evtx-rs (fast) + Plaso (comprehensive formats)
- **Timeline Analysis:** Index into OpenSearch with ECS schema for forensic queries
- **Multi-Tenancy:** Keycloak Organizations + RBAC + per-tenant data isolation
- **Compliance:** ISO 27001:2022, SEC 17a-4, audit trails with hash chains + RFC 3161 timestamping

### Key Decisions
- **Keycloak 26+ Organizations** for multi-tenancy (not Groups)
- **MinIO Object Lock Compliance** for evidence WORM enforcement
- **evtx-rs fast path + Plaso in Firecracker** for parsing
- **OpenSearch with ECS schema + kronos.* provenance**
- **TLS 1.3 + mTLS internally, Vault for KMS/secrets**
- **Chain-of-custody as append-only audit log with per-row hash chain**

### Tech Stack
```
Frontend:      React 19 + Vite + TanStack Router + Tailwind + shadcn/ui
Backend:       FastAPI + Celery (multi-queue)
Database:      Postgres (audit, metadata) + Redis (queue)
Storage:       MinIO (WORM) + Vault (KMS) + KES (encryption)
Indexing:      OpenSearch (ECS + kronos.*)
Auth:          Keycloak 26+ Organizations + JWT + step-up auth
Parsing:       evtx-rs (fast) + Plaso (heavy) + custom text parsers
Containers:    Chainguard/Wolfi base + daily Trivy scans + Cosign SBOM
```

---

## BASE GUIDELINES (All Phases)

### A. Architectural Backbone (Non-Negotiable)

#### A.1 Object-Oriented, Composition-Heavy Design
- **Classes over functions** for extensible concepts (parsers, validators, storage, audit)
- **Abstract base classes** define contracts; concrete classes inherit and specialize
- **Dependency injection** via constructor (DI container as only singleton)
- **Max ~200 lines per class** — delegate to collaborators, no God Classes
- **No global state** — every dependency explicit and injectable

**Why:** Allows new parsers/storage backends to be added without refactoring core logic.

#### A.2 Chain-of-Custody as First-Class Abstraction
- **AuditLog is not optional** — inject `AuditLogService` into every workflow handler
- **Immutable audit events** — one event per state transition (never forgotten)
- **Evidence FSM transitions automatically trigger audit events**
- **Mutations wrap in audit context:** `async with audit_log.audit_context(...): ...`
- **Hash chain:** `row_hash = SHA256(prev_row_hash || canonical_json(event))`

**Why:** Tamper-detection, legal admissibility, regulatory compliance.

#### A.3 Layering & Dependency Direction (Domain-Driven Design)
```
Domain Layer       → Evidence, AuditEvent, TimelineRecord, User (Pydantic models, no ORM)
    ↓ (import from below only)
Application Layer  → Services: EvidenceIntakeService, ParsingOrchestrationService
    ↓ (import from below only)
Adapter Layer      → Repositories, Storage, Queue clients (ABCs + implementations)
    ↓ (import from below only)
External Layer     → Postgres, MinIO, Celery, OpenSearch, Keycloak drivers
```
- **Domain is self-contained** — zero imports of FastAPI, Celery, Postgres, MinIO
- **Services orchestrate** — repositories, queue, cache clients injected via DI
- **Repositories as abstractions** — swap Postgres for DuckDB later without touching domain
- **DTOs cross boundaries** — never pass ORM objects upward

**Why:** Clear separation of concerns, testable at every layer, framework-independent core.

#### A.4 Extensibility Through Abstraction, Not Configuration
- **Parser framework:** abstract `ForensicParser(ABC)` with `ParserRegistry` (no if/elif chains)
- **Storage backends:** abstract `EvidenceStorage(ABC)` (MinIO/S3/GCS swappable)
- **Validators:** abstract `EvidenceValidator(ABC)` (format-specific rules pluggable)
- **Audit sinks:** abstract `AuditEventSink(ABC)` (Postgres/DuckDB/streaming)
- **No hardcoded values** — all from `pydantic.BaseSettings` or Vault

**Why:** New parsers can be registered at startup without code changes.

#### A.5 Async-First, Streaming Over Batching
- **FastAPI endpoints:** `async def` everywhere
- **Parsers yield records one-at-a-time:** `AsyncIterator[TimelineRecord]` (not arrays)
- **No loading entire audit log into memory** — paginate, stream, lazy-load
- **Celery tasks:** async context managers for resource lifecycle
- **Connection pooling:** Postgres, Redis, mTLS certs rotate without restart

**Why:** Memory-efficient, scales to 100+ GB evidence files.

#### A.6 Security Embedded (Not Retrofitted)
- **Input validation at boundaries** — request models, file size checks, org_id claims
- **Mutations wrapped in audit context** — no silent side effects
- **Privilege checks middleware** — `@requires_role("case_lead")` on routes
- **No secrets in code** — all from Vault or env vars (`.env` never committed)
- **Audit logs never contain plaintext credentials or PII**

**Why:** Compliance-ready from day one; no bolt-on security later.

---

### B. Coding Standards

#### B.1 Naming
- **Classes:** `PascalCase`, domain-first (`EvidenceIntakeService`, not `EventService`)
- **Functions:** `snake_case`, verb-first (`validate_evidence()`, not `evidence_validation()`)
- **Interfaces/ABCs:** `PascalCase`, optionally `ABC` suffix (`ParserRegistry`, `AuditLogRepository`)
- **Constants:** `UPPER_SNAKE_CASE` grouped near class definitions
- **Private methods:** `_leading_underscore`, document why not public

#### B.2 Error Handling
```python
class KronOSException(Exception): pass
class ValidationError(KronOSException): pass
class StorageError(KronOSException): pass
class ParsingError(KronOSException): pass
class AuditLogError(KronOSException): pass
class AuthenticationError(KronOSException): pass
```
- **Never silently ignore exceptions** — log context and re-raise or wrap
- **Audit every error:** `await audit_log.log(error_type="...", details={...})`

#### B.3 Type Hints & Documentation
- **Type hints everywhere:** `def ingest_timeline(records: List[TimelineRecord]) -> EvidenceState`
- **Comments only for "why"**, not "what" — naming makes purpose obvious
- **Docstrings for public classes/methods** — one-liner if obvious:
  ```python
  class ForensicParser(ABC):
      """Abstract base for forensic parsers; subclasses implement format-specific logic."""
  ```
- **README per subsystem** with architecture diagrams

#### B.4 Logging & Observability
- **Structured logging** (JSON format): `logger.info("evidence_ingested", extra={"evidence_id": ..., "record_count": ...})`
- **Correlation IDs** via JWT `jti` claim passed through all async hops
- **No sensitive data** — exclude passwords, API keys, evidence content, user IPs
- **Log levels:** DEBUG (internals), INFO (transitions), WARN (retries), ERROR (failures)

#### B.5 Testing
- **No test mocks for domain objects** — use Pydantic factories instead
- **Mock only external dependencies** (S3, Postgres, Celery, Keycloak)
- **Unit tests:** domain logic, execution time <1s
- **Integration tests:** testcontainers (Postgres, MinIO, OpenSearch)
- **Parametrized tests:** format variants (10 EVTX samples, 5 CloudTrail logs)
- **Target coverage ≥80%** for domain logic

#### B.6 Performance Baselines
- **EVTX ingest:** >5000 records/sec on single core
- **OpenSearch query:** <500ms p95 latency
- **Celery task:** <10 minutes (heavy Plaso tasks)
- **Unit test suite:** <5 seconds total
- **No blocking operations** on FastAPI thread

---

### C. Project Structure (Target)

```
kronos/
├── src/
│   ├── domain/                     # Pure domain models, no framework imports
│   │   ├── evidence.py            # Evidence, EvidenceMetadata, EvidenceState FSM
│   │   ├── timeline.py            # TimelineRecord, ECS schema
│   │   ├── audit.py               # AuditEvent, AuditLog semantics
│   │   ├── case.py                # Case, CaseMetadata
│   │   └── user.py                # User, Role, TenantContext
│   │
│   ├── application/                # Business logic, services
│   │   ├── evidence_intake.py      # EvidenceIntakeService
│   │   ├── validation.py           # EvidenceValidator(ABC), implementations
│   │   ├── parsing.py              # ForensicParser(ABC), ParserType
│   │   ├── parser_registry.py      # ParserRegistry
│   │   ├── parsing_orchestration.py # ParsingOrchestrationService
│   │   ├── timeline_ingest.py      # TimelineIngestionService
│   │   ├── audit_log.py            # AuditLogService
│   │   └── multi_tenancy.py        # TenantContextService (Phase 5)
│   │
│   ├── adapter/                    # Port implementations
│   │   ├── storage/
│   │   │   ├── storage.py          # EvidenceStorage(ABC)
│   │   │   ├── s3.py               # S3EvidenceStorage
│   │   │   └── local.py            # LocalEvidenceStorage (testing)
│   │   ├── repository/
│   │   │   ├── audit_log.py        # AuditLogRepository(ABC)
│   │   │   ├── postgres.py         # PostgresAuditLogRepository
│   │   │   ├── evidence.py         # EvidenceRepository(ABC)
│   │   │   └── postgres_evidence.py # PostgresEvidenceRepository
│   │   ├── queue/
│   │   │   ├── task_queue.py       # TaskQueue(ABC)
│   │   │   └── celery.py           # CeleryTaskQueue
│   │   └── opensearch/
│   │       ├── client.py           # OpenSearchClient
│   │       ├── index_template.json # ECS schema + kronos.*
│   │       └── ism_policy.json     # Rollover policy
│   │
│   ├── external/                   # Framework, DB, message queue
│   │   ├── fastapi_app.py          # FastAPI app, exception handlers
│   │   ├── celery_app.py           # Celery app, task definitions
│   │   ├── dependencies.py         # Dependency injection container
│   │   ├── middleware/
│   │   │   ├── auth.py             # Keycloak JWT parsing
│   │   │   ├── tenant_context.py   # TenantContext per-request
│   │   │   └── error_handling.py   # Exception handlers, audit on error
│   │   └── parsers/
│   │       ├── evtx.py             # FastEvtxParser
│   │       ├── cloudtrail.py       # CloudTrailParser
│   │       └── nginx.py            # NginxParser
│   │
│   ├── config.py                   # Pydantic BaseSettings
│   └── exceptions.py               # KronOSException hierarchy
│
├── tests/
│   ├── unit/                       # Domain logic, <1s tests
│   │   ├── domain/test_*.py
│   │   └── application/test_*.py
│   ├── integration/                # Repositories, services with testcontainers
│   │   ├── test_evidence_intake.py
│   │   ├── test_timeline_ingest.py
│   │   └── test_parser_*.py
│   ├── fixtures/                   # Factories, sample files
│   │   ├── evidence_factory.py
│   │   ├── samples/
│   │   │   ├── test.evtx
│   │   │   ├── cloudtrail.json
│   │   │   └── nginx.log
│   │   └── mock_keycloak.py
│   └── conftest.py                 # pytest fixtures, DI overrides
│
├── docs/
│   ├── architecture.md             # Overview, trust zones, FSM diagrams
│   ├── subsystems/
│   │   ├── evidence-intake.md
│   │   ├── parsing.md
│   │   ├── timeline-ingest.md
│   │   ├── audit-log.md
│   │   └── multi-tenancy.md
│   └── deployment.md
│
├── docker/
│   ├── Dockerfile                  # Chainguard/Wolfi base
│   ├── docker-compose.test.yml     # Postgres, MinIO, OpenSearch, Redis, Keycloak
│   └── docker-compose.prod.yml     # Production (Vault, KES, ClamAV)
│
├── .github/
│   └── workflows/
│       ├── test.yml                # Unit + integration tests
│       ├── build.yml               # Trivy scan, SBOM (Syft), container build
│       └── deploy.yml              # Push to registry (post-merge only)
│
├── pyproject.toml                  # Python dependencies, pytest config
├── CLAUDE.md                        # This file
└── README.md                        # Project overview, quick-start
```

---

### D. Code Generation Checklist (Every Commit)

Before pushing, verify:
- [ ] **Type hints** on all functions/methods
- [ ] **Docstrings** on public classes and methods (one-liner if obvious)
- [ ] **No hardcoded values** — all from `BaseSettings` or Vault
- [ ] **No global state** — DI container is only singleton
- [ ] **Audit on mutations** — every state change logged
- [ ] **Error wrapping** — custom exceptions with context
- [ ] **Structured logging** — JSON format, no PII or credentials
- [ ] **Tests written** — at least one unit + one integration per feature
- [ ] **No commented code** — delete or add issue link
- [ ] **Linting clean** — `black`, `ruff`, `mypy` pass with zero warnings
- [ ] **No imports of framework in domain layer** — zero FastAPI/Celery/Postgres/MinIO in `src/domain/` or `src/application/`

---

## PHASE 1: Domain Models, DI, Audit Abstractions (Weeks 1–2)

**Duration:** 2 weeks  
**Deliverables:** Core abstractions, DI container, unit test suite  
**Key Output:** Domain models (Evidence, AuditEvent, TimelineRecord), audit service with hash chain, exception hierarchy

### Context
Phase 1 builds the **immutable backbone** that all downstream subsystems depend on:
- Domain models (Evidence, AuditEvent, TimelineRecord, User, Case) — pure Pydantic
- Dependency injection container (FastAPI + manual DI)
- Audit service abstraction (immutable, append-only, tamper-detected with hash chain)
- Storage & repository abstractions (pluggable backends)
- Exception hierarchy (custom, domain-specific)

**No FastAPI routes yet. No Celery tasks. Pure domain + DI.**

### Objectives

1. **Domain models** (`src/domain/`)
   - `evidence.py`: `Evidence`, `EvidenceMetadata`, `EvidenceState` FSM
   - `timeline.py`: `TimelineRecord` with ECS schema + kronos.* provenance
   - `audit.py`: `AuditEvent`, `AuditEventType` enum
   - `case.py`, `user.py`: Other domain models

2. **Exception hierarchy** (`src/exceptions.py`)
   - `KronOSException`, `ValidationError`, `StorageError`, `ParsingError`, `AuditLogError`, `AuthenticationError`

3. **Repository abstractions** (`src/adapter/repository/`)
   - `audit_log.py`: `AuditLogRepository(ABC)` — append-only interface
   - `evidence.py`: `EvidenceRepository(ABC)` — evidence metadata CRUD

4. **Storage abstractions** (`src/adapter/storage/`)
   - `storage.py`: `EvidenceStorage(ABC)` — presigned URLs, streaming, promotion

5. **Audit service** (`src/application/audit_log.py`)
   - `AuditLogService` with hash chain + context manager

6. **DI container** (`src/external/dependencies.py`)
   - Dependency overrides for testing

7. **Unit tests** (`tests/unit/`)
   - ≥20 tests covering FSM, hash chain, exception handling
   - Coverage ≥80% for domain logic

### Testing Checklist
- [ ] All Pydantic models validate (frozen, required fields)
- [ ] Audit hash chain verified (event2.row_hash ≠ event1.row_hash)
- [ ] `audit_context` succeeds on normal flow, logs error on exception
- [ ] Evidence FSM prevents invalid transitions
- [ ] DI container can override repositories for testing
- [ ] Unit tests run in <5s total
- [ ] mypy: zero type errors
- [ ] Black: code formatted
- [ ] Ruff: zero linting warnings

### Notes
- Do not create FastAPI app yet. That's Phase 2.
- Do not implement concrete repositories (Postgres) yet. Just ABCs.
- Do not add Celery yet. Pure domain + sync/async services.
- Every file in `src/domain/` must be framework-independent.

---

## PHASE 2: Evidence Intake, Validation, Scanning, Hashing (Weeks 3–4)

**Duration:** 2 weeks  
**Deliverables:** Intake workflow, validators, scanning integration, hash service  
**Prerequisites:** Phase 1 merged  
**Key Output:** Evidence upload workflow (UPLOADING → SCANNING → HASHING → RECEIVED), FastAPI routes

### Context
Building on Phase 1, Phase 2 implements the **evidence upload workflow**:
1. User requests presigned URL → S3 multipart setup
2. Client uploads file → MinIO quarantine bucket
3. ClamAV scans → log result → promote to evidence bucket if clean
4. SHA-256 hash computed → immutable metadata stored
5. State FSM: UPLOADING → SCANNING → HASHING → RECEIVED

**No parsing yet. No timeline ingestion. Pure intake + validation.**

### Objectives

1. **Validators** (`src/application/validation.py`)
   - `EvidenceValidator(ABC)`, `MagicByteValidator`, `FileSizeValidator`, `ValidatorChain`

2. **Scanning service** (`src/application/scanning.py`)
   - `ClamAVScanner` with streaming file feed to clamd

3. **Hash service** (`src/application/hashing.py`)
   - `HashService` with SHA-256 + MD5 computation

4. **Evidence intake service** (`src/application/evidence_intake.py`)
   - `EvidenceIntakeService` orchestrating full workflow (presigned URL → scanning → hashing → RECEIVED)

5. **Storage implementation** (`src/adapter/storage/s3.py`)
   - `S3EvidenceStorage` with MinIO-compatible API

6. **Repository implementation** (`src/adapter/repository/postgres_evidence.py`)
   - `PostgresEvidenceRepository` for evidence metadata

7. **FastAPI routes** (`src/external/routes/evidence.py`)
   - `POST /api/evidence/upload/request` — presigned URL
   - `POST /api/evidence/upload/finalize/{evidence_id}` — validate → scan → hash

8. **Integration tests** (`tests/integration/`)
   - ≥10 test cases covering full flow, error cases, state transitions

### Testing Checklist
- [ ] `request_upload` creates UPLOADING evidence, returns presigned URL
- [ ] `finalize_upload` validates, scans, hashes in correct order
- [ ] Audit log shows every step (5+ events per upload)
- [ ] Invalid magic bytes → rejected before scanning
- [ ] Infected file → ERROR state, audit logged
- [ ] Hash computed correctly (SHA-256 matches external tool)
- [ ] Promote succeeds; evidence bucket is WORM-locked
- [ ] Concurrent uploads to same case don't collide
- [ ] Integration tests with testcontainers (Postgres, MinIO)
- [ ] All tests run in <30s

### Notes
- Assume Phase 1 is merged and available. Import domain models freely.
- Storage backend is still abstract. Implement S3 + local test version.
- ClamAV is optional for now. Mock it or use a test clamd container.
- FastAPI app created in Phase 2. Don't add Celery or complex routes yet.
- Audit on every step. The audit log is your contract: if it's not logged, it didn't happen.

---

## PHASE 3: Parser Framework & Implementations (Weeks 5–6)

**Duration:** 2 weeks  
**Deliverables:** Parser registry, EVTX/CloudTrail/Nginx parsers, sandbox task wrappers  
**Prerequisites:** Phase 1 + Phase 2 merged  
**Key Output:** Extensible parser architecture, 3 reference implementations, Celery task framework

### Context
Phase 3 builds the **extensible parser framework** allowing new forensic formats without core refactoring:
- Abstract `ForensicParser(ABC)` base class
- `ParserRegistry` for runtime discovery
- Three reference implementations: EVTX (fast), CloudTrail (JSON), Nginx (text)
- Celery task wrapper for sandbox execution (gVisor for fast, Firecracker for heavy)
- Deterministic OpenSearch `_id` for idempotent retries

### Objectives

1. **Abstract parser base** (`src/application/parsing.py`)
   - `ForensicParser(ABC)` with `validate()`, `parse()`, `supports()` methods
   - `ParserType` enum (FAST, HEAVY)

2. **Parser registry** (`src/application/parser_registry.py`)
   - `ParserRegistry` with registration, lookup, factory pattern
   - No hardcoded if/elif chains

3. **Reference parsers** (`src/external/parsers/`)
   - `evtx.py`: `FastEvtxParser` (evtx-rs binding)
   - `cloudtrail.py`: `CloudTrailParser` (JSON logs)
   - `nginx.py`: `NginxParser` (access logs)
   - Each yields `TimelineRecord` with kronos.* provenance

4. **Parsing orchestration** (`src/application/parsing_orchestration.py`)
   - `ParsingOrchestrationService` coordinating parser selection, task queueing, audit logging

5. **Celery tasks** (`src/external/celery_tasks.py`)
   - `parse_evidence_fast()` for gVisor execution
   - `parse_evidence_heavy()` for Firecracker execution

6. **Unit + integration tests** (`tests/`)
   - ≥15 unit tests (registry, parser detection)
   - ≥5 integration tests (real sample files)

### Testing Checklist
- [ ] Registry registers and retrieves parsers by name
- [ ] `Parser.supports()` correctly identifies EVTX/CloudTrail/Nginx files
- [ ] EVTX parser yields ≥1000 records from sample file
- [ ] CloudTrail parser handles multi-record JSON files
- [ ] Nginx parser parses access log format
- [ ] Each record has kronos.* provenance (evidence_id, parser, record_index)
- [ ] `ParsingOrchestrationService` queues correct task (fast vs. heavy)
- [ ] Celery task injects dependencies correctly
- [ ] Concurrent parse tasks don't interfere
- [ ] All parser tests run in <10s

### Notes
- Parser discovery must be automatic. No hardcoded if/elif chains.
- Streaming is mandatory. Parsers yield records one-at-a-time, not arrays.
- Sandbox integration is stubbed out. Phase 3 focuses on parser architecture; sandbox invocation is Phase 4.
- Audit on success and error. Every parse session logged, success + record count.
- Sample files required. Include real EVTX, CloudTrail JSON, Nginx logs in test fixtures.

---

## PHASE 4: Timeline Ingestion & OpenSearch Integration (Weeks 7–8)

**Duration:** 2 weeks  
**Deliverables:** Timeline normalization, OpenSearch index templates, bulk ingestion, DLS security  
**Prerequisites:** Phase 1 + Phase 2 + Phase 3 merged  
**Key Output:** Complete evidence lifecycle (UPLOADING → COMPLETE), timeline queryable in OpenSearch

### Context
Phase 4 ingests parsed timeline records into OpenSearch with:
- ECS schema normalization
- `kronos.*` provenance block
- Per-tenant, per-case index naming: `kronos-{org_alias}-case-{case_id}-{yyyymm}`
- Document-Level Security (DLS) on `tenant_id`
- Deterministic `_id = SHA1(evidence_id : parser : record_index)` for idempotent retries
- ISM (Index State Management) policy: rollover at 30 GB or 30 days

**No search/UI yet. Pure ingestion, schema, and security.**

### Objectives

1. **Timeline normalization** (`src/application/timeline_normalization.py`)
   - `ECSNormalizer` converting `TimelineRecord` to OpenSearch document (ECS + kronos.*)

2. **Timeline ingestion service** (`src/application/timeline_ingest.py`)
   - `TimelineIngestionService` with batch + flush, deterministic _id

3. **OpenSearch client** (`src/adapter/opensearch/client.py`)
   - Async OpenSearch client with bulk API, template management, DLS role creation

4. **Index template** (`src/adapter/opensearch/index_template.json`)
   - ECS schema + kronos.* provenance block, per-tenant multi-tenancy

5. **ISM policy** (`src/adapter/opensearch/ism_policy.json`)
   - Rollover at 30 GB or 30 days

6. **Integration** of parsing → timeline workflow
   - `ParsingOrchestrationService` calls timeline service on parse success
   - Evidence state transitions to COMPLETE after ingestion

7. **Integration tests** (`tests/integration/`)
   - ≥10 test cases (deterministic IDs, batching, index naming)

### Testing Checklist
- [ ] ECS normalization preserves all record fields
- [ ] _id is deterministic (SHA1 collision test)
- [ ] Index naming matches pattern: `kronos-{org}-case-{case}-{yyyymm}`
- [ ] Batch ingestion works (1000+ records in single bulk call)
- [ ] Auto-flush on batch size
- [ ] ISM policy applies correctly (rollover triggers at 30 GB or 30 days)
- [ ] OpenSearch DLS role created per org
- [ ] Full workflow: evidence.COMPLETE after ingest
- [ ] All audit events logged (parse.start, parse.success, ingest.success)
- [ ] Concurrent ingestion to different orgs/cases doesn't cross boundaries

### Notes
- OpenSearch schema is foundational. Get ECS + kronos.* right first.
- Deterministic _id is critical. It prevents duplicates on retry.
- DLS is security, not just convenience. Enforce at role level.
- Testcontainers required. Integration tests need real OpenSearch.
- Phase 4 + Phase 3 complete the evidence lifecycle: UPLOADING → COMPLETE.

---

## PHASE 5: Multi-Tenancy & Keycloak Integration (Weeks 9–10)

**Duration:** 2 weeks  
**Deliverables:** Keycloak JWT parsing, tenant context, RBAC middleware, query isolation  
**Prerequisites:** All prior phases merged  
**Key Output:** Complete secure backend, production-ready

### Context
Phase 5 wires up **multi-tenant isolation** and **role-based access control** across all subsystems:
- Keycloak JWT parsing (extract `organization` scope + user roles)
- Per-request TenantContext (org_id, user_id, roles)
- RBAC middleware (decorators like `@requires_role("case_lead")`)
- Query filters (all queries scoped to org_id + case_id)
- Evidence deletion requires step-up auth (RFC 9470)

**This is the final phase. Integrates auth into all prior subsystems.**

### Objectives

1. **Keycloak JWT validation** (`src/external/middleware/keycloak_auth.py`)
   - `KeycloakTokenValidator` parsing and verifying JWT

2. **Tenant context** (`src/external/middleware/tenant_context.py`)
   - `TenantContext` extracted from JWT (org_id, user_id, roles)
   - `get_tenant_context()` FastAPI dependency

3. **RBAC decorator** (`src/external/middleware/rbac.py`)
   - `@requires_role("case_lead")` decorator enforcing access

4. **Query isolation middleware** (`src/external/middleware/query_isolation.py`)
   - Enforce that every query is scoped to org_id from TenantContext

5. **Step-up authentication** (`src/external/middleware/step_up_auth.py`)
   - `StepUpAuth` for MFA on sensitive operations (evidence delete)

6. **OpenSearch query builder** (`src/external/middleware/opensearch_isolation.py`)
   - `OpenSearchQueryBuilder` adding tenant_id filter to every query

7. **Evidence deletion with step-up** (update `src/application/evidence_intake.py`)
   - `delete_evidence()` requiring step-up ticket + MFA

8. **FastAPI app integration** (update `src/external/fastapi_app.py`)
   - Middleware, exception handlers, DI overrides

9. **Integration tests** (`tests/integration/`)
   - ≥15 test cases (RBAC, query isolation, step-up)

### Testing Checklist
- [ ] JWT validation succeeds with valid Keycloak token
- [ ] JWT validation fails with expired/invalid signature
- [ ] `TenantContext` extracts org_id + roles correctly
- [ ] `@requires_role` enforces access (403 if role missing)
- [ ] Query isolation: org1 cannot list org2's evidence
- [ ] Step-up auth required for delete
- [ ] Step-up ticket is one-time use
- [ ] OpenSearch queries include tenant_id filter
- [ ] Concurrent requests from different orgs don't interfere
- [ ] Audit log includes step-up verification status
- [ ] All endpoints require Bearer token
- [ ] Middleware runs before all routes

### Notes
- Query isolation is non-negotiable. EVERY query to Postgres/OpenSearch must include org_id filter.
- Step-up auth is for sensitive operations only. Delete + promote require MFA.
- RBAC is layered. Backend + OpenSearch roles work together (defense in depth).
- Test with real Keycloak container. Testcontainers + docker-compose for integration tests.
- This is the final phase. After Phase 5, the backbone is complete and extensible.

---

## Design Review Documents

All architectural decisions are documented and reviewed:
- **Project_Specifications.md** — 6-section narrative (548 lines)
- **reviews/Part_1_Review.md** — Users, Teams, Access Control (2026-04-20)
- **reviews/Part_2_Review.md** — Evidence Intake & CoC (2026-06-16)
- **reviews/Part_3_Review.md** — Parsing & Timeline (2026-06-16)
- **reviews/Part_4_Review.md** — Workflows & UX (2026-06-16)
- **reviews/Part_5_Review.md** — Security & Compliance (2026-06-16)
- **reviews/Part_6_Review.md** — Identity, Auth, SSO (2026-06-16)

Read these before implementing; they contain rationale for every decision.

---

## Git Workflow

```bash
# All work happens on the designated branch:
git checkout claude/focused-wozniak-pz1rqh

# Phase N agent:
1. Create feature branch: git checkout -b phase-N-feature
2. Implement phase (see phase prompt above)
3. Run tests, linting, type checking
4. Commit with clear message
5. Push: git push -u origin phase-N-feature
6. Create draft PR (auto-created by harness)
7. Merge to main when ready

# Next phase agent starts immediately on main
```

---

## Quick Commands

```bash
# Unit tests (fast)
pytest tests/unit/ -v

# Integration tests (requires testcontainers)
pytest tests/integration/ -v

# Type checking
mypy src/

# Linting
ruff check src/ tests/

# Formatting
black src/ tests/

# All checks
mypy src/ && ruff check src/ tests/ && black --check src/ tests/ && pytest tests/unit/
```

---

## Success Criteria

Each phase is **complete** when:
1. ✅ **All deliverables** listed in phase prompt are implemented
2. ✅ **Tests pass** (unit <5s, integration <30s per phase)
3. ✅ **Coverage ≥80%** for domain logic
4. ✅ **Linting clean** (mypy, ruff, black)
5. ✅ **Audit checklist** completed (type hints, docstrings, no hardcodes, etc.)
6. ✅ **PR reviewed** and merged to main

After Phase 5:
- ✅ Full evidence workflow: upload → validate → scan → hash → parse → ingest → query
- ✅ Multi-tenant isolation verified
- ✅ Performance baselines hit
- ✅ Security audit passed (OWASP, secrets scanning, SBOM)
- ✅ Ready for frontend integration + deployment

---

## Contact & Support

- **Branch:** `claude/focused-wozniak-pz1rqh`
- **Implementation Plan:** `/root/.claude/plans/read-the-repo-we-polished-willow.md`
- **Design Specs:** `Project_Specifications.md` + `reviews/Part_*.md`
- **Questions:** Refer to design reviews; all decisions documented with rationale

---

**Last Updated:** 2026-06-24  
**Status:** Ready for Phase 1 agent
