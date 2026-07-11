# KronOS Backend: Implementation Guidelines

**Project:** KronOS — Forensically sound, multi-tenant evidence management and forensic timeline analysis platform  
**Status:** Backend complete (Phases 1–5, 89% coverage). Frontend & infrastructure roadmap in [`roadmap.md`](./roadmap.md).  
**Design authority:** `Project_Specifications.md` + `reviews/Part_*.md`  
**Branch:** Work on designated feature branches; follow git workflow below.

---

## 🚀 Quick Start for All Agents

### For TasksThis document contains the complete Phase 1–5 backend implementation guidelines. The backend core is finished; these sections are reference only.
Warning : Never deploy docker containers or break system. You can use ~/venv/ python env for running tests. Commit your modifications on current branch, push them, but no pull request. **Exception: inside the KronOS sandbox, the nested Docker stack is allowed — see below.**

### Docker is allowed *inside the KronOS sandbox only*

The blanket "never deploy docker containers" rule above exists to protect the
**host**. It does **not** apply when you are running **inside the KronOS
sandbox** — a Sysbox-isolated Docker-in-Docker box (`sandbox/`) built
specifically to exercise the full pipeline, which cannot affect the host
system. Detect the sandbox by the environment variable `IS_SANDBOX=1` and the
`kronos-sandbox` hostname.

**When (and only when) inside the sandbox**, you MAY run the project's nested
Docker stack to bring up services and run true end-to-end tests:

- `make dev` / `make clean` / `make test-integration`
- `docker compose -f docker/docker-compose.dev.yml ...` and
  `docker compose -f docker/docker-compose.test.yml ...`

**Outside the sandbox** (a developer host, CI, or any box without
`IS_SANDBOX=1`), the original rule stands: do not deploy containers; use
`~/venv` for tests. Never run `sandbox/`'s own compose (it manages the box you
are in).

### The `sandbox/` directory is read-only inside the box

When running **inside the KronOS sandbox**, the `sandbox/` directory is
bind-mounted **read-only** — the box can read its own isolation config but
cannot rewrite it. So from inside the box:

- **Do not try to edit any file under `sandbox/`** (Dockerfile, compose,
  firewall, provisioning, systemd units). Writes fail by design; that is not a
  bug. Make sandbox changes from a trusted host checkout, not from inside the
  untrusted box.
- `sandbox/.env`, `sandbox/authorized_keys`, and the SSH host keys under
  `~/.ssh/` are gitignored or machine-local and may be **absent by design** —
  do not recreate or commit them.

If `git status` inside the box shows changes under these paths, ignore them —
never stage or commit them.

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

## E. Ingestion Pipeline Rules (Non-Negotiable)

> Full specification: [`docs/ingestion-pipeline.md`](./docs/ingestion-pipeline.md)

### E.1 The Pipeline Is Fully Autonomous After Upload

Once the client sends `POST /api/evidence/upload/finalize/{id}`, **every subsequent step is triggered by the server**, never by the client.  This rule exists because:

- Parsing must be deterministic and reproducible without client cooperation.
- Every FSM transition is a legally binding audit event; only the server may write them.
- Client-triggered transitions create TOCTOU vulnerabilities and allow users to skip security gates.

The correct autonomous sequence is:

```
finalize_upload (FastAPI)
  └─► _promote() → enqueue dispatch_parse (Celery q.index)
        └─► dispatch_parse → start_parsing()  → PARSING
              └─► parse_artefact_fast|heavy → execute_parse() → COMPLETE
                    └─► finalize_evidence → INGEST_COMPLETED audit event
```

### E.2 Never Trigger Pipeline Steps from the Frontend

- **Do NOT call `POST /api/evidence/parse/start/{id}` from frontend code.**  
  That endpoint is `ORG_ADMIN`-only and exists only for manual operational recovery.
- **Do NOT add any client-side "wait and then call" patterns** that poll or
  sequence server-side transitions.
- **The frontend's only responsibility** after finalize is to subscribe to SSE
  (`GET /api/sse/cases/{id}/evidence`) for state-change notifications.

### E.3 State Transitions Are Server-Side Only

- All FSM transitions are enforced by `EvidenceState.transition_to()` in
  `src/domain/evidence.py`.
- The only code that may call `evidence.with_state(...)` is application-layer
  services (`EvidenceIntakeService`, `ParsingOrchestrationService`) invoked
  from Celery tasks or the `finalize_upload` route.
- **No route handler may directly set evidence state** except via the designated
  service methods.

### E.4 Auto-Dispatch Is the Contract, Not the API

`EvidenceIntakeService._promote()` calls `task_queue.enqueue_dispatch()` as
the last step of finalization.  If the broker is temporarily unavailable the
warning is logged and the `auto_dispatch_received` Celery beat task (runs
hourly at :15) provides automatic recovery — no human intervention required.

**Do NOT** add fallback logic that makes a direct HTTP call to `parse/start`
as a "retry" when the queue fails.  The beat task is the correct recovery
mechanism.

### E.5 `stream_all_by_state` Is for System Tasks Only

`EvidenceRepository.stream_all_by_state()` crosses org boundaries.  It may
only be called from Celery beat tasks (`abort_orphan_uploads`,
`auto_dispatch_received`, `abort_orphan_parses`).  **Never** call it from a
FastAPI route or any code reachable from a user request.

### E.6 Parse/Start Endpoint Is Admin-Only Recovery

`POST /api/evidence/parse/start/{id}` requires `Role.ORG_ADMIN`.  It exists
so an operator can manually unblock evidence stuck in RECEIVED state after a
broker outage.  It must never be called as part of normal upload flow.

---
