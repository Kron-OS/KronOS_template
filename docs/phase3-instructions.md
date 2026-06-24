# Phase 3 Instructions — Parser Framework & Implementations

**Branch:** `claude/tender-heisenberg-rl60wu`  
**Prerequisites:** Phase 1 + Phase 2 are committed on this branch (131 unit tests, 93.7% coverage).  
**Duration:** 2 weeks  
**Goal:** Extensible parser architecture with 3 reference implementations and Celery task wrappers.

---

## Context

Phase 1 built domain models and audit infrastructure.  
Phase 2 built the evidence intake workflow (UPLOADING → RECEIVED).  
Phase 3 begins the next state: RECEIVED → PARSING → COMPLETE.

The key constraint is **no `if/elif` dispatch** — parser selection must be purely polymorphic, driven by `ParserRegistry.get_parser(filename, content_type, header_bytes)`. Adding a new parser in the future must require zero changes to orchestration code.

---

## What Exists Already (Do Not Recreate)

| File | What it provides |
|------|-----------------|
| `src/domain/timeline.py` | `TimelineRecord`, `KronosProvenance` — parser output type |
| `src/domain/evidence.py` | `Evidence`, `EvidenceState` FSM (RECEIVED → PARSING → COMPLETE, any → ERROR) |
| `src/domain/audit.py` | `AuditEventType` — already has `PARSE_STARTED`, `PARSE_COMPLETED`, `PARSE_FAILED` |
| `src/application/audit_log.py` | `AuditLogService.log()` and `audit_context()` context manager |
| `src/adapter/storage/storage.py` | `EvidenceStorage.stream_object(key)` — returns `AsyncIterator[bytes]` |
| `src/adapter/repository/evidence.py` | `EvidenceRepository.update(evidence)` — persist state changes |
| `src/external/dependencies.py` | `configure_dependencies()`, `get_audit_log_service()`, `get_evidence_repository()`, `get_evidence_storage()` |
| `tests/fixtures/factories.py` | `make_timeline_record()`, `make_evidence()`, `make_tenant_context()` |
| `tests/conftest.py` | `InMemoryAuditLogRepository`, `InMemoryEvidenceRepository` |

---

## Deliverables

### 1. `src/application/parsing.py` — Abstract parser base

```python
from __future__ import annotations
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from enum import StrEnum
from src.domain.evidence import Evidence
from src.domain.timeline import TimelineRecord
from src.domain.user import TenantContext


class ParserType(StrEnum):
    FAST = "fast"    # runs in gVisor; completes in seconds
    HEAVY = "heavy"  # runs in Firecracker; may take minutes


class ForensicParser(ABC):
    """Abstract base for all forensic parsers.

    Subclasses implement format-specific parsing logic and register themselves
    with ParserRegistry at startup.  The orchestrator selects a parser by
    calling supports() on each registered instance — no if/elif chains.
    """

    @property
    @abstractmethod
    def parser_name(self) -> str:
        """Stable identifier, e.g. 'evtx-rs', 'cloudtrail', 'nginx'."""

    @property
    @abstractmethod
    def parser_version(self) -> str:
        """Semver string, e.g. '1.0.0'."""

    @property
    @abstractmethod
    def parser_type(self) -> ParserType:
        """FAST (gVisor) or HEAVY (Firecracker)."""

    @abstractmethod
    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        """Return True if this parser can handle the given file."""

    @abstractmethod
    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        """Yield TimelineRecord objects one at a time.

        Must be memory-efficient: do not buffer the entire file.
        Each record must have a fully-populated kronos.* provenance block.
        The record_index must be the zero-based position within this evidence file.
        """
```

**Rules:**
- `parse()` must be an `async def` that returns an `AsyncIterator` (use `async def ... yield` pattern or return an async generator).
- Never load the full file into memory. Accumulate bytes only as needed to decode one record.
- Every `TimelineRecord` yielded must have `kronos.evidence_id`, `kronos.case_id`, `kronos.org_id`, `kronos.sha256`, `kronos.parser`, `kronos.parser_version`, `kronos.record_index`, `kronos.ingest_timestamp` populated.
- `evidence.sha256` may be `None` at parse time; use `""` as a safe fallback (hash is not required for parsing, only for RECEIVED state).

---

### 2. `src/application/parser_registry.py` — Registry

```python
class ParserRegistry:
    """Holds registered ForensicParser instances; selects the right one per file."""

    def register(self, parser: ForensicParser) -> None:
        """Add a parser. Last-registered wins on ties."""

    def get_parser(
        self, filename: str, content_type: str, header_bytes: bytes
    ) -> ForensicParser | None:
        """Return the first parser that supports this file, or None."""

    def all_parsers(self) -> list[ForensicParser]:
        """Return all registered parsers (copy; order is registration order)."""
```

**Rules:**
- Internal storage is a plain list; iteration order determines priority (first-match wins).
- `get_parser` calls `parser.supports(...)` on each entry in order; returns the first truthy result.
- No global state — `ParserRegistry` is instantiated and injected via DI.

---

### 3. `src/external/parsers/evtx.py` — `FastEvtxParser`

**Library:** `evtx` (pyevtx-rs Python binding). Install: `pip install evtx`.

**API:**
```python
import evtx
# evtx.PyEvtxParser accepts a file path or bytes-like object.
with evtx.PyEvtxParser(bytes_buffer) as parser:
    for record in parser.records_json():
        # record is a dict: {"event_record_id": int, "timestamp": str, "data": str}
        event_data = json.loads(record["data"])  # XML-to-JSON converted event
        yield ...
```

`supports()` — return True when `header_bytes[:8] == b"ElfFile\x00"`.

**ECS field mapping:**

| EVTX path | ECS field in TimelineRecord |
|-----------|----------------------------|
| `System.TimeCreated["#attributes"]["SystemTime"]` | `timestamp` (`@timestamp`) |
| `System.Computer` | `host_name` |
| `System.EventID["#text"]` or `System.EventID` | stored in `extra["event.code"]` |
| `System.Channel` | stored in `extra["log.file.path"]` |
| `System.Security["#attributes"]["UserID"]` | `user_id` |
| Everything under `EventData` | merged into `extra` |

`event_kind = "event"`, `event_category = ["host"]`.

**Implementation notes:**
- The `evtx` library is synchronous. Wrap in `asyncio.get_event_loop().run_in_executor(None, ...)` so it doesn't block the event loop, or collect all records synchronously then yield them one by one.
- A simpler approach: read all bytes from stream into a `BytesIO`, pass to `PyEvtxParser`. EVTX files are typically <500 MB and the library requires random access.
- `parser_name = "evtx-rs"`, `parser_version = "0.8"` (or whatever `evtx.__version__` returns), `parser_type = ParserType.FAST`.

---

### 4. `src/external/parsers/cloudtrail.py` — `CloudTrailParser`

**Format:** AWS CloudTrail JSON — `{"Records": [{...}, ...]}` — each record is one API call event.

`supports()` — return True when filename extension is `.json` or `.jsonl` AND `header_bytes` contains `b'"Records"'` (quick prefix check, no full parse).

**ECS field mapping:**

| CloudTrail field | ECS field |
|-----------------|-----------|
| `eventTime` (ISO 8601 string) | `timestamp` |
| `userIdentity.userName` or `userIdentity.principalId` | `user_name` |
| `userIdentity.accountId` | `user_id` |
| `sourceIPAddress` | `extra["source.ip"]` |
| `eventName` | `extra["event.action"]` |
| `eventSource` | `extra["cloud.service.name"]` |
| `awsRegion` | `extra["cloud.region"]` |
| `errorCode` + `errorMessage` | `extra["error.code"]`, `extra["error.message"]` |
| `requestParameters` | `extra["cloudtrail.request_parameters"]` |

`event_kind = "event"`, `event_category = ["cloud"]`.  
`message = f"{record['eventName']} by {user_name} on {record['eventSource']}"`.

**Implementation notes:**
- Stream bytes from `AsyncIterator[bytes]`, accumulate until full JSON, then `json.loads()`.
- CloudTrail files are typically <50 MB; full accumulation is acceptable.
- Handle both `{"Records": [...]}` and NDJSON (one JSON object per line).
- `parser_name = "cloudtrail"`, `parser_version = "1.0.0"`, `parser_type = ParserType.FAST`.

---

### 5. `src/external/parsers/nginx.py` — `NginxParser`

**Format:** Combined Log Format:
```
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref.com/" "Mozilla/5.0 ..."
```

`supports()` — return True when extension is `.log` or `.txt` AND `header_bytes` matches the combined log format regex: `r'^\S+ \S+ \S+ \[[\d/\w: +-]+\] "' `.

**Regex for parsing one line:**
```python
_COMBINED_LOG_RE = re.compile(
    r'(?P<remote_addr>\S+) \S+ (?P<remote_user>\S+) '
    r'\[(?P<time_local>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes_sent>\d+|-) '
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"
```

**ECS field mapping:**

| Nginx field | ECS field |
|-------------|-----------|
| `remote_addr` | `extra["source.ip"]` |
| `time_local` (parsed) | `timestamp` |
| `remote_user` (if not `-`) | `user_name` |
| `status` | `extra["http.response.status_code"]` (int) |
| `bytes_sent` (if not `-`) | `extra["http.response.body.bytes"]` (int) |
| `method` | `extra["http.request.method"]` |
| `path` | `extra["url.path"]` |
| `user_agent` | `extra["user_agent.original"]` |
| `referrer` (if not `-`) | `extra["http.request.referrer"]` |

`event_kind = "event"`, `event_category = ["web"]`, `event_type = ["access"]`.  
`message = f'{method} {path} {status}'`.

**Implementation notes:**
- Stream bytes line-by-line. Use `splitlines()` on each chunk; keep a partial-line buffer for cross-chunk boundaries.
- Skip blank lines and lines that don't match the regex (log rotation headers etc.).
- `parser_name = "nginx"`, `parser_version = "1.0.0"`, `parser_type = ParserType.FAST`.

---

### 6. `src/application/parsing_orchestration.py` — `ParsingOrchestrationService`

```python
class ParsingOrchestrationService:
    """Selects the right parser, queues the task, and executes parsing on the worker."""

    def __init__(
        self,
        evidence_repository: EvidenceRepository,
        storage: EvidenceStorage,
        audit_log: AuditLogService,
        parser_registry: ParserRegistry,
        task_queue: TaskQueue,
    ) -> None: ...

    async def start_parsing(
        self,
        evidence_id: uuid.UUID,
        tenant: TenantContext,
    ) -> Evidence:
        """Transition evidence to PARSING and enqueue the parse task.

        Steps:
        1. Load evidence from repo; assert state == RECEIVED.
        2. Read first 8 KB from storage to detect parser.
        3. Call parser_registry.get_parser(); raise ParsingError if None.
        4. Transition evidence → PARSING; persist.
        5. Log AuditEventType.PARSE_STARTED with parser name in details.
        6. Enqueue task based on parser.parser_type (FAST vs HEAVY).
        7. Return updated evidence.
        """

    async def execute_parse(
        self,
        evidence_id: uuid.UUID,
        tenant: TenantContext,
    ) -> int:
        """Run the full parse; called by Celery worker.

        Steps:
        1. Load evidence; assert state == PARSING.
        2. Detect parser again (registry lookup from header bytes).
        3. Stream object from storage; feed to parser.parse().
        4. For each yielded TimelineRecord, set document_id and yield/buffer.
           document_id = SHA1(f"{evidence_id}:{parser_name}:{record_index}")
        5. On success: transition → COMPLETE; log PARSE_COMPLETED with record_count.
        6. On any exception: transition → ERROR; log PARSE_FAILED with error details; re-raise.
        7. Return total record count.
        """
```

**Deterministic document_id:**
```python
import hashlib

def _make_document_id(evidence_id: uuid.UUID, parser_name: str, record_index: int) -> str:
    key = f"{evidence_id}:{parser_name}:{record_index}"
    return hashlib.sha1(key.encode()).hexdigest()
```

**Rules:**
- `execute_parse` does NOT call the timeline ingestion service (that's Phase 4). It yields/counts records and returns the count. Records can be discarded for now; the important thing is the parse loop works correctly.
- Both `start_parsing` and `execute_parse` must audit every state transition.
- `ParsingError` from `src.exceptions` must be raised when no parser is found.

---

### 7. `src/adapter/queue/task_queue.py` — `TaskQueue(ABC)`

```python
from abc import ABC, abstractmethod
import uuid
from src.domain.user import TenantContext


class TaskQueue(ABC):
    """Abstract task queue — Celery in production, in-memory stub for tests."""

    @abstractmethod
    async def enqueue_parse_fast(
        self, evidence_id: uuid.UUID, tenant: TenantContext
    ) -> str:
        """Enqueue to the fast parse queue. Return the task ID."""

    @abstractmethod
    async def enqueue_parse_heavy(
        self, evidence_id: uuid.UUID, tenant: TenantContext
    ) -> str:
        """Enqueue to the heavy parse queue. Return the task ID."""
```

Also provide `InMemoryTaskQueue` in the same file for unit tests:

```python
class InMemoryTaskQueue(TaskQueue):
    """Captures enqueued tasks without running them — for unit tests."""

    def __init__(self) -> None:
        self.enqueued: list[tuple[str, uuid.UUID, TenantContext]] = []

    async def enqueue_parse_fast(self, evidence_id, tenant):
        task_id = str(uuid.uuid4())
        self.enqueued.append(("fast", evidence_id, tenant))
        return task_id

    async def enqueue_parse_heavy(self, evidence_id, tenant):
        task_id = str(uuid.uuid4())
        self.enqueued.append(("heavy", evidence_id, tenant))
        return task_id
```

---

### 8. `src/adapter/queue/celery_queue.py` — `CeleryTaskQueue`

```python
class CeleryTaskQueue(TaskQueue):
    """Sends tasks to Celery. Import celery app lazily to avoid import cycles."""

    async def enqueue_parse_fast(self, evidence_id, tenant):
        from src.external.celery_app import parse_evidence_fast
        result = parse_evidence_fast.apply_async(
            args=[str(evidence_id)],
            kwargs={"org_id": str(tenant.org_id), "user_id": str(tenant.user_id)},
            queue="parse.fast",
        )
        return result.id

    async def enqueue_parse_heavy(self, evidence_id, tenant):
        from src.external.celery_app import parse_evidence_heavy
        result = parse_evidence_heavy.apply_async(
            args=[str(evidence_id)],
            kwargs={"org_id": str(tenant.org_id), "user_id": str(tenant.user_id)},
            queue="parse.heavy",
        )
        return result.id
```

---

### 9. `src/external/celery_app.py` — Celery app + task definitions

```python
from celery import Celery
from src.config import Settings

settings = Settings()
celery_app = Celery(
    "kronos",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)
celery_app.conf.task_routes = {
    "kronos.parse_fast": {"queue": "parse.fast"},
    "kronos.parse_heavy": {"queue": "parse.heavy"},
}

@celery_app.task(name="kronos.parse_fast", bind=True, max_retries=3)
def parse_evidence_fast(self, evidence_id: str, *, org_id: str, user_id: str) -> int:
    """Fast parse task — runs in gVisor sandbox (stub for now)."""
    import asyncio
    from src.external.dependencies import _build_orchestration_service, _build_tenant_from_task
    tenant = _build_tenant_from_task(org_id, user_id)
    svc = _build_orchestration_service()
    return asyncio.run(svc.execute_parse(uuid.UUID(evidence_id), tenant))

@celery_app.task(name="kronos.parse_heavy", bind=True, max_retries=3)
def parse_evidence_heavy(self, evidence_id: str, *, org_id: str, user_id: str) -> int:
    """Heavy parse task — runs in Firecracker sandbox (stub for now)."""
    # Same as fast for now; Phase 4 will differentiate sandbox type.
    return parse_evidence_fast(self, evidence_id, org_id=org_id, user_id=user_id)
```

Add helpers to `src/external/dependencies.py`:
- `get_parser_registry() -> ParserRegistry` — returns a registry pre-populated with all three parsers.
- `get_task_queue() -> TaskQueue` — returns `CeleryTaskQueue()` in production, overridable for tests.
- `get_parsing_orchestration_service(...) -> ParsingOrchestrationService` — FastAPI dependency.
- `_build_orchestration_service()` and `_build_tenant_from_task(org_id, user_id)` — used by Celery tasks (no FastAPI request context).

Add a new FastAPI route in `src/external/routes/evidence.py`:
```python
@router.post("/parse/start/{evidence_id}", status_code=202)
async def start_parsing(
    evidence_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    orchestrator: Annotated[ParsingOrchestrationService, Depends(get_parsing_orchestration_service)],
) -> EvidenceOut:
    """Transition RECEIVED evidence to PARSING and enqueue the parse task."""
```

---

### 10. Sample fixture files

Create these **small but real** sample files in `tests/fixtures/samples/`:

**`cloudtrail.json`** (minimal but structurally valid):
```json
{
  "Records": [
    {
      "eventVersion": "1.08",
      "userIdentity": {"type": "IAMUser", "userName": "alice", "accountId": "123456789012"},
      "eventTime": "2024-01-15T10:30:00Z",
      "eventName": "DescribeInstances",
      "eventSource": "ec2.amazonaws.com",
      "sourceIPAddress": "192.0.2.1",
      "awsRegion": "us-east-1",
      "requestParameters": {"maxResults": 100},
      "responseElements": null
    },
    {
      "eventVersion": "1.08",
      "userIdentity": {"type": "IAMUser", "userName": "bob", "accountId": "123456789012"},
      "eventTime": "2024-01-15T10:31:00Z",
      "eventName": "RunInstances",
      "eventSource": "ec2.amazonaws.com",
      "sourceIPAddress": "198.51.100.5",
      "awsRegion": "us-west-2",
      "requestParameters": {"imageId": "ami-12345678"},
      "responseElements": {"instancesSet": {"items": [{"instanceId": "i-0abc123"}]}}
    }
  ]
}
```

**`nginx.log`** (combined log format, 5 lines):
```
192.168.1.1 - frank [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "https://example.com/" "Mozilla/5.0"
10.0.0.2 - - [15/Jan/2024:10:00:01 +0000] "POST /api/login HTTP/1.1" 401 256 "-" "curl/7.68.0"
172.16.0.5 - alice [15/Jan/2024:10:00:02 +0000] "GET /dashboard HTTP/1.1" 200 8192 "https://example.com/index.html" "Chrome/120.0"
192.168.1.50 - - [15/Jan/2024:10:00:03 +0000] "GET /robots.txt HTTP/1.0" 404 128 "-" "Googlebot/2.1"
10.10.10.10 - - [15/Jan/2024:10:00:04 +0000] "DELETE /api/resource/42 HTTP/1.1" 204 0 "-" "python-requests/2.31"
```

**For EVTX:** Do not create a synthetic `.evtx` file — the binary format is complex. Instead, tests for `FastEvtxParser` should use a real minimal `.evtx` file generated with `evtx_dump` or downloaded from a test corpus. If `evtx` library is unavailable, the parser tests must be skipped with `pytest.importorskip("evtx")`. Provide a `tests/fixtures/samples/generate_test_evtx.py` script that generates one using the `evtx` library for developers who want to run the full suite.

---

## Tests Required

### Unit tests (`tests/unit/application/`)

**`test_parser_registry.py`** — ≥8 tests:
- `test_register_and_retrieve` — register a parser, `get_parser` returns it when `supports()` is True
- `test_no_match_returns_none` — `get_parser` returns None when no parser supports the file
- `test_first_match_wins` — when two parsers support a file, first registered wins
- `test_all_parsers_returns_registered` — `all_parsers()` length matches registration count
- `test_empty_registry_returns_none` — empty registry returns None
- `test_parser_not_called_after_match` — second parser's `supports()` not called after first matches
- `test_register_multiple_types` — register FAST and HEAVY parsers; both retrievable
- `test_get_parser_calls_supports_with_correct_args` — verify filename/content_type/header_bytes passed correctly

**`test_parsing.py`** — ≥6 tests using a `FakeParser(ForensicParser)` stub:
- `test_fake_parser_supports_correct_files`
- `test_fake_parser_yields_timeline_records`
- `test_timeline_record_has_kronos_provenance`
- `test_record_index_is_sequential`
- `test_parse_empty_stream_yields_nothing`
- `test_document_id_is_deterministic`

**`test_parsing_orchestration.py`** — ≥12 tests:
- `test_start_parsing_transitions_to_parsing` — evidence transitions RECEIVED→PARSING
- `test_start_parsing_enqueues_fast_task` — FAST parser → `enqueue_parse_fast` called
- `test_start_parsing_enqueues_heavy_task` — HEAVY parser → `enqueue_parse_heavy` called
- `test_start_parsing_logs_parse_started` — `PARSE_STARTED` audit event present
- `test_start_parsing_no_parser_raises` — no supported parser → `ParsingError`
- `test_start_parsing_wrong_state_raises` — evidence not RECEIVED → error
- `test_execute_parse_returns_record_count` — count matches yielded records
- `test_execute_parse_transitions_to_complete` — evidence → COMPLETE on success
- `test_execute_parse_logs_parse_completed` — `PARSE_COMPLETED` event with `record_count`
- `test_execute_parse_transitions_to_error_on_failure` — exception → ERROR state
- `test_execute_parse_logs_parse_failed` — `PARSE_FAILED` event on exception
- `test_document_id_is_stable_across_calls` — same inputs produce same SHA1

### Unit tests (`tests/unit/parsers/`)

**`test_cloudtrail_parser.py`** — ≥8 tests:
- `test_supports_json_with_records_key`
- `test_does_not_support_json_without_records_key`
- `test_does_not_support_evtx_extension`
- `test_parses_two_records` — yields exactly 2 records from fixture
- `test_record_timestamp_parsed_correctly`
- `test_record_has_kronos_provenance`
- `test_record_index_sequential`
- `test_empty_records_array_yields_nothing`

**`test_nginx_parser.py`** — ≥8 tests:
- `test_supports_log_file_with_combined_format`
- `test_does_not_support_json_extension`
- `test_does_not_support_unrecognised_log_format`
- `test_parses_five_records` — yields 5 records from fixture
- `test_record_timestamp_timezone_aware`
- `test_record_has_source_ip`
- `test_record_has_http_status_code` — `extra["http.response.status_code"]` is int
- `test_malformed_lines_skipped` — non-matching lines don't raise

**`test_evtx_parser.py`** — ≥5 tests (all must call `pytest.importorskip("evtx")`):
- `test_supports_evtx_magic_bytes`
- `test_does_not_support_json`
- `test_parse_yields_records` — requires `tests/fixtures/samples/test.evtx`; skip if file absent
- `test_record_has_timestamp`
- `test_record_has_kronos_provenance`

**`test_task_queue.py`** — ≥4 tests for `InMemoryTaskQueue`:
- `test_enqueue_fast_records_task`
- `test_enqueue_heavy_records_task`
- `test_returns_task_id_string`
- `test_multiple_enqueues_all_recorded`

### Integration tests (`tests/integration/test_parsing.py`)

Use `@pytest.mark.integration` and skip without Docker. ≥5 tests using real CloudTrail/Nginx fixture files and the `LocalEvidenceStorage` + `InMemoryEvidenceRepository` (no Docker needed for these parsers — only EVTX parser test truly needs nothing extra).

---

## Coding Checklist Before Commit

- [ ] `parser_name`, `parser_version`, `parser_type` implemented on all three parsers
- [ ] `supports()` logic verified against sample files
- [ ] Every `TimelineRecord` has all `KronosProvenance` fields populated (no defaults left as empty/None except `sha256` fallback)
- [ ] `execute_parse` transitions to COMPLETE on success, ERROR on exception
- [ ] `PARSE_STARTED`, `PARSE_COMPLETED`, `PARSE_FAILED` audit events logged
- [ ] `InMemoryTaskQueue` used in all unit tests (no real Celery)
- [ ] `pytest.importorskip("evtx")` guard on all EVTX tests
- [ ] Sample fixture files committed to `tests/fixtures/samples/`
- [ ] `pyproject.toml` updated: add `evtx>=0.8` to main deps
- [ ] `get_parser_registry()` in `dependencies.py` registers all 3 parsers
- [ ] `POST /api/evidence/parse/start/{evidence_id}` route implemented
- [ ] No `if/elif` chains in parser selection code
- [ ] No framework imports in `src/application/parsing.py` or `src/application/parsing_orchestration.py`
- [ ] All tests pass: `pytest tests/unit/ -v`
- [ ] Coverage ≥80%: `pytest tests/unit/ --cov=src --cov-fail-under=80`
- [ ] Linting clean: `ruff check src/ tests/ && black --check src/ tests/`
- [ ] Type checking: `mypy src/`

---

## Quick Commands

```bash
# Install new dependency
pip install evtx

# Run unit tests only
pytest tests/unit/ -v

# Run parser-specific tests
pytest tests/unit/parsers/ -v

# Run with coverage
pytest tests/unit/ --cov=src --cov-fail-under=80

# Lint
ruff check src/ tests/ && black --check src/ tests/

# Type check
mypy src/
```

---

## Agent Kick-Off Prompt (for next session)

> Branch is `claude/tender-heisenberg-rl60wu`. Phases 1 and 2 are committed on this branch (131 unit tests, 93.7% coverage). Phase 3 builds on top — implement the parser framework and 3 reference implementations per `docs/phase3-instructions.md`. All interface contracts, ECS field mappings, test requirements, and the coding checklist are in that file. Read it first, then implement. Do not diverge from the interface signatures defined there without good reason.
