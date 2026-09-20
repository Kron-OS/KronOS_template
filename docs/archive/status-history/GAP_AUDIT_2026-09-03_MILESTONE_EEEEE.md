# Gap Audit — Milestone EEEEE (2026-09-03)

**Scope:** checkpoint 3 of the project owner's "huge work" request — the
on-demand, analyst-triggered path: real `windows.dumpfiles` byte extraction
and real, scoped `windows.registry.printkey` drill-down. Full plan at
`/home/reca/.claude/plans/abstract-imagining-umbrella.md` (approved). This
checkpoint covers PoCs 3-5 plus the full backend (worker, launcher,
`DerivedArtifactStorage`, Celery tasks, routes, audit events). The frontend
(Child Files view, registry browser, download wiring) is Milestone FFFFF,
a separate, later checkpoint — not this doc.

## The real issue / what changed

Milestone CCCCC's eager plugin set covers everything that can run
unconditionally against a memory image. Two real analyst needs cannot: real
byte extraction of a specific file (`windows.dumpfiles`, needs a specific
target) and unscoped registry browsing (`windows.registry.printkey` without
a key filter measured live at >200s — a real, not guessed, reason to keep
it scoped and on-demand). This checkpoint builds both as real,
Celery-task-triggered, analyst-initiated actions.

### PoCs (all real, captured output — `poc/<name>/README.md` + `output.txt`)

- **`poc/volatility_dumpfiles/`** — decisive finding: `windows.filescan`'s
  own `Offset` column is a **physical** address; `plugins.DumpFiles.physaddr
  = [offset]` (not `--virtaddr`) is the real, correct targeting mechanism. A
  real 49,152-byte Firefox cache file was extracted this way from the real
  1.6GB `Challenge.raw` sample. Resolved the bytes-transport question in
  favor of a real temp-file (not base64) — the worker writes bytes to a
  scratch dir, the launcher/service reads and re-uploads them.
- **`poc/volatility_registry_printkey/`** — scoped, non-recursive
  `printkey` (hive `offset` + optional `key`, `recurse=False`) is real,
  fast (~0.35s) and bounded, vs. >200s unscoped. Real bug found and
  resolved: reusing one shared `Context` across two `printkey` calls
  against the same hive raises `LayerException("Layer already exists:
  ...")` — `HiveList.list_hives()` re-adds the hive layer every call and
  volatility3 never deregisters it. Fix: fresh `Context` per call, which is
  also the natural production shape (each on-demand click = a new Celery
  task = a new worker subprocess = a new `Context`).
- **`poc/minio_derived_artifact/`** — a bucket created without
  `ObjectLockEnabledForBucket` is genuinely non-WORM against the real, live
  `docker-minio-1` (confirmed via a real `get_object_lock_configuration`
  call returning `ObjectLockConfigurationNotFoundError`) — put/get
  round-trips real bytes exactly, and delete (blocked on the WORM evidence
  bucket) succeeds here.

Both worker on-demand modes were then re-verified against the **real,
shipped** `docker/volatility/kronos-volatility-worker.py` (not just the
scratch PoC scripts) inside `docker-celery-worker-plaso-1`, producing
identical real output to the PoCs (49,152-byte file; 9 then 5 real registry
rows) — see each PoC's own "Re-verification" addendum.

## Backend built this checkpoint

- **`docker/volatility/kronos-volatility-worker.py`** — two new modes:
  `--dumpfiles-physaddr OFFSET --dumpfiles-output-dir DIR` (real
  `FileHandlerInterface` subclass writing to disk, sha256/size captured)
  and `--registry-hive-offset OFFSET [--registry-key KEY]` (fresh `Context`
  per invocation).
- **`src/external/sandbox/volatility_launcher.py`** — `VolatilityLauncher.
  run_dumpfile()`/`run_registry_key()`, new `DumpedFile`/
  `VolatilityDumpFilesResult`/`VolatilityRegistryKeyResult` dataclasses.
  Never raise for a real extraction failure — reported via `.ok`/`.error`,
  same discipline as the multi-plugin path.
- **`src/adapter/storage/derived_artifact_storage.py` /
  `s3_derived_artifact.py`** — new `DerivedArtifactStorage` ABC +
  `S3DerivedArtifactStorage`, deliberately a separate class/bucket
  (`kronos-derived-{org_alias}`, no Object Lock) from `S3EvidenceStorage`'s
  WORM evidence bucket. New `minio_derived_bucket_prefix` setting
  (`src/config.py`), wired in `startup.py` (both the FastAPI and Celery
  worker_init paths) and `dependencies.py`
  (`get_derived_artifact_storage()`).
- **`src/external/parsers/volatility_on_demand.py`** — new
  `VolatilityOnDemandService`: fetches evidence bytes fresh per call
  (mirrors `VolatilityModule._run_volatility`'s own temp-file pattern),
  runs the launcher, persists results (`StructuredArtifact` +
  `DerivedArtifactStorage` bytes for dumpfiles; rows-only artifact for
  registry), and audits every outcome. `content.enrichment: {}` reserved,
  additive-only slot for a future VirusTotal pass (user said "eventually" —
  nothing else built for it this cycle).
- **`src/domain/audit.py`** — four new `AuditEventType` members:
  `DERIVED_ARTIFACT_EXTRACTION_REQUESTED/EXTRACTED/EXTRACTION_FAILED/
  DOWNLOADED` — a real, distinct chain-of-custody trail for this real
  binary content pulled from evidence on a user's explicit request
  (CLAUDE.md §A.2), not folded into `ARTIFACT_INGEST_*` (which means
  something different: the eager per-evidence-file artifact save).
- **`src/external/celery_app.py`** — two new tasks,
  `kronos.extract_volatility_dump_file`/`kronos.extract_volatility_
  registry_key`, both on `q.parse.plaso` (same worker image, real-verified
  fast enough not to need separate tuning). Both go through
  `run_evidence_coro`/`TaskResources` exactly like every other Celery task
  in this codebase — `TaskResources` gained a `volatility_on_demand_
  service` field.
- **`src/adapter/queue/task_queue.py` / `celery_queue.py`** — new
  `enqueue_volatility_dump_file`/`enqueue_volatility_registry_key` port
  methods (+ `InMemoryTaskQueue` support for tests).
- **`src/external/routes/cases.py`** — three new routes:
  `POST .../volatility/dump-file`, `POST .../volatility/registry-key`
  (both `202 Accepted`, enqueue only, read-role gated like
  `download_evidence` — CLAUDE.md §A.5/§G.3: never a synchronous subprocess
  call on the FastAPI thread), and `GET /{case_id}/artifacts/
  {artifact_id}/download` (streams real derived bytes through the backend,
  same "audit stays synchronous with actual access" reasoning as
  `download_evidence`). New `ArtifactRepository.get_by_id()` (didn't exist
  before — needed for the download route to fetch one artifact's
  `object_key` pointer).

### Real, verified architecture deviation from the original plan

The plan's Stage 3 text said the frontend would "subscribe via the existing
SSE mechanism" for on-demand completion. Real inspection of
`src/external/routes/sse.py` (this checkpoint) found that mechanism is a
per-case poll loop hardcoded to `EvidenceRepository.stream_by_case`/
`Evidence.state` diffing — it has no notion of artifacts at all, and a
new derived artifact never changes `Evidence.state` (the source evidence is
already `COMPLETE`). Building a parallel artifact-aware SSE channel for a
rare, fast (sub-few-second), user-initiated click was judged more
machinery than the real need justifies; the trigger routes return
`202 {taskId}` and Milestone FFFFF's frontend polls the existing
`GET /api/cases/{case_id}/artifacts` route (already used for the Artifacts
tab) for the new kind. Documented here rather than silently diverging from
the approved plan.

## Real, live verification (commands + actual captured output)

- Worker on-demand modes run directly inside `docker-celery-worker-plaso-1`
  against the real `Challenge.raw` sample — see each PoC's
  "Re-verification" section for the real captured JSON.
- `docker exec docker-kronos-backend-1 python3 -c '... wire_dependencies_async() ...'`
  — real DI wiring resolves `S3DerivedArtifactStorage`/`S3EvidenceStorage`
  against the real running container, no `RuntimeError`.
- `app.openapi()` inside the real backend container confirms all three new
  routes are registered: `GET /api/cases/{case_id}/artifacts/
  {artifact_id}/download`, `POST .../volatility/dump-file`,
  `POST .../volatility/registry-key`.
- `celery_app.tasks` inside the real backend container confirms both new
  task names are registered: `kronos.extract_volatility_dump_file`,
  `kronos.extract_volatility_registry_key`.
- New/updated unit tests, run via `~/venv/bin/python -m pytest tests/unit`
  (real dependencies installed, not this repo's bare interpreter):
  `tests/unit/test_volatility_launcher.py` (+5 on-demand tests),
  `tests/unit/parsers/test_volatility_on_demand.py` (new, 6 tests),
  `tests/unit/test_cases_routes.py` (+16 route tests across dump-file/
  registry-key/download). **Full suite: 1994 passed, 1 skipped, 89.13%
  coverage** (no regressions vs. the pre-checkpoint 1971-pass baseline).
  `ruff check`/`ruff format` clean on every touched file.

## Deliberately not built this checkpoint

- Frontend (Child Files view, registry browser, download button wiring) —
  Milestone FFFFF.
- VirusTotal enrichment — `content.enrichment: {}` reserved only, per the
  user's own "eventually."
- `pycryptodome` dependency fix (`hashdump`/`lsadump`/`cachedump` import
  failures) — named in Milestone CCCCC's own doc, scheduled for Milestone
  GGGGG alongside the final E2E/a11y regression pass.
