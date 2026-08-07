# PoC: Automated evidence collection on detection (roadmap M7/H3)

**Objective (roadmap, verbatim):** "A detection triggers forensically-sound
collection (memory, disk, logs) that enters the *existing* evidence pipeline
with full custody -- the strongest synthesis of the SOC and forensic halves
of the platform."

## Judgment call: what "collection" honestly means here (read this first)

Mirroring H2's own precedent exactly: **this platform has no live remote
host-agent, EDR, or fleet-management component anywhere in `src/`.**
Re-confirmed for this item via the identical grep H2 already ran:

```
$ grep -rEn "EDR|osquery|Fleet[A-Z]|HostAgent|host_agent|isolate_host|IsolateHost" src/
src/domain/timeline.py:9:  continuous telemetry (a Zeek/EDR/syslog collector, roadmap M3), which has
src/domain/stream.py:6:wrong for continuous telemetry (a future syslog/EDR/Zeek collector, D1/D2):
src/application/containment_actions.py:10:live-editable mount, and no host-management/EDR/agent component exists
```

Only docstring mentions of a *future* collector -- identical result to H2's
own finding. So "a detection triggers collection of memory/disk/logs" cannot
literally mean "reach out over the network and pull memory off a live,
possibly-compromised endpoint" -- that capability does not exist in this
codebase, full stop.

**What was built instead (option (a) from the dispatch brief, taken as-is):**
an already-existing, real forensic artifact -- staged on storage the backend
can read -- enters the REAL, unmodified `EvidenceIntakeService` pipeline
(real MinIO upload via a real presigned PUT, real Postgres persistence, real
Celery-driven autonomous FSM, real OpenSearch indexing), attributed to the
Detection that triggered it, instead of a human clicking "upload." **Live
remote collection off a compromised host is real, reported, out of scope --
not fabricated here.** The new `PlaybookAction`
(`src/application/evidence_collection_action.py::CollectForensicArtifactAction`)
is deliberately artifact-agnostic (it validates nothing about content, the
real `ParserRegistry` still content-sniffs the real bytes exactly as it does
for a human upload) -- "memory, disk, logs" are simply different files on
the same path, not three different code paths.

**Artifact actually used for the real run below: a real log bundle, not the
memory dump.** E5's own real memory-dump sample (`cridex.vmem`, still on
disk at `/home/reca/scratch/kronos-poc-volatility/cridex.vmem`,
sha256 `02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d` --
matches E5's own documented hash) was investigated first, per the dispatch
brief's own recommended option (a). It was NOT used for the real run below
because of a **real, pre-existing infrastructure gap found during this
item's own investigation, not caused by this item:**

```
$ docker exec docker-celery-worker-plaso-1 /opt/venv/bin/python3 -c "
import os
print(os.environ.get('VOLATILITY_WORKER_PATH'))
print(os.path.exists('/app/volatility-worker/kronos-volatility-worker.py'))"
None
False
```

`docker/Dockerfile.plaso-worker` (the Dockerfile `docker-celery-worker-plaso-1`
is declared to build from) DOES install `volatility3==2.28.0` and copy
`kronos-volatility-worker.py` (confirmed by reading the Dockerfile itself --
E5 added this for real). But the currently-**running**
`docker-celery-worker-plaso-1` container was never rebuilt since E5 landed --
it is running a stale image with neither `volatility3` nor the worker script
present, so a `.vmem` upload routed through the real q.parse.plaso queue
right now would hit `VolatilityScanError`/`ERROR`, for a reason that has
nothing to do with this item's own new code. **Reported, not silently
fixed** -- rebuilding/restarting a shared dev-stack service that other
concurrent work may depend on was judged out of this item's own scope (see
CLAUDE.md's "never touch containers you didn't create" instruction,
interpreted conservatively here: the container is shared infrastructure,
not something this item owns). A real Suricata EVE log bundle
(`tests/fixtures/samples/real/suricata/eve.json`, the SAME real sample C5's
own `chain_detect_from_evidence` PoC already used and proved fires through
the FAST parser path) was used instead for the scripted, captured real run
-- it exercises the identical `CollectForensicArtifactAction` mechanism with
zero dependency on the broken worker image, and both artifact *kinds* go
through the exact same, unmodified `EvidenceIntakeService`/parser-registry
code path (`ForensicParser.supports()` content-sniffs real bytes regardless
of what triggered the upload). **Follow-up, not this item's fix:** rebuild
`docker-celery-worker-plaso-1` from the current `docker/Dockerfile.plaso-worker`
to actually exercise the memory-dump path end-to-end through the real
autonomous pipeline.

## Versions / real dependencies (CLAUDE.md SS F.2 step 1)

- Postgres **16** (`docker-postgres-1`, already running) -- real
  `PostgresDetectionRepository`/`PostgresEvidenceRepository`/
  `PostgresAuditLogRepository`, the same real classes H1/H2/C4 already
  verified against this exact instance.
- MinIO (`docker-minio-1`, already running) -- real `S3EvidenceStorage`,
  real presigned PUT through nginx's TLS-terminated `:9444` reverse proxy
  (`https://kronos.local:9444`), the SAME public endpoint a browser client
  uses (`docker-compose.dev.yml`'s own `MINIO_PUBLIC_ENDPOINT`).
- Redis 7 (`docker-redis-1`, already running) -- real Celery broker
  (`redis://localhost:6379/1`) / result backend (`redis://localhost:6379/2`),
  the SAME broker `docker-celery-worker-1` (already running) already
  consumes in normal operation.
- `docker-celery-worker-1` (already running, unmodified) -- the real
  `kronos.process_intake`/`kronos.dispatch_parse`/`kronos.parse_artefact_fast`
  Celery task bodies from `src/external/celery_app.py`, executing inside the
  real container, not re-implemented or mocked anywhere in this PoC.
- OpenSearch **2.11.1** (`docker-opensearch-1`, already running) -- real
  indexed documents confirmed via a real `_count` query (see "Bonus real
  check" in `output.txt`).

**Why a bare `Celery` client instead of importing `CeleryTaskQueue`/
`src.external.celery_app` directly:** that module instantiates
`config.Settings()` at import time, which requires ~14 unrelated required
fields (Keycloak client secret, Vault token, OpenSearch credentials, etc.)
never touched by the task-*sending* path this PoC needs. A bare
`celery.Celery(broker=..., backend=...)` client sending the exact same real
task names (`kronos.process_intake`, `kronos.dispatch_parse`) to the exact
same real queues (`q.intake`, `q.index`) the real worker already consumes is
equally real on the wire -- only the *sending* object differs; the *task
bodies that actually run* are the real, unmodified, already-running
container's own code.

## What was built

- `src/application/evidence_collection_action.py` --
  `CollectForensicArtifactAction(PlaybookAction)`. Constructor-injects the
  real `DetectionRepository` and the real `EvidenceIntakeService` -- **zero
  new abstractions**, zero edits to `PlaybookActionRegistry`/
  `PlaybookExecutionService` (mirrors H1/H2's own "new action = a
  registration" idiom exactly). `org_id` comes from `tenant` (the caller's
  own authenticated context); `case_id` comes from the looked-up
  `Detection.case_id` -- **never** from `params`, proved for real in this
  PoC's own run (the playbook step's `params` deliberately smuggle a random
  `case_id`/`org_id` that the real output correctly ignores).
- No `src/domain/` changes, no new `AuditEventType`s -- the existing
  `PLAYBOOK_STEP_EXECUTED` audit row (already carrying both `params`
  containing `detection_id` and `output` containing `evidence_id`) already
  makes the Detection -> Evidence custody link independently reconstructable
  from the audit trail alone, exactly as G3's "explainable" contract
  requires; inventing a redundant event type was considered and rejected as
  unnecessary duplication.

## Real run -- 16/16 checks passed (`output.txt`)

```
$ source ~/venv/bin/activate && python poc/detection_triggered_collection/run_poc.py
```

Flow proven, against the real, live dev stack, with every step's real
output captured (`output.txt`):

1. A real `Detection` row is seeded in the real Postgres `detection` table,
   with a real, freshly-generated `case_id`.
2. A real `Playbook` (one step, `collect_forensic_artifact`) is executed via
   the real, unmodified `PlaybookExecutionService.execute()` -- the exact
   same engine H1/H2 already verified, zero code changes to it.
3. `CollectForensicArtifactAction` reads the real
   `tests/fixtures/samples/real/suricata/eve.json` bytes, computes their
   real SHA-256, calls the real `EvidenceIntakeService.request_upload()`,
   performs a real `httpx` PUT of the real bytes to the real MinIO presigned
   URL (through nginx's real TLS termination), then calls the real
   `EvidenceIntakeService.start_intake()` -- which enqueues the real
   `kronos.process_intake` Celery task onto the real broker.
4. The real, already-running `docker-celery-worker-1` picks up the task
   (never started or touched by this PoC) and runs the real, unmodified
   autonomous pipeline: `process_intake` -> `RECEIVED` -> auto-enqueued
   `dispatch_parse` -> `PARSING` -> `parse_artefact_fast` (SuricataEveParser)
   -> `COMPLETE`. Polled purely by reading the real Postgres `evidence`
   table -- no manual `parse/start` call anywhere (CLAUDE.md SS E.2).
5. **Independent re-verification** from a **freshly-opened** Postgres
   connection (not the one that wrote any of the above):
   - The real `Evidence` row's `case_id` equals the real `Detection`'s own
     `case_id` -- not the attacker-supplied value the playbook step's
     `params` deliberately included.
   - The real `Evidence` row's `org_id` equals the real tenant's own
     `org_id` -- not the attacker-supplied value in `params`.
   - The real `Evidence` row's `state` is the real terminal `COMPLETE`, and
     its `sha256` matches the real artifact's own bytes.
   - The real, triggering `Detection` row is **byte-for-byte unchanged**
     (invariant #5 -- this action only ever creates, never mutates).
   - Real `PLAYBOOK_EXECUTION_STARTED`/`PLAYBOOK_STEP_EXECUTED`/
     `PLAYBOOK_EXECUTION_COMPLETED` audit rows exist, and real
     `EVIDENCE_UPLOAD_REQUESTED` (Evidence-side custody) exists in the same
     org's audit trail.
   - The step's own `PLAYBOOK_STEP_EXECUTED` audit row's `params.detection_id`
     and `output.evidence_id` cross-reference correctly -- the Detection ->
     Evidence link is reconstructable from the audit trail alone.
   - `AuditLogService.verify_chain()` confirms the real hash chain is
     intact end-to-end.
6. **Bonus, unscripted, manually run:** a real `_count` query against the
   real OpenSearch cluster's own case-scoped index confirms 6 real documents
   landed there -- `COMPLETE` reflects genuine parsing+indexing, not just an
   FSM label (see `output.txt`'s final section).

## Honest gaps, explicitly out of scope this pass

- **Live remote collection off a compromised host** does not exist and is
  not fabricated here -- see the judgment-call section above. This item
  proves the custody hand-off mechanism for an artifact that already
  exists, which is the real, buildable half of "collection" today.
- **The memory-dump path is untested end-to-end** because of the
  pre-existing `docker-celery-worker-plaso-1` stale-image gap documented
  above -- reported, not fixed (rebuilding a shared container was judged
  outside this item's own scope). The mechanism itself is artifact-agnostic
  and would take the identical code path once that gap is closed.
- **No automatic Detection-event -> Playbook trigger is wired** this pass
  (mirrors H1/H2's own explicitly-flagged gap: "no HTTP route or scheduled/
  Detection-triggered trigger wiring this pass"). This PoC invokes the
  playbook directly, exactly as `poc/playbook_engine/` and
  `poc/containment_approval_gate/` both already do for H1/H2. Deciding
  *when* a Detection should automatically trigger a specific Playbook
  (severity threshold? rule tag? analyst-configured binding?) is real,
  legitimate follow-up scope, not incidental to this item.
- **No streaming PUT** -- the artifact's bytes are read fully into memory
  before hashing/PUT-ing (matches this codebase's own existing precedent in
  every other upload PoC, e.g. `chain_detect_from_evidence`). Fine for the
  small real sample used here; a genuinely large memory dump would want a
  chunked read + chunked httpx body, mirroring `HashService.compute_from_stream`'s
  existing streaming idiom -- flagged in the action's own docstring as real
  follow-up, not built speculatively.
- **Bucket/tenant cleanup:** this run's real MinIO bucket
  (`kronos-evidence-h3poc<hex>-quarantine`/`-evidence`) and Postgres rows
  are deliberately left in place as inspectable proof, matching C4/C5's own
  precedent of not tearing down real evidence created by a PoC run.

## How to re-run

```
source ~/venv/bin/activate
python poc/detection_triggered_collection/run_poc.py
```

Requires the real dev stack up (`docker/docker-compose.dev.yml`) -- all
services healthy as of this run (2026-08-07).
