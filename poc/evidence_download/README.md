# PoC: `GET /api/cases/{case_id}/evidence/{evidence_id}/download`

## What this proves

Milestone X1 (`docs/GAP_AUDIT_2026-08-17.md`) — KronOS previously had no
way for a user to download the original evidence file at all;
`EvidenceStorage.stream_object()` was only ever called internally
(parsing/hashing/scanning). This PoC exercises the new
`src/external/routes/cases.py::download_evidence` route end to end
against real MinIO and real Postgres, not mocks.

## Versions / real dependencies used

- MinIO: `minio/minio:latest`, the real, shared, already-running
  `docker-minio-1` dev-stack container (reachable at `localhost:9000`).
  Safe to share since buckets are per-org and this PoC creates its own
  fresh, throwaway `org_alias` every run.
- Postgres: `postgres:16-alpine`, but a **fresh, throwaway
  `kronos-poc-x1-postgres` container** (port 15432), NOT the shared
  `docker-postgres-1`. See "Real, pre-existing schema drift found" below
  for why.

## Real, pre-existing schema drift found (not this PoC's bug)

An early run against the shared `docker-postgres-1` failed with
`UndefinedColumnError: column "quota_held" of relation "evidence" does
not exist`. Confirmed real and pre-existing: `alembic current` on that
real, shared database reports HEAD (`913567ca653a`) despite the column
genuinely being absent — no migration for this drift exists at all. The
shared DB's `evidence` table predates `quota_held` being added to
`postgres_evidence.py`'s own `sa.Table` (tenant storage quotas), and
`create_tables()`'s `checkfirst=True` only creates missing *tables*,
never adds missing *columns* to an existing one. This exact gap was
already found and explicitly **not** fixed by the Milestone W8 subagent's
own migration commit message (`migrations/versions/20260816_1113_913567ca653a_...py`).
Deliberately not re-fixed here either — real, pre-existing, unrelated
drift on shared infrastructure deserves its own focused migration, not an
X1 side effect. Worked around by using a fresh, throwaway Postgres
container instead (a brand-new table, created from the current, correct
`sa.Table` metadata, never has this drift by construction).

## Run

```
docker run -d --name kronos-poc-x1-postgres -e POSTGRES_DB=kronos \
  -e POSTGRES_USER=kronos -e POSTGRES_PASSWORD=kronos_dev_password \
  -p 15432:5432 postgres:16-alpine
source ~/venv/bin/activate
python poc/evidence_download/run_poc.py
docker stop kronos-poc-x1-postgres && docker rm kronos-poc-x1-postgres
```

Requires the real, shared dev-stack MinIO already running.

## Result

**15/15 real checks passed** (`output.txt`). Real upload through
`EvidenceIntakeService` (validate → scan → hash → promote against real
MinIO), real download via the new route (`httpx.ASGITransport` in-process
— not `TestClient`, whose threaded portal is incompatible with an async
SQLAlchemy engine constructed in this coroutine's own loop, same finding
Milestones W3/W8/W11/W14 already made), confirming: byte-for-byte match
against the real uploaded content, correct `Content-Disposition`/
`Content-Type`, a real `EVIDENCE_DOWNLOAD` audit row persisted in Postgres
with the correct `evidence_id`/`case_id`/filename (and no sensitive
content), 404 for not-yet-promoted evidence, 404 for cross-org access
(never 403 — no cross-org existence leak), and 404 for nonexistent
case/evidence ids.
