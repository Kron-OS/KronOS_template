# PoC: live-browser verification of the new evidence-download UI affordance

**Context.** The Milestone JJ second multi-scenario assessment's
UX/onboarding angle confirmed (static grep — zero matches for "download"
in `frontend/src/components/EvidenceDetailDrawer.tsx`,
`frontend/src/pages/CaseDetailPage.tsx`, `frontend/src/api/evidence.ts`)
that the backend's real, already-verified
`GET /api/cases/{case_id}/evidence/{evidence_id}/download` route
(`poc/evidence_download/`, Gap Audit X1) had no way to be triggered from
the UI at all. This PoC verifies the fix: a new Download button wired into
`EvidenceDetailDrawer.tsx`, calling a new `downloadEvidence()` helper in
`frontend/src/api/evidence.ts` (authenticated `axios` blob fetch +
`URL.createObjectURL` + synthetic `<a download>` click, since the SPA's
Bearer token lives in memory only — a plain `<a href>` navigation would
never attach it).

## Real dependencies

Real dev stack (`docker/docker-compose.dev.yml`): `docker-nginx-1`
rebuilt from this change's own frontend source (`docker compose -f
docker/docker-compose.dev.yml build nginx && ... up -d --no-deps nginx`)
so the new code is actually served, not assumed from source. Real
Keycloak login (`case-lead` / `DevCaseLead#2026`), real Postgres, real
MinIO, real Celery pipeline.

## What this proves

1. Real login, real case creation (`POST /api/cases` → 201).
2. Real evidence upload through the actual `UploadDrawer` UI (`POST
   /api/evidence/upload/request` → 201, `POST
   /api/evidence/upload/finalize/{id}` → 202 Accepted — the async pipeline
   dispatch per CLAUDE.md § E.1, not a synchronous 200).
3. The real, unmodified autonomous pipeline (tusd → hashing → promotion →
   Celery parse) reaches a real post-hashing state, confirmed by polling
   the actual evidence row in the UI (not assumed on a timer).
4. The new Download button is visible in the real `EvidenceDetailDrawer`
   once that state is reached.
5. Clicking it makes the real browser save a real file
   (`page.expect_download` + `download.save_as`) — not a mocked
   assertion.
6. The downloaded file's name (`nginx.log`) and SHA-256 match the real
   uploaded sample **byte-for-byte**.

**9/9 checks passed.** See `output.txt` for the captured run and
`screenshots/` for the evidence row and drawer state.

## Real, unrelated infra issue found and fixed while running this PoC

`docker compose -f docker/docker-compose.dev.yml up -d nginx` (the naive
form) recomputed the full dependency graph and attempted to recreate
`db-migrate`, which failed (`exec: "alembic": executable file not found in
$PATH` inside the `kronos-backend:dev` image, which has no shell either —
a genuinely broken one-shot migration container image, pre-existing and
unrelated to this change). This cascaded into recreating `postgres`,
`opensearch-init`, and `tls-init` containers too and left `nginx` stuck in
`Created` state. Real Postgres data was **not** lost (named volumes
persist across container recreation — independently confirmed via `SELECT
count(*)` on `cases`/`evidence`/`audit_log` before and after: 44/65/2201
rows, unchanged). Worked around by using
`docker compose up -d --no-deps nginx` instead (nginx's actual
dependencies — `kronos-backend`, `keycloak`, `minio`,
`opensearch-dashboards`, `tls-init` — were all already satisfied; only
`db-migrate` recreation, which nothing in nginx's own `depends_on` chain
requires, was the problem). The broken `db-migrate` image is a real,
separate gap for a future pass — not fixed here (out of scope, and this
initiative's convention is one focused change per fix).

## Run

```
~/venv/bin/python3 poc/evidence_download_ui/run_poc.py
```

Requires the dev stack up with a `docker-nginx-1` built from the current
frontend source (see above). Creates a fresh real case each run;
idempotent (a new case/evidence pair every time, nothing to clean up
beyond real Postgres/MinIO rows in the `kronos-dev` org, matching this
initiative's other UI PoCs).
