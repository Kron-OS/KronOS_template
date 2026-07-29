# PoC: cross-org multi-tenancy isolation (real Postgres + MinIO + OpenSearch + Keycloak)

## Versions (pinned, read from this repo)
- Postgres: `postgres:16-alpine` (matches `docker-compose.dev.yml`)
- MinIO: `minio/minio:latest`
- OpenSearch: `opensearchproject/opensearch:2.11.1`
- Keycloak: `quay.io/keycloak/keycloak:26.2`

## What this actually does

Boots the **real** FastAPI app (`src.external.fastapi_app.create_app()`), which
on startup runs the **real, unmodified production wiring path**
(`wire_dependencies_async()` — the exact function FastAPI's own lifespan
calls when `DATABASE_URL` is set), against a real Postgres + MinIO +
OpenSearch, with real Keycloak issuing real JWTs for two real Organizations
(`acme`, `beta`). Then drives the real routes over HTTP
(`fastapi.testclient.TestClient`) with those real tokens, attempting
cross-org access the way an actual attacker (or a confused frontend) would:
by ID, by list, by delete — not by calling repository methods directly.

Two Keycloak orgs were provisioned with the repo's own
`scripts/provision_keycloak_org.sh`, unmodified. Three users: `analyst`
(existing, org `acme`), `case-lead` (existing, org `beta`), and a new
`case-lead-acme` (created for this PoC so each org has a user allowed to
create cases — the RBAC matrix restricts case creation to
`case-lead`/`org-admin`).

## Real finding #1 (bug, fixed): cases were never persisted to Postgres

Reading `src/external/dependencies.py` and `src/external/startup.py` before
running anything showed `_case_repository` defaults to
`InMemoryCaseRepository()` (its own docstring: "for unit tests") at module
scope, and neither `wire_dependencies_async()` (FastAPI startup) nor
`wire_dependencies_sync()` (Celery worker startup) ever constructed a
`PostgresCaseRepository` or passed `case_repository=` into
`configure_dependencies()` — unlike `audit_log_repository` and
`evidence_repository`, which both were wired correctly. This is confirmed,
not assumed: this PoC's first real run printed

```
case_repository wired as: InMemoryCaseRepository
evidence_repository wired as: PostgresEvidenceRepository
```

with a real, reachable Postgres up the whole time. In this configuration,
**every case created via the real API lives only in the FastAPI process's
memory** — gone on restart, and inconsistent across multiple worker
processes/replicas (each would have its own private in-memory dict). This
is a severe production-readiness bug, independent of the isolation question
this PoC set out to test (isolation *within* the in-memory repo was
actually still correct — `InMemoryCaseRepository.get_by_id`/`list_by_org`/
`delete` all filter by `org_id` — the problem was persistence, not leakage).

**Fixed** in `src/external/startup.py`'s `wire_dependencies_async()`:
constructs a real `PostgresCaseRepository(engine)`, runs its
`create_tables()` alongside the other two, and passes
`case_repository=case_repo` into `configure_dependencies()`. Not touched in
`wire_dependencies_sync()` (the Celery worker path) — its own docstring
explains it deliberately avoids wiring loop-bound Postgres singletons
there, and no code path in that process actually needs `CaseRepository`.

Verified after the fix, both by the Python-level type check and directly
querying real Postgres (`output.txt` has the full transcript):
```
case_repository wired as: PostgresCaseRepository
...
$ psql ... SELECT case_id, org_id, title, status FROM cases;
 15f0f714-... | 64d0d9f6-...(acme's org_id) | Acme Incident 001 | open
 d9823460-... | 27d8d7b4-...(beta's org_id) | Beta Incident 001 | open
```

## Real finding #2: `QueryIsolationGuard` and `OpenSearchQueryBuilder` are dead code

`grep -rn "QueryIsolationGuard\|assert_org_scope\|OpenSearchQueryBuilder" src/`
outside their own definition files returns **nothing**. These two classes
in `src/external/middleware/query_isolation.py` and
`opensearch_isolation.py` are never imported or called anywhere. This isn't
a functional bug today — actual isolation is enforced a different way (every
repository method takes `org_id` as an explicit parameter and every route
handler correctly threads `tenant.org_id` through, confirmed by this PoC's
passing checks) — but it means the "belt-and-braces" layer
`docs/subsystems/multi-tenancy.md` describes doesn't actually exist in the
running system. Flagging for the final triage: either wire these in as real
defense-in-depth, or delete them so the docs/code don't imply a protection
that isn't there.

## Isolation checks — all passed against the real stack

| Check | Result |
|---|---|
| acme's case-lead creates a case in acme | 201, real row in Postgres |
| beta reads acme's case by ID | **404** (not 200) |
| beta deletes acme's case | **404** (not 204); case still exists afterward |
| acme's case does not appear in beta's case list | confirmed, 0 cases |
| beta creates its own case; acme cannot read it either | confirmed symmetric |
| analyst (wrong role, correct org) cannot create a case | 403 (RBAC, separate from org isolation) |
| acme requests an evidence upload (real MinIO presigned URL) | 201 |
| beta cannot list evidence under acme's case | **404** |

11/11 checks passed after the case-repository fix (10/11 before — the one
"failure" pre-fix was the case-repository-persistence check itself, by
design, so this PoC keeps re-catching a regression of that bug).

## Gaps / not covered here

- OpenSearch-level document isolation (index-naming + DLS) is **not**
  exercised by this PoC — there is no backend-mediated search/query route in
  this codebase to test (`grep` found none); OpenSearch access is entirely
  via the Dashboards iframe embed with a client-side locked `case_id` filter,
  which is out of scope here and belongs to `poc/opensearch_jwt/` and
  `poc/dashboards_embed/` (separate, planned PoCs).
- Step-up (`aal2`) enforcement on `evidence.delete`/`legal_hold` was not
  exercised in this pass (separate PoC: `poc/auth_flow/`).
- Only Postgres-backed resources (case, evidence) and RBAC were tested;
  audit-log cross-org isolation is covered by `poc/postgres/` instead.
