# PoC: real admin API-key provisioning -> real inbound push -> real revoke

## What this proves

Milestone W8 (`docs/ASSESSMENT_SYNTHESIS_2026-08.md` P1-W5, from
`docs/assessments/incident_response_walkthrough.md` F6, Gap Audit P1-7):
`StaticApiKeyProvisioning` records used to only ever be seeded once, at
process boot, from `Settings`/Vault into a static in-memory dict
(`configure_static_api_key_provisioning` -- formerly named
`configure_static_api_key_provisioning` on `dict[str, StaticApiKeyProvisioning]`
-- had zero real callers anywhere in `src/`, confirmed via a direct grep
before this milestone). There was no way for an operator to provision an
org a real key for `POST /api/integrations/push/{source_type}` without a
full backend restart.

This PoC proves the real fix end to end: a real Alembic migration creates
the new `integration_source_keys` table on the real dev-stack Postgres, a
real HTTP call to the new admin route provisions a real, random API key
(SHA-256-hashed at rest, plaintext returned exactly once), that exact
plaintext key is then used in a REAL inbound push request and is accepted,
and after a REAL revoke call the SAME key is REJECTED on a subsequent push
-- with no process restart anywhere in between.

## Pinned versions (read from this repo, not assumed)

- Postgres: `postgres:16-alpine`, real running `docker-postgres-1`
  container (`docker/docker-compose.dev.yml`) -- not started/stopped by
  this PoC.
- `alembic==1.19.1`, `sqlalchemy==2.0.51`, `asyncpg==0.31.0` (installed in
  `/home/reca/venv`; matches `pyproject.toml`'s `alembic>=1.13`,
  `sqlalchemy[asyncio]>=2.0`, `asyncpg>=0.29` pins).
- `httpx` (pinned `>=0.27` in `pyproject.toml`) via
  `httpx.AsyncClient(transport=httpx.ASGITransport(app=app))` -- the same
  working pattern `poc/kronos_attest_export/run_poc.py` (Milestone W3)
  established, reused here rather than `TestClient` (whose threaded portal
  runs the ASGI app on a separate anyio worker-thread event loop,
  incompatible with the async SQLAlchemy engine created on this
  coroutine's own loop -- a real, previously-confirmed failure mode:
  `asyncpg` raises "Future attached to a different loop").

## What it exercises (real, unmodified classes -- no mocks of the paths under test)

- `migrations/versions/20260816_1113_913567ca653a_add_integration_source_keys_table.py`
  -- applied via a real `python -m alembic upgrade head` subprocess call
  against `docker-postgres-1`.
- `src/adapter/repository/postgres_integration_source_key.py` --
  `PostgresIntegrationSourceKeyRepository` (real INSERT/SELECT/UPDATE, real
  SHA-256 hashing, real `ON CONFLICT` rotation logic).
- `src/external/routes/admin_integration_sources.py` -- `provision`/`list`/
  `revoke`, including real role-gate + real step-up ticket issue/consume.
- `src/external/middleware/integration_source_auth.py` --
  `StaticApiKeyInboundAuthenticator`, now repository-backed.
- `src/external/routes/integration_source_push.py` -- `push_webhook`,
  completely untouched by this milestone (only the authenticator's
  constructor signature changed upstream of it).
- `src/adapter/repository/postgres_audit_log.py` -- real
  `INTEGRATION_SOURCE_KEY_PROVISIONED`/`INTEGRATION_SOURCE_KEY_REVOKED`
  audit events, confirmed persisted and confirmed to never contain the
  plaintext key.

## Run

```
source ~/venv/bin/activate   # or use /home/reca/venv/bin/python directly
python poc/integration_source_key_provisioning/run_poc.py
```

Requires the real dev stack's Postgres reachable at `localhost:5432`
(`docker-postgres-1`, already running -- not started/stopped by this PoC).

## Result

**All 17 checks pass** -- see `output.txt` for the full captured real run
(real `alembic upgrade head` output, real HTTP request/response bodies for
provision/list/push/revoke/push-after-revoke, real structured JSON log
lines including the real audit-event-logged entries).

Key excerpts:

- `alembic upgrade head` exits 0 against the real, already-`create_tables()`
  -populated dev database (this repo's `docs/DATABASE_MIGRATIONS.md` own
  documented "adopting Alembic on an existing deployed database" path --
  `alembic stamp head` was run once, separately, before this migration was
  authored, to align the pre-existing dev database with the Alembic
  baseline; this PoC's own `alembic upgrade head` call is the real,
  repeatable step that then applies the new revision).
- `POST /api/admin/integration-sources/generic-webhook/provision` -> `201`,
  body includes a real plaintext `apiKey`
  (`_6gvvnPZ_JDQFptYfJ-M36qL3xFvzKuGh1u_--yg_yI` in the captured run --
  regenerated fresh on every run, never predictable).
- `GET /api/admin/integration-sources` -> `200`, `total: 1`, the listed
  item has NO `apiKey` field at all.
- `POST /api/integrations/push/generic-webhook` with
  `X-KronOS-Source-Key: <that real key>` -> `202`,
  `{"accepted": true, "duplicate": false, ...}`.
- `DELETE /api/admin/integration-sources/generic-webhook/poc-wazuh-1` ->
  `204`.
- The SAME push, same real key, immediately after revoke -> `401`,
  `{"detail": "Inbound push API key is not provisioned"}`.
- Real `PostgresAuditLogRepository.stream_by_org` confirms exactly one
  `integration_source.key_provisioned` and one `integration_source.
  key_revoked` event, and that neither event's `details` contains the
  plaintext key.

## What this pass did NOT verify (explicit, not a silent gap)

- Concurrent provisioning/rotation racing a request mid-flight (the
  `ON CONFLICT DO UPDATE` in `PostgresIntegrationSourceKeyRepository.
  provision` is atomic at the single-statement level, but no concurrent-
  load test was run).
- The `wazuh`/`suricata-eve`/`zeek-json` named source_types specifically --
  this PoC uses `generic-webhook` (the real, registered, vendor-neutral
  stand-in PUSH source) since the authentication/provisioning path is
  identical regardless of which registered `IntegrationSource` handles the
  body afterward; `push_webhook` itself was explicitly out of scope for
  this milestone.
