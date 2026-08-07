# PoC: Case / ticket integration (roadmap M7/H4 -- closes Milestone M7)

**Objective (roadmap, verbatim from the orchestrator's 2026-08-07 scope
note):** "KronOS's own `Case`/`Detection` entities are internal-only today
-- no code path exists to an external ITSM/ticketing system... Close M7 by
building a pluggable outbound integration: when a `Detection` is triaged
(or a playbook step runs), a real ticket/ticket-update is created in an
external system, with the external ticket id stored back on the KronOS
side for traceability -- never the reverse."

## Judgment call: what "real ticketing system" honestly means here (read this first)

Mirroring H2/H3's own precedent exactly: **no real external ITSM product
(Jira, ServiceNow, PagerDuty, generic webhook receiver, ...) is deployed
anywhere in this dev stack**, and per the roadmap's own binding scope note,
reaching a live third-party SaaS ticketing API is explicitly out of scope
for this unattended pass -- no new accounts, no calls to
`api.atlassian.com`/`servicenow.com`/`pagerduty.com`/etc., even a free
tier. Confirmed via the same style of grep H2/H3 already ran:

```
$ grep -rniE "jira|servicenow|pagerduty|zendesk" src/ docker/
src/exceptions.py:87: ... no PagerDuty/Opsgenie/webhook hook exists ...  (pre-existing, unrelated docstring)
src/application/batch_sealing.py:52: ... no PagerDuty/Opsgenie/webhook hook exists ...  (pre-existing, unrelated docstring)
(the rest of the hits are this pass's own new docstrings explaining the judgment call itself)
```

**What was built instead:** a small, typed `TicketingSystem` ABC
(`src/adapter/ticketing/ticketing_system.py`, mirrors
`EvidenceStorage`/`KeycloakAdminClient`'s own "one small interface, not a
raw HTTP passthrough" idiom -- exactly two methods, `create_ticket`/
`update_ticket`, never a generic `send(method, path, body)` escape hatch)
with ONE concrete implementation, `WebhookTicketingSystem`: a real HTTP
POST, a real JSON envelope, a real response status code and body
inspected. It is verified below against a REAL local HTTP receiver this
PoC itself stands up on `127.0.0.1` (stdlib `http.server`, an ephemeral
port -- not mocked, not `respx`/`httpretty`) standing in for the external
system's inbound webhook endpoint. This satisfies CLAUDE.md SS F's "real or
realistically containerized dependency" bar with real bytes over a real
TCP socket and real status codes on both sides, without a live vendor
account -- exactly the same honesty standard H2 applied to "block
IP"/"isolate host" and H3 applied to "live remote collection."

**Why a generic webhook shape, not a named-vendor SDK shape:** every major
ITSM product's own "generic integration" feature (Jira Automation
webhooks, ServiceNow Inbound REST, PagerDuty Events API v2) already
reduces to the same lowest common denominator this implementation uses:
POST a JSON envelope, read back an id. Modeling `WebhookTicketingSystem`'s
request/response shape on one specific vendor's proprietary SDK would have
been *less* honest than the generic shape actually built -- it would imply
verification against that vendor's real contract, which never happened.
The docstring in `ticketing_system.py` says this explicitly.

## What's real vs. what's a deliberate stand-in

| Component | Real | Stand-in |
|---|---|---|
| Postgres 16 (`docker-postgres-1`) | Yes -- real INSERT/UPDATE/SELECT over a real asyncpg connection | -- |
| `PostgresDetectionRepository` / `PostgresAuditLogRepository` / `AuditLogService` | Yes -- the real, unmodified production classes | -- |
| HTTP transport (`WebhookTicketingSystem` -> receiver) | Yes -- real TCP socket, real HTTP/1.1 request/response, real JSON | -- |
| The "external ticketing system" itself | -- | A local `http.server` receiver this script starts and tears down; generates ticket ids, never a real Jira/ServiceNow/PagerDuty account |
| `SyncDetectionTicketAction` / `PlaybookExecutionService` / `PlaybookActionRegistry` | Yes -- the real, unmodified production classes | -- |

## Pinned versions

- Postgres: `postgres:16-alpine` (`docker/docker-compose.dev.yml`) -- the
  same live `docker-postgres-1` container H1/H2/H3's own PoCs used.
- `httpx>=0.27` (`pyproject.toml`) -- the real HTTP client
  `WebhookTicketingSystem` uses.
- Python stdlib `http.server`/`threading` for the local receiver (no
  version pinning needed -- stdlib).

## Real, pre-existing infrastructure gap found and fixed (not silently patched)

The live dev Postgres's `detections` table was created by H1/H2/H3's own
prior runs, **before** this pass added the `external_ticket_id` column.
Exactly the caveat `postgres_detection.py` already documents next to
`risk_score`/`risk_factors` (the same table's own prior additive-column
landing): `PostgresDetectionRepository.create_tables()`'s
`create_all(checkfirst=True)` only creates missing *tables*, never adds
columns to an existing one. The first real run below failed loudly with a
real `asyncpg.exceptions.UndefinedColumnError` (captured in this
directory's own git history/terminal output before the fix, not
hidden) -- confirming the documented risk is real, not theoretical. Fixed
with the one-time manual migration the code comment already prescribes:

```
$ docker exec docker-postgres-1 psql -U kronos -d kronos -c \
    "ALTER TABLE detections ADD COLUMN IF NOT EXISTS external_ticket_id varchar(256);"
ALTER TABLE
```

This is now a real, permanent fact about the shared dev stack (the column
exists going forward) -- flagged here rather than silently absorbed,
mirroring H3's own "real, pre-existing infrastructure gap found and
reported" precedent for the stale `celery-worker-plaso` image.

## Scenarios covered (see `output.txt` for the actual captured run)

1. **CREATE** -- a real `Detection` row is synced for the first time via a
   real `PlaybookExecutionService` run: a real HTTP POST reaches the real
   local receiver, a real `ticket_id` comes back, and
   `Detection.external_ticket_id` is persisted in real Postgres.
   Independently re-read from a FRESH Postgres connection (not the one
   that wrote it).
2. **UPDATE** -- the SAME Detection is synced again: the real receiver
   gets an update-shaped POST referencing the SAME `ticket_id` (never a
   second, duplicate ticket) -- decided purely from
   `Detection.external_ticket_id` already being set, never from a
   caller-supplied flag.
3. **Invariant #3 (computed, never supplied)** -- the playbook step's own
   `params` deliberately smuggle a different `org_id`/`case_id`; the real
   request the receiver actually received is independently inspected and
   carries the REAL tenant/Detection values, proving the smuggled ones
   were never read (`SyncDetectionTicketAction` never even looks at those
   keys in `params`).
4. **Invariant #5 (derived opinions never mutate primary evidence)** --
   `Detection.triage_state` is confirmed UNCHANGED (still `NEW`) after
   both real ticket syncs, independently re-read from Postgres.
5. **Fail loudly (invariant #8)** -- a third real Detection is synced
   against a deliberately unreachable webhook URL (`127.0.0.1:1`); the
   real call fails with a real `TicketingError`, the playbook halts, a
   real `TICKET_SYNC_FAILED` audit row is written, and
   `Detection.external_ticket_id` is confirmed to remain `None` --
   never a fabricated ticket id.
6. **Tenant isolation** -- a second, unrelated tenant's attempt to sync a
   ticket for the first tenant's `Detection` id halts with a real failed
   step (the lookup is scoped to `(detection_id, tenant.org_id)`, mirrors
   `DetectionTriageService`/`CollectForensicArtifactAction`).
7. **Real audit hash chain intact end-to-end**, independently
   re-verified via `AuditLogService.verify_chain()` on a fresh connection,
   after two successful syncs and one real failure.

**24/24 checks passed.**

## How to run

```
docker ps --format '{{.Names}}' | grep postgres   # confirm docker-postgres-1 is up
~/venv/bin/python3 poc/detection_ticket_integration/run_poc.py
```

No container other than the already-running `docker-postgres-1` is
touched or required -- the "external ticketing system" is a local
`http.server` this script starts and stops itself (no persistent state,
no port left listening after the run).

## What was NOT verified (explicitly out of scope, not silently skipped)

- **No live third-party SaaS ticketing API was ever contacted** -- this is
  the roadmap's own hard boundary for this pass, not an oversight.
- **No HTTP route or Detection-triage-triggered auto-dispatch wiring**
  this pass -- mirrors H1/H2/H3's own identical precedent
  (`SyncDetectionTicketAction`/`WebhookTicketingSystem` are not wired into
  `dependencies.py`/`startup.py`; deciding *when* a triage transition
  should automatically fire this action is real, separate follow-up
  scope, not incidental here).
- **No per-org ticketing configuration** -- `WebhookTicketingSystem`'s
  `webhook_url` is a single, deployment-wide value
  (`Settings.ticketing_webhook_url`, `src/config.py`), the same shape this
  codebase already uses for every other external adapter endpoint
  (`keycloak_url`, `opensearch_url`, `vault_url` are all deployment-wide
  too, never looked up per-org). A per-org override was considered and
  deliberately not built: no other adapter in this codebase does per-org
  config lookup for an external service endpoint, so building one here
  first would be speculative machinery ahead of an actual second caller
  that needs it, not something the roadmap's own invariant #3 requires
  (#3 is about *tenant identity* being computed, never supplied -- which
  this design satisfies: every tenant-derived value that reaches the
  external payload, `org_id`/`org_alias`/`case_id`, comes from
  `TenantContext`/the looked-up `Detection`, never from `params`).
- **Retry/backoff on a failed ticketing call** -- a failed sync is
  reported loudly (raised, audited) and left for the playbook's own
  fail-fast semantics (H1's own design decision) or a future explicit
  retry step; no automatic retry loop was built speculatively here.
