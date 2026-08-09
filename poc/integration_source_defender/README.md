# PoC: DefenderPollSource (roadmap Q4)

Proves Microsoft Defender's real Graph Security API `alerts_v2`
poll-with-cursor mechanism end to end: OAuth2 client-credentials auth,
`$filter=lastUpdateDateTime gt <cursor>` incremental polling,
`@odata.nextLink` pagination, and real `SourceCursor` persistence across
poll cycles via Postgres.

## Real tenant vs. fixture fallback

**No real Azure/Entra ID tenant exists in this sandbox.** Checked:

- `grep -rniE "AZURE_TENANT_ID|AZURE_CLIENT_ID|ENTRA|graph.microsoft.com|login.microsoftonline"`
  across every `*.py`/`*.yml`/`*.yaml`/`*.toml` file in the repo — no hits
  besides this connector's own new code and docstrings referencing the
  research.
- `find . -iname "*.env*"` — only `docker/.env.example`,
  `frontend/.env.example`, `sandbox/.env.example` exist, none reference
  Azure/Entra/Defender.
- `env | grep -i azure` in this process's own environment — empty.

Per roadmap SS1 invariant #9, this PoC therefore uses a **real local HTTP
stand-in server** built to match Microsoft's own current, real, documented
schema — not a live call to `graph.microsoft.com` or
`login.microsoftonline.com`.

## Real docs verified against (fetched 2026-08-09)

- **Alert resource shape**: <https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0>
  — full property table + a complete worked JSON example. This PoC's
  `_alert()` fixture builder uses the exact same field names/shape
  (`id`, `providerAlertId`, `incidentId`, `status`, `severity`,
  `classification`, `determination`, `serviceSource`, `detectionSource`,
  `tenantId`, `title`, `description`, `category`/`categories`,
  `alertWebUrl`, `incidentWebUrl`, `mitreTechniques`, `createdDateTime`,
  `lastUpdateDateTime`, `evidence[]` with a real `deviceEvidence` subtype).
- **List operation + `$filter`/pagination contract**: <https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0>
  — "Optional query parameters" section: *"The following properties support
  `$filter`: **assignedTo**, **classification**, **determination**,
  **createdDateTime**, **lastUpdateDateTime**, **severity**,
  **serviceSource** and **status**. Use `@odata.nextLink` for pagination."*
- **OAuth2 client-credentials token contract**: <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow>
  — exact `POST /{tenant}/oauth2/v2.0/token` form-urlencoded request shape
  (`grant_type=client_credentials&client_id=...&client_secret=...&scope=...`)
  and exact success (`{"token_type":"Bearer","expires_in":...,"access_token":...}`)
  / error (`{"error":"invalid_client",...}`, 400) response shapes.
- **`@odata.nextLink` paging semantics**: <https://learn.microsoft.com/en-us/graph/paging>
  — *"Microsoft Graph returns an `@odata.nextLink` property in the response
  that contains a URL to the next page of results... continue to call
  Microsoft Graph with the `@odata.nextLink` property returned in each
  response until the `@odata.nextLink` property is no longer returned"* and
  *"Any other query parameters that were present in the original request are
  also encoded in this URL."* This PoC's stand-in server's own `nextLink`
  re-encodes `$filter` into the next page's URL for exactly this reason —
  confirmed necessary by testing without it first (the connector would lose
  the filter on page 2 otherwise).

**Real, reportable correction found via this research (CLAUDE.md SS F —
mirrors Q2's Wazuh version correction and Q3's fluent-bit gap, reported not
silently applied).** The roadmap's own Q4 objective text and SS0 research
table both say `$filter=lastUpdateTime gt ...`. **There is no
`lastUpdateTime` property on the real `alert` resource.** The real property
name — confirmed directly from the "List alerts_v2" page's own enumerated
list of `$filter`-eligible properties — is **`lastUpdateDateTime`**. This
connector, its normalizer, and this PoC all use the real name throughout.
Flagged to the orchestrator for updating the roadmap doc's own historical
SS0 table text (this PoC's own STATUS block in the roadmap corrects it for
Q4 itself).

## What's real vs. simulated

| Real | Simulated (documented, not hidden) |
|---|---|
| `httpx.AsyncClient` making real HTTP calls over a real TCP socket | The Graph API service itself (local stand-in, since no real tenant exists) |
| `OAuth2ClientCredentialsOutboundAuthStrategy` — real RFC 6749 §4.4 request, real Bearer token round-trip, real token caching | The Entra ID identity platform itself |
| `DefenderPollSource.poll()` — real `$filter` construction, real `@odata.nextLink` following across 2 real pages per cycle | — |
| The stand-in server's own `$filter` parsing/enforcement (regex + `datetime.fromisoformat` + real list filtering against its own live alert store) | The alert *data* (schema-accurate fixture, not real tenant telemetry) |
| `PostgresSourceCursorRepository` against the real, already-running shared dev Postgres (`docker-postgres-1`, port 5432) — real `INSERT`/`SELECT`/on-conflict-`UPDATE` | — |
| `IntegrationSourceIngestService.run_poll_cycle()` — real dedup/backpressure/audit pipeline | `InMemoryStreamIngestAdapter`/`InMemoryEventDedupChecker`/`InMemoryAuditLogRepository` (PoC-tier doubles, same bar every other Q-series PoC uses — Redis/real audit Postgres independently verified elsewhere) |
| `DefenderAlertNormalizer.normalize()` against all 7 real fetched alerts | — |

## How to run

Requires the shared dev Postgres already running on `localhost:5432`
(`docker-postgres-1` — pre-existing, not created by this PoC):

```bash
/home/reca/venv/bin/python poc/integration_source_defender/run_poc.py
```

The script starts its own ephemeral `ThreadingHTTPServer` (stand-in Entra ID
token endpoint + Graph `alerts_v2` endpoint), runs 3 real poll cycles, and
tears down its own server thread + its own single Postgres row on exit. No
Docker containers are created by this PoC (unlike Q2/Q3, there is no real
self-hostable Defender/Entra ID to containerize).

## Real captured output

See `output.txt` for the full, unedited transcript of the last real run.
Highlights:

1. **Real OAuth2 token exchange** — real form-urlencoded request body
   captured server-side, real minted Bearer token returned, reused
   (`get_valid_token()`'s own cache) across every subsequent call within a
   cycle.
2. **Real pagination followed on both cycles** — cycle 1: `$skip=0` (2
   alerts, `has_more=True`) then `$skip=2` (2 alerts, `has_more=False`);
   cycle 2: `$skip=0` (2 of 3 eligible) then `$skip=2` (1 of 3 eligible).
3. **Real `$filter` enforcement, not a canned response** — cycle 2's
   request carried `$filter=lastUpdateDateTime gt 2026-08-01T00:15:00.0000000Z`
   (A4's own real `lastUpdateDateTime`, persisted from cycle 1), and the
   server's own log line shows it evaluating `3 eligible` out of the 7
   alerts then in its store — the 4 old alerts (A1–A4) were genuinely
   excluded by real `datetime` comparison, not by coincidence.
4. **Real cursor persistence across cycles via Postgres** — cycle 2 used a
   *brand-new* `PostgresSourceCursorRepository` instance against the same
   engine (not the cycle-1 instance's own in-process state) and still
   correctly resumed from `2026-08-01T00:15:00.0000000Z`.
5. **Real empty-page proof** — cycle 3 (no new alerts) got `0 eligible`
   back and the persisted cursor value is provably unchanged
   (`cursor_after_3.cursor_value == cursor_after_2.cursor_value`).
6. **Real auth-failure proof** — a deliberately wrong `client_secret`
   produced a real `401` from the stand-in token endpoint, surfaced as a
   real `IntegrationSourceAuthError`, never silently swallowed.
7. **Real audit trail** — exactly 3 `integration_source.poll_completed`
   events, one per cycle, including the honest `event_count=0` for the
   empty cycle.

Re-run twice during this pass (both real runs produced identical
assertions passing; the second run's own Postgres row was independently
confirmed absent afterward via a direct `SELECT * FROM
integration_source_cursors`).

## Stage reached (roadmap §3)

**Test-stage only**, honestly incomplete on purpose, matching every prior
Q-series item's own precedent: `DefenderPollSource` is registered into the
real DI container's `IntegrationSourceRegistry` **conditionally** —
`configure_defender_poll_source_from_settings()` (`src/external/dependencies.py`)
is wired into `startup.py`'s real startup sequence, but since
`defender_tenant_id`/`defender_client_id`/`defender_client_secret` are all
unset in every environment this repo has (`docker-compose.dev.yml` included
— not touched by this pass), it resolves to the same honestly-disabled
`None` state every unconfigured optional integration in this codebase uses
(mirrors `_splunk_hec_sink`/`_cef_syslog_sink`'s own pattern exactly). No
`docker-compose.dev.yml`/`docker-compose.prod.yml` wiring was added (there
is nothing real to wire — no self-hostable Defender/Entra ID exists to run
in dev, unlike Wazuh/fluent-bit). `SourceCursorRepository`'s own DI default
also remains in-memory in the live app (an existing, inherited Q1 gap, not
introduced or fixed by this pass — this PoC's own real Postgres proof
happens at the PoC layer only, same as Q1's own `PostgresSourceCursorRepository`
PoC).
