# PoC: Microsoft Sentinel Logs Ingestion API sink connector (roadmap R4)

**Milestone:** R — Integration sinks (KronOS → SIEM/SOAR)
**Item:** R4 — Microsoft Sentinel sink connector
**Layer:** L2 (two components genuinely linked: `SentinelHttpSink` /
`SentinelDetectionMapper` ↔ a real local Entra ID + Sentinel Data
Collection Endpoint stand-in)

## Real Azure subscription: checked, genuinely unavailable

Checked directly in this environment before writing any code:

```
$ which az            # no output -- Azure CLI not installed
$ env | grep -i azure # no output -- no AZURE_* credentials/env vars set
```

No Azure CLI, no `AZURE_SUBSCRIPTION_ID`/`AZURE_TENANT_ID`/service-principal
credentials, and no network path to provision a real DCE/DCR/Log Analytics
workspace exist in this sandboxed environment. Per roadmap §1 invariant #9
("no live third-party SaaS call, ever, from any PoC or test ... a real
recorded/replayed response fixture, clearly labeled as such"), this PoC
therefore builds a **real, local, protocol-accurate stand-in** for both real
Azure endpoints involved (the Entra ID v2.0 token endpoint and the Sentinel
Data Collection Endpoint's own Logs Ingestion API), matching Microsoft's own
**current, official documentation** fetched and read directly this pass
(not assumed from memory, not modeled on the now-retired HTTP Data
Collector API) — never a live Azure account.

## Real docs fetched and used this pass (exact URLs + what was verified)

1. **`learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview`**
   — the real URI template:
   ```
   {Endpoint}/dataCollectionRules/{DCR Immutable ID}/streams/{Stream Name}?api-version=2023-01-01
   ```
   Real required headers: `Authorization: Bearer <token>` (audience/scope
   `https://monitor.azure.com` for Azure public cloud), `Content-Type:
   application/json`. Real request body shape — the doc's own worked
   example is a **bare top-level JSON array**:
   ```json
   [{"TimeGenerated": "2023-11-14 15:10:02", "Column01": "Value01", "Column02": "Value02"}]
   ```
   Real custom-table rule: "Custom tables must have the `_CL` suffix."
   Real DCR sample JSON (`streamDeclarations`/`dataFlows`/`destinations`)
   quoted directly from this page informed the stand-in's own DCR-shaped
   validation.

2. **`learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-structure`**
   — the real, closed `streamDeclaration` column-type set: **`string`,
   `int`, `long`, `real`, `boolean`, `dynamic`, `datetime`** (`guid` is
   explicitly NOT available at this layer — "declare those columns as
   `string`"). This is the real mechanism `SentinelDetectionMapper` uses
   for its `dynamic`-typed catch-all/array columns, not an invented one.
   Also confirms: "The stream contains a full list of top-level properties
   that are contained in the JSON data you send" — the real rigidity rule
   the stand-in's schema-mismatch rejection (Scenario 5) enforces.

3. **`learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-code`**
   (PowerShell tab) — the real, complete OAuth2 client-credentials flow:
   ```
   POST https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token
   Content-Type: application/x-www-form-urlencoded
   client_id=...&scope=...&client_secret=...&grant_type=client_credentials
   ```
   and the real, explicit success confirmation quoted verbatim from the
   doc: **"Execute the script, and you should see an `HTTP - 204`
   response."** This is the single most load-bearing fact this PoC
   verifies against — 204, not 200, is the real documented success code,
   confirmed directly from Microsoft's own tutorial text, not inferred.
   Also the doc's own "Troubleshooting" table, quoted directly: **403**
   (app registration lacks the DCR's own `Monitoring Metrics Publisher`
   role), **413**/`TimeoutExpired`/`ReadyBody_ClientConnectionAbort`
   (message exceeds the real 1 MB ceiling), **429** (real per-DCR
   throttle, `Retry-After` header).

4. **`learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits`**
   ("Logs Ingestion API" table) — real, exact numbers: **Maximum size of
   API call: 1 MB** (compressed or uncompressed); **Maximum size for field
   values: 64 KB** (truncated, not rejected — not enforced client-side
   here, see `sentinel_sink.py`'s own docstring); **Maximum data/minute per
   DCR: 2 GB**; **Maximum requests/minute per DCR: 12,000** (both
   `Retry-After`-governed 429s).

5. **`learn.microsoft.com/en-us/python/api/azure-monitor-ingestion/...LogsIngestionClient`**
   — confirms the real, current, pinned `api-version` default (`"2023-01-01"`,
   "overriding this default value may result in unsupported behavior") and
   that the real Python SDK's own `upload()` raises `HttpResponseError` on
   any failure and returns `None` (no body to inspect) on success —
   independently corroborates the "204, no body" contract from a second,
   independent real doc.

6. **`github.com/microsoft/api-guidelines`** (`azure/Guidelines.md`,
   "Handling Errors" section) — Microsoft's own general, cross-service
   Azure REST API error envelope:
   ```json
   {"error": {"code": "InvalidPasswordFormat", "message": "...", "target": "...", "innererror": {...}}}
   ```
   Used here as the real, official, documented shape for the stand-in's
   own 400/403/413 error bodies. **Honesty caveat, explicit per roadmap §1
   invariant #9's "clearly labeled" requirement**: the exact `error.code`
   *string* a real Sentinel Logs Ingestion API returns for a genuine schema
   mismatch is not published in any of the docs fetched this pass (no
   worked example of a 400 body was found) — this PoC's stand-in uses a
   representative code (`InvalidCustomLogFormat`) inside the real,
   confirmed **envelope shape**. The shape is real and cited; the exact
   code string is a reasonable placeholder, not independently verified
   against a live tenant. Flagged, not silently presented as verified.

## What was checked vs. not checked (§3 stage reached)

**Test stage only** (expected for a connector item, mirrors R1/R2/R3's own
identical framing) — no `docker-compose.dev.yml`/`prod.yml` wiring, no
route/playbook-action triggers a real Sentinel push automatically. This PoC
proves the connector's own *logic* end-to-end against the real, documented
contract.

## Rigid schema design (the "hard part" R4 calls out)

See `src/application/sentinel_detection_mapper.py`'s own module docstring
for the full column table and per-field justification. Summary: 14
columns, custom table `KronOSDetection_CL`, stream `Custom-KronOSDetection`.
Core SOC-analyst triage fields (`DetectorName`, `TriageState`,
`RuleSeverity`, `RiskScore`, ids) get first-class typed columns; genuinely
structured/variable-shape `Detection` fields (`rule_matches`,
`attack_tags`, `matched_document_ids`) use the real `dynamic` column type;
secondary/traceability fields (`external_ticket_id`, `synced_at`,
`updated_at`) are bucketed into one `dynamic` catch-all,
`ExtendedProperties` — **never silently dropped**, and never requiring a
DCR schema change to add a new secondary field.

## Sibling-vs-reuse decision (sink)

`SentinelHttpSink` is a sibling `IntegrationSink`, NOT a reuse of
`HttpJsonIntegrationSink` — full justification in `sentinel_sink.py`'s own
module docstring. Short version: `HttpJsonIntegrationSink` requires a
`{"events": [...]}` envelope and a 2xx body with an `accepted` count; the
real Sentinel contract is a bare JSON array with a 204-**no-body** success
— reusing it would make every real Sentinel push fail its own accepted-count
check, always, even on success.

## Auth reuse decision

`SentinelHttpSink` reuses R1's `OAuth2ClientCredentialsAuthenticator`
(`src/adapter/integration_sink/sink_authenticator.py`) **unchanged** — that
class's own docstring already named Sentinel's Entra ID flow as its reason
to exist. It deliberately does **not** reuse/duplicate Q1's
`OAuth2ClientCredentialsOutboundAuthStrategy`
(`src/external/middleware/integration_source_auth.py`) — a different ABC
(`headers() -> dict[str, str]`, no `SinkAuthParams`/cert/verify shape) built
for the opposite direction (KronOS polling an external API with an
externally-injected shared `httpx.AsyncClient`), not something
`IntegrationSink.push_events()`'s own per-call `SinkAuthenticator.prepare()`
contract can consume without an adapter that would net negative versus just
using the collaborator already built for this. Full reasoning in
`sentinel_sink.py`'s own module docstring.

## Running it

```
~/venv/bin/python3 poc/integration_sink_sentinel/run_poc.py
```

Requires `docker-postgres-1` (16) already running
(`docker/docker-compose.dev.yml`) for Scenario 8's real audit-trail proof.
No other container is touched or created. The script starts two real local
`http.server` stand-ins (Entra ID token endpoint + Sentinel DCE ingestion
endpoint) on ephemeral `127.0.0.1` ports and shuts both down cleanly at
the end — independently confirmed nothing is left listening
(`ss -tlnp` re-checked after the run).

## Real captured result (last run)

**29/29 checks passed.** Full unedited output in `output.txt`. Highlights:

- Scenario 1: real OAuth2 client-credentials token exchange — real
  form-encoded POST, real JSON token response, real bearer token issued and
  independently tracked server-side.
- Scenario 2: real OAuth2 failure (wrong client secret) — real 401 +
  RFC 6749 §5.2 `invalid_client` body, surfaced as a real
  `IntegrationSinkError` by the unmodified `OAuth2ClientCredentialsAuthenticator`.
- Scenario 3: real successful push — the exact real 14-column mapped
  record is shown in the output, received byte-for-byte by the real
  stand-in, and independently checked field-by-field against the source
  `Detection`; real 204 → real `ACKNOWLEDGED`.
- Scenario 4: real OAuth2 token caching — 2 real pushes, 1 real token
  fetch (server-side count and authenticator's own count both agree).
- **Scenario 5 (the roadmap's own required case): real, deliberate
  schema-mismatch rejection** — an extra undeclared column
  (`UnexpectedColumn`) triggers a real 400 with the real Azure error
  envelope (`{"error": {"code": "InvalidCustomLogFormat", "message":
  "...UnexpectedColumn..."}}`), surfaced as a real, non-fabricated
  `IntegrationSinkError` — the stand-in did NOT record the bad batch as
  received. A second, independent case (a *missing* declared column) is
  rejected the same honest way.
- Scenario 6: real documented 403 (DCR access not granted to this app
  registration).
- Scenario 7: real documented 413 — both `SentinelHttpSink`'s own real
  client-side 1 MB pre-check (batch never sent) AND a genuinely oversized
  raw request sent directly at the real stand-in (bypassing the sink) to
  confirm the *server's* own real 413 too.
- Scenario 8: full `DetectionSinkPushService` orchestration against the
  real, live dev-stack Postgres 16 — real `SINK_PUSH_ATTEMPTED`/
  `SINK_PUSH_EXECUTED` audit rows independently re-read from a fresh
  connection, real hash chain verified intact.

No bug was found on this pass's first real run (unlike R2/R3, where the
first real run each surfaced a genuine bug) — the mapper's rigid,
by-construction 14-key record shape left little room for a shape mismatch,
and the stand-in's schema check was written independently of the mapper
(not sharing code with it), so this is a real, if less dramatic,
confirmation rather than an untested claim.
