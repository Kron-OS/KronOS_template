# PoC: `IntegrationSink` foundation (roadmap R1, `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md`)

**Objective (roadmap R1, verbatim):** "Design and build the ABC +
`SinkAuthenticator` + `DetectionEventMapper` collaborators per SS4's
constraints, proven against ONE real concrete sink end-to-end before any
other sink connector starts."

## Judgment call: what "real sink" honestly means for R1 (read this first)

Mirroring H4/`detection_ticket_integration`'s own precedent exactly: **no
real named-vendor SIEM/SOAR product (Splunk, Microsoft Sentinel, IBM
QRadar, XSOAR, TheHive, ...) is deployed anywhere in this dev stack**, and
per roadmap SS1 invariant #9, reaching a live third-party SaaS API is a
hard boundary for every PoC in this initiative, not just this one. R1's own
scope (per the roadmap) is the foundation ABC + collaborators, proven
against the two *structurally different, vendor-neutral transport shapes*
research already identified (SS0): generic HTTP-JSON push-with-ack, and
CEF-over-syslog fire-and-forget. Named-vendor sinks (Splunk HEC, generic
CEF, Sentinel) are explicitly R2/R3/R4's own scope, not built here.

**What was built and verified instead:** two real local stand-in
receivers this PoC's own `run_poc.py` stands up and tears down on
`127.0.0.1` --

- A real stdlib `http.server` acting as a generic HEC-shaped JSON
  receiver: real HTTP/1.1 request/response, real JSON body, a real 2xx +
  `{"accepted": N}` confirmation body (and, on request, a real 500 or a
  real accepted-count mismatch to prove the failure paths).
- A real stdlib `http.server` acting as an OAuth2 client-credentials token
  endpoint: real `POST`, real JSON `{"access_token", "expires_in"}` body.
- A real `asyncio.start_server` TCP listener and a real
  `asyncio.DatagramProtocol` UDP listener, both standing in for a
  CEF-over-syslog receiver: real socket bytes read off the wire, no
  application-layer ack (because CEF/LEEF-over-syslog genuinely has none —
  SS0).

Every byte, status code, and response body asserted on below was actually
sent and actually read back over a real local socket — never
`respx`/`httpretty`, never a live vendor account.

## The single most important property verified here

Per the redispatch brief and `src/domain/integration_sink.py`'s own module
docstring: **a caller must never be able to mistake "I wrote it to a
socket" for "the target confirmed receipt."** This PoC's Scenarios 1, 3,
and 4 verify this is honestly modeled, not just documented:

- `HttpJsonIntegrationSink.push_events()` returns `SinkAck(status=
  SinkAckStatus.ACKNOWLEDGED, ...)` **only** after reading back a real 2xx
  response whose own JSON body's `accepted` count matches the real number
  of events sent — any 2xx with a missing/mismatched `accepted` count is
  treated as a real failure (`IntegrationSinkError`), never a fabricated
  partial ack (Scenario 2).
- `SyslogIntegrationSink.push_events()` returns `SinkAck(status=
  SinkAckStatus.UNACKNOWLEDGED, ...)` on **every** non-exceptional call —
  there is no code path in this class that can ever produce
  `ACKNOWLEDGED`, by construction (there's no branch that even checks for
  one — the transport has no confirmation channel to check). Scenarios 3/4
  independently confirm the real receiver actually got the real bytes
  *and* that the sink still, correctly, reports only `UNACKNOWLEDGED`.

This assessment (see the redispatch report) is that the prior session's
design got this exactly right — the honesty is structural (a real,
type-checked enum value each concrete sink is architecturally incapable of
getting wrong for its own transport family), not just asserted in a
docstring.

## What's real vs. what's a deliberate stand-in

| Component | Real | Stand-in |
|---|---|---|
| Postgres 16 (`docker-postgres-1`) | Yes — real INSERT/SELECT over a real asyncpg connection | — |
| `PostgresAuditLogRepository` / `AuditLogService` | Yes — the real, unmodified production classes | — |
| `HttpJsonIntegrationSink` / `SyslogIntegrationSink` / every `SinkAuthenticator` / `DetectionSinkPushService` / `chunk_events` | Yes — the real, unmodified production classes | — |
| HTTP transport (sink → HEC receiver, sink → OAuth2 token endpoint) | Yes — real TCP socket, real HTTP/1.1, real JSON | — |
| TCP/UDP transport (sink → syslog receiver) | Yes — real sockets, real bytes | — |
| The external SIEM/SOAR system itself | — | A local `http.server`/`asyncio` receiver this script starts and tears down; never a real Splunk/Sentinel/QRadar account |
| `GenericJsonStandInMapper` / `GenericCefLikeStandInMapper` | — | Deliberately generic, non-vendor-specific `DetectionEventMapper`s built **only** in this PoC (`run_poc.py`), proving the mapper ABC is pluggable — R2/R3/R4 own the real named-vendor mappers |

## Pinned versions

- Postgres: `postgres:16-alpine` (`docker/docker-compose.dev.yml`) — the
  same live `docker-postgres-1` container prior PoCs (H1–H4) used.
- `httpx>=0.27` (`pyproject.toml`) — the real HTTP client
  `HttpJsonIntegrationSink`/`OAuth2ClientCredentialsAuthenticator` use.
- Python stdlib `http.server`/`threading`/`asyncio` for every local
  receiver (no version pinning needed — stdlib).

No new/upgraded third-party dependency was introduced for R1 — everything
above was already pinned in this repo before this pass.

## Scenarios covered (see `output.txt` for the actual captured run)

1. **HTTP-JSON push-with-ack** — a real local HEC-shaped receiver returns
   a real 2xx + `{"accepted": N}` body; `HttpJsonIntegrationSink` reports a
   real, confirmed `SinkAckStatus.ACKNOWLEDGED`, and the real receiver's
   own request is independently inspected (real `StaticTokenAuthenticator`
   header, real mapped payload).
2. **HTTP-JSON failure paths** — a real 500 response, and a real 2xx with
   a deliberately mismatched `accepted` count, both raise
   `IntegrationSinkError` — never a fabricated/partial ack.
3. **Syslog fire-and-forget (TCP)** — a real local TCP listener receives
   the real CEF-shaped line; the sink reports `UNACKNOWLEDGED`, never
   `ACKNOWLEDGED`.
4. **Syslog fire-and-forget (UDP)** — same honesty property, over a real
   UDP datagram.
5. **Syslog fail loudly** — a real `ConnectionRefusedError` against a real
   closed TCP port (`127.0.0.1:1`) raises `IntegrationSinkError` (the
   deterministic failure case `syslog_sink.py`'s own module docstring
   calls out — a real UDP `sendto()` against a closed port does not
   reliably raise synchronously at all, which is itself an honest
   illustration of syslog's inherently weaker delivery guarantee, not a
   gap in this implementation or its test coverage).
6. **`OAuth2ClientCredentialsAuthenticator` real token caching** — a real
   local OAuth2 token endpoint is hit **exactly once** across **two** real
   pushes, independently confirmed both server-side
   (`OAuth2TokenHandler.fetch_count`) and client-side
   (`authenticator.real_token_fetch_count`), and both real requests are
   confirmed to have carried the identical cached token — this is the
   exact claim `sink_authenticator.py`'s own docstring makes about itself;
   it is verified for real here, not merely asserted.
7. **`DetectionSinkPushService` full orchestration** — 5 real `Detection`s
   mapped via `GenericJsonStandInMapper`, batched via a real
   `max_batch_events=2` ceiling into 3 real HTTP calls, all acknowledged;
   a second run against a deliberately-failing sink proves
   `SINK_PUSH_ATTEMPTED` → `SINK_PUSH_FAILED` audit discipline (ATTEMPTED
   logged *before* the real call, so a crash inside it can never erase the
   attempt); a fresh Postgres connection independently re-reads every
   audit row (3× `SINK_PUSH_EXECUTED` with honestly-`ACKNOWLEDGED` detail,
   1× `SINK_PUSH_FAILED`) and re-verifies the real hash chain via
   `AuditLogService.verify_chain()`. `chunk_events()` is also called
   standalone against the same event stream, confirming it independently
   reproduces the identical `[2, 2, 1]` batching the service itself
   produced.

**25/25 checks passed** (see `output.txt` for the full, unedited captured
run — every line is real stdout from the run above, not paraphrased).

## How to run

```
docker ps --format '{{.Names}}' | grep postgres   # confirm docker-postgres-1 is up
~/venv/bin/python3 poc/integration_sink_foundation/run_poc.py
```

No container other than the already-running `docker-postgres-1` is
touched or required. Every HTTP/TCP/UDP receiver is local, ephemeral, and
confirmed (independently, post-run) to leave nothing listening.

## Which of the roadmap's SS3 three stages was reached

**Test-stage only** — unit tests (mocked `httpx`/real local
sockets, per CLAUDE.md SS B.5) plus this real L1/L2 PoC against real local
stand-in receivers. This is the expected, legitimate state for a
foundation item per SS3's own framing — dev/prod compose wiring is
explicitly R2/R3/R4's own scope once a real named-vendor sink exists to
wire in (there is nothing target-specific to add to
`docker-compose.dev.yml`/`prod.yml` yet; R1 introduces no new service
dependency of its own — `httpx` was already a pinned dependency).

## What was NOT verified (explicitly out of scope, not silently skipped)

- **No live third-party SaaS SIEM/SOAR API was ever contacted** — hard
  boundary for this pass (roadmap SS1 invariant #9), not an oversight.
- **No named-vendor `DetectionEventMapper`** (Splunk HEC envelope, real
  CEF/LEEF field dictionary, Sentinel DCR-shaped columns) — R2/R3/R4's own
  scope, per the roadmap's own milestone breakdown. The two mappers built
  here (`GenericJsonStandInMapper`/`GenericCefLikeStandInMapper`) live
  **only** in `run_poc.py`, not in `src/`, specifically so they are never
  mistaken for a real vendor's actual wire contract.
- **`Elastic`'s real Bulk API per-item `result` field**, **Sentinel's real
  1MB/2GB-min Logs Ingestion ceilings**, **Splunk HEC's real
  ~800MB/5MB ceilings** — `max_batch_events`/`max_batch_bytes` are real,
  honest `None` (undocumented/unobserved) on the generic sinks built here;
  a concrete R2/R4 sink is responsible for setting its own real,
  vendor-verified numbers.
- **No route/playbook-action wiring** — mirrors H4's own identical
  precedent (`DetectionSinkPushService` is not wired into
  `dependencies.py`/`startup.py`/a `PlaybookAction`); deciding when a
  Detection should automatically be pushed to a sink is real, separate
  follow-up scope (R2–R4's own `SyncDetectionToSiemAction`-shaped actions),
  not incidental here.
- **No retry/backoff on a failed sink push** — a failed batch is reported
  loudly (raised, audited) and left for the caller's own retry semantics;
  no automatic retry loop was built speculatively here.
- **UDP's own weaker failure-detection property was not independently
  exercised as a "does NOT raise" positive test** (i.e. deliberately
  sending to a closed UDP port and confirming no exception) — the module
  docstring's own claim about this is accepted as accurately describing
  real UDP `sendto()` semantics (a well-established POSIX/asyncio
  property) rather than re-verified with its own dedicated scenario here;
  flagged so it isn't silently assumed covered by Scenario 5 (which is TCP
  only).
