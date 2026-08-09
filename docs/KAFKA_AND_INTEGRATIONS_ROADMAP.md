# KronOS → Streaming Resilience + EDR/SIEM/SOAR Integration Layer: Roadmap

**Status:** active plan, opened 2026-08-08 per direct project-owner request.
Supersedes nothing in `CLAUDE.md` or the now-closed
`docs/NEXTGEN_SOC_ROADMAP.md` (M0–M8) — every rule there (§A architecture,
§B standards, §E pipeline autonomy, §F verification-first, §G module
system) applies unchanged to every item below. This is a **new,
independent initiative**, not a continuation of the closed roadmap's own
milestone numbering (which stops at M8) — milestones here use a fresh
letter series (P onward) to avoid confusion with the closed doc's A–I.

**Design authority for this roadmap:** three real research passes
commissioned by the project owner 2026-08-08 (Kafka/streaming placement,
EDR/XDR/IDS source-integration landscape, SIEM/SOAR sink-integration
landscape) — full findings preserved in this conversation's history;
load-bearing conclusions restated here as §0 verified facts so a cold
agent doesn't need to re-derive them.

**Explicit, standing authorization (2026-08-08, project owner):** this
initiative may run for months across many autonomous wake-ups. Commit and
push verified work to `feat/nextgen-soc-cert-platform` as it lands — same
scope and same restrictions as the closed roadmap's own 2026-07-29
authorization (§5 below restates it in full so this document is
self-contained).

---

## 0. Verified starting facts (do not re-derive; re-verify only if suspect)

### Streaming resilience (Kafka/Redpanda question)

| Fact | Evidence |
|---|---|
| `StreamIngestAdapter` ABC (`src/adapter/queue/stream_ingest.py`) was already deliberately designed Kafka-swappable — "a new class implementing this same ABC, zero changes to any caller," per its own docstring | direct read |
| Redis Streams' consumer-group design (XREADGROUP/XPENDING/XAUTOCLAIM) already tolerates the failure modes it was built for (client crash, network partition, stuck consumer) — real-verified, `poc/stream_ingest_redis/` 22/22, `poc/stream_backpressure_dlq/` 24/24 | research pass, re-confirmed against the real PoC READMEs |
| Sealed batches (`BatchSealingService`) are durable via WORM MinIO + mandatory RFC3161 TSA + Postgres + Merkle root — **independent of Redis** once sealed. Redis's own durability only matters for the *unsealed backlog* window | `src/application/batch_sealing.py`, direct read |
| **The real, bounded gap**: single-node Redis's AOF-fsync loss window (`everysec` = up to ~1s) on a genuine hard crash (not a graceful restart) — bounded by `SealingTriggerPolicy`'s own short intervals, not unbounded | research pass |
| **`docker-compose.dev.yml`'s Redis has ZERO persistence configured** — no `--appendonly`, no `--save`, no named volume. `docker-compose.prod.yml`'s Redis correctly has `--appendonly yes` + a named volume. This is a bigger, more immediate, nearly-free-to-fix gap than anything Kafka would close | research pass, re-confirmed via direct compose-file read |
| Kafka 4.3.1 (current stable, June 2026, KRaft-only — ZooKeeper fully removed in the 4.x line) and Redpanda v26.2 (July 2026) both require a **minimum 3 nodes** for real HA/replication — there is no smaller real-HA topology for either | research pass, vendor docs |
| **Postgres and MinIO — the components that actually hold KronOS's durable custody guarantee — are themselves single-instance with no HA/replication configured anywhere in this repo.** Adding a 3-node Kafka/Redpanda cluster for the component *furthest downstream* of the real custody guarantee, while the components the guarantee actually depends on remain single-instance, is a real prioritization inconsistency | research pass, confirmed via compose-file grep |
| A `KafkaStreamIngestAdapter`'s "zero changes to any caller" promise would **not** actually hold fully: Kafka has no per-message ack (only cumulative offset commits — happens to still work for `BatchSealingService`'s whole-batch ack pattern), and **no real equivalent to `reclaim_stale()`/`XAUTOCLAIM`** (Kafka's redelivery is a full consumer-group rebalance, coarser-grained, no per-message idle tracking) | research pass |

**Decision, made from this research, do not relitigate without new evidence:**
**Kafka/Redpanda is NOT adopted in this initiative.** See Milestone P.

### Integration sources (EDR/XDR/IDS/SIEM → KronOS)

| Fact | Evidence |
|---|---|
| KronOS's real mTLS collector-ingest path (`src/application/collector_ingest.py`, `src/external/middleware/collector_mtls.py`) is *already* a generic webhook/push receiver — org/source identity from a verified X.509 SAN, dedup by content-hash, produces onto `StreamIngestAdapter` | direct read, already roadmap-D2-verified |
| Three real, dormant configs already exist in-repo but currently monitor **KronOS's own infrastructure**, not a customer's external SOC tooling: `docker/wazuh/` (pinned `wazuh-manager:5.1.0`/`wazuh-dashboard:5.1.0` — comment flags a real 5.0 data-destruction CVE, confirm 5.1.0 doesn't regress it before use), `docker/falco/` (`falcosecurity/falco-no-driver:0.38.2`), `docker/fluent-bit/` (`fluent/fluent-bit:3.1`, already tails KronOS logs → syslog/OpenSearch) | research pass, re-confirmed via direct compose-file read |
| Wazuh's real, documented real-time outbound mechanism is `wazuh-integratord` — a webhook push driven by one `<integration>` block in `ossec.conf` (`hook_url`, `api_key`, `alert_format json`) | research pass, `documentation.wazuh.com` |
| Suricata/Zeek have **no separate live-alert API** — `eve.json`/Zeek JSON logs *are* the live stream; real-time forwarding is a log-shipper tailing the file (exactly what this repo's own `fluent-bit.conf` already does for KronOS's own logs) | research pass |
| Microsoft Defender: the **legacy Alerts REST API is retiring Oct 15 2026** — the current, non-deprecating mechanism is Microsoft Graph Security API `alerts_v2`/`incidents`, OAuth2 client-credentials via Entra ID app registration | research pass, `learn.microsoft.com` |
| CrowdStrike Event Streams API needs a **long-lived, kept-alive HTTP connection** requiring a supervised background worker (not a simple poll-on-schedule) — a materially different, heavier integration shape than the other sources | research pass |
| STIX/TAXII 2.1 is fundamentally a CTI-sharing protocol (indicators/sightings), not a per-vendor "export this product's own alerts" mechanism — no evidence any of the researched EDR/SIEM tools expose their own detections via TAXII for this use case | research pass |

**Prioritized build order (research recommendation, adopted):** **Wazuh →
Suricata/Zeek live-tail → Microsoft Defender** (Graph `alerts_v2`,
poll+cursor). CrowdStrike/SentinelOne are real, valid next-wave candidates
once the poll+cursor and long-lived-streaming worker patterns both exist.

### Integration sinks (KronOS → SIEM/SOAR)

| Fact | Evidence |
|---|---|
| `TicketingSystem` ABC (`src/adapter/ticketing/ticketing_system.py`, H4) is the idiom to mirror — small, typed, no raw passthrough — but its uniform "title/description/severity/metadata" shape does **not** generalize to SIEM sinks, whose event schemas are all structurally different | direct read + research pass |
| Splunk HEC: `Authorization: Splunk <token>`, JSON envelope (`{"time","host","source","sourcetype","index","event"}`), real batching support, real size limits (`max_content_length` ~800MB default, `maxEventSize` 5MB/event) | research pass, `help.splunk.com` |
| Microsoft Sentinel: **legacy HTTP Data Collector API's ingestion ends Sept 14 2026** — current mechanism is the Logs Ingestion API against a pre-provisioned custom table + Data Collection Rule (DCR) + Data Collection Endpoint (DCE), OAuth2 client-credentials, 1MB/call and 2GB/min per-DCR limits | research pass, `learn.microsoft.com` |
| IBM QRadar has **no general-purpose "create event" REST API** — real outbound mechanisms are syslog+LEEF 2.0 or its HTTP Receiver protocol (own inbound listener, supports mTLS) | research pass |
| CEF-over-syslog is the true vendor-neutral universal fallback — no application-layer auth, fire-and-forget (weaker delivery guarantee than an HTTP 2xx+body ack) | research pass |
| TAXII 2.1 is **pull-only in this version** — "Channels" (pub/sub) are reserved but explicitly unspecified. A KronOS-as-TAXII-producer means KronOS *hosting* a collection for others to poll, not KronOS pushing — structurally inverted from every other sink here | research pass, OASIS TAXII 2.1 spec |

**Prioritized build order (research recommendation, adopted):** **Splunk
HEC → generic CEF-over-syslog → Microsoft Sentinel** (Logs Ingestion API,
proves the OAuth2 + rigid-pre-provisioned-schema case). QRadar/XSOAR/TheHive
are real fourth-tier candidates once the mapper abstraction exists. TAXII
is a separate, later "KronOS hosts a collection" initiative, not part of
the push-sink ABC.

---

## 1. Cross-cutting invariants (reused verbatim from the closed roadmap's §1 — still binding)

1. OOP/composition-first (§A.1/A.4) — every new capability is ABC +
   concrete implementations behind it, registered via DI. Adding the next
   source/sink connector must need ZERO edits to existing classes.
2. Layering (§A.3) — zero framework imports in `src/domain/`/`src/application/`.
3. Tenant isolation computed, never supplied — `org_id` always from the
   authenticated `TenantContext`/verified mTLS cert, never from an
   external tool's own payload (mirrors the existing collector-ingest
   invariant exactly — a lying external SIEM must not be able to write
   into another tenant's data any more than a lying internal collector can).
4. Audit every mutation.
5. Derived opinions never mutate primary evidence.
6. Replayability for anything court-facing.
7. Verification-first (§F) — no item is "done" without a real run against
   the real dependency (or a realistic local stand-in for tools with no
   free/self-hostable real instance — see §4's honesty rule) at the pinned
   version, captured output committed.
8. Fail loudly, never silently.
9. **New for this initiative: no live third-party SaaS call, ever, from
   any PoC or test** (H4's own established boundary — mirrored exactly).
   Every connector's real-dependency proof uses a real self-hostable
   instance (Wazuh, TheHive, a real local Splunk/QRadar dev image if one
   exists) or a real local stand-in receiver (mirrors
   `poc/detection_ticket_integration/`'s own real local HTTP receiver
   pattern) — never a live CrowdStrike/SentinelOne/Sentinel/Splunk Cloud
   account. If a tool has no realistic local/free-tier option (e.g.
   CrowdStrike, SentinelOne — both are commercial SaaS-only), the
   connector's PoC must say so honestly and verify against the *documented
   real API contract* (a real recorded/replayed response fixture, clearly
   labeled as such) rather than either skipping verification or reaching
   out live.

## 2. The layered proof discipline (reused verbatim from the closed roadmap's §2)

```
poc/
├── <component>/                    L1  component alone vs. its real dependency
├── <component_a>_<component_b>/    L2  two components genuinely linked
├── chain_<flow>/                   L3  3+ components, one user-visible flow
└── global_<scenario>/              L4  whole platform, realistic scenario
```

## 3. Environment progression: test → dev → prod (new for this initiative, per explicit project-owner instruction)

Every connector in Milestones Q and R follows this exact three-stage gate,
in order — do not skip a stage:

1. **Test stage.** Unit tests (mocked external dependency, per CLAUDE.md
   §B.5) + the real L1/L2 PoC against a real local instance or stand-in
   receiver (§1 invariant 9), run manually against whatever's already
   running (`docker-compose.dev.yml` today, since `docker-compose.test.yml`
   itself has the known OpenSearch-security-disabled/no-TLS gap the
   closed roadmap's I1 already found and deferred — do not assume that gap
   is closed unless a later item in this doc says so). This stage proves
   the connector's *logic* is correct.
2. **Dev stage.** The connector is wired into `docker-compose.dev.yml`
   for real (new service if it needs one, e.g. a real self-hosted Wazuh
   manager for the source connector's own dev verification; env vars for
   API keys/tokens sourced from `.env`, never hardcoded) and run against
   the *actual* long-running dev stack this whole multi-month initiative
   has been using — not a fresh throwaway container per PoC. This stage
   proves the connector survives *this repo's own real deployment
   topology* (real nginx/TLS, real Keycloak-issued tenant context, real
   concurrent load from whatever else is using the dev stack).
3. **Prod stage.** `docker-compose.prod.yml` gets the equivalent wiring
   (mirrors I3's own prod-parity precedent exactly — check for drift
   between dev's and prod's env-var names/defaults the same way I3 found
   real drift for ClamAV). No live prod deployment is expected to exist to
   test against in this sandbox — "prod stage" here means the *compose
   file and its own `docker compose config` validation* are correct and
   parity-checked against dev, mirroring I3's own verification bar
   (`helm lint`/`docker compose config`, not a live cluster).

A connector's STATUS block (§6) must say explicitly which of these three
stages it reached, honestly — "test-stage only, dev/prod wiring is
follow-up" is a legitimate, expected intermediate state for most items,
not a failure.

## 4. Extensibility design (the two new ABCs this initiative builds)

Neither is designed in full here — that is Milestone Q1's/R1's own
dispatched work, per this doc's own "PoC before commitment to a shape"
discipline. What's already decided, from the research:

- **`IntegrationSource`** needs to support (not necessarily all in v1, but
  the shape must not preclude): inbound webhook/push (reuse the existing
  mTLS collector-ingest transport where possible), poll-on-schedule with a
  durable per-source cursor/watermark (new state KronOS doesn't have
  today), and — for CrowdStrike-class tools only, deferred past this
  doc's initial milestones — a long-lived supervised streaming worker.
  Pluggable auth: mTLS (already have it), static API key, OAuth2
  client-credentials (parameterized by token endpoint + scope, not
  hardcoded to one IdP — CrowdStrike's and Microsoft's OAuth servers
  differ). Per-source schema mapping mirrors `SuricataEveParser`'s own
  real/ECS-where-possible, namespaced-passthrough-otherwise idiom, landing
  in `TimelineRecord` (event-shaped) or `StructuredArtifact`
  (tree/graph-shaped, e.g. Defender's `evidence[]` entity list).
- **`IntegrationSink`** needs a pluggable `SinkAuthenticator` collaborator
  (static token, OAuth2 client-credentials, API-key tuple, mTLS — `httpx`
  already supports `cert=`/`verify=` for the mTLS case), a
  `push_events()`-shaped method for the HTTP-JSON family (Splunk HEC,
  Sentinel, QRadar HTTP Receiver, Elastic Bulk, XSOAR, TheHive), a
  **separate** code path for CEF/LEEF-over-syslog (weaker delivery
  guarantee — "the socket write succeeded," not a 2xx+body — must be
  modeled honestly as such, not papered over as equivalent to an HTTP ack),
  and a per-target `DetectionEventMapper` collaborator (schema mapping is
  the most heterogeneous part — do not let it leak into
  `SyncDetectionTicketAction`-style inline composition, which doesn't
  scale past one uniform shape).
- Per CLAUDE.md §G.1's own precedent against parallel class hierarchies:
  if `IntegrationSource` turns out to fit `ForensicParser`'s existing
  shape closely enough (a "does this source produce discrete timestamped
  events" question), the dispatched Q1 agent must justify a *new* ABC
  rather than extending the existing one — don't assume a new hierarchy is
  correct just because this doc sketches one.

## 5. Execution policy (reused, restated in full so this doc is self-contained)

- Sequence anything sharing a file surface; parallelize only disjoint
  surfaces (e.g. Q-series source connectors and R-series sink connectors
  touch almost entirely disjoint files after Q1/R1 land — safe to
  parallelize once both ABCs exist).
- Gates are blocking — none formally declared yet in this doc; Q1 and R1
  (the two foundational ABC designs) are *de facto* gates for everything
  in their own series.
- Orchestrator holds the dev stack — agents must not `down -v` it;
  restarts coordinated.
- **Commit/push authorization (2026-08-08, explicit, standing for this
  initiative)**: same scope/restrictions as the closed roadmap's own
  2026-07-29 authorization — commit and push verified work to
  `feat/nextgen-soc-cert-platform` as it lands, since this may span months
  unattended. Only commit real-PoC-verified work, never a subagent's
  unverified claim (this bit caught two real fabricated numbers in the
  closed roadmap's own final gate — keep independently re-verifying test
  counts/isolation-check counts/etc. before trusting a self-report). Never
  force-push, never touch `main` or any other branch, never rewrite
  history beyond the immediately-preceding commit in the same turn.
- Model policy: orchestrator runs Sonnet 5 high effort; subagents run
  cheaper (Sonnet 5 low/medium effort for well-scoped connector work,
  Haiku medium effort for small/mechanical tasks). No Opus/high-effort
  subagents even for the Q1/R1 gates — those get a more careful, explicit
  brief instead.
- **Standing lesson from the closed roadmap, restated because it will
  recur here too**: if a dispatched subagent leaves a real background
  process running when its own turn ends, do not redispatch a duplicate —
  wait for it (`Bash run_in_background` wait-loop), read the real output
  yourself, finish packaging/verification/commit directly. This was the
  single most common failure-recovery pattern across H3/I1/I4/the quota
  feature.
- Continuation mechanism: harness `CronCreate`, 5-hour cadence, per
  explicit 2026-08-08 request — session-only, auto-expires after 7 days,
  re-arm before it lapses if the initiative is still running (exactly the
  same caveat that applied to the closed roadmap's own cron).

## 6. Agent brief template (reused verbatim from the closed roadmap's §4)

```
ROLE: You own <ID> · <title> for KronOS.
Repo: /home/reca/Claude/Kronos/KronOS_template   Branch: feat/nextgen-soc-cert-platform

READ FIRST: CLAUDE.md §A/§B/§F/§G as applicable. Then this doc's §0
(verified facts), §1 (invariants), §2 (proof layers), §3 (test->dev->prod
gating), §4 (ABC design constraints already decided).

OBJECTIVE (what, and why): <...>

YOU DESIGN THE SOLUTION within §4's constraints. Research the real current
docs for the pinned version. If you conclude part of this doc is wrong or
a better path exists, say so with evidence.

PINNED VERSIONS: <...> (verified by orchestrator; re-verify if suspect)

PROOF BAR: layer <L1-L4>, at poc/<dir>/, real dependency or real local
stand-in per §1 invariant 9 (never a live third-party SaaS). Real captured
output committed. State explicitly which of §3's three stages (test/dev/
prod) you reached.

DELIVERABLES: poc/<dir>/, src/ implementation, tests, full suite green,
this doc's own item updated with a STATUS block.

DO NOT: commit/push (orchestrator does, after review). Touch containers
you didn't create. Call any live third-party SaaS API.
```

---

## Milestone P — Streaming resilience

### P1 · Fix dev compose's missing Redis persistence — L1
**Objective.** `docker-compose.dev.yml`'s Redis has zero persistence
configured (no `--appendonly`, no `--save`, no volume) — confirmed real,
immediate, higher-value, near-zero-cost fix versus adopting Kafka. Mirror
`docker-compose.prod.yml`'s already-correct `--appendonly yes` + named
volume.
**Depends on:** nothing.

### P2 · Document the Kafka non-adoption decision + trigger conditions — L1 (docs only)
**Objective.** Already done by this doc's own §0 — no separate dispatch
needed. Revisit only if one of §0's named trigger conditions becomes real.

---

## Milestone Q — Integration sources (EDR/XDR/IDS/SIEM → KronOS)

### Q1 · `IntegrationSource` foundation — L1/L2
**Objective.** Design and build the ABC + registry per §4's constraints,
proven against ONE real concrete source end-to-end before any other
source connector starts (a gate for Q2–Q4, not parallelizable with them).
**Depends on:** nothing.

**STATUS (2026-08-09): foundation complete, test-stage only, gate open for Q2–Q4.**

Built across two sessions (a prior session's own work on the domain value
objects + ABC/registry survived a session cutoff and is unchanged here;
this session added everything else in the "still needed" list from that
session's own handoff).

- **ABC-vs-`ForensicParser` decision, confirmed, not revised.** The prior
  session's own argument in `src/application/integration_source.py`'s
  module docstring holds: `ForensicParser` requires an `Evidence` object
  (file, hash, case) that structurally does not exist for a live external
  alert, `ParserRegistry` dispatches by content-sniffing which is
  meaningless for a source with no bytes yet at dispatch time, and a
  durable poll cursor + pluggable inbound auth are genuinely new state
  `ForensicParser` has no notion of. Re-verified by reading the real
  existing pipeline end to end (`collector_ingest.py` →
  `stream_ingest.py` → `batch_sealing.py` → `stream_normalization.py`)
  before continuing, per the brief's instruction not to assume the prior
  reasoning was correct just because it existed — it is.
- **What was already there (prior session, verified correct against this
  design):** `src/domain/integration_source.py` (`IntegrationDeliveryMode`,
  `IntegrationSourceIdentity`, `SourceCursor`), `src/application/integration_source.py`
  (`IntegrationSource` ABC + `IntegrationSourceRegistry` + `PollFetchResult`
  + `IntegrationSourceError`), and 3 new `AuditEventType` members in
  `src/domain/audit.py` (`integration_source.push_ingested`/
  `poll_completed`/`poll_failed`).
- **What this session added:**
  - `src/adapter/repository/source_cursor.py` +
    `src/adapter/repository/postgres_source_cursor.py` — `SourceCursorRepository`
    ABC + `InMemorySourceCursorRepository` + `PostgresSourceCursorRepository`,
    mirroring `OrgQuotaRepository`/`postgres_quota.py`'s own pattern exactly.
  - `src/external/middleware/integration_source_auth.py` — pluggable auth:
    `identity_from_collector_identity()` (mTLS reuse — adapts the existing,
    already-verified `CollectorIdentity` from the D2 collector transport,
    no reimplementation), `StaticApiKeyInboundAuthenticator` (new inbound
    transport), and for POLL's outbound side: `ApiKeyOutboundAuthStrategy`,
    `MtlsOutboundAuthStrategy`, `OAuth2ClientCredentialsOutboundAuthStrategy`
    (RFC 6749 §4.4 client-credentials grant, parameterized by token
    endpoint/scope, in-process token caching with a 30s expiry margin).
  - `src/application/integration_source_ingest.py` — `IntegrationSourceIngestService`:
    the real orchestration (backpressure → SHA-256-over-raw-bytes dedup →
    produce onto the existing D1 `StreamIngestAdapter` → persist cursor on
    a non-empty poll page → one audit event per real call), reusing the
    existing stream transport rather than inventing a second one.
  - `src/external/integration_sources/generic_webhook.py` (PUSH) and
    `generic_poll.py` (POLL) — the two concrete stand-ins the brief
    required, not a named vendor (Q2/Q4 do that): a batch-envelope-aware
    generic webhook splitter, and a generic `cursor`/`next_cursor`
    poll client.
  - `src/external/routes/integration_source_push.py`, mounted on the main
    app (`fastapi_app.py`) — unlike the mTLS collector path, a static-API-
    key-authenticated PUSH source needs no special TLS listener, so it
    lives on the main app with its own DI wiring in `dependencies.py`
    (`get_integration_source_registry`/`get_source_cursor_repository`/
    `get_inbound_source_authenticator`/`get_integration_source_ingest_service`,
    plus `configure_static_api_key_provisioning()` as the real startup hook
    — not yet called from `startup.py`, see stage note below).
- **Real PoC (`poc/integration_source_foundation/`), both required shapes,
  real captured output (see that dir's own `output.txt`/`README.md`):**
  (a) a real `uvicorn` server hosting the real FastAPI route, hit by a real
  `httpx` client over a real TCP socket — proved accept/dedup/batch-split/
  wrong-key-401/wrong-source-type-403/stream-length/audit-count all for
  real; (b) a real stdlib `ThreadingHTTPServer` standing in for an external
  poll API, polled by the real `GenericPollSource` across 3 real cycles —
  proved cursor persistence, empty-page-does-not-advance, and a real 401
  surfacing as a real `IntegrationSourceError`; (c) an extra, not-originally-
  required check: `PostgresSourceCursorRepository` against the real,
  already-running shared dev Postgres (create/get/upsert/on-conflict-update,
  own row cleaned up afterward).
- **Tests:** 60 new unit tests added (`tests/unit/adapter/test_source_cursor_repository.py`,
  `tests/unit/application/test_integration_source.py`,
  `tests/unit/application/test_integration_source_ingest.py`,
  `tests/unit/middleware/test_integration_source_auth.py`,
  `tests/unit/integration_sources/test_generic_webhook.py`,
  `tests/unit/integration_sources/test_generic_poll.py`,
  `tests/unit/test_routes_integration_source_push.py`), mocking only
  external dependencies (stream adapter, dedup checker, cursor repository,
  audit log, httpx client) per CLAUDE.md §B.5. Full suite re-run: **1405
  passed, 1 skipped** (1345 passed/1 skipped baseline + these 60, zero
  regressions). `mypy src`: **29 errors**, identical count/file set to the
  documented pre-existing baseline — zero new errors introduced.
- **Stage reached (§3): test-stage only**, honestly incomplete on purpose.
  Dev-stage (real per-org API-key provisioning sourced from Vault/env and
  wired into `startup.py` via the already-built
  `configure_static_api_key_provisioning()` hook) and prod-stage
  (`docker-compose.prod.yml` parity check) are real follow-up work, not
  done here — no concrete named vendor exists yet to provision real keys
  for, so building that wiring now would be speculative rather than
  verified.
- **Known, pre-existing gap surfaced, not fixed (out of Q1 scope, flagged
  for Q4):** `StreamSourceNormalizer.normalize()` can only return a
  `NormalizedStreamEvent` (timeline-shaped) — no artifact-shaped
  equivalent exists yet. A future poll source whose real payload is
  artifact-shaped (Microsoft Defender's `evidence[]` entity list) cannot
  be fully wired to durable storage via the existing normalization
  pipeline until that gap closes. Also: `CollectorIngestService` (the
  existing D2 collector path this session's `IntegrationSourceIngestService`
  deliberately mirrors) does not itself write an audit event per batch —
  an existing, independent gap, not something this pass's own service
  needed to inherit (it audits every call, by design).
- **Not verified, and why:** live OAuth2 client-credentials against a real
  IdP (Entra ID/Okta/etc.) — no such tenant exists in this sandbox and
  reaching one would risk touching a real external account; the strategy
  is instead verified against a mocked token endpoint in
  `tests/unit/middleware/test_integration_source_auth.py` (real RFC 6749
  §4.4 request shape/caching/expiry logic exercised, the actual token
  server's own behavior is not). Real mTLS-authenticated PUSH end-to-end
  (reusing the D2 dual-listener) was not re-run here since D2's own mTLS
  transport is already independently verified in
  `poc/collector_ingest_mtls/` — only the one-line identity adapter
  (`identity_from_collector_identity`) is new and is unit-tested.

### Q2 · Wazuh source connector — L2
**Objective.** Real `wazuh-integratord` webhook → KronOS collector-ingest,
end to end, against a real self-hosted Wazuh manager (the repo's own
dormant `docker/wazuh/` config, pinned `5.1.0` — verify the 5.0
data-destruction CVE doesn't recur in 5.1.0 before trusting it for this).
**Depends on:** Q1.

**STATUS (2026-08-09): DONE — test-stage only, real L2 end-to-end flow
confirmed live (twice: the building session's own run, plus an
independent re-run this pass to remove doubt after a session cutoff).**

- **Pinned-version correction, found before building anything (CLAUDE.md
  §F).** This roadmap item's own `5.1.0` pin does not exist — verified
  against the real Docker Hub tag list (65 tags, newest `5.0.0-beta4`) and
  the real Wazuh GitHub Releases API (newest stable `v4.14.7`). The
  referenced CVE (GHSA-ff9g-85jq-r3g3, real, CVSS-10, in 5.0's
  `inventory_sync`) is fixed in `5.0.0-beta3`, not "5.1" — there is no 5.1
  line. Separately, and decisive for this connector: a real, direct
  inspection of `wazuh/wazuh-manager:5.0.0-beta4` found Wazuh 5.x has
  already removed `wazuh-integratord`/`ossec.conf` entirely (renamed
  config root, renamed control binary, no integratord binary anywhere in
  the image; outbound alerting moved to an undocumented, disabled-by-default
  YAML "engine outputs" mechanism with no 5.x docs published yet). Built and
  verified against `wazuh/wazuh-manager:4.14.7` (current real stable,
  predates the CVE'd subsystem entirely) instead. Flagged, not silently
  applied: `docker/wazuh/docker-compose.wazuh.yml` itself still pins the
  nonexistent `5.1.0` — needs the same fix, left to whoever owns that file
  since it's dormant SIEM-side infra config outside this connector's scope.
- **Built:** `src/external/integration_sources/wazuh.py` (`WazuhPushSource`
  — validates a real Wazuh alert JSON shape, no batch-envelope unwrapping
  since Wazuh's real wire shape has none), `WazuhAlertNormalizer` added to
  `src/application/stream_source_registry.py` (ECS mapping, field reference
  verified against a real captured alert, not vendor docs alone — ISO-8601
  timestamp, `full_log`→`message` with `rule.description` fallback,
  `authentication_failed`/`_success` rule-group promotion to ECS
  `event.category`, `agent.name`→host vs `manager.name` kept separate,
  everything else preserved under `extra["wazuh.*"]`), registered in
  `src/external/dependencies.py` (`get_integration_source_registry()` +
  `reset_dependencies()`).
- **Real mechanism confirmed (corrects the roadmap's own §0 summary
  slightly):** the documented `hook_url`/`api_key`/`alert_format json`
  auto-POST only applies to Wazuh's five built-in vendor integration names
  (slack/pagerduty/shuffle/virustotal/maltiverse) — confirmed by reading
  those scripts' own source inside the running `4.14.7` container. A
  `custom-*` name requires supplying the script yourself;
  `poc/integration_source_wazuh/custom-kronos{,.py}` is that script (real
  argv contract `[alert_file, api_key, hook_url, options_file, debug]`
  confirmed from the bundled `slack.py`'s own `WEBHOOK_INDEX = 3`), and it
  performs the real HTTP POST with `X-KronOS-Source-Key` header.
- **Real PoC (`poc/integration_source_wazuh/`), real captured output,
  run twice:** a real `kronos-poc-wazuh-manager` (`wazuh/wazuh-manager:4.14.7`)
  with a real `<integration>`/`<localfile>` block in `ossec.conf`, a real
  local `sshd` failed-login syslog line appended to trigger the manager's
  own default ruleset (rule 5710, real MITRE ATT&CK mapping), a real
  `kronos-poc-wazuh-receiver` (real KronOS FastAPI app + real
  `WazuhPushSource` + real `IntegrationSourceIngestService`, PoC-tier
  in-memory stream/dedup/audit doubles — same bar Q1's own PoC established).
  Both runs captured: (a) a real connection-refused/DNS failure when
  integratord tried to POST before the receiver container existed, proving
  the trigger is real and not rigged; (b) a real `202 Accepted` once the
  receiver came up, with `accepted=True, duplicate=False`, a real produced
  stream entry, and a real `integration_source.push_ingested` audit event.
  This pass's independent re-run used its own distinct alert content
  (`testverify`/`192.0.2.55` before the receiver existed, `reverify`/
  `198.51.100.222` after) rather than replaying the original captured
  bytes, specifically so the re-run couldn't be confused with re-displaying
  stale output — full transcript in `poc/integration_source_wazuh/output.txt`
  (original session) plus this pass's own terminal history (summarized in
  the PR/handoff notes, not re-appended to `output.txt` to avoid conflating
  two sessions' raw captures in one file).
- **Tests:** `tests/unit/integration_sources/test_wazuh.py` (8 tests,
  including one using the exact real alert body captured from the live
  PoC) + 9 new `WazuhAlertNormalizer` tests added to
  `tests/unit/application/test_stream_source_registry.py`. Full suite,
  before/after via `git stash -u`: baseline (without this connector) **1593
  passed, 1 skipped**; with this connector **1610 passed, 1 skipped** — the
  exact +17 new tests, zero regressions. `mypy src`: **29 errors**,
  identical count/file set to the documented baseline, zero new errors.
  `ruff check`/`black --check` on every touched file (src + tests + poc):
  clean (fixed a few real gaps found this pass — an unused import and
  import-block ordering in the new PoC receiver script and in
  `dependencies.py`'s import block, plus 4 real `E501` long-line violations
  in the PoC script — none pre-existing-baseline violations, all introduced
  by this connector's own new code, now fixed).
- **Stage reached (§3): test-stage only**, honestly incomplete on purpose,
  matching Q1's own precedent: no `docker-compose.dev.yml` service entry
  for a real dev-stack Wazuh manager, no real `StaticApiKeyProvisioning`
  wired into `startup.py`, no `docker-compose.prod.yml` parity check. Real
  follow-up work — the connector's logic is proven, its deployment wiring
  is not yet.
- **Honesty notes:** only PUSH exercised (Wazuh's real mechanism has no
  poll shape); in-memory stream/dedup/audit doubles in the PoC receiver,
  not real Redis/Postgres (those backends are independently verified
  elsewhere, re-proving them here would test Redis, not this connector);
  only one alert shape (`sshd`/rule 5710) forwarded live end-to-end — the
  normalizer's handling of a structurally different alert (an SCA summary
  with no `full_log`/`data.srcuser`/`data.srcip`) is verified in the real
  unit tests, not in the live PoC; `docker/wazuh/docker-compose.wazuh.yml`'s
  own wrong version pin was not fixed here (flagged above, out of this
  connector module's scope).
- **Docker cleanup:** all three `kronos-poc-wazuh-*` resources (manager,
  receiver, network) created by both runs were torn down
  (`docker rm -f`/`docker network rm`) — confirmed via `docker ps -a`/
  `docker network ls` after cleanup; no other container on the host (the
  shared long-running dev stack, `portainer_agent`, or a concurrent
  session's own `kronos-poc-splunk-hec`) was touched.

### Q3 · Suricata/Zeek live-tail source connector — L2
**Objective.** Real log-shipper (fluent-bit, reusing the repo's own
existing config pattern) tailing a real `eve.json`/Zeek JSON log, forwarding
via the same collector-ingest path, mapped via the same ECS logic
`SuricataEveParser` already proved for the batch-file case.
**Depends on:** Q1.

**STATUS (2026-08-09): DONE — test-stage only (expected, see §3).** Built
across two dispatches (an initial pass that hit a real session cutoff
mid-flight with the connector code/tests/PoC scripts/captured output already
on disk, then a delta-aware verification pass that read every file the first
pass had already written before touching anything, then independently
re-derived every proof point rather than trusting the first pass's own
numbers).

- **Shape chosen:** two concrete `IntegrationSource` PUSH classes,
  `SuricataEvePushSource` (`source_type="suricata-eve"`) and
  `ZeekJsonPushSource` (`source_type="zeek-conn-log"`), sharing real,
  verified NDJSON-splitting behavior via a private common base
  (`_TailedNdjsonPushSource`) and differing only in per-line structural
  validation — mirrors `ZipArchiveParser`/`PlasoParser`'s own precedent of
  one shared algorithm with format-specific validation on top, not a
  parallel ABC hierarchy. `SuricataEveStreamNormalizer` reuses
  `SuricataEveParser`'s already-proven `_ECS_BY_EVENT_TYPE`/`_build_message`/
  `_build_extra` mapping by import rather than re-deriving it; `ZeekJsonPushSource`
  deliberately provisions `source_id="zeek-conn-log"` so it resolves to the
  already-existing, already-proven `ZeekConnLogNormalizer` with zero new
  normalizer code. Both registered in `src/external/dependencies.py`
  (`get_integration_source_registry()`/`reset_dependencies()`), unconditionally,
  the same way `WazuhPushSource` already is.
- **Real gap found and flagged (CLAUDE.md SS F), not fixed out-of-scope:**
  this repo's own `docker/fluent-bit/fluent-bit.conf` (dev-stack config for
  KronOS's own logs) sets `Parser json` on every `tail` input but never sets
  `Parsers_File` in `[SERVICE]` — a real `fluent/fluent-bit:3.1` container
  with that config logs `parser 'json' is not registered` at boot and
  silently never JSON-parses that input, meaning that file has almost
  certainly never actually JSON-parsed anything at runtime. Fixed in this
  PoC's own throwaway `fluent-bit.conf` (adding the missing directive);
  **not** fixed in the dormant `docker/fluent-bit/fluent-bit.conf` itself —
  flagged for the orchestrator to route to that file's owner, mirroring Q2's
  own identical precedent for `docker/wazuh/docker-compose.wazuh.yml`'s
  wrong version pin.
- **Real wire format captured, not assumed (fluent-bit's own `http`-output
  docs don't clearly specify it):** `fluent/fluent-bit:3.1`'s `http` output
  with `Format json_lines` sends `Content-Type: application/x-ndjson`, one
  JSON object per originally-tailed line, fluent-bit's own ingestion-time
  `date` field prepended to each object, and multiple records from one
  flush window concatenated as multiple NDJSON lines in a single POST body
  (not a JSON array, not separate requests) — directly informed
  `_TailedNdjsonPushSource.parse_push_event`'s split-on-`\n` implementation.
- **Real end-to-end run:** real `fluent/fluent-bit:3.1` (digest
  `sha256:e72c08...f293e1`, reports `v3.1.10`) tailing a real Suricata alert
  line (byte-for-byte from `tests/fixtures/samples/real/suricata/eve.json`,
  `flow_id=1676750115612680`) and a real-schema Zeek `conn.log` line
  (fields independently verified against Zeek's own `Conn::Info` source),
  both appended live to initially-empty files while fluent-bit was already
  watching via inotify (genuine live-tail, not backfill) — forwarded via two
  real `tail`+`http` routes to a real KronOS FastAPI app
  (`kronos-poc-suricatazeek-receiver` running real
  `SuricataEvePushSource`/`ZeekJsonPushSource` + real
  `IntegrationSourceIngestService`, PoC-tier in-memory stream/dedup/audit
  doubles — same bar Q1/Q2 established). Both real pushes captured with
  real `HTTP status=202`, `accepted=True, duplicate=False`, real produced
  stream entries, and real `integration_source.push_ingested` audit events —
  full transcript in `poc/integration_source_suricata_zeek/output.txt`.
  Cleanup confirmed via `docker ps -a`/`docker network ls` both immediately
  after the original run and again independently at the start of this
  verification pass — no `kronos-poc-suricata*`/`kronos-poc-fluentbit*`
  resource remains, no other container touched.
- **Tests:** `tests/unit/integration_sources/test_suricata_zeek.py`, 24
  tests covering both push sources' NDJSON-splitting/validation (real 6-line
  Suricata fixture reuse, fluent-bit's own observed `date`-field tolerance,
  flow_id-less `stats` events, partial-batch fail-loudly), the reused-mapping
  normalizer (all six real fixture event_types), and registry wiring. Full
  suite, **independently re-derived this verification pass** via a fresh
  `git stash -u`/pop (not trusted from the first pass's own captured
  numbers, which reflected an earlier commit): baseline **1647 passed, 1
  skipped**; with this connector **1671 passed, 1 skipped** — exactly the
  +24 new tests, zero regressions. `mypy src`: **29 errors**, identical
  count to Q2's own documented baseline, zero in either touched file.
  `ruff check`/`black --check` on every touched file (src + tests + poc):
  this verification pass found and fixed two real gaps introduced by the
  first pass — an `E501` long line in `suricata_zeek.py`'s module docstring
  and an unsorted import block in the test file — clean after.
- **Stage reached (§3): test-stage only**, honestly incomplete on purpose,
  matching Q1/Q2's own precedent: no `docker-compose.dev.yml` service entry
  for a real dev-stack fluent-bit-tailing-Suricata/Zeek deployment, no real
  `StaticApiKeyProvisioning` wired into `startup.py`.
- **Honesty notes:** only PUSH exercised (no poll shape for either source);
  in-memory stream/dedup/audit doubles in the PoC receiver, not real
  Redis/Postgres; no real Suricata/Zeek binary run (fluent-bit tailed a
  plain file containing one real and one realistic-but-hand-built line, not
  a live process's own writes); only one line per source forwarded live
  end-to-end (all six real Suricata event_types verified via direct
  normalizer calls and unit tests, not the live pipeline); only `conn.log`
  built for Zeek (`notice.log`/others are a new `source_type` on the same
  shared base, not new work); `docker/fluent-bit/fluent-bit.conf`'s own
  `Parsers_File` gap not fixed here (flagged above, out of this connector
  module's scope).
- **Docker cleanup:** all `kronos-poc-fluentbit-discovery`,
  `kronos-poc-stub-receiver`, `kronos-poc-suricatazeek-receiver`,
  `kronos-poc-suricatazeek-fluentbit`, and `kronos-poc-suricata-net`
  resources torn down and reconfirmed absent (`docker ps -a`/
  `docker network ls`) at the end of this verification pass; no other host
  container (shared dev stack, `portainer_agent`, unrelated concurrent
  sessions) was touched.

### Q4 · Microsoft Defender source connector — L2
**Objective.** Real Graph Security API `alerts_v2` poll-with-cursor
(`$filter=lastUpdateTime gt ...`), OAuth2 client-credentials via a real
Entra ID app registration if a real tenant is available for testing, or a
real recorded/replayed response fixture per §1 invariant 9 if not —
proves the poll+durable-cursor pattern before CrowdStrike's harder
long-lived-stream model is attempted.
**Depends on:** Q1.

**STATUS (2026-08-09): DONE — test-stage only, real fixture-based L2
end-to-end poll+cursor flow confirmed live (real OAuth2 token exchange,
real `@odata.nextLink` pagination on both poll cycles, real Postgres
cursor persistence, real `$filter` enforcement).**

- **Real tenant check performed, negative.** Searched this repo for
  `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/Entra-related config in every
  `*.py`/`*.env*`/`*.yml`/`*.yaml`/`*.toml` file and this process's own
  environment (`env | grep -i azure`) — no real Entra ID tenant or app
  registration exists anywhere in this sandbox. Per §1 invariant 9, built
  and verified against a real local HTTP stand-in server matching
  Microsoft's own current, real, documented schema instead — never a live
  call to `graph.microsoft.com`/`login.microsoftonline.com`.
- **Real docs fetched and verified against (2026-08-09), not assumed:**
  `learn.microsoft.com/en-us/graph/api/resources/security-alert` (full
  `alert` resource property table + worked JSON example),
  `learn.microsoft.com/en-us/graph/api/security-list-alerts_v2` (the
  `$filter`-eligible property list + `@odata.nextLink` pagination
  statement), `learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow`
  (the real `POST /{tenant}/oauth2/v2.0/token` request/response contract),
  `learn.microsoft.com/en-us/graph/paging` (the real "use the whole
  `@odata.nextLink` URL verbatim" contract).
- **Real, reportable correction found via this research (CLAUDE.md §F —
  mirrors Q2's Wazuh version correction and Q3's fluent-bit gap, reported
  not silently applied).** This item's own objective text above and §0's
  research table both say `$filter=lastUpdateTime gt ...`. **There is no
  `lastUpdateTime` property on the real `alert` resource.** The real,
  documented property — confirmed directly from the "List alerts_v2"
  page's own enumerated `$filter`-eligible property list (`assignedTo`,
  `classification`, `determination`, `createdDateTime`,
  **`lastUpdateDateTime`**, `severity`, `serviceSource`, `status`) — is
  `lastUpdateDateTime`. The connector, its normalizer, and its PoC all use
  the real name throughout; this doc's own historical §0 table text is
  left uncorrected above (a historical research artifact) with this note
  as the authoritative correction.
- **Built:** `src/external/integration_sources/defender.py`
  (`DefenderPollSource` — builds `$filter=lastUpdateDateTime gt <cursor>`
  from the persisted `SourceCursor` (omitted on the first-ever poll),
  follows `@odata.nextLink` to exhaustion *within* one `poll()` call
  before returning — a deliberate, documented difference from
  `GenericPollSource`'s "one page per call" contract, since Microsoft's
  own paging docs require draining every page to avoid silently dropping
  alerts — and advances the cursor to the max `lastUpdateDateTime` seen
  across every page, compared as real parsed `datetime` objects rather
  than raw strings so differing fractional-second precision can't corrupt
  the watermark), `DefenderAlertNormalizer` added to
  `src/application/stream_source_registry.py` (ECS mapping:
  `lastUpdateDateTime` → `@timestamp`, `title`/`description` → `message`,
  safe `intrusion_detection`/`info` baseline mirroring
  `WazuhAlertNormalizer`'s own precedent, `evidence[]` preserved verbatim
  under `extra["ms_defender.evidence"]` rather than flattened — deliberate,
  documented, pending the artifact-shaped-normalizer gap Q1's own
  docstring already flagged for this exact connector). Reuses
  `OAuth2ClientCredentialsOutboundAuthStrategy` (Q1) unmodified for the
  real RFC 6749 §4.4 flow.
- **DI wiring (`src/external/dependencies.py`/`src/config.py`):**
  `defender_tenant_id`/`defender_client_id`/`defender_client_secret`/
  `defender_graph_base_url` added to `Settings` (all optional, honestly
  `None`/unset by default — mirrors `splunk_hec_url`/`cef_syslog_host`'s
  own "all must be set together, no partial-credential honest state for
  an OAuth2 client-credentials grant" shape). Unlike Q1/Q2/Q3's zero-arg
  PUSH sources, `DefenderPollSource` cannot be registered unconditionally
  (it genuinely needs real credentials to construct), so
  `configure_defender_poll_source_from_settings()` — wired into
  `startup.py` right after the CEF sink, real startup-sequence
  integration, not a "not yet called" gap like Q1's own static-key
  provisioning — constructs a real `httpx.AsyncClient` + auth strategy +
  `DefenderPollSource` and registers it into the shared
  `IntegrationSourceRegistry` only when all three credentials are present;
  otherwise resolves to the same honestly-disabled `None` state every
  other optional integration in this codebase uses.
- **Real PoC (`poc/integration_source_defender/`), real captured output,
  run three times during this pass (identical assertions passing each
  time; Postgres row absence independently reconfirmed via a direct
  `SELECT` after the final run):** a real stdlib `ThreadingHTTPServer`
  implementing both the real Entra ID token endpoint contract and the real
  `alerts_v2` list/filter/pagination contract, driven by a real
  `httpx.AsyncClient` + real `DefenderPollSource` + real
  `IntegrationSourceIngestService.run_poll_cycle()` against a real
  `PostgresSourceCursorRepository` (the existing shared dev Postgres,
  `docker-postgres-1`, untouched, port 5432 on the host). Proved, all for
  real: (a) cycle 1 — no cursor, no `$filter`, fetches all 4 seed alerts
  across 2 real pages, persists cursor = alert 4's own `lastUpdateDateTime`
  to real Postgres; (b) 3 new alerts appended live to the stand-in
  server's own alert store between cycles; (c) cycle 2 — a *fresh*
  `PostgresSourceCursorRepository` instance (not cycle 1's own in-process
  object) correctly resumes from the real persisted cursor, sends the real
  `$filter=lastUpdateDateTime gt ...` query param, and the stand-in
  server's own log line shows it genuinely evaluating "3 eligible" out of
  7 alerts by real `datetime` comparison (not a canned response) across 2
  more real pages; (d) cycle 3 — no new alerts, real empty page, cursor
  provably unchanged in real Postgres; (e) a deliberately wrong
  `client_secret` produces a real 401 from the stand-in token endpoint,
  surfaced as a real `IntegrationSourceAuthError`; (f) all 7 real fetched
  alerts normalize cleanly via `DefenderAlertNormalizer`; (g) exactly 3
  real `integration_source.poll_completed` audit events, including the
  honest `event_count=0` for the empty cycle. Full transcript in
  `poc/integration_source_defender/output.txt`.
- **Tests:** `tests/unit/integration_sources/test_defender.py` (16 tests —
  filter construction, pagination following/aggregation, max-lastUpdateDateTime
  cursor selection independent of page/list order, empty-page contract,
  malformed-response handling, max-pages safety cap, auth/connection
  failures), 8 new `DefenderAlertNormalizer` tests added to
  `tests/unit/application/test_stream_source_registry.py` (including one
  against Microsoft's own real documented worked JSON example, not a
  hand-crafted guess), `tests/unit/application/test_defender_poll_source_wiring.py`
  (7 tests — unconfigured-by-default, partial-credential honest-disabled
  states, real registration into the shared registry, reset semantics).
  Full suite, before/after via a fresh `git stash -u`/pop (re-derived
  personally this pass, not trusted from any other number): baseline
  **1720 passed, 1 skipped**; with this connector **1751 passed, 1
  skipped** — exactly the +31 new tests, zero regressions. `mypy src`:
  **29 errors**, identical count/file set to the documented Q1/Q2/Q3
  baseline, zero new errors in any touched file. `ruff check`/
  `black --check` on every touched file (src + tests + poc): clean.
- **Stage reached (§3): test-stage only**, honestly incomplete on purpose,
  matching every prior Q-series item's own precedent:
  `configure_defender_poll_source_from_settings()` *is* wired into
  `startup.py`'s real startup sequence (unlike Q1's still-dangling static
  API-key provisioning hook), but since no environment in this repo
  (`docker-compose.dev.yml` included, not touched by this pass) sets the
  three `defender_*` credentials, it resolves to the honestly-disabled
  state on every real run today. No `docker-compose.dev.yml`/
  `docker-compose.prod.yml` wiring was added — there is no real
  self-hostable Defender/Entra ID to containerize, unlike Wazuh/fluent-bit.
- **Known, pre-existing gap inherited, not fixed (flagged, out of this
  connector's own scope):** `SourceCursorRepository`'s own DI default in
  the live app remains `InMemorySourceCursorRepository` — real Postgres
  persistence is proven only at this PoC's own layer (mirrors Q1's own
  identical `PostgresSourceCursorRepository` PoC precedent). Wiring the
  live app's default to Postgres is a real, independent follow-up
  (touches `configure_dependencies()`'s own already-created `engine`, a
  one-line change) that was not made here to keep this connector's own
  diff scoped to Q4's actual objective.
- **Honesty notes:** `evidence[]` (device/file/process/registry-key
  entities) is deliberately preserved verbatim, not flattened into ECS
  host/user/process fields — a real, still-open gap
  (`src/application/integration_source.py`'s own module docstring already
  named this connector as the one that would first hit it: no
  artifact-shaped `StreamSourceNormalizer` return type exists yet); only
  one alert shape (Microsoft's own documented `deviceEvidence` example)
  exercised in the real live PoC pagination flow, though the normalizer's
  handling of alerts with no `evidence`/`title` is covered by the real
  unit tests; the stand-in server's alert *data* is a real-schema-accurate
  fixture, not real tenant telemetry (no real tenant exists to source it
  from); CrowdStrike-class long-lived streaming (a structurally different,
  harder integration shape) remains explicitly out of scope per §0's own
  research.
- **Docker cleanup:** none required — this PoC creates no Docker
  containers (no real self-hostable Defender/Entra ID exists to
  containerize, unlike Q2/Q3's real Wazuh manager/fluent-bit containers);
  its own ephemeral `ThreadingHTTPServer` thread and single Postgres row
  are torn down at the end of every run, confirmed via a direct `SELECT`
  against `integration_source_cursors` after the final run.

---

## Milestone R — Integration sinks (KronOS → SIEM/SOAR)

### R1 · `IntegrationSink` foundation — L1/L2
**Objective.** Design and build the ABC + `SinkAuthenticator` +
`DetectionEventMapper` collaborators per §4's constraints, proven against
ONE real concrete sink end-to-end before any other sink connector starts.
**Depends on:** nothing (disjoint file surface from Q1 — may run in
parallel with Q1 once both are dispatched, per §5's own parallelization rule).

**STATUS (2026-08-08): DONE — test-stage only (expected for a foundation
item, see §3).** Built across two dispatches (an initial pass that hit a
real session cutoff mid-flight, then a delta-aware redispatch that read
every file the first pass had already written before touching anything,
completed the tests/PoC, and fixed lint only — no design changes were
needed).

- **Shape chosen (§4 design constraint, one ABC not two):**
  `IntegrationSink.push_events(events) -> SinkAck` — one method, one small
  ABC (`src/adapter/integration_sink/integration_sink.py`), never a
  per-transport-family method or a parallel ABC hierarchy. The
  ACKNOWLEDGED-vs-UNACKNOWLEDGED distinction §4 calls out as "must be
  modeled honestly, not papered over" lives in a real, type-checked return
  value (`SinkAck`/`SinkAckStatus`, `src/domain/integration_sink.py`), not
  in which code path a caller happened to invoke. Full reasoning + the two
  rejected alternatives are in both modules' own docstrings.
- **Ack-modeling verdict, the redispatch's own explicit assignment:
  CORRECT, no fix needed.** Independently re-derived from first
  principles, not just re-read: `HttpJsonIntegrationSink` has exactly one
  return statement and it is reached only after a real 2xx status code AND
  a real response-body `accepted` count matching the real number of
  events sent — any other outcome raises. `SyslogIntegrationSink` has
  exactly one return statement, unconditionally `UNACKNOWLEDGED`, with no
  branch anywhere in the class that could ever produce `ACKNOWLEDGED` —
  the honesty is structural (impossible to get wrong per-call), not a
  convention a future edit could quietly violate. Verified for real
  end-to-end in `poc/integration_sink_foundation/` Scenarios 1/3/4 (real
  2xx+body → real `ACKNOWLEDGED`; real TCP/UDP socket writes → real
  `UNACKNOWLEDGED`, never the other status).
- **Collaborators:** `SinkAuthenticator` (5 implementations — Null,
  StaticToken, ApiKeyTuple, mTLS via `httpx`'s own `cert=`/`verify=`, and
  OAuth2 client-credentials with real cache/expiry) and
  `DetectionEventMapper` (`MappedSinkEvent` — exactly one of
  `payload`/`raw_text` set, enforced by `__post_init__`) both built and
  tested per §4.
- **Batching:** `chunk_events()` (`src/adapter/integration_sink/batching.py`)
  — shared, target-agnostic count/byte-ceiling chunker; each concrete sink
  only supplies its own real ceilings via `max_batch_events`/`max_batch_bytes`.
- **Tests:** 71 new unit tests added this pass (batching, all 5
  authenticators, `HttpJsonIntegrationSink`, `SyslogIntegrationSink`,
  `MappedSinkEvent`/mapper pluggability, `DetectionSinkPushService`
  orchestration+audit — success AND failure paths for both transport
  families). `HttpJsonIntegrationSink`/OAuth2 tests mock `httpx` (mirrors
  `test_ticketing_system.py`); `SyslogIntegrationSink` tests use real
  local `asyncio` TCP/UDP listeners in-process (no external dependency to
  mock — CLAUDE.md §B.5) plus a real `ConnectionRefusedError`/timeout
  against a real closed port. Full suite: **1416 passed, 1 skipped** (was
  1345/1 pre-existing baseline, independently re-confirmed via
  `git stash -u`, zero regressions). `ruff`/`black` clean on every touched
  file (including two prior-session files that needed reformatting only,
  no logic changes). `mypy`: 29 pre-existing errors, unchanged (zero new).
- **PoC (`poc/integration_sink_foundation/`), 25/25 checks passed, real
  captured output in `output.txt`:** a real local HEC-shaped JSON
  receiver + real local OAuth2 token endpoint (both stdlib `http.server`)
  and a real local TCP (`asyncio.start_server`) + UDP
  (`asyncio.DatagramProtocol`) syslog-shaped receiver, all stood up and
  torn down by the PoC itself (independently confirmed nothing left
  listening afterward) — never a live vendor account, per invariant #9.
  Also proves, for real, the exact claim `sink_authenticator.py`'s own
  docstring makes about itself (two pushes, one real OAuth2 token fetch —
  server-side and client-side counts both confirmed), and runs the real
  `DetectionSinkPushService` end-to-end against the real, live dev-stack
  Postgres 16 (`docker-postgres-1`, untouched/pre-existing — no new
  container created), independently re-reading the audit trail from a
  fresh connection and re-verifying the real hash chain via
  `AuditLogService.verify_chain()`.
- **Stage reached (§3): test-stage only**, exactly as expected for a
  foundation item — no named-vendor target exists yet to wire into
  `docker-compose.dev.yml`/`prod.yml`, and R1 introduces no new service
  dependency of its own (`httpx` was already pinned). Dev/prod wiring is
  real, deliberate R2/R3/R4 scope.
- **Not built here, by design (R2–R4's own scope):** any named-vendor
  `DetectionEventMapper` (Splunk HEC envelope, real CEF/LEEF field
  dictionary, Sentinel DCR-shaped columns); route/playbook-action wiring
  (mirrors H4's own identical "foundation only" precedent); retry/backoff
  on a failed push.
- **Not independently re-verified this pass (flagged, not silently
  assumed):** a dedicated "UDP `sendto()` to a closed port does not
  raise" *positive* test — accepted as an established POSIX/asyncio
  property per the module docstring's own claim, not re-derived with its
  own scenario (Scenario 5's real failure demonstration is TCP-only, by
  design, since TCP is the transport that can produce a real
  deterministic failure).

### R2 · Splunk HEC sink connector — L2
**Objective.** Real HEC token + JSON envelope push of a real `Detection`,
against a real local Splunk instance if a real free/dev-license image
exists (research this — Splunk does ship a free single-instance license
tier), or a real local stand-in HEC-shaped receiver per §1 invariant 9
otherwise, with the real envelope/batching/size-limit behavior honestly
verified either way.
**Depends on:** R1.

**STATUS (2026-08-09): DONE — test-stage only (expected for a connector
item, see §3).** Built across two dispatches (an initial pass that hit a
real session cutoff mid-flight after writing `src/` + most tests but before
running the PoC even once, then a delta-aware resume that read every file
the first pass had already written before touching anything, fixed a real
bug the first-ever real run surfaced, added a real Splunk container on top
of the existing stand-in, and fixed lint).

- **Research question resolved: yes, a real free/self-hostable Splunk
  image exists and was used.** `splunk/splunk` (the vendor's own
  `docker-splunk`/`splunk-ansible`-provisioned image) ships a 60-day
  Enterprise trial that runs as a genuine single self-hosted instance with
  no live account/license-server call at startup — satisfies roadmap §1
  invariant 9 directly. Pinned to `splunk/splunk:9.3.3` (matching the
  Splunk docs version `splunk_hec_sink.py`'s own module docstring was
  verified against). The exact real, current HEC-enablement env vars
  (`SPLUNK_HEC_TOKEN`/`SPLUNK_HEC_PORT`/`SPLUNK_HEC_SSL`) were confirmed by
  fetching `splunk-ansible`'s own current `inventory/environ.py` source
  this pass, not guessed — see `poc/integration_sink_splunk_hec/README.md`.
- **Shape chosen (a sibling `IntegrationSink`, not a subclass/config of
  `HttpJsonIntegrationSink`):** real HEC's wire contract differs from
  `HttpJsonIntegrationSink`'s own generic envelope in two structural ways
  (concatenated-JSON batch body, not a JSON array; a whole-batch
  `{"text","code"}` ack, not a per-event `accepted` count) — reusing the
  generic sink would either force it to special-case Splunk or silently
  misapply a check that could never pass. Full reasoning in
  `splunk_hec_sink.py`'s own module docstring. `SinkAuthenticator` (a plain
  `StaticTokenAuthenticator(scheme="Splunk")`), `chunk_events()`, and the
  `IntegrationSink`/`SinkAck` contract are all reused from R1 unchanged —
  no auth/batching abstraction needed to change for this connector.
  `StaticTokenAuthenticator` gained a `verify: bool | str = True`
  constructor param (plumbed through to `SinkAuthParams.verify`, which R1
  already defined) so a deployment can point at a self-signed-cert HEC
  endpoint without a separate authenticator class.
- **Real ceilings applied, not invented:** `max_content_length` (~800MB,
  `limits.conf`'s `[http_input]` stanza) as the per-request byte ceiling;
  `maxEventSize` (5MB, `inputs.conf`) as the per-event ceiling, rejected
  client-side before any real HTTP call. Not built: HEC's optional indexer
  acknowledgement (`ackId` polling) — flagged as a real, more-granular
  follow-up, not silently skipped (see `splunk_hec_sink.py`'s own
  docstring).
- **Verified for real, twice over, in `poc/integration_sink_splunk_hec/`:**
  (a) **Scenario 0, against the real `splunk/splunk:9.3.3` container** —
  a real push independently re-confirmed *indexed* (not just accepted) via
  Splunk's own real `/services/search/jobs` REST search API, plus real
  wrong-token (403/`code:4`) and real missing-Authorization (401/`code:2`)
  failures against genuine vendor software; (b) **Scenarios 1-5, against
  the existing local HEC-protocol-accurate stand-in** — deep wire-format
  assertions (real concatenated-JSON bytes, full envelope shape, 3-distinct
  auth-failure codes, real batching under a measured byte ceiling,
  `DetectionSinkPushService` orchestration with a real, independently
  re-verified Postgres audit hash chain). **33/33 checks passed** — see
  `poc/integration_sink_splunk_hec/output.txt` for the full unedited run.
- **Bugs the first real run of this PoC actually found (the point of
  §F/this doc's §1 invariant 7):** (1) `splunk_hec_sink.py`'s non-2xx
  error-context builder crashed (`AttributeError`) on a non-2xx response
  whose body is valid JSON `null`/non-dict — fixed with an
  `isinstance(error_body, dict)` guard; (2) the PoC's own byte-ceiling
  scenario asserted an unmeasured "~450-550 bytes/event" estimate that was
  off by ~2x (real, measured size is 902 bytes) and a ceiling that could
  never force a real multi-event batch split — fixed to a measured
  902-byte baseline and a 2000-byte ceiling that forces a real 2+2+1
  split; (3) the PoC's audit-row-count assertion had a real off-by-one
  (assumed a scenario that never touches `DetectionSinkPushService`
  contributed an audit row) — fixed to match the real observed count.
  None of these were catchable by reading the code; only running it
  surfaced them.
- **Tests:** 37 new unit tests this pass (`SplunkHecSink` success/failure
  paths including the two error-path hardening cases in flight at the prior
  session's cutoff — real HEC 403/`code:4` auth failure surfaced in
  `IntegrationSinkError.context`, and a non-2xx non-JSON body falling back
  gracefully; `SplunkDetectionMapper` envelope-shape/field-mapping;
  DI wiring `configure_splunk_hec_sink_from_settings`/
  `get_splunk_hec_sink`/`get_splunk_detection_mapper`; 2 new
  `StaticTokenAuthenticator.verify` tests). Full suite: **1513 passed, 1
  skipped** (was 1476/1 pre-existing baseline, independently re-confirmed
  via `git stash -u`, zero regressions). `mypy`: 29 pre-existing errors,
  unchanged (zero new, none in touched files) — re-confirmed current this
  pass. `ruff`/`black` clean on every touched file (`src/` and `tests/`
  and the new `poc/` script).
- **Stage reached (§3): test-stage only**, as expected — `docker
  run` for `kronos-poc-splunk-hec` is documented in the PoC README but the
  connector is not yet wired into `docker-compose.dev.yml`/`prod.yml` (no
  route/playbook-action triggers a real push automatically yet, mirrors
  R1's own "foundation/connector only" precedent). Dev/prod wiring is
  Milestone S scope.
- **Not built here, by design (R2's own scope boundary):** any
  route/playbook-action wiring that would push a `Detection` to Splunk
  automatically; HEC indexer acknowledgement (`ackId` polling); retry/backoff
  on a failed push (mirrors R1's own identical deferral).

### R3 · Generic CEF-over-syslog sink connector — L2
**Objective.** Real CEF-formatted message over real syslog transport,
against a real local syslog receiver — proves the ABC's second,
non-HTTP, no-ack transport shape.
**Depends on:** R1.

**STATUS (2026-08-09): DONE — test-stage only (expected for a connector
item, see §3).** Built across two dispatches (an initial pass that wrote
`src/application/cef_detection_mapper.py`, both new test files, the
`Settings`/DI/startup wiring, and a first cut of `run_poc.py` but hit a
real session cutoff mid-flight before ever running the PoC once; a
delta-aware resume that read every file the first pass had already written
before touching anything, confirmed all imports were actually already
correct, ran the PoC for the first time, found and fixed a real bug the
first real run surfaced, then completed lint/mypy/regression verification).

- **Design decision (sibling sink class vs. reuse) — reuse
  `SyslogIntegrationSink` (R1) unchanged, the opposite conclusion from R2's
  own sibling-class choice for Splunk HEC, and deliberately so.** CEF's
  real wire shape (verified against the official Micro Focus/OpenText CEF
  spec + corroborating docs, cross-checked against Microsoft Sentinel's own
  CEF-via-AMA connector docs) is an ordinary RFC 3164 BSD-syslog line whose
  message body starts with the literal token `CEF:0|...` — nothing about
  it needs different *socket* behavior from any other line
  `SyslogIntegrationSink` already sends; the entire CEF-specific
  requirement (RFC 3164 header, escaping rules) is string-formatting work
  that belongs to the mapper, not the transport. Only
  `CefDetectionMapper` (`src/application/cef_detection_mapper.py`) is new;
  `SyslogIntegrationSink` itself has zero changes this pass. Full reasoning
  in `cef_detection_mapper.py`'s own module docstring and
  `poc/integration_sink_cef_syslog/README.md`.
- **Real, spec-verified escaping rules implemented** (Micro Focus/OpenText
  CEF spec, corroborated by the CEF White Paper and Microsoft Sentinel's
  CEF-via-AMA docs): header/"prefix" zone escapes `|`→`\|` and `\`→`\\`
  (leaves `=` untouched); extension zone escapes `=`→`\=` and `\`→`\\`
  (leaves `|` untouched); backslash-escaping always applied first in both
  zones. RFC 3164 (not RFC 5424) confirmed as the universally-used
  CEF-over-syslog framing across every real vendor guide found
  (Palo Alto, Centrify, Microsoft Sentinel).
- **Ack-modeling honesty re-confirmed, not assumed still true after R2**:
  direct code reading confirms `SyslogIntegrationSink.push_events()` still
  has exactly one `return` statement, always `SinkAckStatus.UNACKNOWLEDGED`
  — structurally incapable of `ACKNOWLEDGED`, unchanged by this pass since
  the file itself was not touched.
- **Verified for real in `poc/integration_sink_cef_syslog/`** — real local
  `asyncio` TCP + UDP receivers on `127.0.0.1` (no realistic free
  self-hostable "real CEF SIEM" adds anything beyond a protocol-accurate
  stand-in for this transport, unlike R2's Splunk case — the wire format
  IS the whole contract), plus the real, live dev-stack Postgres 16 for the
  audit-trail scenario. Six scenarios: clean TCP push + field-by-field
  round-trip parse (independently re-derived parser, not reusing the
  mapper's own escaping helpers); same over UDP; the roadmap's own required
  deliberate escaping edge case (`|`, `\`, `=` all present in
  `detector_name`/`rule_name`/`finding_id`) with both round-trip recovery
  AND direct wire-byte assertions of the escaped form; re-confirmed
  `UNACKNOWLEDGED`-only honesty; a real `ConnectionRefusedError` failure
  path; and full `DetectionSinkPushService` orchestration with a real
  Postgres audit hash chain independently re-verified from a fresh
  connection. **35/35 checks passed** — see
  `poc/integration_sink_cef_syslog/output.txt` for the full unedited run.
- **Bug the first real run of this PoC actually found (the point of
  §F/this doc's §1 invariant 7):** the PoC's own Scenario 3 wire-level
  assertion asserted an unescaped substring for a header-zone field
  (`rule_name`) that itself contains a `|` — the mapper correctly escaped
  it to `\|` per spec, but the assertion expected the fully-unescaped
  string. The round-trip recovery check (proving the mapper's actual
  output was correct) passed from the first run; only the PoC's own
  direct-wire-bytes assertion string was wrong. Fixed to assert the
  correctly-escaped substring, with the check's label updated to explain
  why. This was caught only because the PoC was actually run and its FAIL
  output actually read.
- **Tests:** 49 new unit tests this pass (`CefDetectionMapper` field
  mapping/severity mapping/escaping for both header and extension zones/
  optional `cs2`+`cn1` omission; DI wiring
  `configure_cef_syslog_sink_from_settings`/`get_cef_syslog_sink`/
  `get_cef_detection_mapper`, mirroring `test_splunk_hec_sink_wiring.py`'s
  own shape). Full suite: **1579 passed, 1 skipped** (was 1530/1
  pre-existing baseline, independently re-confirmed via a fresh
  `git stash -u`/pop this pass — exactly +49, zero regressions). `mypy`:
  29 pre-existing errors, unchanged (zero new, none in touched files) —
  independently re-confirmed via the same `git stash -u`/pop this pass.
  `ruff`/`black` clean on every touched file (`src/`, `tests/`, and the
  `poc/` script).
- **Stage reached (§3): test-stage only**, as expected — no
  route/playbook-action triggers a real CEF push automatically yet, mirrors
  R1/R2's own "foundation/connector only" precedent. Dev/prod wiring is
  Milestone S scope.
- **Not built here, by design (R3's own scope boundary):** any
  route/playbook-action wiring that would push a `Detection` over
  CEF-over-syslog automatically; retry/backoff on a failed push (mirrors
  R1/R2's own identical deferral); LEEF (QRadar's other native format) —
  flagged as a real, plausible-but-out-of-scope follow-up sharing most of
  `SyslogIntegrationSink`'s transport, not silently assumed covered by CEF.

### R4 · Microsoft Sentinel sink connector — L2
**Objective.** Real Logs Ingestion API push against a real pre-provisioned
DCR/DCE/custom-table (needs a real Azure subscription — if unavailable,
verify against the documented real API contract with a real recorded
response fixture, per §1 invariant 9), proving the OAuth2 +
rigid-pre-provisioned-schema mapping case.
**Depends on:** R1.

**STATUS (2026-08-09): DONE — test-stage only (expected for a connector
item, see §3).** Built in a single pass; no real Azure subscription was
available in this sandbox (checked directly — no `az` CLI installed, no
`AZURE_*` env vars set — see `poc/integration_sink_sentinel/README.md`'s
own "Real Azure subscription: checked, genuinely unavailable" section), so
per §1 invariant 9 this verifies against a real, local, protocol-accurate
stand-in built from Microsoft's own current, official docs (fetched and
read directly this pass, not assumed from memory or modeled on the
now-retired HTTP Data Collector API) rather than skipping verification.

- **Real docs fetched this pass (exact URLs, full citations in the PoC
  README):** `logs-ingestion-api-overview` (URI template, headers, bare-JSON-
  array body shape, `_CL` custom-table suffix), `data-collection-rule-structure`
  (the real, closed `streamDeclaration` column-type set —
  `string`/`int`/`long`/`real`/`boolean`/`dynamic`/`datetime`, and the real
  "every top-level property must be declared" rigidity rule),
  `tutorial-logs-ingestion-code` (the real OAuth2 client-credentials flow
  against `login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, and the
  load-bearing, explicitly-quoted fact that real success is **HTTP 204, no
  body** — not 200), `service-limits` (real 1 MB/call, 64 KB/field, 2 GB/min
  + 12,000 req/min per-DCR ceilings), the Python `LogsIngestionClient` SDK
  reference (independently corroborates the 204-no-body contract), and
  `github.com/microsoft/api-guidelines` (the real, general Azure REST API
  error envelope `{"error": {"code", "message"}}` used for the stand-in's
  own structured failure bodies — honestly flagged as a real, cited
  **shape** with a representative, not independently-tenant-verified,
  `code` string, since no real 400-body worked example exists in any doc
  fetched this pass).
- **Rigid-schema design (the roadmap's own "hard part"):** a 14-column
  custom table (`KronOSDetection_CL`, stream `Custom-KronOSDetection`) —
  full column table + per-field justification in
  `src/application/sentinel_detection_mapper.py`'s own module docstring.
  Core SOC-analyst triage fields get first-class typed columns; genuinely
  structured/variable-shape `Detection` fields (`rule_matches`,
  `attack_tags`, `matched_document_ids`) use the real, verified `dynamic`
  column type; secondary/traceability fields (`external_ticket_id`,
  `synced_at`, `updated_at`) are bucketed into one `dynamic` catch-all,
  `ExtendedProperties` — never silently dropped. Every record carries
  exactly these 14 keys every time (nullable columns still appear as JSON
  `null`), matching the real DCR contract's own "full list of top-level
  properties" requirement.
- **Sibling-vs-reuse (sink): `SentinelHttpSink` is a sibling
  `IntegrationSink`, not a reuse of `HttpJsonIntegrationSink`** — a third,
  independently-arrived-at confirmation of `SplunkHecSink`'s (R2) own
  precedent, for a different structural reason: Sentinel's real body is a
  bare JSON array (not `{"events": [...]}`) and its real success is 204
  **with no body** (no `accepted` count to ever read), so reusing the
  generic sink would make every real push fail its own accepted-count
  check, always, even on success. Full reasoning in `sentinel_sink.py`'s
  own module docstring.
- **Auth reuse decision (the roadmap's own explicit "decide and justify"
  instruction): reuses R1's `OAuth2ClientCredentialsAuthenticator`
  unchanged** (that class's own docstring already named Sentinel's Entra ID
  flow as its reason to exist) — deliberately does **not** reuse or
  duplicate Q1's `OAuth2ClientCredentialsOutboundAuthStrategy`
  (`src/external/middleware/integration_source_auth.py`): a different ABC
  (`headers() -> dict[str, str]`, no `SinkAuthParams`/cert/verify shape)
  built for the opposite direction (KronOS polling, with an
  externally-injected shared `httpx.AsyncClient`) that does not fit
  `IntegrationSink.push_events()`'s own per-call `SinkAuthenticator.prepare()`
  contract without an adapter that would net negative versus just reusing
  the collaborator R1 already built for exactly this. No new authenticator
  class was written.
- **Verified for real in `poc/integration_sink_sentinel/`** — a real local
  Entra ID v2.0 token endpoint + a real local Sentinel DCE ingestion
  endpoint (both real stdlib `http.server` stand-ins matching the exact
  documented contract above), plus the real, live dev-stack Postgres 16 for
  the audit-trail scenario. Eight scenarios: real OAuth2 token exchange
  (success); real OAuth2 failure (wrong secret, real RFC 6749 §5.2
  `invalid_client` 401); real successful push (real 204 → `ACKNOWLEDGED`,
  exact 14-column record independently verified field-by-field against the
  source `Detection`); real OAuth2 token caching (2 pushes, 1 fetch);
  **the roadmap's own required deliberate schema-mismatch case** — an
  undeclared extra column AND, independently, a missing declared column,
  both real 400s with the real Azure error envelope, surfaced as real
  `IntegrationSinkError`s, never a fabricated ack; real documented 403 (DCR
  access not granted); real documented 413 (both `SentinelHttpSink`'s own
  client-side pre-check AND a genuinely oversized raw request against the
  real stand-in); and full `DetectionSinkPushService` orchestration with a
  real Postgres audit hash chain independently re-verified from a fresh
  connection. **29/29 checks passed** — see
  `poc/integration_sink_sentinel/output.txt` for the full unedited run.
- **No bug found on the first real run** (unlike R2/R3, whose first real
  runs each surfaced a genuine bug) — flagged honestly, not overclaimed:
  the mapper's rigid, by-construction 14-key record shape left little room
  for a shape mismatch, and the stand-in's own schema check was written
  independently of the mapper (no shared code), so this is a real, if less
  dramatic, confirmation rather than an untested claim.
- **Tests:** 44 new unit tests this pass (`SentinelDetectionMapper` rigid
  14-column shape/nullable-columns/dynamic-columns/`ExtendedProperties`
  catch-all; `SentinelHttpSink` success/failure paths including the real
  204-only-success contract, real 403/429/401 failure surfacing, real
  oversized-batch client-side rejection, and a non-dict JSON error body
  defended against from the start (mirrors `SplunkHecSink`'s own
  first-real-run bug, pre-empted here rather than discovered);
  DI wiring `configure_sentinel_sink_from_settings`/`get_sentinel_sink`/
  `get_sentinel_detection_mapper`, mirroring `test_cef_syslog_sink_wiring.py`'s
  own shape). Full suite: **1647 passed, 1 skipped** (was **1603/1**
  pre-existing baseline, independently re-confirmed via a fresh
  `git stash -u`/pop this pass — exactly +44, zero regressions). `mypy`:
  **29 pre-existing errors, unchanged** (zero new, none in any touched
  file — independently re-confirmed via the same `git stash`-free run of
  `mypy src/` this pass). `ruff`/`black` clean on every touched file
  (`src/`, `tests/`, and the `poc/` script).
- **Stage reached (§3): test-stage only**, as expected — no
  `docker-compose.dev.yml`/`prod.yml` wiring, no route/playbook-action
  triggers a real Sentinel push automatically yet, mirrors R1/R2/R3's own
  "foundation/connector only" precedent. Dev/prod wiring is Milestone S
  scope.
- **Not built here, by design (R4's own scope boundary):** any
  route/playbook-action wiring that would push a `Detection` to Sentinel
  automatically; a true end-to-end "landed in the destination table"
  confirmation (204 only confirms the API layer's own synchronous
  acceptance — DCR transform/ingestion is itself asynchronous, structurally
  the same class of gap as `SplunkHecSink`'s own deferred `ackId` polling);
  64 KB per-field-value client-side enforcement (server truncates silently,
  never rejects, so there is nothing to defend against client-side);
  retry/backoff on a failed push (mirrors R1–R3's own identical deferral).

---

## Milestone S — Rollout hardening (cross-cutting, after Q/R connectors exist)

Full test→dev→prod wiring (§3) for whichever of Q2–Q4/R2–R4 haven't yet
reached the "dev"/"prod" stage during their own initial build — this
milestone exists so a connector isn't required to finish all three stages
in one dispatch if that's too large, without silently leaving prod-parity
undone forever the way the closed roadmap's own I3 had to retroactively
discover and fix for ClamAV/OpenSearch-security.

---

## Milestone T — Full-repo audit of what's still left

After P/Q/R land (or substantially land), a fresh audit pass: reconcile
against `docs/IMPROVEMENT_IDEAS.md`'s own list, the closed roadmap's old
Part-3-equivalent remaining gaps, and anything new found while building
the integration layer. Produces its own prioritized fix/build plan,
executed the same PoC-first way.

## Milestone U — Multi-scenario subagent assessment

Dispatch multiple subagents to assess the tool from different angles: a
real incident-response walkthrough (does the platform actually support an
analyst working a real multi-source incident end to end, now that sources/
sinks exist), a security/red-team review, a new-customer-onboarding/UX
review, a scale/reliability review. Collect real reports, synthesize a
plan prioritizing **maintainability, flexibility, and security first** per
explicit project-owner instruction, execute it.

---

## 7. Notes for the next wake-up

- Update this file's own items with real `**STATUS (date): ...**` blocks
  as they land, exactly matching the closed roadmap's own tone/rigor
  (real captured output, honest gaps, explicit stage-reached per §3).
- If a milestone/item here turns out wrong once real implementation
  starts, update this doc rather than silently deviating — same rule the
  closed roadmap held itself to throughout.
