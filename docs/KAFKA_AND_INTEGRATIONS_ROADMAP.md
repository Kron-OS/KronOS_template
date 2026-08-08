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

### Q2 · Wazuh source connector — L2
**Objective.** Real `wazuh-integratord` webhook → KronOS collector-ingest,
end to end, against a real self-hosted Wazuh manager (the repo's own
dormant `docker/wazuh/` config, pinned `5.1.0` — verify the 5.0
data-destruction CVE doesn't recur in 5.1.0 before trusting it for this).
**Depends on:** Q1.

### Q3 · Suricata/Zeek live-tail source connector — L2
**Objective.** Real log-shipper (fluent-bit, reusing the repo's own
existing config pattern) tailing a real `eve.json`/Zeek JSON log, forwarding
via the same collector-ingest path, mapped via the same ECS logic
`SuricataEveParser` already proved for the batch-file case.
**Depends on:** Q1.

### Q4 · Microsoft Defender source connector — L2
**Objective.** Real Graph Security API `alerts_v2` poll-with-cursor
(`$filter=lastUpdateTime gt ...`), OAuth2 client-credentials via a real
Entra ID app registration if a real tenant is available for testing, or a
real recorded/replayed response fixture per §1 invariant 9 if not —
proves the poll+durable-cursor pattern before CrowdStrike's harder
long-lived-stream model is attempted.
**Depends on:** Q1.

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

### R3 · Generic CEF-over-syslog sink connector — L2
**Objective.** Real CEF-formatted message over real syslog transport,
against a real local syslog receiver — proves the ABC's second,
non-HTTP, no-ack transport shape.
**Depends on:** R1.

### R4 · Microsoft Sentinel sink connector — L2
**Objective.** Real Logs Ingestion API push against a real pre-provisioned
DCR/DCE/custom-table (needs a real Azure subscription — if unavailable,
verify against the documented real API contract with a real recorded
response fixture, per §1 invariant 9), proving the OAuth2 +
rigid-pre-provisioned-schema mapping case.
**Depends on:** R1.

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
