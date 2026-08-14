# KronOS Gap Audit — 2026-08 (Milestone T)

**Status:** research/planning document only. No `src/` code was changed to
produce this audit. Produced per `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md`'s
own Milestone T charter, after Milestones P (streaming resilience), Q/R (six
EDR/SIEM connectors), and S (rollout hardening) substantially landed.

---

## §0 Method

Five independent passes, each cross-checked against the real repo state
(not assumed from a doc's own claims):

1. **`docs/IMPROVEMENT_IDEAS.md` reconciliation.** Read in full (178 lines,
   5 sections). Every item checked against `src/`/`frontend/src`/`poc/`/
   `docker/` via targeted `grep`/`find` and, where ambiguous, a direct file
   read (e.g. `kronos_attest/report.py`'s real `case_report()` signature,
   `src/adapter/opensearch/client.py`'s real `bulk_index()` body).
2. **`docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` full read** (1627 lines, all
   of §0 and every STATUS block P1/P2/Q1–Q4/R1–R4/S). Every "not built
   here" / "honesty note" / "known gap" sentence extracted verbatim into
   §1 below, then independently re-verified against current `src/` (e.g.
   `celery_app.py`'s `beat_schedule` re-read directly to confirm no
   Defender/poll task exists; `grep`ed for any caller of
   `DetectionSinkPushService` to confirm zero route/playbook wiring exists
   for any of the three sinks).
3. **`docs/NEXTGEN_SOC_ROADMAP.md` closing gates (I1–I5, lines
   2498–2990)** read in full. Every explicitly-deferred, not-a-"won't-fix"
   item extracted and spot-checked against current code (e.g. confirmed
   `docker-compose.test.yml` still sets `DISABLE_SECURITY_PLUGIN=true`;
   confirmed `TenantUsageService.get_current_usage_bytes()` is still an
   uncached `SUM()` query, now confirmed *live* per-upload via
   `StorageQuotaGate`).
4. **Fresh codebase pass:**
   - `grep -rn "TODO\|FIXME\|XXX\|not implemented\|NotImplementedError" src/`
     — only 2 real hits, both an intentional, documented
     `NotImplementedError` in `src/application/integration_source.py`
     (an ABC default, not a gap). The codebase is otherwise free of
     inline TODO markers — a genuinely clean result, not a false negative
     (spot-checked the grep pattern against files known to have prose
     containing "XXX"-shaped strings, e.g. `firecracker.py`'s own
     `tmpXXXX` example, to confirm the pattern wasn't over-matching and
     hiding real hits elsewhere).
   - `rm -rf .mypy_cache && mypy src` (venv activated per repo convention)
     — **29 errors in 10 files**, matching every STATUS block's own
     "unchanged baseline" claim exactly. Read every error; triaged below
     (§1, MYPY-1/MYPY-2).
   - `pytest tests/unit -q --cov=src --cov-report=term-missing` — **1678
     passed, 1 skipped**, 90% total coverage. Read the full per-file
     report; identified `src/external/routes/admin.py` (61%),
     `src/external/routes/evidence.py` (71%), and
     `src/external/dependencies.py`/`fastapi_app.py` (78%/81%) as the
     real outliers versus neighboring files (most application/domain
     files are 94–100%), then read the actual uncovered line ranges in
     each to judge risk (error-handling branches vs. real untested
     security logic vs. expected-uninstrumented startup/wiring code).
5. **Security-specific pass.** Read `src/external/routes/integration_source_push.py`
   end-to-end and `src/external/middleware/integration_source_auth.py`
   (both `StaticApiKeyInboundAuthenticator` and
   `identity_from_collector_identity`) to confirm `org_id`/`source_id`
   come exclusively from the verified credential, never the request body
   — confirmed, no gap. Grepped every sink/source module and
   `detection_sink_push.py`/`integration_source_ingest.py` for
   `logger.*`/`context=`/audit `details=` calls near secret-handling code
   to confirm no raw token/secret ever reaches a log line, exception
   `context` dict, or audit-log `details` blob — confirmed clean (HEC
   token, Sentinel/Defender client secrets, CEF host/port never appear in
   any of the three; `src/config.py` consistently types all of them as
   `SecretStr`). Also read `src/external/routes/admin.py`'s
   `update_user_role`/`remove_user` handlers directly to confirm org
   membership/role mutations are scoped to `tenant.org_id` and
   `_assert_user_in_org()`-checked before any Keycloak write — confirmed
   correct on inspection, but flagged in §1 as a **verification gap**
   (no real-Keycloak integration/PoC run exists for these specific flows,
   only unit tests with mocked `httpx`).

---

## §1 Prioritized gap list

Legend: **P0** security-critical · **P1** real functional gap · **P2**
nice-to-have/polish. Size: **S** (<1 day agent effort) · **M** (1–3 days) ·
**L** (multi-day/needs design).

### P0 — security-critical

| # | Gap | Where | Size |
|---|---|---|---|
| P0-1 | `docker-compose.prod.yml` sets `OPENSEARCH_URL=http://...` on `kronos-backend`/`celery-worker`, but the security-plugin-enabled OpenSearch it points at (unlike dev's correctly-`https://` config) only serves HTTPS. Flagged by I3 (2026-08-07), never fixed. If prod genuinely can't reach OpenSearch over the URL it's configured with, this is either a hard outage or (worse) a silent fallback/plaintext-internal-traffic risk on a platform whose whole model assumes TLS 1.3 + mTLS internally (CLAUDE.md tech stack). Needs a real decision (fix the scheme, or confirm a reverse-proxy/sidecar TLS-terminates in between) before prod is trusted for real traffic. | `docker/docker-compose.prod.yml`, flagged in `docs/NEXTGEN_SOC_ROADMAP.md` I3 | S–M |

No new P0 (tenant-isolation-breaking, secret-leaking, or auth-bypass) issues
were found in the six new Q/R connectors or the routes examined — see §0.5.
That is a real, positive finding worth stating plainly, not just an absence
of a section.

### P1 — real functional gaps

| # | Gap | Where | Size |
|---|---|---|---|
| P1-1 | **No caller anywhere pushes a `Detection` to any of the three built sinks.** `DetectionSinkPushService`/`SplunkHecSink`/`CefSyslogSink`/`SentinelHttpSink` are all real, tested, and dev/prod-wired for config — but zero routes and zero `PlaybookAction`s call `DetectionSinkPushService.push()`. The entire R-series (Milestones R1–R4, six connectors' worth of sink work) is currently unreachable from any real KronOS workflow. | `src/application/detection_sink_push.py` (confirmed via grep: no callers in `src/external/routes/` or `src/application/playbook_actions.py`); roadmap R1–R4 "Not built here, by design" notes | M (a `SyncDetectionToSiemAction` `PlaybookAction`, mirroring `SyncDetectionTicketAction`/H4's own precedent) |
| P1-2 | **Defender poll source is registered but never invoked.** `configure_defender_poll_source_from_settings()` runs at startup and registers a real `DefenderPollSource`, but `celery_app.py`'s `beat_schedule` has no task calling `IntegrationSourceIngestService.run_poll_cycle()` on a timer. Confirmed still true by direct re-read of `beat_schedule` (6 tasks, none integration-source-related). Setting real Defender credentials today makes the source *available*, not *active*. Same class of gap will recur for any future poll-mode source (CrowdStrike-class excepted, deferred). | `src/external/celery_app.py`; `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` Q4 Milestone S update | S–M (new beat task + a `run_dependencies_sync`-safe per-task client, since Defender's OAuth2 strategy holds a process-lifetime `httpx.AsyncClient` — flagged as unsafe to naively copy R2/R3/R4's fix) |
| P1-3 | **Splunk HEC `ackId` indexer-acknowledgement polling not built.** A 2xx+body from HEC only confirms the event was *accepted*, not that Splunk's indexer actually wrote it — the more rigorous ack mode exists in HEC's own protocol and is explicitly deferred. | `src/adapter/integration_sink/splunk_hec_sink.py` docstring; roadmap R2 | M |
| P1-3 (V6) | **V6 STATUS: RESOLVED — built and verified for real.** `SplunkHecSink` now supports opt-in `enable_indexer_ack=True`: real `X-Splunk-Request-Channel` header on every push, real `ackId` parsed from the push response, and a new `check_ack_status()` method polling the real `/services/collector/ack` endpoint. Design decision (full reasoning in the sink's own module docstring): synchronous polling inside `push_events()` with a real, bounded, per-sink-configured timeout (`ack_poll_timeout`, default 30s), resolving to a genuine third `SinkAckStatus.ACK_PENDING` (`src/domain/integration_sink.py`) if the timeout elapses before confirmation — never raised, never fabricated as `ACKNOWLEDGED`. `check_ack_status()` doubles as the separate out-of-band resolution mechanism for a caller that would rather not block. Proven against a real `splunk/splunk:9.3.3` container with a real `useACK=1` HEC token (created via a real REST call, since neither `docker-splunk` nor `splunk-ansible`'s `getHEC()` exposes a `SPLUNK_HEC_*` env var for it — confirmed by re-reading `environ.py`'s source this pass): real push → real `ackId` → real poll returning `false` at t≈0.004s → real poll returning `true` at t≈1.02s (`poc/splunk_hec_ack_polling/output.txt`, 17/17 checks, first real run, no bug found). Also real-verified and now handled: HEC's own "read-once" ack semantics (a resolved `true` ackId returns `false` on re-query — matches Splunk's own documented behavior, not a bug), the real `400`/`code:10` "Data channel is missing" error when a channel is omitted against a `useACK=1` token, and the real `400`/`code:11` "Invalid data channel" error for an unrecognized channel. `DetectionSinkPushService`/`SinkPushResult.all_acknowledged` required **zero code changes** — both already treat any non-`ACKNOWLEDGED` status as unconfirmed by construction. | `src/adapter/integration_sink/splunk_hec_sink.py`; `src/domain/integration_sink.py`; `src/config.py`; `src/external/dependencies.py`; `poc/splunk_hec_ack_polling/` | Done — disabled by default (`splunk_hec_enable_indexer_ack=False`), since it requires a real, separate, operator-driven `useACK=1` token change on the Splunk side that KronOS cannot itself apply. |
| P1-4 | **Sentinel push: 204 only confirms Logs Ingestion API acceptance, not DCR-transform/table-ingestion success** (structurally the same class of gap as P1-3 — ingestion is asynchronous past the synchronous API layer). No mechanism exists to confirm data actually landed in `KronOSDetection_CL`. | `src/adapter/integration_sink/sentinel_sink.py`; roadmap R4 | M–L (would need a real Azure subscription + Log Analytics query to close for real, not just design) |
| P1-4 (V6) | **V6 STATUS: DESIGNED, explicitly NOT implemented or run** — same real constraint R4 itself already hit (no Azure subscription available in this sandbox; re-confirmed this pass: no `az` CLI, no `AZURE_*` env vars). A real, cited-against-current-docs design was added to `sentinel_sink.py`'s own module docstring: the real `azure-monitor-query` package (current major `2.0.0`), `azure.monitor.query.aio.LogsQueryClient.query_workspace(workspace_id, query, timespan=...)` (real method signature/return shape — `LogsQueryResult`/`LogsQueryStatus.SUCCESS` — fetched from Microsoft's own current SDK overview doc this pass), a real KQL query (`KronOSDetection_CL \| where FindingId == '<finding_id>' \| count`, using `FindingId` — the mapper's own real, non-nullable, documented column — as the correlation key), and a named, real, additional required Azure RBAC role (`Log Analytics Reader` on the destination workspace, distinct from ingestion's own `Monitoring Metrics Publisher` DCR role). Explicitly designed as a **standalone class outside the `IntegrationSink` hierarchy** (`SentinelIngestionConfirmationChecker`, not a `SentinelHttpSink` method) since the Query SDK takes an `azure-identity` `TokenCredential` directly, not this package's own `SinkAuthenticator`/`SinkAuthParams` contract — a real, justified reason no code was forced to fit the existing shape. No `src/` class was written, no dependency was added to `pyproject.toml`, and no stand-in/mocked client was built to simulate a "pass" — writing a class with nothing real to run it against would itself be the "plausible code without a captured real run" failure mode this initiative exists to stop. Closing this for real needs a real Azure subscription with a real Log Analytics workspace + DCR + app registration holding both RBAC roles. | `src/adapter/integration_sink/sentinel_sink.py` docstring | Design-only — not started as an implementation task, correctly gated on real Azure access per CLAUDE.md SS F. |
| P1-5 | **fluent-bit `Syslog_Severity_Key level` bug: numeric 0–7 severity expected, KronOS's own structured logger emits a keyword string (`"info"`).** Confirmed live during Milestone S (`[warn] ... invalid severity: 'info'`) — falls back to a default severity rather than failing, so it's silently wrong rather than broken, which is worse for anyone relying on real severity-based syslog routing downstream. | `docker/fluent-bit/fluent-bit.conf`; roadmap Q3/Milestone S | S (a `modify`/`lua` filter translating level string → syslog severity int) |
| P1-6 | **`nginx_logs` Docker volume exists with no real producer.** nginx doesn't write access logs to any shared volume in this repo, so the volume declaration is a no-op — anyone assuming nginx access logs flow into the SIEM stack (a reasonable assumption given fluent-bit/Wazuh/Falco all exist) would be wrong. | `docker/fluent-bit/docker-compose.fluent-bit.yml`; roadmap Q3/Milestone S | S–M (real nginx access-log config + volume mount) |
| P1-7 | **`StaticApiKeyProvisioning` has no real per-(org, source) provisioning flow.** `configure_static_api_key_provisioning()` exists as a hook but is never called from `startup.py`; there's no way today for an operator to actually issue a customer a static API key for the generic-webhook/Wazuh PUSH path in a running deployment. Investigated (not just noted) during Q2's Milestone S pass and correctly judged to need a real design decision (how does an operator provision a per-tenant key — admin route? CLI? Vault-seeded?), not a copy-paste fix. | `src/external/middleware/integration_source_auth.py`; `src/external/startup.py`; roadmap Q1/Q2 | L (needs a design decision before implementation — candidate for its own scoped item, see §3) |
| P1-8 | **`SourceCursorRepository`'s live DI default is still `InMemorySourceCursorRepository`, not `PostgresSourceCursorRepository`.** Every poll-mode source's cursor (Defender's included) is lost on any backend/worker restart, silently re-polling from scratch or (if the external API doesn't tolerate an unset `$filter` gracefully) re-ingesting everything. `PostgresSourceCursorRepository` exists, is tested, and is proven against real Postgres in three separate PoCs — it's just never wired as the real app default. | `src/external/dependencies.py`; roadmap Q1/Q4 "known, pre-existing gap inherited, not fixed" | S (one-line DI default change + a migration-adjacent Postgres table check, since there's no migration tool — see P1-14) |
| P1-9 | **`StreamSourceNormalizer.normalize()` has no artifact-shaped return path.** Every `IntegrationSource` today can only produce `NormalizedStreamEvent` (timeline-shaped). Microsoft Defender's real `evidence[]` (device/file/process/registry-key entities) is preserved verbatim under `extra["ms_defender.evidence"]` instead of being properly modeled, and any future artifact-shaped poll/push source (a Volatility-class SIEM export, a graph-shaped alert) hits the same wall. Named as a known gap by Q1's own module docstring, confirmed still open by Q4. | `src/application/stream_normalization.py`; `src/application/integration_source.py` module docstring | L (needs a `StructuredArtifact`-producing sibling to `NormalizedStreamEvent`, plumbed through the whole D1→D3 pipeline) |
| P1-10 | **Only 4 of 23 OpenSearch Security Analytics log types have any first-party KronOS parser** (`windows`, `cloudtrail`, `network`, `apache_access` — and `apache_access`'s own 2 prepackaged rules don't even match `NginxParser`'s access-log shape, per I1's own finding). The other 19 SA log-type rule categories (`ad_ldap`, `azure`, `github`, `gworkspace`, `m365`, `okta`, `s3`, `vpcflow`, `waf`, `dns`, `others_*`) can never fire against real KronOS-ingested data today, regardless of how much rule-pack work happens. This bounds the platform's real detection coverage far more than rule count does. | I1 finding, `docs/NEXTGEN_SOC_ROADMAP.md` §M8 | L (per-log-type parser/normalizer work, prioritize by real customer log sources) |
| P1-11 | **MTTD is structurally incapable of measuring real detection latency against historical forensic evidence.** I2 proved every `Detection` this platform can produce is built from a document whose `@timestamp` was rewritten to "now" before a Security-Analytics monitor could ever fire on it — so the metric can only ever reflect "SA schedule interval + sync latency," never genuine time-to-detect for ingested-but-backdated evidence. This is a structural property of the whole SA-monitor-based detection pipeline, not a calculator bug — worth flagging prominently since I2's own `MetricCalculator` framework could otherwise ship a customer-facing "MTTD" number that quietly means something different from what the label implies. | `src/application/metric_mttd.py`; `docs/NEXTGEN_SOC_ROADMAP.md` I2 finding #4 | L (would need a genuinely different detection-latency measurement approach, or an explicit UI label change — "SA cycle time," not "MTTD" — until/unless a non-SA-monitor detection path exists) |
| P1-11 (V7) | **V7 STATUS: RESOLVED (relabel-only, as scoped).** `MeanTimeToDetectCalculator` renamed to `SecurityAnalyticsCycleTimeCalculator`; `metric_name` changed from `"mttd_seconds"` to `"sa_cycle_time_seconds"`; module docstring rewritten to lead with the honest "why not MTTD" rationale (same structural finding, now stated as the metric's own definition rather than a caveat below it). Confirmed, not assumed: grepped `src/external/` for `MetricRegistry`/`get_metric_registry`/`metric_name` before touching anything — **zero real customer-facing HTTP surface exists for any metric today** (no route, no schema); `metric_calculator.py`'s own docstring already documents this as deliberate ("not wired into the DI container in this pass," mirroring G1's `RarityBaselineScorer` precedent), confirmed still true. So this rename has zero live blast radius — it is purely "bake the honest name in now, before a UI/API consumer exists, instead of a breaking rename later" per the V7 brief's own framing. `poc/metrics_kpis/README.md`/`output.txt` (the real captured numbers under the old name) deliberately left untouched as historical evidence of the actual run; the numbers are still valid, only the old label was wrong. | `src/application/metric_sa_cycle_time.py`; `tests/unit/application/test_metric_sa_cycle_time.py` | Done |
| P1-12 | **No real migration tool (Alembic or equivalent).** Confirmed: zero references to `alembic` anywhere in the repo. Every new Postgres column this multi-month initiative has added (risk_score, risk_factors, external_ticket_id, storage quota fields, `integration_source_cursors` table, etc.) has landed via `create_all`-only, which — per the codebase's own repeated comments — "only adds missing TABLES, not columns," meaning a real deployed DB needs a manual, undocumented, error-prone `ALTER TABLE` pass to actually pick up months of schema changes. This is now a materially larger risk than when `IMPROVEMENT_IDEAS.md` first flagged it, given how much schema has landed since (P1-8's Postgres cursor table is the latest addition to the pile). | repo-wide; `docs/IMPROVEMENT_IDEAS.md` §3 | L (Alembic adoption + a real baseline migration capturing current schema state) |
| P1-12 (V4) | **V4 STATUS: RESOLVED.** Real `alembic>=1.13` (1.19.1 installed/exercised) adopted, async `env.py` per Alembic's own documented cookbook pattern, combined `MetaData` built from all 14 `postgres_*.py` modules (`migrations/target_metadata.py`), real baseline migration generated and verified against a real throwaway Postgres: `alembic upgrade head` from empty produces a schema column-for-column/constraint-for-constraint/index-for-index identical to `create_tables()`'s own output across all 21 tables (`poc/alembic_migration_baseline/`, real captured output, zero mismatches). Boot-sequence design decision: a one-shot `db-migrate` init container (mirroring the existing `keycloak-init`/`opensearch-init` pattern) now runs `alembic upgrade head` before `kronos-backend`/`celery-worker*`/`celery-beat` start in all three compose files; `create_tables()` invocations were REMOVED from `src/external/startup.py`'s `wire_dependencies_async()`/`wire_dependencies_sync()` (the 14 repositories' own `create_tables()` classmethods are unchanged and still used directly by `tests/integration/conftest.py`). | `alembic.ini`; `migrations/`; `docs/DATABASE_MIGRATIONS.md`; `poc/alembic_migration_baseline/` | Done — explicit stated gap: upgrade-from-an-existing-populated-database was not tested (only empty-database round-trip); `docs/DATABASE_MIGRATIONS.md` documents the `alembic stamp head` procedure for that case. |
| P1-13 | **`TenantUsageService.get_current_usage_bytes()` is an uncached `SUM(size_bytes)` query, now confirmed live on every evidence upload** (`StorageQuotaGate` calls it on every quota check, not hypothetically — quota enforcement landed and is active). No caching/rate-limiting layer exists yet; real-world query cost under load has not been measured. | `src/application/tenant_usage.py`; `src/application/quota_gate.py` | S–M (measure first per CLAUDE.md §F discipline, then decide whether a cache is even needed) |
| P1-14 | **`docker-compose.test.yml` still has `DISABLE_SECURITY_PLUGIN=true` and no TLS/Keycloak scaffolding**, blocking any CI-realistic run of anything that depends on the A3 isolation model (OpenSearch DLS, Keycloak-issued tenant context) — this is why the detection-validation harness (I1), and by extension any future connector's "dev stage" work, still runs manually against the shared dev stack rather than in CI. Confirmed unchanged by direct file read. This single fix would unblock CI wiring for I1's harness, all six Q/R connectors' own dev-stage verification, and any future security-plugin-dependent test. | `docker/docker-compose.test.yml`; flagged independently by I1 and `IMPROVEMENT_IDEAS.md` §3 | L (enable + verify security plugin in test compose, add TLS/`step-ca`/Keycloak-init scaffolding, confirm footprint fits a GitHub Actions runner — named by I1 as its own scoped follow-up) |
| P1-15 (V5) | **V5 STATUS: RESOLVED.** `invite_user`/`update_user_role`/`remove_user` now have real-Keycloak integration coverage (`tests/integration/test_admin_routes_real_keycloak.py`, 6/6 real checks passed against the shared dev-stack Keycloak 26.2), calling the real route handlers directly with zero mocks: real user creation + org-linking (confirmed via a second, independent Admin API call, never trusted from the route's own response), a real cross-org email-reuse rejection (409, AUTH-003/AUTH-011), a real role change that persists and is read back fresh, a real 403 cross-org role-change rejection, a real org-membership removal (confirmed the realm-level account survives — `remove_user` only unlinks org membership, documented not assumed), and a real cross-org removal attempt correctly blocked (surfaces as a real 503 — see "real bug" note below). Every mutation's audit event (`ORG_USER_INVITED`/`ORG_USER_ROLE_CHANGED`/`ORG_USER_REMOVED`) was independently read back from a fresh `PostgresAuditLogRepository` connection. **No tenant-isolation bug found** — the original P1-15 code-review finding holds up under real execution. **One real, minor, non-security finding:** `_to_http_error()` only special-cases Keycloak's 400/409; a real 404 (e.g. `remove_user` targeting a non-member) falls through to a generic 503 "service unavailable," which is misleading to an org-admin even though the isolation guarantee itself holds (confirmed: the target user is never actually removed). See `poc/admin_routes_real_keycloak/README.md` for the full account, including a real, previously-unverified precondition this item confirmed (the `kronos-backend` service account's `manage-realm` role is in fact sufficient for the Organizations Admin API in Keycloak 26.2 — not documented anywhere before this pass). | `src/external/routes/admin.py`; `tests/unit/test_admin_routes.py`; `tests/integration/test_admin_routes_real_keycloak.py`; `poc/admin_routes_real_keycloak/` | Done — follow-up noted: `_to_http_error()`'s 404→503 fallback could be made more precise (e.g. a dedicated 404 branch), left as a real but low-severity, non-blocking polish item, not fixed in this pass to keep it scoped to verification per the V5 brief. |
| P1-16 | **Postgres and MinIO — the components the platform's actual custody guarantee depends on — remain single-instance with no HA/replication configured anywhere**, while this initiative spent real research effort on Kafka/Redpanda HA for the *stream ingest* layer (correctly concluded not worth adopting) without addressing the more load-bearing gap underneath it. Confirmed unchanged (§0 of the Kafka roadmap itself calls this "a real prioritization inconsistency" but no follow-up item was opened). | `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` §0; `docker/docker-compose.prod.yml` | L (Postgres HA/replication and MinIO multi-node/erasure-coding are both real infra projects, not quick fixes — likely needs its own scoped research pass first, mirroring how the Kafka question itself was handled) |

### P2 — nice-to-have / polish / lower-risk debt

| # | Gap | Where | Size |
|---|---|---|---|
| P2-1 | `mypy` baseline: 13 of the 29 errors cluster in `src/adapter/repository/postgres_sealed_batch.py`'s `_from_row()` — a `dict[str, object]` row shape forces every field access to `object`, producing cascading `arg-type`/`attr-defined`/`unused-ignore` noise. Read directly: not a live bug (the runtime values are correct; `_asdict()` from a real SQLAlchemy row always has the right types) — but a real, fixable type-precision gap (e.g. a `TypedDict` or per-field `cast()`) that's currently hiding real errors in noise, should a genuine `None`/wrong-type row ever occur. | `src/adapter/repository/postgres_sealed_batch.py:124-142` | S |
| P2-2 | Remaining ~7 mypy errors are `Missing type arguments for generic type "dict"` (`ism_tiering.py`, `ecs_field_registry.py`, `ism_manager.py`, `custom_rule_detector_provisioner.py`) and a few `no-any-return`/`no-untyped-def` — all mechanical, low-risk typing-hygiene debt, no evidence of a live bug in any of them. Three genuinely worth a closer look: `evidence_intake.py:732/737/746` (`Item "None" of "IsmLifecycleManager | None" has no attribute ...`) — confirmed these are guarded by an `if self._ism_manager is not None` check mypy can't narrow through a stored `self` attribute reassigned indirectly; a quick local-variable-narrowing fix would both satisfy mypy and remove a real (if currently prevented by call-site discipline) null-deref risk surface. | various, see mypy output | S |
| P2-3 | `src/external/routes/evidence.py` at 71% unit coverage — mostly exception/error-handling branches (quota-exceeded 413, validation 422, generic 500, retry-eligibility 409/422 branches) rather than the core autonomous-pipeline logic itself. Lower risk than P1-15 since these are defensive branches, not membership/role mutation, but still worth closing given CLAUDE.md §E's emphasis on this exact pipeline's correctness. | `src/external/routes/evidence.py` | S–M |
| P2-4 | Volatility3 module coverage stops at `pstree`/`psscan`. The sandboxed-runtime/worker-image/queue-routing infrastructure is proven for two plugins; extending to `malfind`/`netscan`/`dlllist`/`cmdline` is now mostly per-plugin wiring, not new architecture (confirmed: `_plugin_to_kind()`/`_build_artifact()` in `src/external/parsers/volatility.py` are already plugin-name-generic). | `src/external/parsers/volatility.py`; `docs/IMPROVEMENT_IDEAS.md` §1 | M per plugin |
| P2-5 | `kronos-attest case_report` still takes `events: list[dict]` from an offline audit-log export (`kronos_attest/report.py:71`) — confirmed by direct read, not fixed since `IMPROVEMENT_IDEAS.md` flagged it. For a platform whose flagship claim is court-admissible chain of custody, the report CLI not live-re-reading MinIO/Postgres/TSA at report time remains a real credibility gap. | `kronos_attest/report.py` | L |
| P2-6 | No real Kubernetes install has ever been attempted for `charts/kronos/` — `helm lint`/`helm template` pass (confirmed, including the new opensearch-security-init hook per I3), but `helm install` against a live cluster has never run. | `charts/kronos/`; `docs/IMPROVEMENT_IDEAS.md` §1 | L (needs a real or kind/minikube-class cluster) |
| P2-7 | Zero Playwright spec files exist despite a full `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` (254 lines) being written. Confirmed via `find` — no `playwright.config*`, no `*.spec.ts` under any `playwright` path in `frontend/`. The plan is real and detailed; none of it has been executed. | `docs/PLAYWRIGHT_E2E_TEST_PLAN.md`; `frontend/` | L |
| P2-8 | Frontend has zero `dark:` Tailwind classes anywhere — dark mode is not implemented, not just unaudited (confirmed via repo-wide grep, count 0). `IMPROVEMENT_IDEAS.md` framed this as "audit whether it's already covered"; it is not. | `frontend/src/` | M |
| P2-9 | CLAUDE.md §B.6's own "<5s unit suite" baseline is a confirmed, explained FAIL (9.36–10.85s, ~2x over even with `--no-cov`), attributed to legitimate suite growth (700→1316+ tests) rather than a regression. The baseline document itself (`CLAUDE.md`) has not been updated to reflect a realistic target, so this will keep showing up as a "FAIL" in every future audit unless the number in the doc is revised. | `CLAUDE.md` §B.6; `docs/NEXTGEN_SOC_ROADMAP.md` I5 | S (just update the documented baseline, e.g. to "<15s", with the real measured number as justification) |
| P2-10 | I2's Analyst-Workload metric was confirmed computable but not built; a related minor bug was found in passing and not fixed — playbook-driven (automated) triage transitions record `actor_username: "unknown"` instead of a real system-actor label, which would under/mis-count in any future workload metric built on this data. | `src/application/playbook_execution.py` identity resolution; I2 finding | S |
| P2-11 | MTTA (a real, weaker, honestly-computable proxy for MTTR — "time to first triage engagement") was confirmed feasible via real `DETECTION_TRIAGE_TRANSITIONED` audit rows but never built. True MTTR remains confirmed **not** honestly computable (no join key between a containment action and the Detection it responded to — `containment.action_*` audit events key on `user_id`/`session_id`, never `detection_id`). | `docs/NEXTGEN_SOC_ROADMAP.md` I2 | M (MTTA) / L (true MTTR needs a new join key, i.e. a schema change) |
| P2-11 (V7) | **V7 STATUS: RESOLVED.** `MeanTimeToAcknowledgeCalculator` (`metric_name="mtta_seconds"`) built, mirroring `FalsePositiveRateCalculator`'s audit-trail-driven shape: streams `AuditEventType.DETECTION_TRIAGE_TRANSITIONED` rows for the org, takes the *earliest* `occurred_at` per `detection_id` (first engagement, not verdict — a Detection can transition more than once), computes `first_triage_at - Detection.synced_at`. Aggregation mirrors the renamed SA-cycle-time calculator's own choice: mean, with min/max/median in `detail`. Honesty discipline matched exactly: a Detection with zero triage events contributes nothing (never a fabricated `0.0`); an org with no Detections, or none yet triaged, gets `value=None` + a plain-language `unavailable_reason`. `detection_id` is pulled from `event.details["detection_id"]` with a bare `uuid.UUID(...)` subscript (no try/except) — deliberately fail-loud, since `DetectionTriageService.transition()` always populates this field for a platform-written event, so its absence signals real corruption, not an honest gap (mirrors the same bare-subscript idiom already used in `playbook_actions.py`/`evidence_collection_action.py`/`ticket_sync_action.py`). 10 new unit tests (normal case, first-of-multiple-transitions, mean/min/max/median aggregation, mixed triaged/untriaged, unrelated-event-type filtering, org isolation, malformed-detection_id raises) — all passing against Pydantic-factory fixtures, no mocks. **Not wired into DI** (`src/external/dependencies.py` has zero `MetricRegistry`/`get_metric_registry` references for *any* of the 5 calculators today — confirmed by grep, not assumed; this is `metric_calculator.py`'s own documented, deliberate design, not an oversight this item introduced) — wiring all 5 together is real, legitimate follow-up scope once a concrete UI/route consumer exists, not fabricated here to look "integrated". True MTTR remains confirmed not honestly computable (unchanged from I2). | `src/application/metric_mtta.py`; `tests/unit/application/test_metric_mtta.py` | Done — DI wiring (`get_metric_registry()` in `dependencies.py`) intentionally left as follow-up alongside the other 4 already-unwired calculators, not done piecemeal for just this one. |
| P2-12 | No command palette, no cross-evidence unified timeline UI, no detection-health customer-facing dashboard, no rule-pack marketplace/catalogue UI, no usage-dashboard UI, no `DetectionSummaryService`/AI-assisted triage narrative — all confirmed absent via targeted grep of `frontend/src`/`src/`. All are real, named `IMPROVEMENT_IDEAS.md` §2/§4 product-value ideas, none started. Bundled here as one line since they're independent, additive product features rather than gaps in already-committed work. | `docs/IMPROVEMENT_IDEAS.md` §2/§4 | L each |

---

## §2 IMPROVEMENT_IDEAS.md reconciliation table

| Idea (§ in IMPROVEMENT_IDEAS.md) | Status | Reason |
|---|---|---|
| Wire the SIEM stack (Wazuh/Falco/fluent-bit) that never fired (§1) | **Partially done** | Q2/Q3/Milestone S fixed real, previously-undiscovered bugs in all three compose files and got fluent-bit to real dev-stage (a live record confirmed indexed in real dev-stack OpenSearch); Wazuh manager itself was never brought up live in the shared dev stack (host memory constraint, honestly deferred); the SA-detection-rule-pack side of "SIEM signal flowing in" is unaffected by this — Wazuh/Falco alerts still don't flow into KronOS's own Detection pipeline, only KronOS's own logs flow out to fluent-bit/OpenSearch. |
| `kronos-attest case-report` doesn't live-re-read MinIO/Postgres/TSA (§1) | **Still open** | Direct read of `kronos_attest/report.py:71` confirms `case_report()` still takes `events: list[dict]` from an offline export. |
| Volatility3 module beyond pstree/psscan (§1) | **Still open** | `src/external/parsers/volatility.py` module docstring itself still lists only `pstree`/`psscan` as run today. |
| Real Kubernetes deployment of `charts/kronos/` (§1) | **Still open** | I3 (2026-08-07) added real Helm wiring (ClamAV host, opensearch-security-init hook) and verified via `helm lint`/`helm template` only — no live cluster `helm install` has ever run, confirmed by I3's own "NOT verified against a real Kubernetes cluster" note. |
| Real browser E2E coverage (§1, Playwright plan) | **Still open** | Plan document exists (254 lines); zero spec files, zero Playwright config found. |
| AI-assisted triage narrative generation (§2) | **Still open** | No `DetectionSummaryService` or equivalent found anywhere in `src/`. |
| Real cross-evidence unified timeline view (§2) | **Still open** | No matching component found in `frontend/src`. |
| Detection-health customer-facing dashboard (§2) | **Still open** | I2's `MetricCalculator` framework (the stated prerequisite) now exists and is real-verified server-side, but no frontend consumer of it exists yet — the prerequisite landed, the feature didn't. |
| Rule-pack marketplace/sharing (§2) | **Still open** | No marketplace/catalogue surface found; `RulePack`/Cosign-signing (the stated prerequisite, C3) remains the only piece in place. |
| Cost/scale transparency dashboard (§2) | **Still open** | The stated prerequisite (tenant-quota work) is now live (§1 confirms `StorageQuotaGate` actively enforces it), but no usage-dashboard UI consumes it yet. |
| A real migration tool (Alembic) (§3) | **Done (Milestone V4)** | Real `alembic` adoption + verified baseline migration + `db-migrate` boot-sequence integration, replacing `create_tables()`-only schema management — see P1-12's "V4 STATUS" row and `docs/DATABASE_MIGRATIONS.md`. |
| Cached/rate-limited layer for `TenantUsageService` (§3) | **Still open, now genuinely live (not hypothetical)** | Confirmed `StorageQuotaGate` calls the uncached query on every real upload today — see P1-13. |
| `OpenSearchClient.bulk_index`'s silent partial-failure mode (§3) | **Done** | Direct read of `src/adapter/opensearch/client.py:115-157` shows `bulk_index()` now inspects every `_bulk` response item and raises a `StorageError` (with the full list of failed documents in `context`) on any partial failure — no longer silent. This closes a real, previously-flagged forensic-data-loss risk. |
| Real Firecracker microVM isolation for Plaso (§3) | **Still open** | `FirecrackerLauncher`'s own class docstring: "Spawns the Plaso worker subprocess" — still a subprocess-in-container, not a hardened microVM. |
| Structured-artifact presentation layer (§3) | **Still open** | No typed-by-`kind` renderer registry found in `frontend/src`; `StructuredArtifact.content` is still opaque JSON with no dedicated UI. |
| Real CI-capable security-enabled compose profile (§3) | **Still open, now blocking more things than when written** | `docker-compose.test.yml` unchanged (`DISABLE_SECURITY_PLUGIN=true`); I1 independently re-confirmed this blocks CI wiring for the detection-validation harness too — see P1-14. |
| Status-color-language design pass (§4) | **Still open** | Cosmetic/UX, out of scope for this audit's depth of check; no evidence of a deliberate pass having happened. |
| Empty states / first-run experience (§4) | **Still open** | Not checked in depth (low severity, UX-only). |
| Command palette (§4) | **Still open** | No `cmdk`/command-palette component found in `frontend/src`. |
| Real-time collaborative presence (§4) | **Still open** | Not checked in depth; no evidence found, matches doc's own framing as a longer-horizon idea. |
| Dark mode (§4) | **Still open, confirmed absent (not just unaudited)** | Zero `dark:` Tailwind classes anywhere in `frontend/src` — see P2-8. |
| Dashboards embed visual-seam polish (§4) | **Not checked** | Requires visual/manual inspection this audit didn't perform; no code-level signal either way. |
| Multi-org user support (§5) | **Still open** | `KeycloakTokenValidator` (`src/external/middleware/keycloak_auth.py`) still reads a single `org_id` from the JWT's organization claim (`org_info["id"]`, singular) — the "backend just reads the first org today" framing is confirmed unchanged. |
| Detection-to-evidence-to-report one-click workflow (§5) | **Still open** | The individual pieces exist (H3's `evidence_collection_action.py`, `kronos_attest`'s report generation, I2's metrics) but no single guided flow chains them — confirmed via grep, no orchestrating service/route found. |
| Track D (sandboxed third-party parser execution) (§5) | **Still open, deliberately** | No `SandboxedExternalParser` or manifest/Cosign-gate mechanism found in `src/`; explicitly gated behind first-party modules being solid, per CLAUDE.md §G.3 — see §4 below. |

---

## §3 Proposed execution plan — Milestone V (continuing the roadmap's letter series)

Grouped in priority order. Objectives only — no full agent briefs (per this
task's own scope boundary); the orchestrator writes those after reviewing
this document.

**V1 · Prod OpenSearch TLS-scheme fix (P0-1).** Resolve whether
`docker-compose.prod.yml`'s `OPENSEARCH_URL=http://...` is a real bug (prod
literally cannot reach a TLS-only OpenSearch as configured) or is masked by
an untracked reverse-proxy/sidecar TLS termination — either fix the scheme
or document why it's safe, with a real `docker compose config` +
connectivity check as proof. Highest priority: it's the one finding in this
audit with a plausible path to an actual outage or plaintext-internal-traffic
exposure in a deployment that believes itself production-configured.

**V2 · Close the "built but never called" loop for Q/R connectors (P1-1,
P1-2, P1-8).** Three related items that all share one root cause — real,
tested connector logic sitting behind a DI/wiring gap with no real trigger:
(a) a `SyncDetectionToSiemAction` `PlaybookAction` (or equivalent route) so
at least one of Splunk/CEF/Sentinel actually fires from a real workflow;
(b) a Celery beat task calling `IntegrationSourceIngestService.run_poll_cycle()`
for Defender, with the per-task-client safety work the Milestone S notes
already flagged as necessary; (c) flip `SourceCursorRepository`'s live DI
default to `PostgresSourceCursorRepository` so poll cursors actually survive
a restart. Do (c) first — it's the smallest, de-risks (b), and has zero
design ambiguity.

**V3 · CI-realistic security-enabled compose profile (P1-14).** Named
independently by both roadmaps (I1 and `IMPROVEMENT_IDEAS.md`) as the single
highest-leverage infra fix — unblocks CI wiring for the detection-validation
harness, all six Q/R connectors' real dev-stage verification, and any future
security-plugin-dependent test, instead of everything continuing to run
manually against the shared dev stack forever.

**V4 · Real migration tooling — Alembic adoption (P1-12).** The
create-all-only-adds-tables risk has been accumulating for months across
multiple initiatives and is now large enough (quota fields, cursor tables,
risk-score columns, etc.) that a real deployed environment attempting to
pick up this branch's schema changes without hand-written `ALTER TABLE`s is
a genuine, not theoretical, risk. Do this before the schema grows further.

**V5 · Real-Keycloak verification for org-admin membership routes (P1-15).**
Apply the same verification-first bar already applied to the six Q/R
connectors to `admin.py`'s invite/role-change/remove-member flows — no bug
is suspected (code review found none), but these routes are exactly the
kind of security-relevant surface CLAUDE.md §F's discipline exists for, and
they are currently the biggest verification gap of that class left in the
codebase.

**V6 · Sink acknowledgement depth — Splunk `ackId` polling, Sentinel
ingestion confirmation (P1-3, P1-4).** Lower priority than V1/V2/V3 because
the current honest `ACKNOWLEDGED`/`UNACKNOWLEDGED` modeling is not
*wrong*, just less granular than it could be — worth doing once the sinks
are actually wired into a real workflow (V2), not before.

**V7 · Detection-latency metric relabeling + MTTA build (P1-11, P2-11).**
Cheap, high-integrity-value: rename/re-scope the MTTD metric's UI-facing
label to avoid a customer-facing metric quietly meaning something narrower
than its name implies, and build the already-proven-feasible MTTA proxy
metric using the same `MetricCalculator` framework.

**V8 · fluent-bit severity fix + nginx access-log producer (P1-5, P1-6).**
Both small, both real, both flagged-not-fixed twice now (originally and at
Milestone S) — low effort, closes two genuinely dangling loose ends in the
SIEM overlay stack before it's revisited again.

**V9 · SA log-type parser coverage expansion (P1-10).** Larger, should be
sequenced by real customer log-source priority (a scoping question for the
project owner, not purely a technical one) rather than started blind —
flagged here as next in priority order but likely needs its own
requirements pass before an agent brief can be written.

**V10 · Postgres/MinIO HA research pass (P1-16).** Mirrors how the
Kafka/Redpanda question itself was handled — a dedicated research pass
first (what's the real failure mode being protected against, what's the
minimum real-HA topology for each), before any implementation commitment.
Sequenced last among P1s because it's the largest and most infrastructure-
disruptive item on this list; do not rush it the way Kafka was correctly
not rushed.

**Mypy/coverage hygiene (P2-1, P2-2, P2-3)** are small enough to fold into
whichever of V1–V10 happens to touch the same files, rather than dispatching
standalone agents for typing cleanup alone.

---

## §4 Explicitly NOT in scope / deliberately deferred

These are real, named gaps this audit re-confirmed — stated here so a
future audit doesn't re-flag them as newly missed:

- **CrowdStrike/SentinelOne-class long-lived streaming-worker EDR
  sources.** Explicitly deferred past the entire P/Q/R/S milestone set per
  the Kafka roadmap's own §0 research (a structurally heavier integration
  shape — a supervised, kept-alive HTTP connection, not poll-on-schedule or
  webhook-push). Correct to defer until the current poll+cursor and
  webhook-push patterns are both further exercised in production; revisit
  once V2/V9 land.
- **Track D — sandboxed third-party/customer-supplied parser execution.**
  Confirmed still not started (`SandboxedExternalParser` doesn't exist).
  CLAUDE.md §G.3 gates this behind first-party modules being solid, and
  that condition genuinely isn't met yet (only 4/23 SA log types have
  first-party coverage — P1-10). Do not build a shortcut sandboxed-execution
  path "just this once" per CLAUDE.md's own explicit instruction.
- **Redis's ~1s AOF-fsync loss window on the unsealed backlog.** A real,
  bounded, already-accepted risk per the Kafka roadmap's own §0 (bounded by
  `SealingTriggerPolicy`'s short intervals) — not re-opened here; only
  re-flag if a `SealingTriggerPolicy` interval materially lengthens.
  P1-16 (Postgres/MinIO HA) is a different, larger, *not*-yet-accepted risk
  and should not be conflated with this one.
- **Kafka/Redpanda adoption.** Re-confirmed correctly not adopted; no new
  evidence surfaced during this audit that changes that verdict (§0 of the
  Kafka roadmap already documents the trigger conditions that would
  re-open it — none are true today).
- **QRadar/XSOAR/TheHive sink connectors, STIX/TAXII-as-producer.** Real,
  valid fourth-tier candidates per the Kafka roadmap's own prioritized
  build order — not started, correctly not yet in scope given the
  higher-priority "built but never called" gap (P1-1) in the three sinks
  that *do* exist.
- **UX/visual polish items** (status-color design pass, empty states,
  dashboards-embed visual seam, real-time presence) — real per
  `IMPROVEMENT_IDEAS.md` §4 but explicitly lower priority than any
  P0/P1 item above per this audit's own severity ordering; not scheduled
  into Milestone V.
- **Cost/dashboard/marketplace/AI-narrative product features**
  (§2/§4 of `IMPROVEMENT_IDEAS.md`, bundled as P2-12) — real, additive
  product value, not gaps in already-committed work; left for a future,
  separate product-prioritization pass rather than folded into this
  gap-closing milestone.

---

## V1 STATUS (2026-08-10): DONE

Orchestrator independently re-confirmed P0-1 before fixing (not just
trusted the audit's own claim): direct read of
`docker/opensearch/opensearch.yml` confirmed no
`plugins.security.ssl.http.enabled` override exists, so the security
plugin's default (HTTPS-only) applies; direct read of
`docker-compose.dev.yml` confirmed its own OpenSearch-facing vars
correctly use `https://` throughout, for the identical image; and,
beyond what the audit itself flagged, a third occurrence was found in
the same pass — `opensearch-security-init`'s own `OS_BASE` also used
`http://`, meaning the security bootstrap step itself could never have
reached a real HTTPS-only OpenSearch either, not just kronos-backend/
celery-worker's own runtime traffic.

Fixed all three (`docker/docker-compose.prod.yml` lines ~167, ~272,
~387 pre-fix) to `https://opensearch:9200`. No other setting needed to
change alongside this: app-side cert verification is already correctly
relaxed for OpenSearch's self-signed demo cert
(`verify_certs=False`, `src/external/startup.py`), and
`provision_opensearch_security.py` already builds its own
`ssl.CERT_NONE` context. `docker compose -f docker-compose.prod.yml
config` re-validated clean (exit 0, real required vars supplied) after
the fix.

---

## V2 STATUS (2026-08-10): DONE — all three sub-items (a/b/c)

Closed the "built but never called" loop for P1-1/P1-2/P1-8 in the order
the audit itself specified ((c) first, smallest/de-risks (b)).

**(c) — P1-8, `SourceCursorRepository`'s live default.** Confirmed the
same pattern every other Postgres-backed repository in
`src/external/dependencies.py` already uses (e.g. `_org_quota_repository`):
the raw module-level literal stays `InMemorySourceCursorRepository()`
(the honest "no real startup wiring has run yet" default), and the real
flip happens in `wire_dependencies_async()`/`wire_dependencies_sync()` —
`configure_dependencies()` gained a new `source_cursor_repository`
parameter (same "`None` keeps current binding" idiom as
`org_quota_repository`), `wire_dependencies_async()` now builds a real
`PostgresSourceCursorRepository(engine)` and passes it in, and both
`wire_*` functions now call `PostgresSourceCursorRepository.create_tables()`
alongside every other repository's own table creation. Real Postgres
round-trip proof (fresh engine writes, a **completely separate** fresh
engine/repository instance reads the same cursor back, then updates it)
captured in `poc/v2_connector_wiring/source_cursor_postgres_default/`
against the real shared dev-stack `docker-postgres-1`.

**(b) — P1-2, Defender poll beat task.** New `src/external/celery_defender.py`
(`run_defender_poll_cycle()`) + a new `poll_defender_alerts` Celery beat
task (`src/external/celery_app.py`, every 10 minutes, `q.index` queue).
Design choice (full reasoning in `celery_defender.py`'s own docstring and
the PoC's README): a **fresh, task-scoped `httpx.AsyncClient` per poll
cycle**, not a dedicated long-lived event-loop thread — Microsoft's own
v2.0 client-credentials docs (fetched 2026-08-10) show a real
`expires_in: 3599` (~60 min) token lifetime, so losing the FastAPI
process's cross-cycle token cache at a 10-minute poll interval costs one
extra cheap token POST per cycle, a strictly smaller cost than risking
the "Future attached to a different loop" failure class
`wire_dependencies_sync()`'s own 2026-08-09 comment flagged as the reason
Defender was never wired into Celery in the first place. Two new
`Settings` fields (`defender_poll_org_id`, `defender_poll_source_id`)
supply the explicit org attribution a poll-mode source needs (no honest
per-alert attribution signal exists in the payload itself). Real,
two-consecutive-invocation proof — real Postgres cursor persistence +
advancement, real Redis stream production, real per-cycle audit trail,
and the honest "not configured" skip path — captured in
`poc/v2_connector_wiring/defender_poll_beat_task/`, using a real local
`httpx.MockTransport` stand-in for Entra ID/Graph (never a live Microsoft
call) that the real hardcoded production hostnames are asserted against.

**(a) — P1-1, `DetectionSinkPushService` has a real caller.** New
`SyncDetectionToSiemAction` (`src/application/sync_detection_to_siem_action.py`),
mirroring `SyncDetectionTicketAction`'s exact shape (H4's own precedent):
constructor-injected collaborators, tenant-scoped Detection lookup, and
(unlike the ticket action) zero self-auditing — it delegates entirely to
`DetectionSinkPushService`, which already logs
`SINK_PUSH_ATTEMPTED`/`_EXECUTED`/`_FAILED` around the real outbound call.
One instance is registered per configured sink (`action_name` is
`sync_detection_to_siem_{splunk,cef,sentinel}`), so a deployment with more
than one sink configured gets one action per sink, never a silent
registry-overwrite. Also closed a larger, previously-undiscovered
adjacent gap while wiring this in: `PlaybookActionRegistry`/
`PlaybookExecutionService` had **zero DI wiring at all** anywhere in
`src/external/dependencies.py` before this — every concrete
`PlaybookAction` (including the two that already existed,
`TransitionDetectionTriageAction`/`LogNotificationAction`) only ever got
registered inside test files. New `get_playbook_action_registry()`/
`get_playbook_execution_service()` FastAPI dependencies now build a real
registry with all real, currently-wireable actions registered (Splunk/
CEF/Sentinel `SyncDetectionToSiemAction`s only when their respective sink
is actually configured; `SyncDetectionTicketAction` is deliberately still
NOT registered — no concrete `TicketingSystem` implementation exists
anywhere in this codebase yet, and registering it against a fabricated
one would be exactly the "plausible code without a captured real run"
failure mode CLAUDE.md §F exists to stop). No new HTTP route was added to
actually *dispatch* a `Playbook` from a real request — that gap (there is
still no route anywhere that calls `PlaybookExecutionService.execute()`)
is real, larger than this item's own scope, and not closed here; flagged
as a candidate follow-up, not silently left implied-fixed.

**Verification:** fresh `pytest tests/unit -q` (no stash needed — tree
was clean at `5b38559` before this pass started) baseline
**1678 passed, 1 skipped**, 89.94% coverage; after this pass,
**1701 passed, 1 skipped**, 89.82% coverage (23 new tests, zero
regressions). `mypy src` baseline and post-change both **29 errors in 10
files**, identical set, zero new. `ruff check`/`black --check` clean on
every touched file.

**What was NOT verified, and why:** the literal `@celery_app.task`
decorator/dispatch glue for `poll_defender_alerts` itself was not
separately unit-tested — `src/external/celery_app.py` is excluded from
this repo's own coverage config (`pyproject.toml`'s `omit` list, "needs a
real Celery broker"), matching the pre-existing convention that none of
the other 6 beat tasks in that file have a direct unit test either; the
underlying function it delegates to (`run_defender_poll_cycle()`) is
both unit-tested (fast "not configured" branches) and proven for real
end-to-end via the PoC. Splunk/CEF/Sentinel `SyncDetectionToSiemAction`
registration was verified only for Splunk in the wiring test (CEF/
Sentinel follow the identical code path — same `if sink is not None and
mapper is not None` shape — so a second/third near-duplicate test was
judged low-value, not skipped for lack of trying). Sentinel/CEF sinks'
own HTTP-speaking behavior is unchanged and already covered by their own
pre-existing dedicated tests, not re-verified here.

---

## V3 STATUS (2026-08-10): DONE (local verification) — GHA-hosted-runner fit asserted, not CI-confirmed

Closed P1-14. Real resource-fit investigation before committing to an
approach, per this item's own brief: measured the already-running real dev
stack (`docker stats`, not torn down) to get real OpenSearch-security-ON
vs. baseline numbers (opensearch 729MiB, keycloak 369MiB, clamav — the
heaviest service in the whole dev stack — 949MiB), then read I1's own
finding text closely to determine the real requirement was OpenSearch DLS
+ a real Keycloak-issued tenant context, **not** full mTLS/browser SSO
(`step-ca`/`tls-init`/nginx exist only for the interactive Dashboards-SSO
flow, which neither I1's harness nor this item's own minimum bar uses).
Scoped the fix accordingly: enable OpenSearch security + real Keycloak org
provisioning in `docker/docker-compose.test.yml`; deliberately leave out
`step-ca`/TLS/ClamAV/tusd/nginx (not needed, and ClamAV alone would have
added more RAM than every other new service combined).

**Real, measured scoped-stack footprint** (fresh boot, `docker stats`):
opensearch 933MiB, keycloak 548MiB, postgres 35MiB, redis 3.7MiB, minio
105MiB — **~1.63GB total**, comfortably inside a standard GHA runner's 7GB.
Real boot timing: base services healthy in 41s, full provisioning +
verification in 46s wall time (warm local image cache — see PoC README for
why this number can't be directly read as a GHA-cold-pull number).

**Design decision:** `.github/workflows/security-integration-tests.yml` is
a new, additive, **nightly cron + `workflow_dispatch`** workflow — not a
per-PR gate, and not a replacement for the existing lightweight
`integration-tests.yml`. This agrees with I1's own original recommendation
but for a fuller, evidence-based set of reasons (tax proportionality —
only security-plugin-dependent code paths need this; real GHA cold-image-pull
risk this local measurement can't rule out; matches this initiative's own
established "local now, scoped nightly CI follow-up" precedent) — full
reasoning and the real numbers behind it in
`poc/ci_security_enabled_stack/README.md`.

**Real bugs found while building this** (not anticipated from
source-reading alone; full accounts in the PoC README): (1) OpenSearch
2.12.0+ (this file's own pinned 2.13.0, not dev's 2.11.1) refuses to boot
at all without `OPENSEARCH_INITIAL_ADMIN_PASSWORD` — a genuine version-
specific behavior change that copying dev's config verbatim would have
missed entirely; (2) Compose override files concatenate `ports:` rather
than replace them — needed the compose-spec `!override` merge tag for the
PoC's own local, non-shipped port remap; (3) OpenSearch's real
`roles_key=dashboard_roles` config (`scripts/provision_opensearch_security.py`)
needs the `kronos-dashboard-roles` client scope explicitly attached to any
new `directAccessGrantsEnabled` client — not one of the realm's default
scopes, and every real shipped client has direct grants disabled, so this
had never been exercised before.

**What was verified for real, locally, and captured** (MINIMUM BAR, all
three; `poc/ci_security_enabled_stack/output.txt`, 11/11 checks, and
independently re-run as `tests/integration/test_security_enabled_stack.py`,
3/3 passed against the same live stack): (a) OpenSearch's security plugin
genuinely enabled (not `DISABLE_SECURITY_PLUGIN=true`) and DLS/tenant-role
provisioning via the real, unmodified `provision_opensearch_security.py`;
(b) a real Keycloak instance with the real `kronos-realm.json` import and a
real provisioned org (`kronos-test`, via the real, unmodified
`provision_keycloak_org.sh`) issuing a real JWT that
`KeycloakTokenValidator` (previously never exercised against a live
Keycloak anywhere in this repo — it's in `pyproject.toml`'s coverage `omit`
list for exactly that reason) genuinely validates, including rejecting a
tampered token; (c) an I1-equivalent tenant-isolation proof — two real
users in two real, different Keycloak Organizations each see only their
own org's document through OpenSearch's real DLS enforcement.

**What remains unconfirmed, explicitly:** this item could not trigger an
actual GitHub Actions run from this sandbox. The GHA-hosted-runner resource
fit is asserted from this host's own real measurements (docker stats on an
identical scoped stack) plus image-size arithmetic for the cold-pull
question, not confirmed by a live GHA execution — mirrors this whole
initiative's own "prod stage: compose config validated, no live cluster"
honesty pattern. `docker compose -f docker-compose.test.yml config` and
`-f docker-compose.dev.yml config` both re-validated clean after this
change; `docker-compose.prod.yml` was not touched by this item.

**Verification:** fresh `pytest tests/unit -q` (real `git stash -u` +
re-run, not trusted from memory) — baseline **1701 passed, 1 skipped**,
89.82% coverage (matches V2's own recorded numbers exactly); after this
pass, **identical: 1701 passed, 1 skipped**, 89.82% coverage (zero new
unit tests — this item is infra/`poc`/`tests/integration`-only, zero
`src/` changes). `mypy src` baseline and post-change both **29 errors in 10
files**, identical set, zero new. `ruff check`/`black --check` clean on
every touched Python file (`poc/ci_security_enabled_stack/*.py`,
`tests/integration/test_security_enabled_stack.py`).

**Own PoC containers/volumes torn down** (`kronos-poc-cisec-*` project) at
the end of this pass; the shared `docker-compose.dev.yml` stack and
`portainer_agent` were only ever observed (`docker stats`), never
started/stopped/modified.

---

## V5 STATUS (2026-08-10): DONE — real bug NOT found (isolation holds); one minor error-mapping finding

Closed P1-15. Applied CLAUDE.md §F's verification-first bar to
`src/external/routes/admin.py`'s `invite_user`/`update_user_role`/
`remove_user` — previously exercised only against a mocked `httpx`
(`tests/unit/test_admin_routes.py`).

**Instance used:** the shared, already-running `docker-compose.dev.yml`
Keycloak 26.2 (`docker-keycloak-1`, confirmed healthy via `docker ps`,
reachable at `http://localhost:8080`), per this initiative's own standing
instruction to use it directly rather than standing up a new one. Its real
`kronos` realm and real `kronos-dev` org (three real users) were never
touched — this item created and fully deleted its own two throwaway orgs
(`kronos-v5-test-a`/`kronos-v5-test-b`) and throwaway users, independently
re-verified clean afterward via a fresh Admin API read
(`poc/admin_routes_real_keycloak/output.txt`).

**Real precondition confirmed before writing anything** (not assumed): the
`kronos-backend` confidential client's service account — the identity
`admin.py`'s own `_get_service_account_token()` authenticates as — is only
granted `manage-users`/`view-users`/`manage-realm`/`view-realm` in
`kronos-realm.json`, none of which is named "manage-organizations." Tested
directly against the real running Keycloak: a real client-credentials token
for `kronos-backend` genuinely lists organizations and reads org members
with 200s. This confirms `manage-realm` is in fact sufficient for the
Organizations Admin API in Keycloak 26.2 — a real assumption every one of
`admin.py`'s Keycloak calls depends on, never independently confirmed
before this pass.

**What was actually run, real, against real Keycloak** (all six routes
called as real coroutines, zero `httpx` mocks; `tests/integration/
test_admin_routes_real_keycloak.py`, 6/6 passed):

1. `invite_user` — real user created, real org-A membership confirmed via a
   **second, independent** Admin API call (never trusted from the route's
   own return value), confirmed NOT linked to org B, confirmed the
   `analyst` realm role, confirmed the `ORG_USER_INVITED` audit event by
   reading it back from a **fresh** `PostgresAuditLogRepository` connection
   (testcontainers Postgres, not the in-process writer).
2. `invite_user` cross-org negative case — an org-A admin attempted to
   reuse an email that is a real member of org B only: real 409
   (AUTH-003/AUTH-011), confirmed the org-B user's role/membership
   untouched.
3. `update_user_role` — real role change, confirmed via a fresh Admin API
   read that the stale managed role was removed and the new one persisted
   (`_set_realm_role`'s set-replace semantics verified both directions),
   confirmed the `ORG_USER_ROLE_CHANGED` audit event read back fresh.
4. `update_user_role` cross-org negative case — real 403 from
   `_assert_user_in_org`, confirmed the target's real roles were completely
   unchanged, confirmed no audit event was written for the rejected
   attempt.
5. `remove_user` — real org-A membership removal confirmed via a fresh
   Admin API read. **Documented, not assumed:** the realm-level account
   (`GET /users/{id}`) still exists afterward — `remove_user` only ever
   DELETEs the org-membership link, never the account itself.
6. `remove_user` cross-org negative case — a standalone probe (outside the
   pytest assertion's `>= 400` check) captured the **exact** real value:
   `503` ("Keycloak Admin API returned server error"). Keycloak's own real
   response to this DELETE against a non-member is a 404;
   `_to_http_error()` only special-cases 400/409, so this real 404 falls
   through to the generic 503 branch. **The isolation guarantee genuinely
   holds** (the org-B user remains a real member of org B in both runs) —
   this is a real, minor, non-security error-mapping imprecision, not a
   tenant-isolation bug.

**No tenant-isolation bug found** — the original P1-15 code-review finding
("correctly org-scoped ... no tenant-isolation bug found") holds up under
real execution against a real Keycloak, across all three routes and all
four required scenarios (invite/role-change/remove/cross-tenant negative).

**Real fixture-only finding along the way:** this realm's Keycloak rejects
org creation with `domains: []` ("You must provide at least one domain") —
`scripts/provision_keycloak_org.sh` nominally tolerates an empty
`ORG_DOMAIN`, but every real invocation in this repo (dev's
`ORG_DOMAIN=kronos.dev`, V3's `org-b.kronos-ci.test`) always sets one, so
this path had never actually been exercised. Not a bug in `admin.py`
(which never creates orgs) — just this item's own test fixture needing a
real domain like every other real caller in the repo.

**Verification:** fresh `pytest tests/unit -q` (real `git stash -u` +
re-run, personally observed, not reconstructed from memory) — baseline
**1701 passed, 1 skipped**; after this pass, **identical: 1701 passed, 1
skipped** (zero new unit tests — this item is `tests/integration`/`poc`-only,
zero `src/` changes). Full `tests/integration` suite: **123 passed, 1
skipped** (includes this item's own 6 new tests; the 1 skip is pre-existing
and unrelated — `testcontainers[minio]` path, not this item's Keycloak
skip gate, which did not trigger since the real Keycloak was reachable).
`mypy src` baseline and post-change both **29 errors in 10 files**,
identical set, zero new (no `src/` files touched). `ruff check`/
`black --check` clean on every touched Python file
(`tests/integration/test_admin_routes_real_keycloak.py`) and on
`pyproject.toml`'s new `admin_routes_real_keycloak` marker registration.

**Real cleanup confirmed:** a fresh Admin API read after the run shows only
the pre-existing `kronos-dev` org and its three real users
(`admin`/`analyst`/`case-lead`), plus one unrelated, pre-existing
`poc-h2-user-*` account from an earlier, different milestone's PoC that
this item did not create and did not touch — zero `kronos-v5-*`/`v5-*`
debris remained (`poc/admin_routes_real_keycloak/output.txt`).

---

## V6 STATUS (2026-08-14): DONE — Splunk built-and-verified, Sentinel design-only (real constraint unchanged)

Closed P1-3 (Splunk HEC `ackId` indexer-acknowledgement polling) for real;
P1-4 (Sentinel ingestion confirmation) designed only, per its own real,
unchanged "no Azure subscription available" constraint (same one R4 hit).

**P1-3 — Splunk HEC `ackId` polling, built and verified against a real
Splunk container.** `SplunkHecSink` gained opt-in `enable_indexer_ack`
support: a real `X-Splunk-Request-Channel` GUID header on every push when
enabled, real `ackId` parsing from the push response, and a new
`check_ack_status()` method that POSTs the real `/services/collector/ack`
endpoint. **Design decision** (full reasoning in the sink's own module
docstring): synchronous polling inside `push_events()` with a real,
bounded, per-sink-configured timeout (`ack_poll_timeout`, default 30s;
`ack_poll_interval`, default 1s) — resolving to a genuine **third**
`SinkAckStatus`, `ACK_PENDING` (`src/domain/integration_sink.py`), if the
timeout elapses before confirmation. Never raises on a timeout (a real,
expected, benign outcome of asynchronous indexing) and never fabricates
`ACKNOWLEDGED`. `check_ack_status()` is also the separate, explicit
out-of-band mechanism a caller can use to resolve a pending ack later
without blocking. `DetectionSinkPushService`/`SinkPushResult.all_acknowledged`
required **zero code changes** — both already treat any non-`ACKNOWLEDGED`
status as unconfirmed by construction, so `ACK_PENDING` is handled
correctly without a special case.

**Real research before writing any code (CLAUDE.md §F):** confirmed by
re-fetching `splunk-ansible`'s own current `inventory/environ.py`
`getHEC()` source that no `SPLUNK_HEC_*` env var can enable `useACK` — it
genuinely requires Splunk Web or a real REST call
(`POST .../data/inputs/http/<name> -d useACK=1`, Splunk's own documented
cURL-management page, fetched this pass). A real ack-enabled HEC token was
created via that exact real REST call against a fresh
`kronos-poc-splunk-hec-ack` container (`splunk/splunk:9.3.3`, same pinned
digest R2 already verified). The real wire contract was then hand-verified
with `curl` *before* touching `splunk_hec_sink.py`: `ackId` (not `ackID`)
is the real response key; a push without the channel header against a
`useACK=1` token returns a real, distinct `400`/`{"code":10,"text":"Data
channel is missing"}`; the ack-poll response shape is
`{"acks":{"<id>":true|false}}`; and — a real, previously-undocumented-in-
this-repo behavior confirmed by hand — **once an `ackId` resolves `true`,
Splunk deletes its status; re-querying the same id returns `false` again**
(matches Splunk's own documented language, not a bug). An unrecognized/
malformed channel on the ack endpoint returns a further real, distinct
`400`/`{"code":11,"text":"Invalid data channel"}`.

**Real captured proof** (`poc/splunk_hec_ack_polling/`, 17/17 checks
passed, first real run, no bug found): a real push through the real,
unmodified production `SplunkHecSink` returned a real `ackId`; the real
poll sequence observed was **`false` at t≈0.004s, `true` at t≈1.02s**
(`ack_poll_attempts=2`, `ack_poll_elapsed_seconds≈1.02`) — a genuine,
timing-dependent confirmation, not assumed instant. A second scenario with
a deliberately near-zero `ack_poll_timeout=0.001` produced a real
`ACK_PENDING` (one real poll attempt observing `false`, no exception); a
third scenario then resolved that same pending `ack_id` to `true` via the
separate `check_ack_status()` call after a real 2-second wait, proving the
out-of-band mechanism works independently of `push_events()`. Real negative
cases (missing channel → `code:10`; invalid channel → `code:11`) were also
proven, along with full `DetectionSinkPushService` orchestration whose
`SINK_PUSH_EXECUTED` audit row was read back fresh from Postgres with the
honestly-confirmed `ack_status: "acknowledged"`, and the audit hash chain
verified intact.

**P1-4 — Sentinel ingestion confirmation: designed, explicitly NOT run.**
Same real constraint R4 itself already hit, re-confirmed this pass (`which
az` → no output; `env | grep -i azure` → no output — no Azure CLI, no
`AZURE_*` credentials, no path to a real DCE/DCR/Log Analytics workspace in
this sandbox). Per this item's own brief, no stand-in "confirmation" was
built against a fake client — a stand-in has no real DCR transform
pipeline to confirm anything against, so a passing PoC against one would
prove nothing real and would itself be a fabricated-honesty failure. Instead,
`sentinel_sink.py`'s own module docstring was extended with a real,
cited-against-current-docs design: the real `azure-monitor-query` package
(current major `2.0.0`), `azure.monitor.query.aio.LogsQueryClient.query_workspace(workspace_id,
query, timespan=...)` (real method signature/return shape —
`LogsQueryResult`/`LogsQueryStatus.SUCCESS`/`.tables` — fetched from
Microsoft's own current SDK overview doc this pass), a real KQL query
(`KronOSDetection_CL | where FindingId == '<finding_id>' | count`, using
`FindingId` — the mapper's own real, non-nullable, already-documented
column — as the correlation key), and a named, real, additional required
Azure RBAC role (`Log Analytics Reader` on the destination workspace,
distinct from ingestion's own `Monitoring Metrics Publisher` DCR role — a
real, separate grant an operator must make). Designed as a **standalone
class outside the `IntegrationSink` hierarchy**
(`SentinelIngestionConfirmationChecker`) with a real, justified reason: the
Query SDK takes an `azure-identity` `TokenCredential` directly, not this
package's own `SinkAuthenticator`/`SinkAuthParams` contract, so it
genuinely cannot be a `push_events()`-shaped method on `SentinelHttpSink`.
**No `src/` class was written, no dependency was added to `pyproject.toml`,
and no stand-in/mocked client was built** — closing this for real needs a
real Azure subscription with a real Log Analytics workspace + DCR + app
registration holding both RBAC roles.

**Hard invariant re-verified by direct code reading (not assumed):** the
`SinkAck`/`SinkAckStatus`/`IntegrationSink` ABC's core honesty property —
a caller can never mistake "accepted" for "confirmed" — was strengthened,
not weakened, by this work. Every `raise IntegrationSinkError(...)` site in
`splunk_hec_sink.py` was counted by hand: **11 total** (7 pre-existing and
unchanged from R2 — empty batch, wrong-transport-family payload, oversized
event, unreachable backend, non-2xx response, no usable code/text, and
non-zero code — plus **4 new this pass**: missing `ackId` when
`enable_indexer_ack=True`, and 3 inside the new `check_ack_status()`
covering unreachable backend, non-2xx response, and a malformed/non-dict
`acks` body). Every one is tied to a specific real, never-fabricated
cause. The only two non-exceptional returns from `push_events()` are the
pre-existing `ACKNOWLEDGED` path (code==0, ack disabled or confirmed
within the poll window) and the new `ACK_PENDING` path (poll timeout,
indexer confirmation not yet obtained) — no path can return `ACKNOWLEDGED`
without either a real `code==0` (ack disabled) or a real
`indexer_confirmed=True` (ack enabled) actually observed.

**Verification:** fresh `pytest tests/unit -q` (real `git stash -u` +
re-run, personally observed) — baseline **1701 passed, 1 skipped**, 90.14%
coverage (matches V5's own recorded test count exactly; coverage % differs
by a fraction of a percent from V5's own recorded 89.82%, consistent with
normal cross-run coverage-tool rounding on an unchanged tree, not a real
discrepancy); after this pass, **1715 passed, 1 skipped**, 90.19% coverage
(14 new tests — 13 in `tests/unit/adapter/test_splunk_hec_sink.py`
covering the channel header, `ackId` parsing, confirmed-within-window,
timeout-to-`ACK_PENDING`, missing-`ackId` rejection, ack-URL derivation,
and `check_ack_status()`'s own success/failure/malformed-response paths;
1 in `tests/unit/application/test_splunk_hec_sink_wiring.py` proving the
three new `Settings` fields actually reach the real `SplunkHecSink`
constructor — zero regressions). Fixing the DI wiring change also required
updating two pre-existing test fixtures
(`tests/unit/application/test_splunk_hec_sink_wiring.py`,
`tests/unit/external/test_playbook_action_registry_wiring.py`) whose
`SimpleNamespace` `Settings` stand-ins didn't yet have the three new
fields — a real, expected consequence of extending `Settings`, not a bug.
`mypy src` baseline and post-change both **29 errors in 10 files**,
identical set, zero new. `ruff check`/`black --check` clean on every
touched Python file.

**Own PoC container torn down** (`kronos-poc-splunk-hec-ack`) at the end of
this pass — the shared `docker-postgres-1` container was only ever used
(never stopped/modified), matching this initiative's own standing
convention.
