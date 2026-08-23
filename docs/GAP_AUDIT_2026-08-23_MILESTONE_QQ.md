# Gap Audit — Milestone QQ (2026-08-23)

Continuation of the JJ-PP gap-audit chain (docs/GAP_AUDIT_2026-08-23_MILESTONE_PP.md),
targeting the remaining tenant-isolation/auth middleware siblings and the
Celery task/queue layer.

---

## 1. Remaining middleware siblings reviewed, no new gap

Full direct read of `tenant_context.py`, `rbac.py`, `collector_mtls.py`,
and `integration_source_auth.py`. Confirmed:

- `tenant_context.py`/`rbac.py`: straightforward JWT-to-`TenantContext`
  dependency plus role/case-ownership checks (`assert_case_access`/
  `assert_case_lead_or_admin`), both correctly giving org-admin an org-wide
  bypass and requiring real ownership/membership otherwise.
- `collector_mtls.py`: `X509SanCollectorIdentityExtractor` correctly relies
  entirely on the TLS transport's own `CERT_REQUIRED` handshake for
  signature/chain/expiry verification (verified empirically in
  `poc/collector_ingest_mtls/` per the module's own docstring) and only
  parses the already-verified peer cert's URI SAN — no redundant
  re-verification, no gap.
- `integration_source_auth.py`: `StaticApiKeyInboundAuthenticator` correctly
  delegates key hashing to `IntegrationSourceKeyRepository.get_by_key()`
  (confirmed: the plaintext key is never compared directly, only its
  SHA-256 hash) rather than hashing/comparing inline. `OAuth2ClientCredentials
  OutboundAuthStrategy`'s token cache correctly applies a 30s expiry safety
  margin per RFC 6749 §4's own recommendation.

`keycloak_auth.py` was also read in full but turned out to already have a
deep, dedicated review pass in `docs/access-management-review.md` — JWT
algorithm allow-list, clock skew, audience/typ claim checks, and the
"reads the first `organization` claim entry" v1 scope decision (documented
in `docs/subsystems/multi-tenancy.md` as deliberately multi-org-ready-for-v2,
not an oversight) are all already confirmed correct there. Not re-litigated.

No new gap found in any of these five files.

---

## 2. Celery task/queue layer reviewed — one dead/misleading log field, FIXED

Full direct read of `src/adapter/queue/task_queue.py`, `event_dedup.py`,
`celery_queue.py`, `stream_ingest.py`, and `src/external/celery_runtime.py`,
`celery_app.py` (941 lines), `celery_streaming.py` (469 lines) — none of
which had a dedicated full-file review in the JJ-PP chain (only passing
mentions in Milestones CC/Z and the base gap-audit doc).

**Finding.** `dispatch_parse()` (`celery_app.py`) took a
`parser_type: str = "fast"` kwarg used only to populate the
`"dispatch_parse_done"` log line's `parser_type` field. Confirmed via
repo-wide grep (production code and every test file) that no caller
anywhere ever passes a non-default value — `celery_queue.py`'s
`enqueue_dispatch()` never sets it, and there is no other call site. The
real fast-vs-heavy routing decision is made one call frame down, inside
`ParsingOrchestrationService.start_parsing()`, which independently detects
the parser via the registry and already logs the true value via its own
`"parse_queued"` info log and `PARSE_STARTED` audit event (both include
`parser`/`parser_type`/`queue`). So the field wasn't merely unused — it was
actively wrong: any evidence routed to the heavy Plaso queue still produced
a `"dispatch_parse_done"` log line claiming `parser_type="fast"`, which
could mislead someone debugging the pipeline by log line alone rather than
cross-referencing `parse_queued`/the audit trail.

Same class of finding as Milestone NN's removal of the dead, misleading
`_MAX_HEADER_BYTES` constant — a value that looks meaningful but is either
dead or actively incorrect should be removed, not left to accumulate false
confidence in whoever reads it next.

**Fix.** Removed the `parser_type` parameter and the field from the log
call entirely, rather than threading the real value through from
`start_parsing()` — the correct information is already recorded correctly
one frame down, so nothing is lost.

**Verification.** Full suite: **2031 passed, 2 skipped** (no test
referenced the removed kwarg, confirmed by grep before removing it).
Coverage 90.25% (gate 80%). `ruff`/`black` clean. `mypy` repo-wide: 29
errors, identical to the pre-existing baseline, zero new.

Everything else in these seven files was clean: `celery_runtime.py`'s
`run_evidence_coro()` correctly disposes the engine and closes the
OpenSearch client in a `finally` block even on task failure;
`event_dedup.py`'s `RedisEventDedupChecker` uses a real atomic
`SET NX EX`, no GET-then-SET race window; `stream_ingest.py`'s
`RedisStreamIngestAdapter` is extensively live-verified
(`poc/stream_ingest_redis/`, 22/22 checks) with correct per-org/per-source
key isolation and non-blocking `SCAN`-based discovery; `celery_app.py`'s
UTC-vs-local-date bug in `anchor_audit_log` was already fixed in an earlier
pass and confirmed still correct; every beat task's per-item failure
isolation (one org/pair's failure never blocks the rest of the cycle) is
applied consistently across `abort_orphan_*`, `run_seal_pending_cycle`, and
`run_sync_org_findings_cycle`; `celery_streaming.py`'s `org_alias`
resolution via `KeycloakAdminClient` (rather than reusing the evidence-DAG's
`"system"` placeholder) is correctly reasoned as necessary to avoid
collapsing every org's telemetry into the same OpenSearch index.

---

## Recommendation for the next wake-up cycle

The tenant-isolation middleware layer and the Celery task/queue layer are
both now fully reviewed — treat as exhausted unless new code lands there.
Reasonable next candidates, none reviewed in the JJ-QQ chain yet:

1. The frontend route/component layer (`frontend/src/`) — has had
   UX-gap-focused review (Milestones KK/MM) but not a security/correctness
   direct-read pass (e.g. client-side input handling, XSS surface in any
   `dangerouslySetInnerHTML`-style code, auth-token storage/handling).
2. `src/adapter/repository/*.py` (Postgres repositories) — every one
   individually implements its own tenant-scoping `WHERE` clause per
   `access-management-review.md`'s own description; worth confirming that
   claim file-by-file rather than by description alone.
3. `src/application/*` files not yet named in any prior milestone doc:
   `asset_enrichment.py`, `ioc_enrichment.py`, `ioc_feed_ingestion.py`,
   `stix_ioc_parser.py`, `yara_rules.py`/`yara_rule_pack_service.py`,
   `cost_gate.py`, `sealing_trigger_policy.py`.

Also still open from prior milestones, unchanged:
1. The lower-value optional SIEM/EDR secrets
   (`splunk_hec_token`/`sentinel_client_secret`/`defender_client_secret`)
   confirmed to degrade safely with `secrets_dir` but not yet moved off
   plaintext `environment:` in `docker-compose.prod.yml`.
2. Keycloak's own `KC_DB_PASSWORD`/`KC_ADMIN_PASSWORD` — no native
   file-secret convention exists in Keycloak 26.x itself.
3. The Postgres sync-replica ops-policy decision
   (`docs/POSTGRES_MINIO_HA_RESEARCH.md` §1.6) remains open for the
   project owner.
