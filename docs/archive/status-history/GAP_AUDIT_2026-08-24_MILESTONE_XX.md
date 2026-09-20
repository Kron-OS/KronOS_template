# Gap Audit — Milestone XX (2026-08-24)

Continuation of the JJ-WW gap-audit chain (docs/GAP_AUDIT_2026-08-24_MILESTONE_WW.md).
This pass covered all of Milestone XX's named candidates.

---

## 1. Remaining named frontend components reviewed — one real, significant drift, FIXED

`Spinner.tsx`, `LoginPage.tsx`, `ConfirmDialog.tsx`, `StatusPill.tsx`,
`RiskScorePill.tsx`, `TriageStatePill.tsx`, `ConnectorStatusPill.tsx` are
all trivial config-lookup/presentational components — no logic to get
wrong. `RiskScorePill.tsx`'s claim about `src/application/risk_scoring.py
`'s `SEVERITY_NORMALIZED_LEVELS` spacing was cross-checked against the
real backend constant and confirmed accurate.

`ErrorCatalogue.tsx`, however, had a real, significant drift — see §2.

## 2. `ErrorCatalogue.tsx`: reason codes drifted from the real backend `error_reason` strings — FIXED

**Finding.** Cross-checked `ERROR_CATALOGUE`'s keys and `retryable` flags
against the real, authoritative set of `error_reason` strings the backend
actually produces (`grep -rn "with_error(" src/` across
`evidence_intake.py`/`parsing_orchestration.py`/`celery_app.py`) and
against `src/domain/evidence.py`'s own `is_retryable_error_reason()`/
`_TERMINAL_ERROR_REASONS`/`_TERMINAL_ERROR_PREFIXES` — the same
"confirmed against real X, not assumed" discipline this chain has applied
throughout, rather than trusting the catalogue's own plausible-looking
entries. Found:

- **Three dead keys**: `invalid_magic_bytes` (real: `no_parser_found`),
  `file_too_large` (real: `size_limit_exceeded`),
  `ingest_count_mismatch` (real: `ingest_failed`) — each real backend
  reason fell through to the generic "Unknown error" fallback, showing
  the raw machine code as the title, despite a correctly-worded entry
  existing under the wrong key.
- **Two inverted `retryable` flags**: `hash_mismatch` is backend-TERMINAL
  (`_TERMINAL_ERROR_REASONS`) but said `retryable: true`; `parse_timeout`
  is backend-retryable but said `retryable: false`.
- **Two unmatchable dynamic reasons**: `infected:{threat_name}` and
  `intake_failed:{exception type}` are runtime-templated and could never
  match a fixed dict key at all — no prefix-matching mechanism existed.
- **Three fictional entries**: `tsa_unreachable`, `parser_oom`,
  `storage_error` never correspond to any real `error_reason` the backend
  has ever set (confirmed absent from every `with_error(...)` call site
  — `tsa_unreachable` exists only as a log-event name, never as an
  `Evidence.error_reason`).

**Confirmed not a functional/security bug**: the real Retry button in
`EvidenceDetailDrawer.tsx` is gated by the server-computed
`evidence.retryAction` field (`_retry_action_for`,
`src/external/routes/evidence.py`), which already uses the real backend
classification correctly — `ERROR_CATALOGUE`'s own `retryable` field only
drives a cosmetic badge/wording next to the error title. Still a real,
worth-fixing defect: a wrong "is this retryable" label on a forensics
platform is misleading, not merely cosmetic noise.

**Fix.** Corrected all keys/flags to the real strings, added the two
missing real codes (`intake_timeout`, `validation_failed`), added
prefix-based matching for the two dynamic reasons, removed the three
fictional entries.

**Tests.** Rewrote `ErrorCatalogue.test.tsx` to exercise the real backend
codes throughout (the old tests exercised the catalogue's own fictional
entries, which never caught the drift). Verified via `git stash` that 11
of 18 tests fail against the pre-fix source, including the exact
`hash_mismatch` retryable-badge inversion.

**Verification.** Full frontend suite: **101 passed** (93 → 101, +8 net
new/changed tests). `oxlint` clean (one pre-existing, unrelated warning
confirmed via `git stash`). `tsc -b` clean, `vite build` succeeds.
Committed as `98f07d2`.

---

## 3. Remaining OpenSearch/external adapter files reviewed, no new gap

Full direct read of `src/adapter/opensearch/rule_catalog.py`,
`correlation_client.py`, `correlation_rule_provisioner.py`, and
`src/external/collector_app.py`, `mtls_protocol.py`, `run_dual_listener.py`
— all extremely well-verified with real, cited PoC evidence (a genuine
uvicorn ASGI-TLS-extension gap independently confirmed by grepping
uvicorn's own source, a real correlation-rule PUT-update behavior
confirmed against the live cluster with an incrementing `_version`
readback, honest documentation of a cluster-wide, unscoped correlation
API with tenant isolation deliberately pushed to the one calling service).

One narrow, low-probability edge case noted but not fixed:
`SecurityAnalyticsCorrelationRuleProvisioner._rule_name()` truncates the
computed `kronos-{org_alias}-{scenario_name}` name to 50 characters (the
real SA rule-name length limit) — for an org alias longer than roughly 41
characters, every scenario name for that org would truncate to the same
50-character prefix, causing different scenarios to silently collide and
overwrite each other. Not fixed this pass: no evidence this provisioner
has any live caller today (mirrors the already-documented "zero real
callers" status of the sibling `CorrelationSyncService
.sync_org_correlations()` from Milestone NN), and realistic org aliases
are far short of the threshold — worth a defensive fix (raise instead of
silently truncating past the point of uniqueness) if/when this class
gets a real caller wired up.

No new gap found in any of the six files.

---

## Recommendation for the next wake-up cycle

The JJ-XX chain has now covered nearly every file in `src/application/`,
`src/adapter/`, the container/queue/middleware layers, and the frontend.
Given this pass and Milestone UU both found real issues (UU found none,
XX found the ErrorCatalogue drift), the well has not run dry, but
candidates are getting narrower. Reasonable next areas:

1. `src/domain/*.py` files — pure domain models have had less direct,
   dedicated attention than the adapter/application layers throughout
   this whole JJ-XX chain (most reviews touched domain logic only
   incidentally, via the service/adapter that uses it).
2. The remaining, not-yet-independently-named `frontend/src/hooks/`
   files (`useDarkMode.ts`, `useEvidenceSSE.ts` if not already covered)
   and `frontend/src/utils/cn.ts`.
3. If a second consecutive pass finds nothing new, seriously consider a
   fresh multi-scenario assessment (mirroring Task #14/#27) or picking up
   one of the long-standing project-owner-decision items instead of
   continuing to hunt for ever-smaller candidates.

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
4. (UX-focused, not this audit chain's charter) `AdminPage.tsx`'s
   `UserRow` role-change/remove-user mutations have no `onError` handling.
5. `SecurityAnalyticsCorrelationRuleProvisioner._rule_name()`'s narrow
   truncation-collision edge case (§3 above) — low priority, no known
   live caller.
