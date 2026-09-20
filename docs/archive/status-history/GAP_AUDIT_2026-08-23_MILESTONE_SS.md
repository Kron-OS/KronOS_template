# Gap Audit — Milestone SS (2026-08-23)

Continuation of the JJ-RR gap-audit chain (docs/GAP_AUDIT_2026-08-23_MILESTONE_RR.md).
This pass closed RR's deferred audit-log finding and did the first
security/correctness direct-read pass over the frontend layer.

---

## 1. `stream_by_case`/`stream_by_evidence` missing defense-in-depth org scoping — FIXED

**Finding.** Continuation of Milestone RR's own deferred item.
`AuditLogRepository.stream_by_case(case_id)`/`.stream_by_evidence
(evidence_id)` were the only two methods on that ABC with no `org_id`
parameter — every sibling method (`get_latest_hash`, `get_latest_sequence`,
`append_atomic`) already takes it. Same shape as Milestone RR's
`RulePackRepository`/`YaraRulePackRepository`/`IOCFeedRepository
.list_versions()` fix.

Re-investigated the real blast radius before starting (smaller than RR's
own worst-case estimate): only **one** test file
(`tests/integration/test_evidence_intake.py`) calls these two methods
directly; the ~40-file count from grepping `InMemoryAuditLogRepository`
mostly reflected unrelated methods (`log`/`append`/`get_latest_hash`) via
the shared `audit_repo`/`audit_service` fixtures.

Confirmed the one real production caller (`GET /{case_id}/audit`,
`src/external/routes/cases.py`) already double-protects via a
`case_repo.get_by_id(case_id, tenant.org_id)` pre-check plus a redundant
per-event `org_id` filter — not a live exploit today — but the repository
layer is where CLAUDE.md §G.3's org-scoping invariant is supposed to hold
even if an upper layer's own check is ever buggy or missing.

**Fix.** Added `org_id` to `stream_by_case`/`stream_by_evidence` on the ABC
(`src/adapter/repository/audit_log.py`), `PostgresAuditLogRepository` (real
WHERE-clause filter), and `InMemoryAuditLogRepository`
(`tests/conftest.py`). Updated the one production call site (now passing
`tenant.org_id`; kept the now-redundant post-filter as a second, cheap
layer) and the one test call site.

**Tests.** New `TestStreamByCaseAndEvidenceOrgScoping` class in
`test_audit_log.py`, proving a real event logged under org_a is invisible
when streamed with org_b. Verified via `git stash` that both new tests
fail against the pre-fix source (`TypeError: takes 2 positional arguments
but 3 were given`) and pass with the fix.

**Verification.** Full suite: **2037 passed, 2 skipped** (2035 → 2037, +2
new tests). Coverage 90.26% (gate 80%). Also ran the real Postgres-backed
integration suite directly (`tests/integration/test_evidence_intake.py`,
testcontainers) — all 9 tests pass, including the modified
`stream_by_evidence` call. `ruff`/`black` clean. `mypy` repo-wide: 29
errors, identical baseline, zero new. Committed as `c37a7e9`.

---

## 2. Frontend `api/client.ts`: 401-refresh interceptor dropped the very request that triggered it — FIXED

**Finding.** First security/correctness direct-read of the frontend layer
(prior frontend milestones KK/MM were UX-gap-focused). `keycloak.ts` and
its supporting utilities (`store/auth.ts`, `utils/jwt.ts`,
`utils/parseTenantContext.ts`) were reviewed and found clean — well
documented, no token ever touches Web Storage, and KK's own prior step-up
bug fix there was confirmed still correct. `api/client.ts`'s 401-refresh
interceptor, however, had a real, live bug with **zero existing test
coverage**.

On a 401, the interceptor read:

```js
if (!isRefreshing) {
  isRefreshing = true
  try {
    const refreshed = await refreshAccessToken()
    if (refreshed) {
      pendingRequests.forEach((cb) => cb())
      pendingRequests = []
    }
  } finally { isRefreshing = false }
}
return new Promise((resolve) => {
  pendingRequests.push(() => { ...; resolve(apiClient(originalRequest)) })
})
```

The request that actually enters the `if (!isRefreshing)` branch pushes
its own retry callback onto `pendingRequests` only **after** that block
has already run and flushed the queue — so in the common single-request
case, `pendingRequests` is still empty when the flush happens, and the
triggering request's own callback then sits in the array forever, with
nothing left to ever call it again. Net effect: the single most common
path — one request hits a 401, the token refresh succeeds — leaves that
exact request's promise unresolved permanently. The user sees a
permanently hung request (a spinner that never stops) right after their
token naturally expires and silently refreshes, while any brand-new
request made afterward works fine — masking the bug in casual manual
testing, since it looks like "the app recovered." A second, related bug:
on refresh **failure**, any queued concurrent requests were dropped the
same way (never invoked at all), hanging instead of rejecting.

**Fix.** The triggering request now retries itself directly once its own
refresh settles, instead of re-queueing behind an already-flushed array.
`pendingRequests` callbacks now receive the refresh outcome so genuinely
concurrent requests are properly resolved (retried) or rejected — never
silently dropped.

**Tests.** New `frontend/src/__tests__/client.test.ts` (previously zero
coverage), exercising the real `apiClient` axios instance and its real
interceptor chain end-to-end — only the low-level HTTP adapter is mocked,
not axios itself. Four cases: the triggering request retries and resolves
after a successful refresh; a request rejects (rather than hanging) on
refresh failure; the aal2 step-up-challenge path is untouched; a
genuinely concurrent second request queues behind an in-flight refresh
and is retried once it resolves. Verified via `git stash` that 3 of the 4
new tests reproduce a real hang (test timeout) against the pre-fix
source — the 4th (aal2 redirect) was never on the buggy path and correctly
passes both ways. (Constructing the genuine-concurrency test case required
care: a naive "fire both requests back-to-back" approach raced ahead of
axios's own real async dispatch pipeline and produced a false read on the
first attempt — resolved by signalling on the adapter's own actual
dispatch rather than guessing a fixed number of microtask/macrotask ticks.)

**Verification.** Full frontend suite: **88 passed** (84 → 88, +4 new
tests). `oxlint` clean, `tsc -b` clean, `vite build` succeeds. Committed
as `433c3f3`.

---

## Recommendation for the next wake-up cycle

1. Continue the frontend review: `frontend/src/api/*.ts` (the per-resource
   API modules: `cases.ts`, `containment.ts`, `admin.ts`, `connectors.ts`,
   `detections.ts`, `evidence.ts`) and the route/page components under
   `frontend/src/pages/`/`components/` — only `api/client.ts` and the
   auth-adjacent files got a dedicated pass this cycle.
2. `src/application/*.py` files not yet named in any prior milestone doc:
   `asset_enrichment.py`, `ioc_enrichment.py`, `ioc_feed_ingestion.py`,
   `stix_ioc_parser.py`, `yara_rules.py`, `cost_gate.py`,
   `sealing_trigger_policy.py`.

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
