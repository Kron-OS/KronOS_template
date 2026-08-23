# Gap Audit — Milestone PP (2026-08-23)

Started as a continuation of the parser/OpenSearch adapter chain (JJ-OO),
targeting the SOAR/playbook engine as the next "recently-landed or
never-independently-reviewed" candidate. Investigation redirected mid-pass
once it became clear most of that area (H2/H3/H4's approval-gate and
containment-action layer) had already had real, substantial review and
fixes in Milestones EE, FF, GG, HH, JJ, and LL — re-reading it again would
have been redundant. The genuinely fresh ground turned out to be the
tenant-isolation middleware layer, which had never been named in any prior
gap-audit doc.

---

## 1. Core H1 playbook engine reviewed, no new gap

Full direct read of `src/domain/playbook.py`, `src/application/playbook.py`,
`src/application/playbook_actions.py`, and `src/application/
playbook_execution.py` — the engine itself, as opposed to the two example
actions Milestone GG already spot-checked. Confirmed:

- `Playbook`/`PlaybookStep` are frozen, pure-data Pydantic models (no
  framework imports), matching the `RulePack`/`CustomRule` "content is
  data, never code" precedent this codebase already established.
- `PlaybookActionRegistry` is a plain dict keyed by `action_name` —
  correctly simpler than `ParserRegistry`'s content-sniffing match list,
  since a playbook step names its action explicitly.
- `PlaybookExecutionService.execute()`'s fail-fast design (halt on first
  step failure, one `PLAYBOOK_STEP_EXECUTED`/`_FAILED` audit row per step,
  never batched) is applied consistently; every code path (missing
  registered action, an action raising, a normal success) produces exactly
  one step result and one audit event, and `PlaybookExecutionResult.
  succeeded` correctly requires both `not halted_early` and every result
  being `SUCCESS`.
- `TransitionDetectionTriageAction`/`LogNotificationAction` do not audit
  anything themselves (single audit boundary, as designed) and correctly
  raise `PlaybookError` for malformed params rather than silently no-op'ing.

No new gap found.

---

## 2. P2-10 (playbook actor-identity placeholder) re-confirmed resolved

`docs/GAP_AUDIT_2026-08.md`'s P2-10 flagged automated playbook-driven
triage transitions recording `actor_username: "unknown"`. Milestone Z
already checked this and found the literal placeholder absent from `src/`
today. Re-checked directly this pass against the current
`PlaybookExecutionService`/`DetectionTriageService` code: both always use
`tenant.username`/`tenant.user_id` from the real `TenantContext` passed
in, never a hardcoded placeholder. Confirmed still resolved — no action
needed, noted here only so a future pass doesn't re-investigate from
scratch a third time.

---

## 3. `opensearch_isolation.py`/`query_isolation.py` reviewed, confirmed honest dead code

Both files are self-documented as unwired scaffolding for a hypothetical
future direct-search API — `OpenSearchQueryBuilder` (wraps a query with a
hard `kronos.org_id` term filter) and `QueryIsolationGuard` (raises
`AuthorizationError` on an org_id mismatch) are never imported by any
route today. Real tenant isolation is enforced elsewhere: OpenSearch via
Document-Level Security on the JWT's `org_id` claim, Postgres via each
repository's own `WHERE org_id = ...` clause. This is consistent with
`reviews/Static_Compliance_Pentest_Review.md`'s own AUDIT-15 item, not a
live gap masquerading as a fix. No new gap found; no live security risk
since nothing routes through these classes.

---

## 4. `step_up_store.py`: `RedisTicketStore` burned a ticket on any mismatch — FIXED

**Finding.** `StepUpAuth` issues one-time, 5-minute step-up tickets for
MFA-gated destructive operations (e.g. `DELETE /api/evidence/{id}`), backed
by a pluggable `TicketStore`: `InMemoryTicketStore` (dev/single-replica) or
`RedisTicketStore` (required for the multi-replica prod deployment per the
module's own docstring — audit finding M-4). The two stores are meant to
be interchangeable; the existing test suite parametrizes every store-level
test over both (`_make_stores()`), implicitly asserting identical
semantics.

`RedisTicketStore.consume()` called `GETDEL` unconditionally, before
comparing the presented `(user_id, operation, resource_id)` against the
stored value — so ANY presentation of a valid ticket_id, even with wrong
fields, permanently deleted the ticket. `InMemoryTicketStore.consume()`
only sets `ticket.used = True` on an actual field match, leaving a
mismatched ticket fully valid for a later, correct redemption. The
`RedisTicketStore` docstring claimed unconditional `GETDEL` was "at least
as strict as the in-memory store" — factually wrong; it's a different,
strictly less forgiving property, not a stronger one.

Empirically confirmed the divergence by exercising both stores directly:

```
memory: mismatch_attempt=MISMATCH, legit_retry_after=CONSUMED
redis : mismatch_attempt=MISMATCH, legit_retry_after=NOT_FOUND
```

**Real impact.** This only matters in the deployment that actually needs
`RedisTicketStore` — multi-replica production. A single client-side bug
(a stale retry, a double-submit racing with a slightly different
`resource_id`, a frontend timing issue) or a guessed ticket_id would
permanently burn a still-valid ticket before the legitimate holder acted,
forcing a full step-up MFA re-challenge for no security benefit. This is
exactly the class of prod-only-reproducible divergence this audit chain
exists to catch — a test run against the dev-default `InMemoryTicketStore`
would never surface it. (Ticket ids are 122-bit UUIDs returned only in a
`POST /api/step-up/ticket` response body, never a URL or log line, so an
external attacker guessing one to deliberately trigger this is not
realistic — the live-impact scenario is a benign client-side retry/race,
not a targeted attack.)

**Fix.** `RedisTicketStore.consume()` now does `GET` + Python-side
comparison first, calling `GETDEL` only on an actual match — exactly
`InMemoryTicketStore`'s semantics. A benign race between two concurrent
redemption attempts presenting the SAME correct fields is still resolved
safely: at most one caller's `GETDEL` can return the real value, so
single-use is preserved even though the check is no longer a single
round-trip. `_RedisLike` protocol extended with `get()`; test double
(`_FakeRedis`/`_BytesRedis`) updated to match.

**Tests.** New `test_mismatch_does_not_burn_the_ticket_for_a_later_
legitimate_retry` in `tests/unit/middleware/test_step_up_store.py`,
parametrized over both stores like the existing tests. Verified via `git
stash` to FAIL against the pre-fix `RedisTicketStore` (`redis` label:
`NOT_FOUND` instead of `CONSUMED` on the legitimate retry) and pass with
the fix applied.

**Verification.** Full suite: **2031 passed, 2 skipped** (2029 → 2031,
+1 new test). Coverage 90.25% (gate 80%). `ruff`/`black` clean on changed
files. `mypy` repo-wide: 29 errors, identical to the pre-existing
baseline, zero new.

---

## Recommendation for the next wake-up cycle

The SOAR/approval-gate/containment-action layer (H2-H4) has now had
extensive, real coverage across EE/FF/GG/HH/JJ/LL/this pass — treat it as
exhausted unless new code lands there. The tenant-isolation middleware
layer turned out to have one real file left uncovered
(`step_up_store.py`, now fixed); its remaining siblings
(`collector_mtls.py`, `integration_source_auth.py`, `keycloak_auth.py`,
`rbac.py`, `tenant_context.py`) have not been individually confirmed
clean or dirty this pass and are reasonable next candidates, along with
the Celery task/queue layer (`src/adapter/queue/`, `src/external/
celery_app.py`/`celery_runtime.py`/`celery_streaming.py`) and the frontend
route/component layer, none of which have had a dedicated direct-read pass
in the JJ-PP chain.

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
