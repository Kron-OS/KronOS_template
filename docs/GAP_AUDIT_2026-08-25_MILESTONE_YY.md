# Gap Audit — Milestone YY (2026-08-25)

Continuation of the JJ-XX gap-audit chain. This pass covered every file in
`src/domain/` (27 files -- the full set) plus the remaining, previously
unreviewed `frontend/src/hooks/`/`utils/` files.

---

## 1. `frontend/src/hooks/useEvidenceSSE.ts`: misleading comment — FIXED

**Finding.** `startPolling()`'s own comment claimed the fallback loop
"re-fetches the ticket each cycle" -- it never did. The real fallback path
abandons SSE entirely (not just the current connection) and only dispatches
a `kronos:sse-poll` DOM `CustomEvent`; `CaseDetailPage.tsx`'s own listener
turns that into a plain REST `invalidateQueries()` call. No behavior was
wrong, only the comment describing it -- but a wrong comment on the
SSE-vs-polling fallback boundary is exactly the kind of thing that misleads
the next person touching this file into "fixing" a ticket-refresh path that
doesn't exist.

**Fix.** Corrected the comment to describe the real mechanism, and removed
the unnecessary `async` keyword on the `setInterval` callback (nothing
inside was ever awaited). No behavior change -- not test-worthy as a new
regression case, matching this chain's established "dead/misleading
comment" fix category (Milestone QQ's `dispatch_parse` log-field removal,
Milestone NN's `_MAX_HEADER_BYTES` removal), which were committed without a
dedicated new test since there was nothing to regress.

**Verification.** Full frontend suite: 101 passed (unchanged). `oxlint`
clean (one pre-existing, unrelated warning). `tsc -b` + `vite build`
succeed. Committed as `93fd49c`.

`useDarkMode.ts` and `utils/cn.ts` (previously reviewed this milestone) are
both trivial/well-documented -- no issues.

---

## 2. Full `src/domain/` sweep — no new gap found

Read every remaining domain file end-to-end for the first time this pass
(dedicated reviews, not incidental via an adapter/service): `merkle.py`,
`user.py`, `approval.py`, `case.py`, `audit.py`, `timeline.py`,
`provenance.py`, `stream.py`, `artifact.py`, `risk.py`, `quota.py`,
`dead_letter.py`, `asset.py`, `rule_pack.py`, `yara_rule_pack.py`,
`sealed_batch.py`, `ioc_feed.py`, `collector.py`, `integration_source.py`,
`metrics.py`, `rarity.py`, `anomaly.py`, `integration_sink.py`,
`playbook.py`, plus fresh dedicated (not incidental) full reads of
`evidence.py` and `detection.py`, which had previously only been touched
in passing via other services.

This is the most heavily-scrutinized layer of the codebase by a wide
margin: every file already carries extensive rationale docstrings citing
specific prior PoCs, prior gap-audit findings, and named invariants
(roadmap invariant #3/#5/#6, CLAUDE.md §A.3/§G.3). Specific things checked
and confirmed clean:

- **FSM invariant enforcement**: `EvidenceState`/`DetectionTriageState`
  both correctly gate every transition through `transition_to()`; no
  bypass path found. `Evidence.with_error()` correctly refuses to fire on
  an already-terminal state (`COMPLETE`/`ERROR`).
- **`is_retryable_error_reason()` vs. `is_parse_stage_error_reason()`
  ordering** (`src/domain/evidence.py`, `src/external/routes/evidence.py`):
  confirmed every call site checks `is_retryable_error_reason()` first —
  `no_parser_found` is deliberately in both `_TERMINAL_ERROR_REASONS` and
  `_PARSE_STAGE_ERROR_REASONS`, and nothing ever calls the parse-stage
  check without the retryable gate in front of it, so a terminal,
  parse-stage reason can never be mis-routed to an offered retry.
  `_retry_action_for()` (`src/external/routes/evidence.py:504`) has the
  correct ordering too.
  - Investigated and **ruled out** (not a bug) a suspected `Role` enum
    underscore-vs-hyphen drift between `src/domain/user.py` and the
    frontend's hyphenated `Role` type: traced every route that touches
    role strings and confirmed the enum's Python value never crosses an
    API boundary directly (`admin.py` always uses raw Keycloak strings
    filtered against a separately-defined hyphenated `_MANAGED_ROLES`
    set, not the enum).
- **Provenance circular-import structure** (`provenance.py` /
  `timeline.py` / `stream.py`): the `ProvenanceBase` leaf-module split and
  the discriminated `Provenance` union placement are correctly structured
  to avoid the documented A→B→A cycle; imports actually match what the
  docstrings claim.
- **`PlaybookExecutionResult.started_at`/`completed_at`** both use
  independent `default_factory=datetime.now(UTC)` — checked whether a
  caller could accidentally leave one to its default while explicitly
  setting the other (which would silently produce an inconsistent
  duration); confirmed the one real construction site
  (`src/application/playbook_execution.py:145`) sets both explicitly from
  real captured timestamps, so the independent defaults are dead code for
  every actual caller, not a live bug.
- **`SealedBatch`'s `leaf_hashes`/`message_ids`/`event_count` alignment**
  is enforced by a real `model_validator`, not just documented.
- Confirmed (already known from Milestone XX, re-verified) the one
  outstanding low-priority edge case in
  `SecurityAnalyticsCorrelationRuleProvisioner._rule_name()`'s 50-char
  truncation remains unfixed, still no known live caller.

No new gap found in any of the 27 domain files.

---

## Recommendation for the next wake-up cycle

This is the second-lightest pass in the JJ-YY chain (one real but
comment-only frontend fix; the domain-layer well, unlike prior layers this
chain audited, appears to have started this pass already near-saturated
rather than running dry mid-pass — every file already had prior-audit-grade
documentation before this pass touched it). Per Task #42's own standing
guidance ("if this pass also finds nothing new... seriously consider
switching strategy"), the next milestone should NOT continue a third
consecutive line-by-line file sweep of an already-well-covered layer.
Concrete next candidates, roughly in priority order:

1. **A fresh multi-scenario assessment** (mirroring Task #14/#27) — this
   chain has now spent milestones JJ through YY (18 milestones) doing
   direct code review; a scenario-driven assessment (walk a real
   end-to-end user/attacker flow end-to-end, e.g. "tenant B tries to see
   tenant A's playbook execution audit trail via every route that returns
   one") tends to surface a different class of bug (cross-cutting,
   integration-level) than per-file review does.
2. Pick up one of the long-standing project-owner-decision items instead
   of continuing to hunt for ever-smaller candidates (all unchanged from
   Milestone XX, listed below).
3. If a scenario assessment also comes back clean, this is a natural point
   to re-arm the CronCreate job with an updated STATE AS OF section (job
   `0b6703d2`, created 2026-08-23, now ~2 days from its 7-day expiry as of
   this pass and due for re-arm within the next 1-2 wake-ups regardless of
   audit findings).

Still open from prior milestones, unchanged:
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
   truncation-collision edge case — low priority, no known live caller.
