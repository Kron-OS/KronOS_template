# Gap Audit — Milestone JJ (2026-08-21)

Follow-up to `docs/GAP_AUDIT_2026-08-21_MILESTONE_II.md` (Milestone II),
which recommended a second full multi-scenario assessment (Task #14,
round 2) mirroring the original's structure — incident-response
walkthrough, security/red-team review, UX/onboarding review,
scale/reliability review — scoped to everything landed since the
original assessment (Milestones W through II, ~30 substantive changes).

Four subagents were dispatched in parallel, each in its own worktree. Two
completed cleanly with real, captured findings (security, scale/
reliability); one hit a session-limit cutoff with real, complete PoC
artifacts already in its worktree (salvaged directly rather than
redispatched); one (UX/onboarding) died with zero progress and was
redispatched fresh (its notification had not yet landed when this
milestone's fix work began, and is tracked separately).

This document covers the most severe finding — a real, exploitable
approval-gate bypass — its fix, and independent verification of both the
finding and the fix. The remaining findings from this same assessment
round are listed at the end as not-yet-actioned.

---

## The finding: step-up ticket resource scoping was not enforced

**Discovered by:** the security/red-team-review subagent, captured in
`poc/stepup_ticket_resource_mismatch/` (worktree
`agent-a4cf667535d8b7db7`). Independently re-derived and re-run by the
orchestrator before any fix was written (see "Independent verification"
below) — this was not accepted on the subagent's word.

**The mechanism.** `ContainmentAction.execute()`
(`src/application/containment_action.py`) consults an injected
`ApprovalGate` before any destructive `_perform()` call. Before this fix,
`ApprovalGate.authorize(action_name, params, tenant)` read the resource
being authorized from `params["approval_resource_id"]` — a value supplied
by the **same caller**, independently, at both ticket-mint time
(`POST /api/step-up/ticket`) and ticket-consume time (the containment
route). Nothing cross-checked it against the actual target of the
destructive action (`params["session_id"]` for
`RevokeKeycloakSessionAction`).

**The attack.** A caller holding a real, valid ticket minted "for" session
X could revoke a completely different, real, live session Y by sending
`sessionId=Y` (the real target) alongside `approvalResourceId=X` (matching
only the ticket, not the actual target). The one-time-use guarantee on the
ticket itself still held — a ticket could still only be consumed once —
but the guarantee that it was consumed *for the resource it was minted
for* did not exist. Full mechanism and severity notes:
`poc/stepup_ticket_resource_mismatch/README.md` (original finding section,
kept for the record).

**Confirmed real, not theoretical**, against the real dev stack (Keycloak
26.2.5, Postgres 16) before any fix: the original PoC run revoked a real
session Y using a ticket nominally scoped to session X, verified via an
independent, fresh Keycloak Admin API re-check (9/9 checks passed).

---

## Independent verification (before writing the fix)

Per this initiative's standing rule that no subagent's finding is accepted
without independent re-derivation:

- Read `src/application/approval_gate.py`, `containment_action.py`,
  `containment_actions.py`, and `src/external/routes/detections.py`
  directly, confirming by inspection that `approval_resource_id` and
  `session_id` were read completely independently with zero cross-check
  (`approval_gate.py`'s old `authorize()` read
  `params.get("approval_resource_id")`; `RevokeKeycloakSessionAction
  ._perform()` read `params["session_id"]`/`params["user_id"]` separately;
  neither ever compared them).
- Personally re-ran the subagent's own captured `run_poc.py` script
  (not just read its prior output) against the real, unmodified
  pre-fix code — independently reproducing the identical result: session Y
  revoked via a ticket minted for session X, confirmed via a fresh Admin
  API re-check.

Only after this independent reproduction was the fix designed.

---

## The fix

Chosen approach: make `resource_id` an explicit, server-computed,
mandatory argument threaded through the whole approval-gate call chain,
rather than a smaller patch that would just validate
`approval_resource_id == session_id` inside the existing structure. The
smaller patch would have left a redundant, confusable caller-supplied
field in the API contract, inviting the same class of bug in a future
containment action. The chosen fix removes that field from the contract
entirely.

- **`src/application/approval_gate.py`**: `ApprovalGate.authorize()`
  abstract signature is now
  `authorize(action_name, resource_id, params, tenant) -> ApprovalDecision`.
  `StepUpApprovalGate` consumes the ticket via
  `TicketStore.consume(ticket_id, user_id, action_name, resource_id)`
  using the caller-passed `resource_id` directly — no longer reading
  `params.get("approval_resource_id")`. `StaticPolicyApprovalGate`'s
  signature matches (org/action-level only; `resource_id` unused by
  design, documented inline).
- **`src/application/containment_action.py`**: new abstract method
  `_resource_id(params) -> str` — every concrete `ContainmentAction` must
  derive the REAL target of the action from its own params. `execute()`
  calls it right after the `CONTAINMENT_ACTION_ATTEMPTED` audit log and
  before the gate is consulted; if derivation itself raises (malformed
  params), that is now audited as `CONTAINMENT_ACTION_FAILED` and
  re-raised, exactly mirroring how a real backend failure in `_perform()`
  is already handled.
- **`src/application/containment_actions.py`**:
  `RevokeKeycloakSessionAction._resource_id()` returns
  `params["session_id"]` directly — the same value `_perform()` itself
  operates on, so there is no second, independently-suppliable value that
  could diverge from it.
- **`src/external/routes/detections.py`**: removed the
  `approvalResourceId` field from `RevokeKeycloakSessionIn` entirely, and
  the route code that forwarded it into `params`. Confirmed via grep that
  the model has no `extra="forbid"`, so any caller still sending the
  now-dead field (e.g. an unmodified old PoC/test body) is silently,
  harmlessly ignored rather than erroring — no breaking change to
  well-formed legitimate callers.

### Tests

- `tests/unit/application/test_approval_gate.py`: rewritten for the new
  4-argument signature; added
  `test_ticket_cannot_be_replayed_against_a_different_real_resource` — the
  gate-level regression test for the exact attack, including confirming a
  denied mismatch does **not** burn the ticket (a legitimate follow-up
  against the real resource still succeeds).
- `tests/unit/application/test_containment_action.py`: `_FakeDestructiveAction`
  gained the now-required `_resource_id()` implementation.
- `tests/unit/external/test_playbook_action_registry_wiring.py`: updated
  the one direct `gate.authorize()` call site to the new signature.
- `tests/unit/application/test_routes_detections.py`: removed the two
  now-dead `approvalResourceId` values from existing request bodies; added
  `test_ticket_for_one_session_cannot_revoke_a_different_real_session` — a
  **route-level** regression test (real FastAPI app via `TestClient`, only
  the `KeycloakAdminClient` mocked) proving the fix holds at the HTTP
  surface, not just the gate unit level, and that the mismatched attempt
  does not consume the ticket.
- `poc/revoke_session_route/run_poc.py`: removed the two now-dead
  `approvalResourceId` values (both already matched the real `sessionId`,
  so behavior is unchanged).

### Verification performed

- Full backend suite: `python -m pytest -q --no-cov` → **1999 passed, 2
  skipped**, zero failures (re-run twice: once immediately after the
  fix+tests, once again after a `black` reformat of the fully-rewritten
  `test_approval_gate.py`, to confirm the reformat introduced no
  regression).
- `ruff check` / `black --check` / `mypy` on every file touched by this
  fix: clean. (Two pre-existing, unrelated lint issues in
  `test_containment_action.py` and `poc/revoke_session_route/run_poc.py`
  were confirmed via `git stash` to predate this change — not introduced
  here, not fixed here, out of scope for this milestone.)
- **Re-ran `poc/stepup_ticket_resource_mismatch/run_poc.py` against the
  fixed code**, against the same real Keycloak 26.2.5 / Postgres 16 dev
  stack, with the script updated to assert the fixed (denied) behavior:
  **13/13 checks passed** — the mismatched attempt is denied
  (`succeeded=false`, `CONTAINMENT_ACTION_DENIED` audited, no Keycloak
  call made, session Y independently confirmed still alive), and the
  ticket is *not* burned by the denial — a legitimate follow-up request
  against the ticket's real resource (session X) still succeeds, with a
  real `DELETE .../sessions/<session_x>` reaching Keycloak and returning
  204. Captured output: `poc/stepup_ticket_resource_mismatch/output.txt`.

---

## PoC evidence copied into the main checkout

The following real, captured PoCs from the assessment's subagent
worktrees were copied into this checkout's `poc/` directory as permanent,
committed evidence (per CLAUDE.md §F.3's own convention — none of this
was regenerated from memory, all copied verbatim from the worktree that
produced the real captured run):

- `poc/stepup_ticket_resource_mismatch/` — this milestone's own finding
  (updated post-fix, see above).
- `poc/redis_prod_secret_cli_exposure/` — real finding, not yet fixed
  (see below).
- `poc/postgres_sync_replica_failure/` — real finding, not yet fixed
  (see below).
- `poc/ir_walkthrough_case_scoping/` — real finding from the
  incident-response walkthrough subagent, not yet fixed (see below).

---

## Other findings from this assessment round — not yet actioned

These are real, independently-verified gaps surfaced by the same
four-subagent assessment. They are lower severity than the approval-gate
bypass above (which is why it was fixed first) and are recorded here so
the next wake-up cycle can pick them up without re-deriving them:

1. **Redis prod secrets exposed via `docker inspect`.**
   `docker-compose.prod.yml`'s `redis-auth-streams`/`redis-celery`
   services pass `--requirepass ${REDIS_..._PASSWORD}` as a `command:`
   argv, unlike `postgres`'s own correct `_FILE`-based secret pattern.
   `docker inspect --format '{{json .Config.Cmd}}'` reveals the plaintext
   password even though `docker top`/`ps aux` from inside the container do
   not (Redis rewrites its own process title post-startup) — a broader
   exposure surface (any read-only Docker-API/monitoring principal) than
   local shell access. Independently re-confirmed via a fresh, disposable
   `docker run`/`docker inspect` repro, not just the subagent's own
   report. Fix: move both Redis services to a secret-file-based entrypoint
   script, mirroring `docker/postgres/replica-entrypoint.sh`'s existing
   pattern for `REPL_PASSWORD`. See `poc/redis_prod_secret_cli_exposure/README.md`.

2. **Postgres synchronous replication: a dead standby blocks all primary
   writes indefinitely**, not just degrades throughput — confirmed via a
   real PoC (a 12s-bounded `INSERT` timing out while the sync standby was
   down; both blocked inserts completing once it reconnected). This
   repo's real prod config (`synchronous_standby_names` naming one
   replica, `synchronous_commit=on`) has no configured timeout for this
   scenario, and it is undocumented in
   `docs/POSTGRES_MINIO_HA_RESEARCH.md`/`docs/deployment.md`/
   `charts/kronos/values.yaml` (confirmed via grep — zero mentions). Needs
   at minimum a documentation fix; possibly an ops/design decision
   (application-level timeout, alerting, runbook) that this initiative
   should not make unilaterally. See
   `poc/postgres_sync_replica_failure/README.md`.

3. **Containment/SIEM-sync audit events are not case-scoped.**
   `DetectionTriageService.transition()` correctly passes
   `case_id=detection.case_id` to every audit log call (confirmed at
   `src/application/detection_triage.py` lines 62, 78).
   `ContainmentAction.execute()` and `DetectionSinkPushService.push()` do
   **not** (confirmed via grep — zero `case_id` matches in either file) —
   meaning containment/SIEM-sync audit events are invisible both to
   `kronos-attest case-report` (strict `case_id` filter) and the live
   `GET /api/cases/{case_id}/audit` route a case lead would actually
   check. Fix: pass `case_id` through the same way
   `DetectionTriageService` already does.

4. **No frontend UI for `revoke-session`/`sync-to-siem`.** A real,
   confirmed UX gap from the incident-response walkthrough — these
   backend containment/sink capabilities have no way for an analyst to
   trigger them from the UI.

5. **`riskScore`/`riskFactors` computed server-side, never surfaced in the
   frontend.** `src/external/routes/detections.py`'s `DetectionOut`
   exposes `riskScore` (confirmed at the route's response model), but
   `frontend/src/types/index.ts`'s `Detection` type has no matching field
   (confirmed via grep — zero matches) and no UI surfaces it.

Items 4 and 5 came from the UX/onboarding angle; the original subagent
covering that angle died with zero progress and was redispatched. Its
findings (if any beyond what a subsequent quick check already surfaced
above) will be folded into a future milestone once that redispatch
completes.

---

## Recommendation for the next wake-up cycle

In priority order:
1. Item 3 above (case-scoped audit trail) — small, mechanical, same
   pattern already proven elsewhere in the codebase.
2. Item 1 above (Redis secret handling) — small, mechanical, same pattern
   already proven elsewhere in the codebase (`replica-entrypoint.sh`).
3. Item 2 above (Postgres sync-replica documentation) — at minimum a docs
   fix; flag the deeper ops-policy question to the project owner rather
   than deciding it unilaterally.
4. Items 4/5 (frontend UX gaps) — larger scope, likely worth their own
   milestone once the redispatched UX/onboarding subagent's full findings
   are in hand.
