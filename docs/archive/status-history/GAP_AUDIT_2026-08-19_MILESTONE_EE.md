# Gap Audit — Milestone EE (continuation, 2026-08-19)

Follow-up to `docs/GAP_AUDIT_2026-08-18_MILESTONE_DD.md` (Milestone DD,
fully resolved: DD1 CLOSED). DD's own execution plan pointed at extending
the "direct review of recently-landed code" method to parts of the
codebase not yet freshly re-examined this way — this pass reviewed the
SOAR/response subsystem (roadmap Milestone M7, items H1/H2).

---

## EE1 — `RevokeKeycloakSessionAction` (H2's real, deeply-verified containment adapter) was never reachable via any API

**STATUS (2026-08-19, commit `af2cce7`): CLOSED, verified live.**

H2 (`docs/NEXTGEN_SOC_ROADMAP.md`, roadmap Milestone M7) shipped a
genuinely real, destructive containment action —
`RevokeKeycloakSessionAction`, gated by a mandatory `ApprovalGate`
(`ContainmentAction.execute()`'s own template-method sequence: audit the
attempt, consult the gate, audit denial/failure/success, never skip the
gate) — verified at the time with 19/19 real checks against live
Keycloak 26.2.5 and Postgres 16, including tenant isolation holding even
against an *approved-but-cross-tenant* attempt. H2's own status note
explicitly, honestly flagged what it did NOT do: **"no HTTP route or
scheduled/Detection-triggered trigger wiring this pass... not yet wired
into `dependencies.py`/`startup.py`."** Confirmed still true before
dispatching this item (direct grep: zero references to
`RevokeKeycloakSessionAction` anywhere in `src/external/routes/` or
`src/external/dependencies.py`) — a real, well-built, thoroughly-tested
capability that no user of the platform could actually invoke.

This mirrors exactly what Milestone W1 already did for a *different*
previously-unwired action (`SyncDetectionToSiemAction`) — this item does
the same for H2's own containment adapter.

**Fix:**
- New DI wiring in `src/external/dependencies.py`/`src/external/startup.py`:
  `configure_keycloak_admin_client_from_settings()` (real
  `HttpxKeycloakAdminClient`, "None means not configured" honest-disabled
  shape matching the existing SIEM-sink providers), `get_containment_approval_gate()`
  (`StepUpApprovalGate` sharing the *same* `TicketStore` singleton the
  real `POST /api/step-up/ticket` route already issues tickets through —
  a new `StepUpAuth.ticket_store` property was added specifically so this
  doesn't build a second, drifting ticket store for the same real
  concept), `get_revoke_keycloak_session_action()`. `revoke_keycloak_session`
  now registers in `PlaybookActionRegistry` whenever a real Keycloak
  client is configured.
- New route: `POST /api/detections/{detection_id}/contain/revoke-session`,
  mirroring `sync_detection_to_siem`'s exact idiom (ad hoc single-step
  `Playbook` → `PlaybookExecutionService.execute()` → the same
  `PlaybookExecutionResultOut` response shape) but **role-gated more
  narrowly** — `ORG_ADMIN`/`CASE_LEAD` only, deliberately excluding
  `ANALYST` (unlike the SIEM-sync route), a real, reasoned distinction:
  pushing to a SIEM is read-mostly and reversible; revoking a live user's
  session has real, immediate, destructive user-facing impact. The
  `ApprovalGate` inside `ContainmentAction.execute()` remains a *second*,
  independent gate on top of this role check, not a substitute for it.
- `containment_action.py`/`containment_actions.py`/`approval_gate.py`
  themselves — confirmed **completely untouched** (`git diff --stat`
  empty on all three), their own 22 pre-existing H2 tests pass unmodified.
  This item is wiring-only, exactly as scoped.

**Verified end-to-end (`poc/revoke_session_route/`), through the real new
route, real Keycloak 26.2.5, real Postgres 16 — 21/21 checks, not just
re-confirming H2's own already-proven class-level behavior:**
1. A real analyst logs in via real Authorization Code + PKCE, obtains a
   real step-up ticket via the real `POST /api/step-up/ticket` route,
   then a real `POST .../contain/revoke-session` call revokes the real
   session — independently re-confirmed gone via a fresh Admin API call.
2. The identical call with **no** ticket is denied (200, audited denial
   in the response body, not a raised error) — session independently
   confirmed **still alive**; real `CONTAINMENT_ACTION_ATTEMPTED`/`_DENIED`
   rows exist, no `_EXECUTED` row.
3. A **second real org**'s real user, with a **valid** step-up ticket, is
   still rejected (org-membership check inside `_perform()` fires after
   the gate passes) — session independently confirmed still alive, a real
   `_FAILED` row, never `_EXECUTED`.
4. `ANALYST`- and `READ_ONLY`-only tenants both get a real 403 from the
   route's own role gate, never silently allowed through.

New tests: 9 route-level tests (`tests/unit/application/test_routes_detections.py`,
mocking only `KeycloakAdminClient`, exercising the real action/gate/audit
chain through the route) + 8 DI-wiring tests
(`tests/unit/external/test_playbook_action_registry_wiring.py`). Full
backend suite before/after: 1976 → 1993 passed (+17, zero regressions,
including the pre-existing H2 test files), 2 skipped both times.
`ruff`/`black`/`mypy` clean. Independently re-verified by the orchestrator
before merge (not just the subagent's self-report): real diff read
(confirming H2's own gate/audit logic files are untouched), real PoC
output inspected, all 43 new + 22 pre-existing tests re-run directly,
full suite count (1993/2) matched exactly, no leftover `kronos-poc-*`
containers.

**Priority: P1** — a real, previously-inaccessible, already-deeply-verified
SOC capability (revoke a compromised user's active session) is now
actually usable, closing a deliberate, honestly-documented scope cut from
the platform's original response/SOAR milestone.

---

## Other areas reviewed this pass

- **H1/M8/H3/H4** (playbook engine core, evidence collection, case/ticket
  integration): not yet given the same direct-review treatment this pass
  — EE1 consumed the full session's review budget on H2 specifically,
  given its severity (a real destructive-action subsystem) once EE1's own
  finding was surfaced. Worth a dedicated future pass.

## Execution plan

**EE1**: found via direct review, dispatched (substantial enough for a
subagent + worktree, unlike DD1's small direct fix), independently
re-verified and merged this pass.

Remaining candidates, unchanged, both either low-value or blocked:
- `charts/kronos/files/nginx.conf.template` Helm sync — no live
  consequence yet.
- Prod OpenSearch demo-cert gap — needs a real project-owner TLS
  decision, not attempted.

New candidate surfaced but not yet started: a direct review pass over
H1/M8/H3/H4 (the rest of the SOAR/response subsystem) and the six
EDR/SIEM connectors from Milestones P/Q/R/S, following the same method
that found EE1.
