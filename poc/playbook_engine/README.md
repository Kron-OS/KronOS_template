# PoC: Playbook engine (roadmap M7/H1)

**Objective (roadmap):** "OOP, pluggable: `PlaybookAction(ABC)` + registry,
declarative playbook definitions as data. Deterministic and fully audited —
every step, input, output and decision recorded. New action = registration,
not an edit."

## Scope boundary (binding, not incidental)

Roadmap H2 (the very next item) is a separate, explicitly-gated item for
real containment actions with an external, destructive side effect
(isolate a host, block an IP, revoke a session). H1 ships with only
non-destructive example actions:

- `TransitionDetectionTriageAction` — drives the real, already-existing
  `DetectionTriageService.transition()` (roadmap C4). A real, non-destructive,
  already-audited FSM move entirely within KronOS's own data.
- `LogNotificationAction` — entirely stateless, no side effect at all.

## Versions / real dependency (CLAUDE.md §F.2 step 1)

Postgres 16 (`docker-postgres-1`, already running on this host,
`postgresql+asyncpg://kronos:...@localhost:5432/kronos` — the same real
DSN every other PoC in this repo that touches Postgres directly already
uses). No new external plugin/service is involved — the "real dependency"
here is the real Postgres-backed `PostgresDetectionRepository` and
`PostgresAuditLogRepository`, not a new integration surface.

## What this PoC actually does (`run_poc.py`)

1. **Scenario 1 — real success run.** Seeds a real `Detection` row into
   Postgres (`triage_state=NEW`), then executes a real, declarative
   two-step `Playbook` (`transition_detection_triage` →
   `log_notification`) through the real, unmodified
   `PlaybookExecutionService`. Confirms: both steps ran and succeeded; the
   real Detection row's `triage_state` actually changed to `INVESTIGATING`
   in Postgres (re-read from the database, not just the in-memory return
   value); real `PLAYBOOK_EXECUTION_STARTED`/`PLAYBOOK_STEP_EXECUTED` (×2)/
   `PLAYBOOK_EXECUTION_COMPLETED` audit rows exist with the exact
   step/action/params/output recorded; `AuditLogService.verify_chain()`
   confirms the real hash chain is intact.
2. **Scenario 2 — real failure run.** A playbook whose first step attempts
   an illegal FSM transition (`NEW` → `TRUE_POSITIVE` directly, skipping
   `INVESTIGATING`) real-halts before its second step ever runs. Confirms:
   the real Detection row's `triage_state` is unchanged (still `NEW`) —
   proving the failed step made no partial change; a real
   `PLAYBOOK_STEP_FAILED` audit row exists with the real
   `DetectionStateError` message; the hash chain is STILL intact after a
   failure (a failure must never corrupt the audit chain).
3. **Scenario 3 — "new action = registration, not an edit," proved
   concretely, not asserted.** Both `TransitionDetectionTriageAction` and
   `LogNotificationAction` are registered into the SAME
   `PlaybookActionRegistry` and were ALREADY run through the identical
   `PlaybookExecutionService.execute()` code path in Scenario 1 — this
   scenario just points at that fact rather than re-deriving it, since a
   second, separate "prove it again" run would be redundant, not stronger
   evidence.

## Real captured output

See `output.txt` — the actual, unedited stdout of the last real run:
**16/16 checks passed** against the real, live Postgres 16 instance.

## Design decision: fail-fast on step failure

A failing step halts the remaining playbook rather than continuing. A
later step (e.g. a notification describing "what was done") would be
actively misleading if an earlier step silently failed but execution
continued as if nothing happened. This is the same conservative instinct
roadmap H2 will apply to destructive actions ("no destructive action
without explicit authorization") — prefer stopping over guessing. A
future per-step "continue on failure" flag is real, legitimate follow-up
scope, not built speculatively here.

## Explicitly flagged gaps, not this item's scope

- No HTTP route or scheduled/Detection-triggered trigger wiring this pass
  (mirrors F1/F3/F4/G1/G2's own precedent of shipping the mechanism first).
  `PlaybookExecutionService`/`PlaybookActionRegistry` are constructed
  directly by whatever future caller needs them, not yet reachable from
  the running application or wired into `dependencies.py`/`startup.py`.
- No playbook *persistence* — a `Playbook` is pure in-memory data this
  pass; a `PlaybookRepository` for storing/versioning authored playbooks
  (mirroring `RulePack`'s own versioned-repository shape) is real,
  legitimate follow-up scope for whenever an authoring UI/API is built,
  not required to prove this item's own mechanism.
- Only two example actions ship; H2 will add the first genuinely
  destructive ones behind its own approval-gate mechanism.

## Run

```
~/venv/bin/python3 poc/playbook_engine/run_poc.py
```

Requires `docker-postgres-1` already running (real dev-stack Postgres 16,
`kronos`/`kronos_dev_password`) — the same already-running container every
other PoC in this repo that touches Postgres directly already assumes.
