# PoC: Containment action adapters + approval gates (roadmap M7/H2, GATE)

**Objective (roadmap, verbatim):** "Containment adapters (isolate host,
block IP, revoke session) behind an ABC. **Gate:** prove no destructive
action can execute without either an explicit policy authorization or
human approval, and that every attempt is audited whether or not it
succeeded. Ties to existing step-up auth."

## Judgment call: which named example has a real target? (read this first)

The roadmap names three examples ("isolate host, block IP, revoke
session") as illustrations, not a mandate to build exactly three. This
item's brief was explicit: shipping a fabricated/no-op adapter for a
target that doesn't really exist is the CLAUDE.md SS F failure mode
("plausible code with no captured real run"), applied to this gate. Each
was investigated for real before deciding:

- **Revoke session -- REAL, shipped.** Keycloak 26.2.5 (`docker-keycloak-1`,
  already running) has a real, documented Admin REST API for exactly this:
  `GET /admin/realms/{realm}/users/{id}/sessions` and
  `DELETE /admin/realms/{realm}/sessions/{session}`. The already-provisioned
  `kronos-backend` confidential client's service account already holds
  `realm-management` `manage-users`/`view-users` (see
  `docker/keycloak/kronos-realm.json`'s own AUTH-001 comment) -- no new
  credentials, no new grants needed. This is the strongest real,
  destructive, verifiable target in this repo's dev stack, and it's what
  this PoC exercises end to end.
- **Block IP -- investigated, NOT shipped (real gap, not fabricated).**
  Checked `docker-compose.dev.yml`'s `nginx` service: its config
  (`docker/nginx/nginx.conf.template`) is baked into the image at *build*
  time via envsubst, with no live-editable bind mount (only `tls_certs` is
  mounted, read-only). There is no ModSecurity/WAF, no ipset/nftables
  sidecar, and no cloud security-group API anywhere in this dev stack. The
  only way to "block an IP" today would be either (a) editing the shared
  nginx container's files directly and reloading -- mutating a container
  this session didn't create, for every other agent's shared dev stack, for
  a change with no real rollback path -- or (b) host-level iptables/nftables
  manipulation, which is outside KronOS's own trust boundary and requires
  host root no `src/` code has or should have. Neither is a real,
  KronOS-owned enforcement point; both would be fabricating a destructive
  action with no real backing service, exactly what this item's brief says
  not to do. **Scoped out.** A real future implementation needs an actual
  owned enforcement point -- e.g. a dedicated nftables sidecar exposing a
  minimal, KronOS-authenticated HTTP API to add/remove exactly one rule, or
  (in a cloud deployment) a real security-group/NACL API -- not a shortcut
  through the shared reverse proxy.
- **Isolate host -- investigated, NOT shipped (confirmed, not assumed).**
  Re-confirmed via `grep -rEn "EDR|osquery|Fleet[A-Z]|HostAgent|host_agent|isolate_host|IsolateHost" src/`:
  the only hits are two docstring mentions of a *future* Zeek/EDR/syslog
  collector (`src/domain/timeline.py`, `src/domain/stream.py`, roadmap M3)
  -- no host-management/EDR/fleet/agent component of any kind exists
  anywhere in `src/` today. **Scoped out**, not fabricated. A real future
  implementation needs an actual host-side agent or EDR integration
  (osquery, a cloud instance-quarantine API, or a real EDR vendor API) to
  call into -- there is nothing to adapt to yet.

One real, deeply-verified containment action is the deliverable here, not
three (one real, two fabricated).

## Versions / real dependencies (CLAUDE.md SS F.2 step 1)

- Keycloak **26.2.5** (`quay.io/keycloak/keycloak:26.2` per
  `docker/docker-compose.dev.yml`, confirmed live via
  `docker exec docker-keycloak-1 kc.sh --version` -> `Keycloak 26.2.5`),
  already running (`docker-keycloak-1`).
- Postgres 16 (`docker-postgres-1`, already running) -- real
  `PostgresAuditLogRepository`/`AuditLogService`, same idiom
  `poc/playbook_engine/` already established.
- `httpx` (pinned in `pyproject.toml`), real scripted Authorization Code +
  PKCE login reusing `poc/auth_flow/auth_helpers.py`'s own
  `real_browser_login()` -- no password grant, no hand-minted tokens, no
  fabricated session ids.

## Real, live Keycloak Admin API shapes confirmed BEFORE writing `src/`

Per CLAUDE.md SS F ("find real docs/examples for that exact version...
prefer official docs... a PoC against the wrong version is worse than no
PoC"), the following were confirmed against the real, live
`docker-keycloak-1` (26.2.5) via a real `kronos-backend` service-account
admin token, before any `src/` code was written:

```
GET  /admin/realms/kronos/users/{id}/sessions            -> 200 [ {...} ]
DELETE /admin/realms/kronos/sessions/{sessionId}          -> 204 (real success)
DELETE /admin/realms/kronos/sessions/{alreadyGoneId}      -> 404 {"error":"Sesssion not found"}
GET  /admin/realms/kronos/organizations/{orgId}/members/{userId}  -> 200 (member) / 404 (not a member)
```

The literal `{"error":"Sesssion not found"}` (note Keycloak's own typo,
"Sesssion") is reproduced verbatim in `src/adapter/keycloak/admin_client.py`'s
own docstring and in this PoC's unit test
(`tests/unit/adapter/test_keycloak_admin_client.py`) -- proof this was
actually run, not assumed from memory or generic REST-API conventions.

## What this PoC actually does (`run_poc.py`)

Drives the real, unmodified `src/` classes -- `StepUpApprovalGate`,
`StaticPolicyApprovalGate` (`src/application/approval_gate.py`),
`ContainmentAction`/`RevokeKeycloakSessionAction`
(`src/application/containment_action(s).py`), `HttpxKeycloakAdminClient`
(`src/adapter/keycloak/admin_client.py`), and the real, unmodified H1
`PlaybookActionRegistry`/`PlaybookExecutionService` -- against the real
Keycloak 26.2.5 and real Postgres 16.

1. **Scenario 0 -- a real session exists.** A real scripted Authorization
   Code + PKCE login as `analyst` against the live dev-stack Keycloak (via
   `kronos.local`, not password grant) creates a real session; its id is
   confirmed present via a fresh, independent `GET .../sessions` call.
2. **Scenario 1 -- DENIED.** The same real session's id is targeted by a
   real `Playbook` step with **no** `approval_ticket_id` at all. The step
   raises `ContainmentActionDeniedError`, the playbook halts. A **fresh,
   independent** Admin API call confirms the real session is **still
   alive** -- the gate is a real precondition, not merely code that
   returns without doing anything. Real Postgres rows
   (`CONTAINMENT_ACTION_ATTEMPTED`, `CONTAINMENT_ACTION_DENIED`) exist for
   this exact attempt; no `CONTAINMENT_ACTION_EXECUTED` row for it.
3. **Scenario 2 -- APPROVED.** A real one-time step-up ticket is minted
   (`InMemoryTicketStore.put()`, the same primitive
   `POST /api/step-up/ticket` uses internally) and embedded in the step's
   params. The real revoke executes; a **fresh, independent** Admin API
   call confirms the real session is now **gone**. Real
   `CONTAINMENT_ACTION_EXECUTED` row exists; `AuditLogService.verify_chain()`
   confirms the hash chain is intact across the denied-then-approved
   sequence. Replaying the identical (already-consumed) ticket a second
   time is denied, not silently re-authorized -- the one-shot guarantee
   verified for real.
4. **Scenario 3 -- tenant isolation.** A real second Keycloak organization
   and a real second user are created via the Admin API (mirrors
   `scripts/provision_keycloak_org.sh`'s own pattern), that user
   real-logs-in for a real second session. The **original** tenant then
   attempts to revoke that **second org's** session -- **with a valid
   approval ticket** -- and is rejected with `AuthorizationError` because
   the target user is not a member of the acting tenant's own org
   (confirmed via a real, independent `is_org_member` Admin API check, not
   trusted from playbook params). A fresh Admin API call confirms the
   second org's session is **still alive**; a real
   `CONTAINMENT_ACTION_FAILED` row exists, never `_EXECUTED`.
5. **Scenario 4 -- extensibility.** `StaticPolicyApprovalGate` (a second,
   completely different `ApprovalGate` -- an explicit, admin-configured
   allow-list, no human ticket at all) authorizes a real revoke of a
   **third** real session (`case-lead`), through the exact same
   `ContainmentAction`/`RevokeKeycloakSessionAction` and
   `PlaybookExecutionService` code, with zero changes to either --
   concretely proving "new approval mechanism = new class."
6. **Cleanup.** The temporary second org and user are deleted via the real
   Admin API.

## Real captured output

See `output.txt` -- the actual, unedited stdout of the last real run:
**19/19 checks passed** against the real, live Keycloak 26.2.5 and
Postgres 16. Re-run twice in a row to confirm idempotency (no leftover
state from one run breaking the next) -- both runs passed 19/19 cleanly;
`output.txt` is the second (final) run.

## Real bugs/findings surfaced by actually running this (not by reading docs)

1. **Keycloak 26.2.5 rejects `domains: []` on organization creation** with
   a real 400 `{"errorMessage":"You must provide at least one domain"}` --
   not documented as obvious from the Organizations API shape alone; found
   by actually POSTing it. Fixed by giving each PoC-created org a real,
   unique `.invalid` domain.
2. **Keycloak 26.2.5 requires organization `name` to be unique, not just
   `alias`.** A second real run reusing the same hardcoded org `name`
   while a prior (crashed) run's org of the same name still existed
   produced a real `409 Conflict` -- found by hitting it, not by reading
   the OpenAPI schema (which doesn't call this out). Fixed by suffixing
   `name` with the same per-run random suffix as `alias`.
3. **This realm's Declarative User Profile requires `firstName`/`lastName`
   for a real login to complete.** A user created via the Admin API
   without them is created successfully (201), but a real login then
   redirects to a real `VERIFY_PROFILE` required-action page instead of
   issuing tokens (`302` to
   `.../login-actions/required-action?execution=VERIFY_PROFILE`) --
   confirmed live, not assumed from the realm's `kronos-realm.json`
   User Profile config alone. Fixed by always setting both fields.
4. **`DELETE /admin/realms/{realm}/sessions/{id}` on an already-gone
   session returns a literal `{"error":"Sesssion not found"}`** (Keycloak's
   own typo, reproduced verbatim in `src/`) -- confirmed this is real
   Keycloak 26.2.5 behavior, not a KronOS bug, and is treated as a
   legitimate terminal outcome (not an error) in
   `HttpxKeycloakAdminClient.revoke_session()`.
5. **A stale leftover PoC-only Keycloak test user
   (`kronos-poc-containment-1785740103`) and an empty
   `poc/containment_approval_gate/` directory were found in the shared
   checkout before this pass started** -- artifacts of an apparently
   earlier, incomplete attempt at this exact roadmap item that died before
   writing any real code or committing. The stray user was deleted via the
   real Admin API (harmless, additive cleanup); the directory was empty so
   nothing to reconcile. Reported here for the record, not silently
   absorbed.
6. **The dev stack's nginx/step-ca leaf cert had already expired** (valid
   only Aug 1-2 2026; today is Aug 6) when this PoC started -- the exact,
   already-documented recurring friction from
   `docs/NEXTGEN_SOC_ROADMAP.md` SS5. Fixed via the documented remedy
   (`docker compose -f docker/docker-compose.dev.yml up -d tls-init &&
   docker restart docker-nginx-1`) before any login attempt.

## Design decisions (why, not just what)

- **Audit ordering: `CONTAINMENT_ACTION_ATTEMPTED` before the gate is even
  consulted.** A bug or crash inside the `ApprovalGate` itself must never
  erase the fact an attempt happened -- "every attempt is audited whether
  or not it succeeded" is read literally here, including attempts the gate
  fails to evaluate cleanly.
- **`CONTAINMENT_ACTION_DENIED` is a distinct event from
  `CONTAINMENT_ACTION_FAILED`.** "No approval was present" (the gate
  working correctly) and "the real backend rejected the call" (a genuine
  failure) are different facts a court-facing audit trail must not
  conflate -- this is why Scenario 3's cross-org rejection is `_FAILED`
  (a real `AuthorizationError` from inside `_perform`, after the gate
  already approved it), while Scenario 1's is `_DENIED` (the gate itself
  said no).
- **`ContainmentAction` is a template-method base, not a bespoke
  per-action approval check.** `RevokeKeycloakSessionAction` implements
  only `_perform()`; the gate-consult-then-audit sequence is inherited
  verbatim. A future `BlockIpAction` (once a real enforcement point
  exists) or any other destructive action reuses this exact sequence with
  zero new approval/audit logic of its own -- directly answering the
  brief's "design the approval gate as its own abstraction... so future
  gated actions reuse it without bespoke per-action approval logic."
- **`StepUpApprovalGate` reuses the real, existing `TicketStore`
  (`src/external/middleware/step_up_store.py`), not `StepUpAuth`.**
  `StepUpAuth.consume_ticket` raises `fastapi.HTTPException`, which would
  leak a framework dependency into this application-layer module
  (CLAUDE.md SS A.3). `TicketStore`/`ConsumeResult` have zero framework
  imports of their own despite living under `external/middleware/` (a
  pre-existing placement, not this module's choice) -- reusing them
  directly is the smaller layering compromise versus inventing a second,
  parallel ticket-store abstraction for the exact same real concept.
- **Tenant isolation is checked twice, defense in depth.**
  `RevokeKeycloakSessionAction._perform()` independently verifies (a) the
  target `user_id` is a real member of the acting tenant's own org (a
  fresh `is_org_member` Admin API call, never trusted from params) and
  (b) the named `session_id` actually belongs to that `user_id`'s own
  real, live session list -- a caller cannot revoke an arbitrary session
  id merely by pairing it with a user_id who happens to be a real org
  member.

## Explicitly flagged gaps, not this item's scope

- No HTTP route or scheduled/Detection-triggered trigger wiring this pass
  (mirrors H1's own precedent) -- `ContainmentAction`/`ApprovalGate`/
  `HttpxKeycloakAdminClient` are not yet wired into
  `dependencies.py`/`startup.py`.
- "Block IP" and "isolate host" are real, reported gaps (see the judgment
  call section above), not silently dropped -- they need a real owned
  enforcement point that doesn't exist in this dev stack yet.
- `StaticPolicyApprovalGate`'s allow-list is constructor-only (in-memory);
  a persisted, admin-editable policy store is real, legitimate follow-up
  scope once an authoring UI/API exists (mirrors `RulePack`'s own
  precedent of starting in-memory before a versioned repository was
  built).

## Run

```
~/venv/bin/python3 poc/containment_approval_gate/run_poc.py
```

Requires `docker-keycloak-1` and `docker-postgres-1` already running. If
`kronos.local`'s TLS cert has expired (`docs/NEXTGEN_SOC_ROADMAP.md` SS5's
documented daily friction):

```
docker compose -f docker/docker-compose.dev.yml up -d tls-init
docker restart docker-nginx-1
```

Idempotent and safe to re-run: creates its own fresh real sessions/org/user
each run and cleans up the org/user afterward (revoked sessions are
already gone; nothing else persists beyond real Postgres audit rows, which
accumulate exactly like every other real audited action in this system).
