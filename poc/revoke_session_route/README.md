# PoC: `POST /api/detections/{id}/contain/revoke-session` (Gap Audit EE1)

**Objective.** H2 (roadmap M7, `poc/containment_approval_gate/`) shipped one
real, deeply-verified containment action (`RevokeKeycloakSessionAction`,
gated by `ApprovalGate`, 19/19 real checks against live Keycloak) but
**never wired it into any HTTP route or `dependencies.py`/`startup.py`** --
an explicitly-flagged, honestly-reported scope cut at the time. EE1 (this
item) does for `RevokeKeycloakSessionAction` exactly what Milestone W1
already did for `SyncDetectionToSiemAction`: adds the DI wiring and one
new HTTP route. This PoC proves that wiring actually works, against the
real dependency, not just that the pre-existing unit tests still pass.

## Versions / real dependencies (CLAUDE.md SS F.2 step 1)

- Keycloak **26.2.5** (`quay.io/keycloak/keycloak:26.2` per
  `docker/docker-compose.dev.yml`, confirmed live via
  `docker exec docker-keycloak-1 kc.sh --version` -> `Keycloak 26.2.5`),
  already running (`docker-keycloak-1`) -- identical instance H2's own
  PoC used.
- Postgres 16 (`docker-postgres-1`, already running) -- real
  `PostgresAuditLogRepository`/`AuditLogService`.
- `httpx` (pinned in `pyproject.toml`) for both the real scripted
  Authorization Code + PKCE login (`poc/auth_flow/auth_helpers.py`) and
  the real in-process HTTP client (`httpx.ASGITransport` against the
  real, unmodified `create_app()`).
- FastAPI's own TestClient was deliberately NOT used -- its threaded
  portal is incompatible with an async SQLAlchemy engine created in this
  coroutine's own loop (the same W3/W8/W11/W14 finding
  `poc/evidence_download/run_poc.py` already documents and works around
  the same way).

## What "real" means here, precisely

Two layers, both exercised for real, in order (see `run_poc.py`'s own
module docstring for the full reasoning):

1. **DI wiring** -- `configure_keycloak_admin_client_from_settings()`
   (patched `Settings`, but real `kronos-backend`/`kronos-backend-secret`
   values, real Keycloak URL) is called for real, then the real,
   unmodified `get_playbook_action_registry()` (the function `src/external/
   dependencies.py` already had, extended this pass to also call the new
   `get_revoke_keycloak_session_action()`/`get_containment_approval_gate()`)
   is called directly and asserted to produce a registry containing a
   real, working `RevokeKeycloakSessionAction` -- not a hand-built
   registry that bypasses the new wiring code entirely.
2. **HTTP route** -- that real registry (plus a real Postgres-backed
   `AuditLogService` and the real, unmodified `create_app()`) is driven
   through the real new route via `httpx.ASGITransport`. `get_tenant_context`
   is the only dependency overridden (mirrors `poc/evidence_download/
   run_poc.py`'s own established in-process pattern -- the route/gate/
   audit/Keycloak logic under test is 100% real; only JWT parsing itself
   is bypassed by injecting the same claims a verified JWT would have
   produced). `get_step_up_auth()` is genuinely NOT overridden: the real
   `POST /api/step-up/ticket` route and this PoC's own
   `StepUpApprovalGate` share the exact same `TicketStore` singleton the
   real DI container manages, via `configure_step_up_auth()` +
   `create_app(step_up_ticket_store=...)` -- proving the real
   ticket-issuance-to-consumption loop closes through two different
   routes, not two independent stores that happen to agree in a test.

## Real users (already provisioned in `docker/keycloak/kronos-realm.json`)

- `analyst` / `DevAnalyst#2026` (realm role `analyst`, id
  `10000000-...-0002`) -- the session-revocation TARGET in scenarios (a)/(b).
- `admin` / realm role `org-admin` (id `10000000-...-0001`) -- used only
  as the CALLER identity's `user_id` (`TenantContext` is constructed
  directly with `roles={ORG_ADMIN}`, not via a real login for this
  identity -- mirrors H2's own PoC, which also never did a real login for
  its calling tenant, only for the sessions being revoked).
- A real, throwaway second org + second user (created/deleted via the
  real Admin API, `kronos-poc-ee1-org-<random>` / `poc-ee1-user-<random>`)
  for the cross-tenant scenario (c) -- cleaned up at the end of the run.

## Scenarios (all four required by this item's brief)

Run twice in a row to confirm idempotency -- **21/21 checks passed both
times** (`output.txt` is the second/final run).

1. **(a) Real ticket -> real revoke.** A real scripted PKCE login as
   `analyst` creates a real session, confirmed alive via a fresh, direct
   Admin API call. A real ticket is minted via the real
   `POST /api/step-up/ticket` route (`operation=revoke_keycloak_session`,
   `resource_id=<the real session id>`). The real new
   `POST /api/detections/{id}/contain/revoke-session` route is called with
   that ticket -- returns 200, `succeeded=true`, real output
   `{"revoked": true, ...}`. A **fresh, independent** Admin API call
   confirms the session is genuinely **gone**.
2. **(b) No ticket -> denied, session survives.** A second real `analyst`
   login creates a second real session. The identical route call with NO
   ticket fields returns 200, `succeeded=false`, error names the denial
   (`"... denied by step_up_mfa: ..."`). A fresh Admin API call confirms
   the session is **still alive**. Real Postgres
   `CONTAINMENT_ACTION_ATTEMPTED`/`_DENIED` rows exist for this exact
   session id; no `_EXECUTED` row.
3. **(c) Cross-tenant -> rejected even with a VALID ticket.** A real
   second Keycloak org + real second user are created via the Admin API;
   that user logs in for real, and a real, VALID step-up ticket is minted
   for that session. The original (`kronos-dev`) tenant's caller then
   attempts to revoke it -- rejected (`succeeded=false`, error names the
   real org-membership rejection), because `RevokeKeycloakSessionAction`'s
   own independent `is_org_member` check (never trusting the ticket alone)
   fails. A fresh Admin API call confirms the second org's session is
   **still alive**. Real `CONTAINMENT_ACTION_FAILED` row exists, never
   `_EXECUTED`. The temporary org/user are deleted afterward.
4. **(d) Role-gating enforced.** An `ANALYST`-only tenant (and, for
   defense-in-depth, a `READ_ONLY`-only tenant) both get a real HTTP 403
   from the new route -- never silently allowed through, confirming the
   `requires_role(Role.ORG_ADMIN, Role.CASE_LEAD)` gate this route uses is
   deliberately narrower than `sync_detection_to_siem`'s own
   `ORG_ADMIN`/`CASE_LEAD`/`ANALYST` gate (see the route's own docstring
   for why).

## Real captured output

See `output.txt` -- unedited stdout of the second (idempotency-confirming)
real run: **21/21 checks passed** against the real, live Keycloak 26.2.5
and Postgres 16, through the real new HTTP route.

## Design decisions (why, not just what)

- **`get_tenant_context` is the only dependency override.** Everything
  downstream of it -- role gate, gate-consult-then-audit sequence, real
  Keycloak Admin API calls, real Postgres audit rows -- is the real,
  unmodified `src/` code path a production request would take. This is
  the established in-process verification idiom for this initiative
  (`poc/evidence_download/run_poc.py`), applied here for the first time
  to a destructive, approval-gated action rather than a read path.
- **`get_step_up_auth()` is deliberately NOT overridden.** Using the real
  process-wide singleton (configured once via `configure_step_up_auth()`)
  proves the real `POST /api/step-up/ticket` route and this route's own
  `StepUpApprovalGate` genuinely share one `TicketStore` -- exactly the
  real production wiring `get_containment_approval_gate()`
  (`src/external/dependencies.py`) implements, not a PoC-only shortcut.
- **`configure_keycloak_admin_client_from_settings()` is exercised with a
  patched `Settings` object, not real env vars for the whole app.**
  Constructing a full, valid `Settings()` requires many unrelated required
  fields (Vault, database URL, MinIO, ...) that have nothing to do with
  this item; patching `src.config.Settings` to return only the
  Keycloak-relevant fields (with the REAL `kronos-backend`/
  `kronos-backend-secret` values, not fabricated ones) mirrors
  `tests/unit/external/test_playbook_action_registry_wiring.py`'s own
  established pattern for the pre-existing Splunk/CEF/Sentinel sink
  getters, applied here to the new Keycloak admin client getter.
- **`detection_id` in the URL is audit-context only.** Unlike
  `SyncDetectionToSiemAction`, `RevokeKeycloakSessionAction` never looks
  the `Detection` up -- a random UUID is used throughout this PoC, exactly
  as the route's own docstring states is the intended, correct behavior.

## Run

```
~/venv/bin/python3 poc/revoke_session_route/run_poc.py
```

Requires `docker-keycloak-1` and `docker-postgres-1` already running. If
`kronos.local`'s TLS cert has expired (`docs/NEXTGEN_SOC_ROADMAP.md` SS5's
documented daily friction -- hit on this exact run, see below):

```
docker compose -f docker/docker-compose.dev.yml up -d tls-init
docker restart docker-nginx-1
```

Idempotent and safe to re-run: creates its own fresh real sessions/org/user
each run and cleans up the temporary org/user afterward (revoked/denied
sessions are either already gone or will expire naturally like any other
real login; nothing else persists beyond real Postgres audit rows, which
accumulate exactly like every other real audited action in this system).

## Real friction hit while running this (not fabricated)

The dev stack's nginx/step-ca leaf cert had already expired (valid only
through Aug 18 13:58 UTC; this PoC ran ~23:12 UTC the same day) when this
PoC started -- the exact, already-documented recurring friction
`docs/NEXTGEN_SOC_ROADMAP.md` SS5 describes and H2's own PoC hit too.
Fixed via the documented remedy above before the first real login attempt;
no other new findings surfaced (this route/wiring reuses H2's own
already-verified Keycloak API shapes and quirks unchanged).
