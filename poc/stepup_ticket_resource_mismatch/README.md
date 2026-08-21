# PoC: step-up ticket "resource scoping" is not actually enforced (adversarial red-team review)

**STATUS: FIXED (Gap Audit Milestone JJ).** This PoC originally proved the
attack below succeeded. `ApprovalGate.authorize()` now takes an explicit,
server-computed `resource_id` argument (`RevokeKeycloakSessionAction
._resource_id()` derives it from the real `session_id`); the vulnerable
caller-supplied `approvalResourceId` field has been removed from
`RevokeKeycloakSessionIn` entirely. `run_poc.py` and `output.txt` have been
updated to re-run the identical attack shape against the fixed code —
**13/13 checks now pass, confirming the attack is denied** (see "Fix
verification re-run" below). The sections immediately below describe the
finding as originally discovered, kept for the record.

**Objective.** The red-team review brief for this pass explicitly asks:
"can a ticket minted for one action/resource be replayed against a
different one?" This PoC answers that concretely for
`StepUpApprovalGate` (`src/application/approval_gate.py`), the gate
consulted by `ContainmentAction.execute()`
(`src/application/containment_action.py`) before `RevokeKeycloakSessionAction`
(`src/application/containment_actions.py`) ever calls the real Keycloak
Admin API.

## Versions / real dependencies (CLAUDE.md SS F.2 step 1)

Same real dev stack as `poc/revoke_session_route/` (Milestone EE1),
already running when this PoC was written: Keycloak **26.2.5**
(`docker-keycloak-1`), Postgres 16 (`docker-postgres-1`). No new
containers created.

## The finding

`StepUpApprovalGate.authorize(action_name, params, tenant)` is called by
`ContainmentAction.execute()` with:

- `action_name` = `RevokeKeycloakSessionAction.action_name`, a **fixed
  constant string** (`"revoke_keycloak_session"`) — the same value for
  *every* invocation of this action, regardless of which
  `user_id`/`session_id` is the real target.
- `resource_id` = `params["approval_resource_id"]`, an **entirely
  caller-chosen free-form string**, supplied independently:
  - at mint time, via `POST /api/step-up/ticket` (`resource_id` in the
    request body — the route does not check it against anything),
  - at consume time, via `POST /api/detections/{id}/contain/revoke-session`
    (`approvalResourceId` in the request body).

Nothing anywhere — not the route (`src/external/routes/detections.py`),
not `StepUpApprovalGate.authorize()`, not
`RevokeKeycloakSessionAction._perform()` — ever cross-checks that
`approval_resource_id` equals, or is derived from, the actual
`session_id`/`user_id` the destructive action targets.
`RevokeKeycloakSessionAction._perform()` never even receives
`approval_resource_id`; it operates purely on `params["user_id"]`/
`params["session_id"]`.

The consequence: a caller who already holds a real, valid step-up ticket
"for" resource A can present it (matching only the string) while asking
the real action to operate on a completely different resource B, and the
gate authorizes it. The one-time-use guarantee (`TicketStore.consume`)
still holds — a given ticket id can still only be spent once — but the
guarantee that it's spent *for the resource it was nominally issued for*
does not exist.

## Real repro (`run_poc.py`)

1. Real Keycloak login (`analyst` / real Authorization Code + PKCE) twice,
   producing two real, independent, live sessions X and Y for the same
   user.
2. A real ticket is minted via the real `POST /api/step-up/ticket` with
   `resource_id=<session X's real id>`.
3. **The attack:** `POST /api/detections/{id}/contain/revoke-session` is
   called with `sessionId=<session Y's real id>` (the actual target) but
   `approvalResourceId=<session X's real id>` (matching the ticket, not
   the actual target) and the ticket id from step 2.
4. Result: **200, `succeeded=true`**, the real Keycloak Admin API receives
   a real `DELETE .../sessions/<session Y>` call and returns 204. A fresh,
   independent Admin API re-check confirms session Y is genuinely gone.
   Session X — the ticket's *nominal* resource — is untouched (still
   alive), proving `resource_id` had zero real bearing on which resource
   was actually acted upon.

**9/9 checks passed.** See `output.txt` for the captured run (full raw
output also at `/tmp/mismatch_poc_output.txt` on the host).

## Severity / exploitability notes

- This is **not** a privilege-escalation bug: a caller still needs
  `ORG_ADMIN`/`CASE_LEAD` role (route-gated) and the target `user_id`
  must belong to the caller's own tenant (`RevokeKeycloakSessionAction`'s
  own `is_org_member` check) — cross-tenant abuse is still blocked, as
  Milestone EE1's own PoC already verified.
- Within those bounds, though, the "per-resource step-up" property this
  mechanism's own docstrings imply (`StepUpApprovalGate`'s docstring:
  "ticket scoped to `(operation=action_name, resource_id=<caller-chosen>)`")
  does not actually bind the human-approval moment to the specific,
  real-world resource being acted on. A single MFA re-authentication for
  "I want to revoke a session" can be redirected, at the moment of use, to
  ANY session the caller can otherwise name — including one a human
  approver (in a workflow where a *different*, higher-privilege person
  reviews "please approve revoking session X" before minting the ticket)
  never actually agreed to. Since this deployment's current flow has the
  *same* user mint and consume their own ticket (self-service step-up, not
  dual control), the practical impact today is limited to: a
  UI/detection-driven "confirm this specific session" prompt is not a
  real security boundary — only "this actor recently proved MFA for this
  action type" is.
- This is the general shape Milestone FF1 already flagged as a recurring
  risk class ("an unvalidated identifier flowing from a lower-trust
  boundary into a higher-trust operation") — here the lower-trust input is
  the request body's own `sessionId`, and the "validation" that looks like
  it scopes the approval to a specific resource does not actually do so.

## Fix implemented (Gap Audit Milestone JJ)

`ApprovalGate.authorize()` now takes `resource_id` as an explicit,
mandatory positional argument (`authorize(action_name, resource_id, params,
tenant)`) rather than reading it out of `params`. `ContainmentAction` gained
a new abstract `_resource_id(params) -> str` method that every concrete
action must implement to derive the REAL target from its own params;
`ContainmentAction.execute()` calls it (auditing
`CONTAINMENT_ACTION_FAILED` and re-raising if derivation itself fails) and
passes the result to `authorize()` before the gate is ever consulted.
`RevokeKeycloakSessionAction._resource_id()` returns `params["session_id"]`
directly — the same value `_perform()` itself operates on, so there is no
longer a second, independently-suppliable field that could diverge from
it. `RevokeKeycloakSessionIn.approvalResourceId` has been removed from the
route's request model entirely; any future `ContainmentAction` subclass is
now required (abstract method) to make the same real-target derivation
explicit, rather than being free to invent its own disconnected
`resource_id`.

## Fix verification re-run

Same real dependencies (Keycloak 26.2.5, Postgres 16), same attack shape,
run again after the fix:

1. Real ticket minted for session X (as before).
2. Attack: `POST .../contain/revoke-session` with `sessionId=session_y`,
   `approvalTicketId=<X's ticket>` (no `approvalResourceId` field — it no
   longer exists on the request model).
3. Result: **200, `succeeded=false`**, `CONTAINMENT_ACTION_DENIED` audited,
   no Keycloak revoke call made. Session Y independently re-confirmed
   alive via the Admin API.
4. The ticket is NOT burned by the denied mismatch: a legitimate follow-up
   request naming the ticket's real resource (`sessionId=session_x`)
   still succeeds — `succeeded=true`, a real `DELETE
   .../sessions/<session_x>` reaches Keycloak (204), and session X is
   independently confirmed gone while session Y remains alive.

**13/13 checks passed.** See `output.txt` for the captured post-fix run.

## Run

```
~/venv/bin/python3 poc/stepup_ticket_resource_mismatch/run_poc.py
```

Requires `docker-keycloak-1`/`docker-postgres-1` already running. If
`kronos.local`'s TLS leaf cert has expired (hit during this exact run —
the same recurring dev-stack friction `poc/revoke_session_route/README.md`
already documents):

```
docker compose -f docker/docker-compose.dev.yml up -d tls-init
docker restart docker-nginx-1
```

Idempotent: creates two fresh real sessions each run; post-fix, session X
is legitimately revoked by the script's own step 3 and session Y is left
alive (expires naturally, like any real login) — nothing else persists
beyond real Postgres audit rows.
