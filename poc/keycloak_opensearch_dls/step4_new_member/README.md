# PoC: brand-new org member added after setup, zero further OpenSearch calls (step 4)

Isolates the actual scaling claim from `../../opensearch_jwt/option_a_flat_claim/README.md`:
step 3 (`../`) provisioned all 3 users *before* OpenSearch was even
configured, so it never actually proved "a new member needs zero
OpenSearch-side changes" -- it's consistent with that claim, but doesn't
demonstrate it. This PoC does: OpenSearch is fully configured first (one
generic DLS role, one static mapping -- printed with an explicit marker in
`run_poc.sh`), and only *after* that does a brand-new Keycloak user get
created and linked into the already-existing org.

## What this actually does
`run_poc.sh` provisions org A with a single initial member (`user-a1`),
configures OpenSearch (JWT authc + the one generic `kronos-generic-tenant`
role + its one static mapping), then prints an explicit marker: everything
after it is Keycloak-only. `run_poc.py` then creates a brand-new user
(`user-a3-latecomer`, never defined anywhere in the realm import), links
them into the *existing* org A by re-invoking the real, unmodified
`../provision_keycloak_org.sh` (which correctly detects the org already
exists and only performs the member-link + attribute steps), and logs in
as them for real.

## Two more real Keycloak Admin REST findings (neither anticipated, both empirically caught)

### Finding 1: `POST /users` silently ignores a client-supplied `id`
A first attempt sent `{"id": "<uuid4 I generated>", ...}` expecting Keycloak
to honor it (as realm import and org creation both effectively do for
Keycloak-known ids). It doesn't: the user is created successfully (`201`)
under a **different, server-generated** id, silently. Every subsequent
call keyed on the id I'd generated (member-link, attribute PUT) failed --
member-link with `400`, attribute PUT with `404` — because that id
belonged to no real user. **Fixed**: extract the real id from the response's
`Location` header (`.../users/<real-id>`), not from the request body.

### Finding 2: `realmRoles` in the same creation payload is also silently ignored
A first attempt included `"realmRoles": ["analyst"]` in the same `POST
/users` body, expecting the role to be assigned at creation time. It wasn't:
the resulting real token's `roles` claim was just
`["default-roles-kronos", "offline_access", "uma_authorization"]` — no
`analyst` — which made every OpenSearch search `403 Forbidden` (no
privileges matched the mapped role). **Fixed**: realm role assignment needs
its own explicit call, `POST /users/{id}/role-mappings/realm` with the
role's `{id, name}` (fetched via `GET /roles/{name}` first).

Both are generic `POST /users` REST-payload gotchas — worth remembering for
any future Keycloak user-provisioning code (this repo doesn't have any yet
that creates users via REST; `provision_keycloak_org.sh` only ever links
*existing* users to orgs).

## Result: 8/8 real checks passed (`output.txt`)
- Baseline: pre-existing `user-a1` isolated to org A's doc.
- Brand-new user created, then linked into the **already-existing** org A
  via the unmodified provisioning script — which correctly reports
  `Organization kronos-dls-a already exists` rather than creating a
  duplicate.
- The new user's real JWT carries the identical flat `org_id` as the
  org's original member.
- The new user's real search against real OpenSearch is correctly
  DLS-isolated to org A's doc — with the printed marker confirming no
  `/_plugins/_security/*` call happened anywhere after OpenSearch's
  one-time setup, for this or any other member event.

This is the concrete proof the design in `option_a_flat_claim/README.md`
promised: onboarding a new org member is a Keycloak-only operation from
here on, full stop.

## Files
- `run_poc.sh` — bootstrap (OpenSearch + Keycloak + org A w/ one member,
  fully configures OpenSearch, then prints the Keycloak-only marker)
- `run_poc.py` — creates the brand-new user, links them into the existing
  org via the real `../provision_keycloak_org.sh`, verifies real DLS isolation
- `output.txt` — captured transcript of the last real run (8/8 passed)

## Cleanup
```bash
docker rm -f kronos-poc-kcosdls4-opensearch kronos-poc-kcosdls4-keycloak
```
