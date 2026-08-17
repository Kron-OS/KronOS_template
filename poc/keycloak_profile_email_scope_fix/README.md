# PoC: real `profile`/`email` Keycloak client scopes (Gap Audit Milestone Y2)

**Component pair:** `docker/keycloak/kronos-realm.json` ↔ real Keycloak
26.2 (`quay.io/keycloak/keycloak:26.2`, the version pinned in
`docker/docker-compose.dev.yml`).

## Background

Milestone X3's own real browser-login PoC (`poc/keycloak_browser_login/`)
incidentally captured a real, minor bug: a genuinely minted access token
for the `case-lead` test user had `preferred_username: null` and
`email: null`. X3 documented it as out-of-scope and moved on.

## Root cause (confirmed, not assumed)

`docker/keycloak/kronos-realm.json` defines its own explicit
`clientScopes` array. That array's own `acr` entry already carries a
comment explaining exactly why: *"Defined explicitly because an explicit
`clientScopes` array suppresses Keycloak's built-in defaults; required
for step-up (acr=aal2)."* The realm's `defaultDefaultClientScopes` list
still references `profile` and `email` by name, but because no
`clientScopes` entry in this file actually *defined* them (only `acr` was
manually re-added, since step-up specifically needed it), those two
referenced scope names never corresponded to real scope objects after
import — confirmed directly via the real Keycloak boot log:

```
WARN  [org.keycloak.models.utils.RepresentationToModel] (main) Referenced client scope 'profile' doesn't exist. Ignoring
WARN  [org.keycloak.models.utils.RepresentationToModel] (main) Referenced client scope 'email' doesn't exist. Ignoring
```

So the `preferred_username`/`email`/`email_verified` protocol mappers that
normally live inside Keycloak's built-in `profile`/`email` scopes were
never attached to any client, and never appeared in any token minted by
this realm.

**Ruled out as a possible cause (confirmed, not assumed):** the frontend's
own `scope: 'openid organization'` request (`frontend/src/keycloak.ts:157`)
was initially suspected, but `profile`/`email` are *default* client
scopes per the realm's own `defaultDefaultClientScopes` list — Keycloak
always includes default scopes in the token regardless of the `scope=`
request parameter (that parameter only affects *optional* scopes). Even
requesting `scope: 'openid profile email organization'` explicitly would
have made no difference while `profile`/`email` didn't exist as real
scope objects in the realm.

## Fix

Added real, version-correct `profile` and `email` client scope
definitions (protocol mappers included) to `docker/keycloak/kronos-realm.json`'s
`clientScopes` array, mirroring exactly how `acr` was already explicitly
re-added for the same reason. **Not hand-written from memory** — exported
directly from a real, fresh, throwaway Keycloak 26.2 instance's own
default `master` realm via the real Admin REST API
(`GET /admin/realms/master/client-scopes`), per CLAUDE.md §F ("find real
docs/examples for that exact version... prefer the official project docs
and the official GitHub repo"). `id` fields (instance-specific) were
stripped so Keycloak generates fresh ones on import.

**Real bug caught by this same verification process, before it was ever
committed:** an initial version of the added `description` text (an
explanation of *why* these scopes are explicit, matching this repo's own
convention of using JSON `description` fields to carry comments) was too
long for Keycloak's `CLIENT_SCOPE.DESCRIPTION` column
(`VARCHAR(255)`) — the real dev Keycloak crashed on boot with `Value too
long for column "DESCRIPTION CHARACTER VARYING(255)"`. Caught immediately
by actually restarting the real container and reading its real logs
(exactly the failure mode CLAUDE.md §F exists to catch), not assumed to
work. Fixed by shortening both descriptions to ~140 chars.

## How this was verified (real, not assumed)

1. Real fresh Keycloak 26.2 instance (`kronos-poc-y2-keycloak-defaults`,
   port 18080) started, authenticated as its own bootstrap admin, and
   real `profile`/`email` client scope JSON exported via the real Admin
   REST API. Torn down after export.
2. Added the real scope definitions to `kronos-realm.json`. First attempt
   crashed the real dev Keycloak on restart (see "real bug caught" above)
   — fixed and re-verified.
3. Restarted the real dev `docker-keycloak-1` (`KC_DB: dev-mem`, so every
   restart re-imports `kronos-realm.json` fresh — confirmed via
   `docker logs` showing `Realm 'kronos' imported` / `Import finished
   successfully` with no more "doesn't exist. Ignoring" warnings for
   `profile`/`email`).
4. Ran this directory's `run_poc.py` — a real Chromium browser (via
   Playwright, reusing `poc/keycloak_browser_login/`'s proven real-login
   pattern, no mocked routes) logs in as the real, pre-existing
   `case-lead` test user and decodes the real, freshly minted access
   token.
5. **Real regression caught and root-caused before declaring success:**
   the first two verification runs showed `organization: None` in the
   decoded token — a real, working claim before this session started
   (per X3's own captured `output.txt`). Rather than assume this was
   caused by this fix, isolated it directly: `git stash`ed the
   `kronos-realm.json` change, restarted Keycloak with the *original*
   (unfixed) file, and re-ran the same login — `organization: None`
   persisted *even without this fix*, proving it wasn't caused by this
   change. Root cause: `docker-compose.dev.yml`'s `keycloak-init` service
   provisions the `kronos-dev` Organization and its membership via
   real, one-shot Admin API calls *at `docker compose up` time* — this
   state lives in Keycloak's `dev-mem` (in-memory) storage and is wiped
   by any container restart done in isolation, not by the static realm
   import. Restored by re-running `docker compose -f
   docker-compose.dev.yml up keycloak-init` (and `dashboards-tenant-init`
   for full consistency) after restoring this fix — confirmed the fully
   clean, final run below has `organization` correctly populated again.
6. Full backend test suite before/after: 1954 passed, 2 skipped both
   times (true no-op delta — this fix touches only
   `docker/keycloak/kronos-realm.json` and `poc/`, no `src/` change).

**Side effect worth noting, not a bug:** restarting `docker-keycloak-1` in
isolation (required to pick up this realm.json fix) generates a fresh,
random `org_id` for the `kronos-dev` Organization on re-provisioning
(Keycloak Organizations aren't stable across a `dev-mem` restart). Any
pre-existing case/evidence data in the shared dev Postgres tagged with the
*previous* `org_id` is now tenant-orphaned (correctly isolated, not
visible under the new org — this is the multi-tenancy isolation working
as designed, not a leak). This is an inherent property of `KC_DB:
dev-mem` combined with restarting Keycloak specifically, not something
this fix introduces or needs to address.

## How to run

```
/home/reca/venv/bin/python poc/keycloak_profile_email_scope_fix/run_poc.py
```

Requires: the real dev stack up (`docker/docker-compose.dev.yml`),
`docker-keycloak-1` already restarted with this fix's `kronos-realm.json`,
and `keycloak-init`/`dashboards-tenant-init` re-run if Keycloak was
restarted since the last `docker compose up` (see "side effect" above).
