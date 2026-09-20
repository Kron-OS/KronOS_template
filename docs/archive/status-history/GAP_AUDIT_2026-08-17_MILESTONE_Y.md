# Gap Audit — Milestone Y (continuation, 2026-08-17)

Follow-up to `docs/GAP_AUDIT_2026-08-17.md` (Milestone X, fully resolved:
X1/X2a/X2b/X3 all CLOSED). Re-checked that doc's "still genuinely blocked"
list first — none of those items (V9 customer-log-source scoping, COMP-9
live-Wazuh dependency, Volatility3's explicit pause, real k8s/gVisor
unavailability, deferred v2 features) have become newly actionable since
2026-08-17. This doc covers what was found by going deeper rather than
re-scanning from scratch.

---

## Y1 — `evidence.quota_held` schema drift, found three times, never fixed

**STATUS (2026-08-17, commit TBD): CLOSED, verified live.**

`migrations/versions/20260816_1113_913567ca653a_add_integration_source_keys_table.py`
(Milestone W8) already found and documented, but deliberately did not fix,
a real drift on the shared dev Postgres container (`docker-postgres-1`):
stamped at Alembic head yet genuinely missing the `evidence.quota_held`
column the baseline migration (`56c861716f8f`) defines. The same drift was
rediscovered twice more (Milestone X1's `poc/evidence_download/`, X2a's
`poc/postgres_replication/`), each time routed around with a fresh
throwaway Postgres container rather than root-caused and fixed.

**Root cause, confirmed directly against the real container (not
assumed):**

```
$ docker exec docker-postgres-1 psql -U kronos -d kronos -tAc \
    "SELECT column_name FROM information_schema.columns \
     WHERE table_name='evidence' AND column_name='quota_held';"
(no rows)
$ docker exec docker-postgres-1 psql -U kronos -d kronos -tAc \
    "SELECT version_num FROM alembic_version;"
913567ca653a
```

This container predates this repo's adoption of Alembic
(`docs/DATABASE_MIGRATIONS.md`). When the baseline migration was created,
this already-existing database was `alembic stamp`ed to head (correct,
standard practice for baselining an existing DB — `upgrade` would try to
`CREATE TABLE` on tables that already exist), but its live `evidence`
table predates the `quota_held` column being added to
`postgres_evidence.py`'s `sa.Table` (task #6, tenant storage quota). The
pre-Alembic `create_tables()`'s `checkfirst=True` only ever created
missing *tables*, never added missing *columns* — so the column was never
actually added, and stamping recorded this DB as "head" without the drift
ever being reconciled.

**This is a one-time repair, not a systemic risk:** a genuinely fresh
install's `db-migrate` init container runs `alembic upgrade head` from an
empty database, so the baseline's own `CREATE TABLE` already includes
`quota_held` correctly on any new deployment. Only this specific
long-lived, pre-Alembic dev database (and any other environment with the
same pre-Alembic history) needed the repair.

**Fix:** new migration
`20260817_2053_5a0779975c5a_repair_evidence_quota_held_drift.py`, head
after `913567ca653a`. Uses `ALTER TABLE evidence ADD COLUMN IF NOT EXISTS
quota_held boolean NOT NULL DEFAULT false` (not `op.add_column`, which
would error on a fresh DB where the baseline already created the column)
— a safe no-op everywhere except the drifted case. `downgrade()` is
deliberately a no-op with a docstring explaining why (dropping a real
baseline column on downgrade would be destructive on any normally
provisioned database).

**Verified end-to-end (`poc/quota_held_migration_repair/`):** ran
`alembic upgrade head` against the real, live-drifted
`docker-postgres-1` — column now exists with correct
type/nullable/default, `alembic_version` advanced to the new head. Also
ran the full migration chain from an empty, fresh, throwaway
`postgres:16-alpine` container to confirm the new migration's `IF NOT
EXISTS` guard is a safe no-op when the baseline already created the
column correctly (no error). Full backend test suite before/after: 1954
passed, 2 skipped both times (true no-op delta — `migrations/`-only
change, no `src/` touched). `ruff`/`black`/`mypy` clean on the new file.

After this migration, `poc/evidence_download/`, `poc/postgres_replication/`,
and any future PoC against the real shared dev DB no longer need a
throwaway-Postgres workaround for this specific issue — the shared DB's
schema is now genuinely correct.

**Priority: P1** — real, three-times-rediscovered, developer-friction gap
with a small, safe, well-verified fix; not user-facing (this is a dev
environment fix), but removes a recurring source of wasted investigation
time and closes a real "researched, decided, never executed"-shaped gap
per this initiative's own discipline (the W8 migration explicitly deferred
the fix, this closes that deferral).

---

## Y2 — Keycloak realm's `profile`/`email` client scopes are referenced but never defined; `preferred_username`/`email` never appear in any token

**STATUS (2026-08-17, commit TBD): CLOSED, verified live.**

**Real, confirmed finding, surfaced incidentally by Milestone X3's own
real browser-login PoC** (`poc/keycloak_browser_login/output.txt`): the
real access token minted for the real `case-lead` test user during a
genuine Keycloak-hosted login carries `preferred_username: null` and
`email: null` — `sub`/`roles`/`acr`/`organization` are all correctly
populated, but the two standard OIDC identity claims are never present.
X3's own report noted this as a minor, out-of-scope finding
(`frontend/src/components/Layout.tsx`'s `{user.username}` renders empty
in the header) without root-causing it.

**Root cause, confirmed by direct code/config read:**

`docker/keycloak/kronos-realm.json` defines its own explicit
`clientScopes` array (`acr`, `kronos-roles`, `kronos-sub`, `organization`,
`kronos-org-id`, `kronos-dashboard-roles`) — and that array's own `acr`
entry carries a comment explaining exactly why it exists: *"Defined
explicitly because an explicit `clientScopes` array suppresses Keycloak's
built-in defaults; required for step-up (acr=aal2)."* The realm's
`defaultDefaultClientScopes` list still references `profile` and `email`
by name (`['roles', 'profile', 'email', 'web-origins', 'acr',
'kronos-roles', 'kronos-sub', 'organization', 'kronos-org-id']`), but
because no `clientScopes` entry in this file actually *defines* `profile`
or `email` (only `acr` was manually re-added, since step-up specifically
needed it), those two referenced scope names don't correspond to real
scope objects in this realm after import — so the `preferred_username`/
`email`/`email_verified`/etc. protocol mappers that normally live inside
Keycloak's built-in `profile`/`email` scope definitions were never
attached to any client, and never appear in any token minted by this
realm.

Confirmed the frontend's own OIDC client config
(`frontend/src/keycloak.ts:157`, `scope: 'openid organization'`) is
**not** the cause (a red herring initially suspected): `profile`/`email`
are *default* client scopes per the realm's own
`defaultDefaultClientScopes` list, and Keycloak always includes default
scopes in the token regardless of the `scope=` request parameter (that
parameter only affects *optional* scopes) — so even if the frontend
requested `scope: 'openid profile email organization'` explicitly, it
would make no difference while `profile`/`email` don't exist as real
scope objects in the realm.

**Fix:** added real, version-correct `profile` and `email` client scope
definitions (matching Keycloak 26.2's own built-in defaults, protocol
mappers included — **exported directly from a real, fresh, throwaway
Keycloak 26.2 instance's own default realm via the real Admin REST API,
not hand-written from memory**, per CLAUDE.md §F) to
`docker/keycloak/kronos-realm.json`'s `clientScopes` array, mirroring
exactly how `acr` was already explicitly re-added for the same reason.

**Real bug caught by this same verification process, before it was ever
committed:** an initial version of the added scope descriptions exceeded
Keycloak's `CLIENT_SCOPE.DESCRIPTION` column's `VARCHAR(255)` limit — the
real dev Keycloak crashed on boot (`Value too long for column
"DESCRIPTION CHARACTER VARYING(255)"`), caught immediately by actually
restarting the real container and reading its real logs, not assumed to
work. Fixed by shortening the descriptions.

**Real regression caught and root-caused before declaring success (not a
regression from this fix):** the first verification runs showed the
previously-working `organization` claim now `None`. Rather than assume
this fix caused it, isolated it directly — `git stash`ed the
`kronos-realm.json` change, restarted Keycloak with the *original*
(unfixed) file, and confirmed `organization: None` persisted even
*without* this fix. Root cause: `docker-compose.dev.yml`'s `keycloak-init`
one-shot job provisions the `kronos-dev` Organization and its membership
via real Admin API calls at `docker compose up` time; that state lives in
Keycloak's `dev-mem` storage and is wiped by restarting the container in
isolation (which this fix's own realm-config change required), not by the
static realm import. Restored by re-running `docker compose -f
docker/docker-compose.dev.yml up keycloak-init dashboards-tenant-init`
after restoring the fix.

**Verified end-to-end (`poc/keycloak_profile_email_scope_fix/`):** a real
Chromium browser (Playwright, reusing `poc/keycloak_browser_login/`'s
proven real-login pattern, no mocked routes) logs in as the real
`case-lead` user and decodes a real, freshly minted access token — 9/9
checks pass: `preferred_username='case-lead'`, `email='caselead@kronos.dev'`,
`email_verified=True`, `organization`/`roles` still correctly present (no
regression), and the frontend header now genuinely renders
`case-lead / kronos-dev` (previously just `/ kronos-dev`, per X3's own
screenshot). Full backend test suite before/after: 1954 passed, 2 skipped
both times (true no-op delta — only `docker/keycloak/kronos-realm.json`
and `poc/` touched, no `src/` change).

**Side effect worth noting, not a bug:** restarting `docker-keycloak-1` to
pick up this fix generated a fresh, random `org_id` for the `kronos-dev`
Organization (Organizations aren't stable across a `dev-mem` restart).
Pre-existing case/evidence data in the shared dev Postgres tagged with the
previous `org_id` is now tenant-orphaned — correct multi-tenancy isolation
working as designed, not a leak, but worth knowing if the case list looks
emptier after this change.

**Priority: P2** — real bug, user-visible (empty username in the header),
but cosmetic, not a security or data-integrity issue; well-scoped once the
root cause was found.
