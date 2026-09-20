# Gap Audit — Milestone DDD (2026-08-27)

**Scope:** Milestone CCC's own recommendation #2 — attempt a complete, real
`docker compose -f docker-compose.prod.yml up`, end-to-end rather than
service-by-service, to find any remaining production-infra blockers
systematically. Executed exactly that, in an isolated `kronos-poc-prod-verify`
Compose project (never touching the real running dev stack), real containers
throughout, real logs/HTTP responses read at every step, per CLAUDE.md §F.

**Result: found and fixed seven real, independent, previously-undocumented
bugs.** Every one of them would have blocked a real `docker compose -f
docker-compose.prod.yml up -d` at the exact command README.md's own "Path A"
section tells an operator to run. Reached a genuinely complete, healthy stack
by the end: real Postgres+replica+sync-replication, real Redis
(auth-streams+celery), real MinIO, real OpenSearch (security genuinely
enabled), real Keycloak (realm imported, org created), real ClamAV, real
`db-migrate` (Alembic against real Postgres), and two real `kronos-backend`
+ two real `celery-worker` replicas all up and answering/consuming for real
(`/healthz` → `200 {"status":"ok"}`, Celery worker bound to `q.index`/
`q.intake`/`q.parse.fast` against real `redis-celery`).

---

## Bug 1 — every Docker secret was `external: true`, which plain `docker compose` rejects outright

`external: true` is a Docker **Swarm** concept (`docker secret create` +
`docker stack deploy`). Confirmed live: `docker compose -p
kronos-poc-prod-verify -f docker-compose.prod.yml up -d postgres` failed
immediately —

```
service:postgres:1 unsupported external secret db_password
unsupported external secret db_password
```

— before Postgres, the very first secret-consuming service, could even be
created. Nothing past this point in the file could ever have started via the
exact command README.md's own "Path A — Docker Compose (single host)"
section documents. `docker/secrets/` didn't even exist as a directory before
this fix (confirmed: `ls docker/secrets/` → "No such file or directory"),
even though README.md's own instructions already told an operator to
`printf ... > secrets/db_password.txt` into it.
`poc/postgres_replication/README.md` PART 3 had already independently hit
and worked around this identical issue for its own one-off run (scoped to
`db_password`/`replication_password` only, in a throwaway PoC copy) — this
fix applies the same, now-standard fix to all ten secrets in the real
shipped file.

**Fix:** every `secrets:` entry converted from `external: true` to `file:
./secrets/<name>.txt`. Added `docker/secrets/README.md` (tracked) explaining
the convention, and `/docker/secrets/*.txt` to `.gitignore` (the directory
itself is tracked via the README; the real secret material never is).

**Verified:** real `file:` secrets created locally, `docker compose up -d
postgres` → `healthy`.

---

## Bug 2 — Keycloak: `fgap-v2` is not a real feature at the pinned version

`KC_FEATURES: organization,token-exchange,fgap-v2` made Keycloak exit(2) at
boot, before serving a single request:

```
fgap-v2 is an unrecognized feature, it should be one of [account, account-api,
admin, admin-api, admin-fine-grained-authz, authorization, ...]
```

Traced the origin: `reviews/Part_6_Review.md` describes "FGAP v2"
(Organizations as an admin-permission resource type) as a **Keycloak 26.7.0
(May 2026)** feature. This repo pins **26.2** (needed for the `organization`
token claim, but predates 26.7). `grep -rn fgap src/` confirms zero
production code depends on it today — this was a forward-looking design note
wired into the compose file prematurely, never run.

**Fix:** removed `fgap-v2` (no equivalent flag exists at 26.2 — nothing to
swap it for). Revisit alongside a real Keycloak 26.7+ upgrade if
`Part_6_Review.md`'s design is actually implemented.

**Verified:** Keycloak boots past feature validation.

---

## Bug 3 — OpenSearch: the bind-mounted config file silently defeated the security demo installer

`docker-compose.prod.yml` bind-mounted `docker/opensearch/opensearch.yml`
(containing one line: `plugins.security.unsupported.restapi.allow_securityconfig_modification: true`)
over the container's own `config/opensearch.yml`. A prior milestone had
already found and fixed a *related* issue (removing the `:ro` flag) but
never re-verified the fix actually worked. It didn't. Real boot log:

```
/usr/share/opensearch/config/opensearch.yml seems to be already configured
for Security. Quit.
...
Caused by: OpenSearchException[plugins.security.ssl.transport.keystore_filepath
or ... pemcert_filepath ... must be set if transport ssl is requested.]
```

Root cause: OpenSearch's bundled demo installer checks whether
`opensearch.yml` already contains **any** `plugins.security.*` key —
including this file's single, SSL-unrelated REST-API flag — and if so skips
populating the transport-SSL cert paths and copying the demo certs entirely.
The security plugin then loads with SSL required and zero certs configured,
and crashes. `docker-compose.dev.yml`'s own opensearch service (proven
working, `poc/opensearch_dashboards_sso/`) never hit this because it does
**not** mount any file over `opensearch.yml` — it passes the identical flag
as an `environment:` override instead, leaving the file for the demo
installer to populate unimpeded.

A second, independent bug surfaced in the same log: OpenSearch ≥2.12 (this
pins 2.13.0; dev deliberately pins 2.11.1) requires
`OPENSEARCH_INITIAL_ADMIN_PASSWORD` or the demo installer refuses to set any
admin credential and quits.

**Fix:** dropped the bind mount; added
`plugins.security.unsupported.restapi.allow_securityconfig_modification=true`
as an `environment:` entry (mirrors dev's proven pattern) and
`OPENSEARCH_INITIAL_ADMIN_PASSWORD=${OPENSEARCH_ADMIN_PASSWORD:?...}` (reuses
the same real admin password this file's `opensearch-security-init` already
required). Also added a real healthcheck (previously absent) and converted
`opensearch-security-init`'s `depends_on` from start-order-only to
`condition: service_healthy`.

**Verified:** real container reaches `healthy`; `opensearch-security-init`
then runs to completion for real: `openid authc domain configured.
kronos-generic-tenant role + rolesmapping ensured. provision_opensearch_security:
complete`.

---

## Bug 4 — Keycloak: HTTPS-only production mode silently disabled the internal HTTP listener everything else depends on

Once bugs 2–3 were fixed enough to reach this, Keycloak's own startup log
read:

```
Listening on: https://0.0.0.0:8443
```

**No HTTP listener at all.** Quarkus's production `start` command, once
HTTPS certs are configured, disables the plain HTTP listener unless
explicitly re-enabled. This silently broke every internal caller this same
file wires to `http://keycloak:8080` — not just `keycloak-init` (which hangs
in its own retry loop for ~5 minutes then hard-fails), but far more
severely, **`kronos-backend`/`celery-worker`'s own `KEYCLOAK_URL:
http://keycloak:8080`**, which real JWT verification (JWKS fetch) depends on
for every single authenticated request. This compose file, as shipped, would
have made production JWT auth completely non-functional — not a
provisioning inconvenience, a total auth outage.

**Fix:** `KC_HTTP_ENABLED: "true"`. Internal container-network traffic never
leaves the trusted Docker network (nginx is the only real external HTTPS
termination point in this file), so the internal hop has no need to also be
TLS.

**Verified:** real log after the fix: `Listening on: http://0.0.0.0:8080 and
https://0.0.0.0:8443`.

---

## Bug 5 — Keycloak: no bootstrap admin account configured at all

Distinct from bug 4. Even with HTTP reachable, `keycloak-init` failed:

```
ERROR: could not obtain admin token (check KC_ADMIN_USER / KC_ADMIN_PASSWORD)
```

Real Keycloak log: `LOGIN_ERROR ... error="user_not_found" ... username="admin"`.
Unlike `docker-compose.dev.yml` (`KC_BOOTSTRAP_ADMIN_USERNAME`/`PASSWORD`
explicitly set), prod's `keycloak` service never configured a bootstrap
admin at all — meaning no one, not even a human operator via the Admin
Console, could ever log into a fresh production deployment.

**Fix:** `KC_BOOTSTRAP_ADMIN_USERNAME: ${KEYCLOAK_ADMIN:-admin}` /
`KC_BOOTSTRAP_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}` — reusing the exact
same vars `keycloak-init` already consumed as `KC_ADMIN_USER`/
`KC_ADMIN_PASSWORD`, so the two can't drift apart.

**Verified:** real log: `Created temporary admin user with username admin`.

---

## Bug 6 — Keycloak: no realm-import mechanism existed at all

With auth working, `keycloak-init` still failed:

```
ERROR: realm 'kronos' does not exist; provision the realm before the org
```

`docs/deployment.md` already *instructs* an operator: "Ensure
`docker/keycloak/kronos-realm.json` is mounted and Keycloak has
`--import-realm` flag" — but `docker-compose.prod.yml` itself never did
either. `command: start` had no `--import-realm`, and no volume mounted
`kronos-realm.json` at all.

**Fix:** `command: start --import-realm` (confirmed live: this is a genuine
Quarkus CLI option, not `start-dev`-only — works identically under
production `start` with real Postgres storage and HTTPS+bootstrap-admin
active) + `./keycloak/kronos-realm.json:/opt/keycloak/data/import/kronos-realm.json:ro`,
mirroring dev's already-proven pattern.

**Verified:** real log: `Realm 'kronos' imported` / `Import finished
successfully`.

---

## Bug 7 — `keycloak-init`: `ORG_DOMAIN` defaulted to empty, but Keycloak's real API requires at least one

With the realm present, org creation still failed: `create organization ->
HTTP 400` / `ERROR: organization kronos could not be created or found`.
Reproduced directly against the real Admin REST API:

```json
{"errorMessage":"You must provide at least one domain"}
```

`ORG_DOMAIN: ${KRONOS_ORG_DOMAIN:-}` had no required-value guard, so an
operator following the file's own defaults gets a silent, unexplained
failure with no indication a domain was the missing ingredient.

**Fix:** `ORG_DOMAIN: ${KRONOS_ORG_DOMAIN:?KRONOS_ORG_DOMAIN is required --
Keycloak's real Organizations API rejects an org with zero domains}`,
matching this file's own `OPENSEARCH_ADMIN_PASSWORD` precedent for a var
with no safe default.

**Verified:** real `create organization -> HTTP 201`, `provision_keycloak_org:
complete`, exit 0.

---

## Full-stack verification, in order (all real containers, `kronos-poc-prod-verify` project)

1. `vault` → healthy, `vault-init` → real transit/kv/policy/approle setup
   (re-confirms Milestone CCC's fix still holds).
2. `postgres` → healthy (bugs 1 fix confirmed).
3. `postgres-replica` → healthy; `postgres-replication-init` → real
   sync-replication flip, exit 0 (re-confirms prior replication work still
   holds).
4. `redis-auth-streams` / `redis-celery` → healthy.
5. `minio` → up. `clamav` → healthy.
6. `opensearch` → healthy (bug 3 fix). `opensearch-security-init` → real
   completion.
7. `keycloak` → real HTTP+HTTPS listeners, real realm import, real
   bootstrap admin (bugs 2, 4, 5, 6 fixes). `keycloak-init` → real org
   creation, exit 0 (bug 7 fix).
8. `db-migrate` (real locally-built backend image, tag `poc-verify`) → real
   Alembic run against real Postgres, three real revisions applied, exit 0.
9. `kronos-backend` (2 replicas) → real Uvicorn boot, real `GET /healthz` →
   `200 {"status":"ok"}`.
10. `celery-worker` (2 replicas) → real boot, bound to real `redis-celery`
    broker/backend, real `q.index`/`q.intake`/`q.parse.fast` queues.

Isolated project fully torn down afterward (`down -v --remove-orphans`);
throwaway secrets/certs deleted; locally-built `poc-verify` image removed.
The real running dev stack (`docker-dev-*`) was never stopped, restarted, or
touched — cross-checked before and after (`docker ps`).

**Self-correction worth recording:** mid-pass, an early `curl
https://localhost:8443/realms/master` "successfully verifying Keycloak" was
actually hitting the **real dev stack's own nginx** (which independently
publishes host port 8443) — not the isolated PoC container, which publishes
no ports to the host at all. Caught by cross-referencing
`/proc/net/tcp`inside the actual PoC container (no listener matched) before
trusting the result, and re-verified correctly via `docker run --network
kronos-poc-prod-verify_default curlimages/curl ...` from then on. Recorded
here per CLAUDE.md §F's spirit — a wrong verification is exactly the kind of
mistake this whole process exists to catch, including from itself.

---

## Still open, not new (cross-checked against prior milestones)

- **TSA image** (Milestone BBB): `freetsa/freetsa:latest` doesn't exist on
  Docker Hub (`pull access denied`) — pending a project-owner TSA vendor
  decision, unchanged.
- **KES AppRole auto-injection + TLS cert provisioning** (Milestone CCC):
  both still genuinely unsolved design gaps, unchanged — not re-attempted
  this pass (kes wasn't the focus; confirmed it still reaches the same two
  already-documented gaps, no regression).
- `docker/pki/` — confirmed still correctly unwired/dormant (Milestone CCC),
  not touched.

## New, not yet investigated

- `KC_DB_URL: jdbc:postgresql://postgres:5432/kronos` — Keycloak shares the
  **same** `kronos` database as the application (confirmed while resetting
  state between test runs: `DROP SCHEMA public CASCADE` on that DB dropped
  Keycloak's own tables). Not clearly a bug (many real deployments do
  share a Postgres instance across schemas/databases deliberately), but
  worth a deliberate look: no separate database/schema isolation between
  Keycloak's own ~80 tables and KronOS's application tables today.
- The `plugins.security.*` demo-installer "already configured" trap (bug 3's
  root cause) is a general OpenSearch behavior, not specific to this one
  file — worth a mental note for any *future* custom `opensearch.yml` in
  this repo, dev included, if it ever needs one again.

## Recommendation for the next milestone

1. Both remaining KES gaps (Milestone CCC) are the most concrete, scoped
   remaining production-infra work if that vein is picked back up.
2. The Keycloak/app shared-database question above is worth a short,
   dedicated look — low effort, could be a real finding or a confirmed
   non-issue.
3. Otherwise, return to a fresh scenario-tracing round or an area not yet
   covered in the JJ–DDD sequence.
