# `make dev` fix — non-root init containers can't read bind-mounted scripts on Docker Desktop/WSL2

**Not a component-pair PoC** (no new external dependency involved) — kept
under `poc/` anyway per CLAUDE.md §F.2's "capture the actual output, don't
just describe it" rule, since this is a real bug found by a real user run
that needed a real re-run to confirm the fix.

## The bug, as reported

A real user ran `make clean && make dev` on a Docker-Desktop/WSL2 host and
got:

```
keycloak-init-1  | sh: can't open '/provision_keycloak_org.sh': Permission denied
keycloak-init-1 exited with code 2
...
Container docker-keycloak-init-1 Error service "keycloak-init" didn't complete successfully: exit 2
service "keycloak-init" didn't complete successfully: exit 2
make: *** [Makefile:10: dev] Error 1
```

`make dev` runs `docker compose -f docker/docker-compose.dev.yml up` in the
foreground (no `-d`), so any service exiting non-zero aborts the whole
command — the entire dev stack never comes up.

## Root cause

`keycloak-init` and `dashboards-tenant-init` used `image: curlimages/curl:latest`
with the provisioning script **read-only bind-mounted** from the host:

```yaml
volumes:
  - ../scripts/provision_keycloak_org.sh:/provision_keycloak_org.sh:ro
entrypoint: ["sh", "/provision_keycloak_org.sh"]
```

`curlimages/curl` runs as a **non-root** user (`curl_user`, uid 100 —
confirmed: `docker run --rm curlimages/curl:latest id` → `uid=100(curl_user)`).
On a native Linux Docker host the real host file mode (`0755`, world-readable
— confirmed: `ls -la scripts/provision_keycloak_org.sh` → `-rwxrwxr-x`)
is preserved 1:1 through the bind mount, so this was never seen here. But
Docker Desktop's bind-mount layer (used for WSL2 integration) doesn't
reliably preserve read access for non-root container UIDs on host-mounted
files — a well-known class of Docker Desktop bug.

This is confirmed, not guessed, by the user's own captured log: in the
*same* failing run, `opensearch-init` (`image: python:3.12-alpine`, which
has no `USER` directive and therefore runs as **root**) bind-mounts its own
script the same way and succeeded (`provision_opensearch_security: complete`,
exited 0), while the two curl-based (non-root) init containers were the
only ones that failed.

## The fix

Stop relying on the host bind-mount's permission bits for these two
services. Bake the scripts into the image at build time instead — `COPY`
normalizes ownership/permissions inside the image layer, independent of
the host filesystem or its Docker Desktop translation:

- `docker/init/Dockerfile.keycloak-init`
- `docker/init/Dockerfile.dashboards-tenant-init`

Both are `FROM curlimages/curl:latest` + `COPY --chmod=0755 <script> /<script>`
+ `ENTRYPOINT ["sh", "/<script>"]`. `docker-compose.dev.yml` and
`docker-compose.prod.yml`'s `keycloak-init` now `build:` these instead of
bind-mounting. `opensearch-init` was left as a bind mount deliberately —
it already runs as root and wasn't broken; converting it too was out of
scope for the reported bug (would be pure churn per CLAUDE.md's
no-speculative-refactor rule).

## What was actually run (this host, Linux, not WSL2 — can't reproduce the
## WSL2-specific failure directly, so the fix is verified by (a) confirming
## the new build-based services work correctly here, and (b) the direct
## before/after comparison against the user's own captured non-root-fails/
## root-succeeds evidence above)

```
$ docker compose -f docker/docker-compose.dev.yml build
...
 Image docker-keycloak-init            Built
 Image docker-dashboards-tenant-init   Built
 Image docker-nginx                    Built
 Image kronos-backend:dev              Built
 Image docker-celery-worker-plaso      Built

$ docker compose -f docker/docker-compose.dev.yml up -d
... (all 18 services start)

$ docker inspect docker-keycloak-init-1 --format 'ExitCode: {{.State.ExitCode}}'
ExitCode: 0

$ docker logs docker-keycloak-init-1
provision_keycloak_org: realm=kronos org=kronos-dev base=http://keycloak:8080
Declared org_id as an admin-managed User Profile attribute.
Creating organization kronos-dev
create organization -> HTTP 201
Organization ID: db34a2e8-47fd-4944-8c8e-c4e1fa5ec148
Linked member 10000000-0000-4000-8000-000000000001 -> HTTP 201
Set org_id attribute for 10000000-0000-4000-8000-000000000001 -> HTTP 204
Linked member 10000000-0000-4000-8000-000000000002 -> HTTP 201
Set org_id attribute for 10000000-0000-4000-8000-000000000002 -> HTTP 204
Linked member 10000000-0000-4000-8000-000000000003 -> HTTP 201
Set org_id attribute for 10000000-0000-4000-8000-000000000003 -> HTTP 204
provision_keycloak_org: complete

$ docker ps -a --filter "name=dashboards-tenant-init" --format '{{.Names}}: {{.Status}}'
docker-dashboards-tenant-init-1: Exited (0) 2 seconds ago

$ docker logs docker-dashboards-tenant-init-1
provision_dashboards_tenant: realm=kronos org=kronos-dev os_base=https://opensearch:9200
Resolved org kronos-dev -> db34a2e8-47fd-4944-8c8e-c4e1fa5ec148
Tenant kronos-kronos-dev ensured.
Role kronos-dash-kronos-dev ensured.
Rolesmapping kronos-dash-kronos-dev -> backend_role db34a2e8-47fd-4944-8c8e-c4e1fa5ec148 ensured.
provision_dashboards_tenant: complete

# Full stack settles healthy (18/18 services), including opensearch-dashboards
# reporting "healthy" via its real /auth/openid/login route (only reachable
# once the security-dashboards plugin and Keycloak SSO wiring both actually work).

$ curl -sk -o /dev/null -w "HTTP %{http_code}\n" https://localhost:9200/_cluster/health
HTTP 401          # unauthenticated request correctly rejected -- OS security genuinely enabled

$ curl -sk -u admin:admin https://localhost:9200/_cluster/health
{"cluster_name":"docker-cluster","status":"yellow", ... "number_of_nodes":1, ...}

$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8000/healthz
HTTP 200
```

Stack torn down cleanly afterward (`docker compose -f docker/docker-compose.dev.yml down`)
— no orphaned containers/volumes left from this verification run.

## Residual risk / honesty note

This fix was verified end-to-end on a native Linux Docker host, where the
original bug never reproduced in the first place. It was **not** verified
on an actual Docker-Desktop-on-Windows/WSL2 host (none available in this
environment). The fix is high-confidence because it removes the exact
mechanism (host bind-mount permission translation for a non-root container
user) that the user's own log shows differs between the failing services
(non-root) and the succeeding one (root) in the same run — but if a WSL2
host has some *other*, unrelated permission-denial cause, this fix would
not address it. If `make dev` still fails identically on the original
reporting machine after this change, the next diagnostic step is to run
the same `id` / `ls -la` checks used here directly on that host.
