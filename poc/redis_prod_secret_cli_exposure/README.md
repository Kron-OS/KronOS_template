# PoC: Redis passwords in `docker-compose.prod.yml` leak via `docker inspect` (Milestone X2b)

**Objective.** Adversarial red-team review of new attack surface landed since
the last full assessment, specifically "Real Postgres replication + Redis
DB-role separation added to the prod deployment topology — new
service-to-service credentials/network paths." This checks how the two new
Redis instances (`redis-auth-streams`, `redis-celery`, Milestone X2b,
`docker/docker-compose.prod.yml`) supply their `requirepass` credential,
compared to how the same file's Postgres primary/replica (Milestone X2a)
supply theirs.

## The finding

`docker/docker-compose.prod.yml`:

```yaml
redis-auth-streams:
  image: redis:7-alpine
  command: redis-server --requirepass ${REDIS_AUTH_STREAMS_PASSWORD:-changeme} --appendonly yes
  ...
redis-celery:
  image: redis:7-alpine
  command: redis-server --requirepass ${REDIS_CELERY_PASSWORD:-changeme} --appendonly yes
  ...
```

Both Redis passwords are interpolated directly into the container's
`command:` — i.e. into its argv — by Compose at deploy time. Compare this
to the SAME file's Postgres primary, added earlier in the same X2/X2a/X2b
work:

```yaml
postgres:
  image: postgres:16-alpine
  environment:
    POSTGRES_PASSWORD_FILE: /run/secrets/db_password
  secrets: [db_password, replication_password]
```

Postgres's password is a real Docker secret (`/run/secrets/db_password`,
a file mounted with restricted permissions, never part of the container's
argv or inspectable config) — the pattern this same compose file already
knows how to do correctly, including for the new X2a replication password
(`REPL_PASSWORD` is read from a secret file in
`docker/postgres/replica-entrypoint.sh`, not passed as a CLI flag). The two
new Redis instances, added in the very next milestone (X2b) by the same
initiative, do not follow that established pattern — they pass the
credential as a literal CLI argument, the exact class of bug Gap Audit
Milestone CC (`docs/GAP_AUDIT_2026-08-18_MILESTONE_CC.md`, CC1) already
found and fixed for `kronos-attest`'s CLI flags ("leaks credentials into
`ps`/shell history"), just relocated to production infrastructure config
instead of an operator CLI tool.

## Real repro

A throwaway container (`kronos-poc-redis-secret-exposure`, cleaned up
immediately after), reproducing the exact `command:` shape used in
`docker-compose.prod.yml`:

```
$ docker run -d --name kronos-poc-redis-secret-exposure redis:7-alpine \
    redis-server --requirepass SuperSecretRedisPW123 --appendonly yes

$ docker inspect kronos-poc-redis-secret-exposure --format '{{json .Config.Cmd}}'
["redis-server","--requirepass","SuperSecretRedisPW123","--appendonly","yes"]
```

**The plaintext password is returned verbatim by `docker inspect`.** This
is a genuinely different (and broader) exposure surface than "local `ps`
on the host": `docker inspect` (and its API equivalent, `GET
/containers/{id}/json`) is commonly available to principals who do NOT
have arbitrary shell access to the host or container — e.g. a read-only
monitoring/observability agent, a container-introspection dashboard
(Portainer, cAdvisor, Grafana Docker exporters), any sidecar granted a
read-only bind-mount of `/var/run/docker.sock`, or `docker compose config`
run by a CI pipeline that only needs to validate the compose file. Every
one of those sees the resolved plaintext Redis password, even though none
of them were ever granted the `.env` file or Docker secrets themselves.

Notably, `docker top`/`ps aux` from *inside* the running container do
**not** show the password (Redis rewrites its own process title after
startup to hide `--requirepass` from a live process listing) — so a
naive check with just `ps` would miss this. `docker inspect`'s
`Config.Cmd` is unaffected by that self-masking, since it reflects the
container's original launch configuration, not its current runtime argv.

## Severity / exploitability notes

- This is a defense-in-depth/blast-radius finding, not a directly
  externally-exploitable one: it requires *some* form of Docker
  daemon-API access (inspect-level, not necessarily shell/exec), which is
  already a meaningfully privileged position. It does not, by itself, let
  an external attacker reach these Redis instances (they are not exposed
  by any `ports:` mapping in the prod file — confirmed by grep).
- It is nonetheless real and directly analogous to the already-fixed CC1
  finding, in code from the *same* initiative that fixed CC1 — the fix
  pattern (route real secrets through Docker secrets / a file / an
  entrypoint script, never bake them into `command:`) already exists
  twice in the same file (`POSTGRES_PASSWORD_FILE`,
  `replica-entrypoint.sh`'s own `REPL_PASSWORD` handling) and was not
  applied to the two new Redis services added immediately afterward.
- `redis-auth-streams` backs `RedisTicketStore` (step-up tickets) and the
  stream-ingest DB — i.e. this is the credential protecting the exact
  step-up ticket mechanism this same review's PoC #1
  (`poc/stepup_ticket_resource_mismatch/`) already found a real scoping
  gap in. An actor who can read this password (via `docker inspect`)
  could connect directly to `redis-auth-streams` and read/forge/delete
  step-up tickets directly in Redis (`kronos:stepup:<id>` keys — see
  `RedisTicketStore._PREFIX`), bypassing the ticket-consumption logic
  entirely (a full authentication bypass for the step-up mechanism, not
  just the resource-mismatch issue), which raises the practical severity
  of this finding above "just credential hygiene."

## Fix would need to address

Both `redis-auth-streams`/`redis-celery` should read their `requirepass`
value from a mounted Docker secret via a small entrypoint script (the
same shape `docker/postgres/replica-entrypoint.sh` already established
for `REPL_PASSWORD` in this same file), e.g.
`redis-server --requirepass "$(cat /run/secrets/redis_auth_streams_password)"`,
rather than interpolating the env var directly into `command:`.

## Cleanup

`kronos-poc-redis-secret-exposure` was removed immediately after this
capture (`docker rm -f kronos-poc-redis-secret-exposure`) — no PoC
container was left running. Nothing in the shared dev stack
(`docker-redis-1`, etc.) was touched; this used a standalone, separately
named container.
