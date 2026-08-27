# `docker/secrets/`

`docker-compose.prod.yml` reads Docker secrets from `file:` sources in this
directory (fixed in Gap Audit Milestone DDD — the file previously declared
every secret `external: true`, which real, verified execution of the exact
command README.md's own "Path A" section documents (`docker compose -f
docker-compose.prod.yml up -d`) rejects outright: `external: true` is a
Docker Swarm concept and plain `docker compose` refuses it with "unsupported
external secret `<name>`" before the first secret-consuming service can even
start).

Provision each file per README.md's "Path A — Docker Compose (single host)"
instructions before `docker compose -f docker-compose.prod.yml up -d`, e.g.:

```bash
printf '%s' "$(openssl rand -base64 32)" > db_password.txt
```

`database_url.txt` / `redis_auth_streams_url.txt` / `celery_broker_url.txt` /
`celery_result_backend_url.txt` each hold a full, pre-assembled connection
string (not a bare password) — see
`poc/backend_prod_secret_config_env_exposure/README.md`'s "Operational
contract" for the exact DSN shape each one needs.

**Never commit the `.txt` files themselves** — `.gitignore` excludes
`/docker/secrets/*.txt`; only this README is tracked.
