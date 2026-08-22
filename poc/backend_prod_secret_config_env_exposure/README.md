# PoC: `docker-compose.prod.yml`'s backend/celery/db-migrate services leak DSN passwords via `docker inspect Config.Env`

**STATUS: FIXED (Gap Audit Milestone MM).** See "Fix" and "Real, captured
verification" below.

## Versions pinned

- `pydantic-settings` — this repo's dev venv has **2.14.2** installed
  (`python3 -c "import pydantic_settings; print(pydantic_settings.__version__)"`),
  confirmed against the actual venv the dispatch named. `pyproject.toml` only
  floors `>=2.3`, so a fresh `docker build` (the real image used for step 5 of
  this PoC) picked up **2.15.0** instead — a real, disclosed drift (see
  `output.txt`'s own note). The `secrets_dir`/`SecretsSettingsSource` API used
  here is identical in both versions (read directly from the installed
  package source at `.../pydantic_settings/sources/providers/secrets.py` and
  `main.py` for 2.14.2, then re-verified working end-to-end against the
  2.15.0-based built image in step 5) — no version-specific behavior gap was
  found, but the drift itself is a legitimate, separate finding worth fixing
  (pin pydantic-settings to an exact/compatible-release version) that this
  milestone does not attempt to fix.
- `alembic` — 1.19.0 pinned per `poc/alembic_migration_baseline/README.md`
  (unchanged by this milestone).
- `redis:7-alpine`, `postgres:16-alpine` — same pinned tags
  `docker-compose.prod.yml` already uses elsewhere.

## Real docs used

`pydantic_settings/sources/providers/secrets.py` (`SecretsSettingsSource`)
and `pydantic_settings/main.py` (`SettingsConfigDict.secrets_dir`,
`BaseSettings.__init__`'s `_secrets_dir` override), read directly from the
installed package in this repo's own venv — not a stale doc page. Key facts
extracted (see the class' own docstring/code, not paraphrased from memory):

- `secrets_dir` is a real `SettingsConfigDict` option. `None` (the default)
  disables the file-secrets source entirely.
- The source looks up **one file per field, named after the field**
  (case-insensitively, `find_case_path`) inside `secrets_dir` — there is no
  way to point one file at a group of fields, and no per-component (host/
  user/password) decomposition built in. This directly settled the "(a) vs
  (b)" design question posed in the dispatch: since the lookup is always
  "one field -> one file," the natural, lowest-friction shape is one file
  per DSN (design (a): full pre-assembled DSN string per secret), not
  splitting into host/port/user/password sub-fields (design (b) would still
  need a `field_validator`/model assembly step in `src/config.py` *and* the
  same one-file-per-field constraint for each sub-field — strictly more
  moving parts for no real benefit here, since Postgres/Redis DSNs are
  already a single connection-string value everywhere else in this codebase,
  e.g. `settings.database_url`, `startup.py`'s `create_async_engine(...)`).
- File content is `.strip()`ped, so a trailing newline (the common shape of
  a `docker secret create ... - <<<"$VALUE"` or an `echo`-created secret
  file) is handled automatically.
- Source priority (`BaseSettings.settings_customise_sources`'s default,
  unmodified order): `init` > `env` > `dotenv` > `secrets_dir` file. A stray
  plaintext env var would still win over a `secrets_dir` file for the same
  field — verified directly in `tests/unit/test_config.py::
  TestSecretsDirPath::test_plain_env_var_still_wins_over_secrets_dir_file`.
  Not exploited in production (this fix *removes* the plaintext env var
  entirely rather than layering the file source on top of it), but worth
  knowing so a half-migrated deploy fails obviously rather than silently.
- A `secrets_dir` that doesn't exist at all only emits a `warnings.warn(...)`
  (not an exception) and the source degrades to returning nothing — every
  field then falls through to pydantic's own pre-existing "field required"
  `ValidationError` if no other source supplies it. Verified directly
  (`tests/unit/test_config.py::TestMissingOrEmptySecretRaisesClearly::
  test_nonexistent_secrets_dir_raises_field_required`).
- **The one real gap in `secrets_dir`'s own contract**: a secret file that
  *exists but is empty* (or whitespace-only) resolves to `""` — a
  syntactically valid `str` that sails straight past pydantic's "is this
  field present" check, since it *is* present, just blank. This is exactly
  the "sensible, clear error, not a silent wrong connection" case flagged in
  the dispatch — closed here with a small `field_validator` (see "Fix"
  below), not by pydantic-settings itself.

## The finding

`docker-compose.prod.yml`'s `db-migrate`/`kronos-backend`/`celery-worker`
services (already confirmed real by the orchestrator before this PoC was
written) baked real Postgres/Redis passwords directly into their
`environment:` block via connection-string interpolation, e.g.:

```yaml
DATABASE_URL: postgresql+asyncpg://kronos:${POSTGRES_PASSWORD}@postgres:5432/kronos
REDIS_URL: redis://:${REDIS_AUTH_STREAMS_PASSWORD}@redis-auth-streams:6379/0
CELERY_BROKER_URL: redis://:${REDIS_CELERY_PASSWORD}@redis-celery:6379/1
CELERY_RESULT_BACKEND: redis://:${REDIS_CELERY_PASSWORD}@redis-celery:6379/2
```

`docker inspect <container> --format '{{json .Config.Env}}'` returns these
fully-resolved, plaintext connection strings — the same class of finding
Gap Audit Milestone LL already fixed for `redis-auth-streams`/`redis-celery`'s
own `command:` argv (`poc/redis_prod_secret_cli_exposure/`), but this time
the exposure is in `Config.Env`, not `Config.Cmd`. Milestone LL's own PoC
README explicitly flagged this exact gap as "Related, NOT fixed here" —
this milestone closes it.

**Real service count correction (found during this PoC, worth noting
honestly):** the dispatch named 5 services (`db-migrate`, `kronos-backend`,
`celery-worker`, `celery-worker-plaso`, `celery-beat`). Only **3** of those
actually exist in `docker-compose.prod.yml` today and have this DATABASE_URL/
REDIS_URL/CELERY_* env-var pattern at all — confirmed via
`grep -n "plaso\|celery-beat" docker/docker-compose.prod.yml`, which finds
zero service blocks for either. `celery-worker-plaso` appears only in a
*comment* on `celery-worker` (referencing `docker-compose.dev.yml`, where it
does exist), and `celery-beat` appears nowhere in the prod file at all —
Milestone LL's own writeup names it in prose too, but its actual diff never
added it either. This is itself a separate, pre-existing gap (prod has no
scheduled-task/beat service and no Plaso worker at all) — **not fixed here**,
out of scope for a secrets-exposure fix, flagged for its own future
milestone. This PoC and the accompanying `src/`/`docker-compose.prod.yml`
changes therefore cover the 3 real services: `db-migrate`, `kronos-backend`,
`celery-worker`.

## Why Milestone LL's own fix pattern (shell entrypoint script) doesn't apply here

`docker/redis/redis-secret-entrypoint.sh` (Milestone LL's fix) works because
`redis:7-alpine` ships a real shell. `kronos-backend`'s own image
(`docker/Dockerfile`) does **not** — its runtime stage is
`cgr.dev/chainguard/python:latest`, confirmed distroless-style directly:

```
$ docker run --rm --entrypoint sh kronos-backend-secret-fix-test sh -c "echo hi"
exec: "sh": executable file not found in $PATH
```

`docker/Dockerfile`'s own comment on `ENTRYPOINT []` explains why: the base
Chainguard image bakes in `ENTRYPOINT ["/usr/bin/python"]`, which would
otherwise swallow any `command:` override (e.g. `alembic upgrade head`) as
arguments to `python` itself (`python alembic upgrade head` → "can't open
file '/app/alembic'"). Clearing it restores normal exec-form semantics: a
`command:` override is looked up on `$PATH` (`/opt/venv/bin` is first) and
exec'd directly — no shell, no `sh -c` wrapping. A `.sh`-based
entrypoint-script fix is therefore not available for this image.

## Fix

Two separate mechanisms, because `kronos-backend`/`celery-worker` and
`db-migrate` resolve their DSN through genuinely different code paths:

1. **`kronos-backend`/`celery-worker`** both instantiate a bare
   `src.config.Settings()` (confirmed: `src/external/startup.py:95,435` and
   `src/external/celery_app.py:50`, no args). `src/config.py`'s
   `model_config` now sets `secrets_dir=os.environ.get("KRONOS_SECRETS_DIR")
   or None` — `None` (unset, dev's real state) is a complete no-op,
   preserving `docker-compose.dev.yml`'s existing plain-env-var behavior
   exactly. Setting `KRONOS_SECRETS_DIR=/run/secrets` in prod makes
   `database_url`/`redis_url`/`celery_broker_url`/`celery_result_backend`
   resolve from real Docker secret files instead. A new
   `field_validator(mode="before")` (`Settings._reject_blank_dsn`) closes
   the one gap noted above: an existing-but-empty secret file now raises a
   clear `ValidationError` naming the field, instead of silently becoming
   an empty-string DSN.

2. **`db-migrate`** (`command: alembic upgrade head`) does **not** go
   through `Settings()` at all — `migrations/env.py`'s own docstring
   documents this as deliberate (`Settings()` needs ~15 unrelated MinIO/
   OpenSearch/Keycloak/Vault fields a migration-only run has no reason to
   need) and reads `os.environ["DATABASE_URL"]` directly. The `secrets_dir`
   fix above therefore does nothing for this service. Fixed instead by
   extracting `_database_url()`'s logic into a new, pure
   `migrations/db_url.py::resolve_database_url()` that adds a
   `DATABASE_URL_FILE` fallback (mirrors the official `postgres` image's
   own `POSTGRES_PASSWORD_FILE` convention, already used elsewhere in this
   same compose file) — `env.py` now just calls it. Split into its own
   module because `migrations/env.py` imports `alembic.context` at module
   level, an unconfigured proxy outside a real `alembic` invocation
   (confirmed: `import migrations.env` outside alembic raises
   `AttributeError: module 'alembic.context' has no attribute 'config'`),
   making `env.py` itself unsafe to import from a unit test.

`docker-compose.prod.yml`: all three services now mount the relevant Docker
secrets and set only a *path* (`KRONOS_SECRETS_DIR` / `DATABASE_URL_FILE`),
never a resolved connection string, in `environment:`. Four new external
secrets added: `database_url`, `redis_auth_streams_url` (mounted with
`target: redis_url` — the deployer-facing secret *name* documents which
Redis instance/password it holds; the mounted *filename* is what
`secrets_dir`'s lookup actually needs), `celery_broker_url`,
`celery_result_backend_url`.

## Operational contract (real, must be documented for whoever deploys this)

Each of the four new secrets' **content is the full, pre-assembled DSN
string**, not a bare password — a deployer with the existing
`db_password`/`redis_auth_streams_password`/`redis_celery_password` secrets
already provisioned needs to additionally run (Swarm-mode example; adapt for
whatever secrets backend a given orchestrator uses):

```sh
printf 'postgresql+asyncpg://kronos:%s@postgres:5432/kronos' "$(cat db_password_value)" \
  | docker secret create database_url -
printf 'redis://:%s@redis-auth-streams:6379/0' "$(cat redis_auth_streams_password_value)" \
  | docker secret create redis_auth_streams_url -
printf 'redis://:%s@redis-celery:6379/1' "$(cat redis_celery_password_value)" \
  | docker secret create celery_broker_url -
printf 'redis://:%s@redis-celery:6379/2' "$(cat redis_celery_password_value)" \
  | docker secret create celery_result_backend_url -
```

This is a real, one-time provisioning step, not automated by this change —
the same honest tradeoff the dispatch's own design option (a) named
up-front ("simplest, avoids needing to know/reconstruct DSN component
parts, but means the deployer must pre-assemble the full DSN into a
secret").

## Real, captured verification

See `run_poc.sh` (re-runnable) and `output.txt` (the actual captured output
from running it) for the full sequence:

1. Real backend image built from `docker/Dockerfile`.
2. Disposable `kronos-poc-secretfix-postgres`/`-redis` containers.
3. Real secret files (full DSN per file, field-named).
4. **db-migrate path**: real `alembic upgrade head` against the real
   disposable Postgres via `DATABASE_URL_FILE` — 3 real migrations applied,
   23 real tables created, confirmed via `psql \dt`.
5. **kronos-backend/celery-worker path**: a script that calls bare
   `Settings()` (identical call to `startup.py`/`celery_app.py`) with
   `KRONOS_SECRETS_DIR` set, then opens **real** `asyncpg`/`redis.asyncio`
   connections through `settings.database_url`/`redis_url`/
   `celery_broker_url`/`celery_result_backend` and confirms `SELECT 1`/
   `PING` — all four succeeded.
6. `docker inspect --format '{{json .Config.Env}}'` on both real running
   containers: **zero** occurrences of either real password
   (`R3alSecretPW!987`, `R3disSecretPW!123`) anywhere in the full `docker
   inspect` JSON for either container — confirmed with an explicit `grep -c`
   across the entire inspect output, not just `Config.Env`.
7. `docker compose -f docker/docker-compose.prod.yml config` with dummy
   values exported for every referenced var: exit code 0, clean resolve.
8. Full backend suite: **2025 passed, 2 skipped** (2004 + 21 new tests, zero
   regressions — confirmed against this branch's own real baseline, not
   `main`, since this worktree branched from `feat/nextgen-soc-cert-platform`
   which already carries milestones through LL/MM(1/2)). `ruff`/`black`/
   `mypy` clean on `src/config.py`, `migrations/env.py`,
   `migrations/db_url.py`, and both new test files. Pre-existing,
   *unrelated* lint debt (77 ruff errors, 30 files needing `black`
   reformatting) confirmed via `git stash` to be identical with and without
   this change — none of it touches the 5 files this milestone changed.
9. Everything disposable (`kronos-poc-secretfix-*` containers/network,
   built test image, temp secret files) torn down immediately after
   capture. The shared dev stack (`docker-kronos-backend-1`, etc.) was
   never touched.

## Honest scope limits (do not overclaim)

This closes the `docker inspect`/Docker-API-level exposure (`Config.Env`),
matching Milestone LL's own scoped threat model (a principal with
inspect-only, non-shell Docker access). It does **not**, and cannot, prevent
the resolved plaintext DSN from appearing in the *running process's own*
`/proc/PID/environ` once `Settings()` has read it into memory — the process
legitimately needs the plaintext value to open a real connection, exactly
like Postgres/Redis themselves. Reading `/proc/PID/environ` requires actual
shell/exec access inside the container, a materially higher-privilege
position than `docker inspect`, and is out of scope here (same honest
caveat Milestone LL's own PoC README already states for its own fix).
