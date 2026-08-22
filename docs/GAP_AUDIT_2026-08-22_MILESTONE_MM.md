# Gap Audit — Milestone MM (2026-08-22), part 2/2

Part 1/2 (commit `6ec6b67`, a separate parallel worktree) surfaced
`riskScore`/`riskFactors` in the frontend UI. This is part 2/2: closing the
`docker inspect --format '{{json .Config.Env}}'` plaintext-secret exposure
that Milestone LL's own PoC (`poc/redis_prod_secret_cli_exposure/README.md`,
"Related, NOT fixed here" section) flagged but explicitly left open for a
future milestone, in `docker-compose.prod.yml`'s `db-migrate`/
`kronos-backend`/`celery-worker` services.

Full writeup, real captured commands/output, and the design-decision
research trail: `poc/backend_prod_secret_config_env_exposure/README.md` +
`output.txt`. This document is the milestone-level summary.

---

## 1. Backend/celery/db-migrate `Config.Env` secret exposure — FIXED

**Finding** (already confirmed real by the orchestrator before this work
started, and independently re-confirmed here): `docker-compose.prod.yml`'s
`db-migrate`/`kronos-backend`/`celery-worker` services interpolated real
Postgres/Redis passwords directly into `environment:` values, e.g.
`DATABASE_URL: postgresql+asyncpg://kronos:${POSTGRES_PASSWORD}@postgres:...`.
`docker inspect --format '{{json .Config.Env}}'` returns these fully
resolved, in plaintext — the same class of exposure Milestone LL fixed for
`redis-auth-streams`/`redis-celery`'s `command:` argv, but this time in
`Config.Env` rather than `Config.Cmd`.

**Real, honest correction found while scoping this** (documented in the
PoC README's own "The finding" section): the dispatch for this work named 5
services (`db-migrate`, `kronos-backend`, `celery-worker`,
`celery-worker-plaso`, `celery-beat`). Only 3 of those actually exist in
`docker-compose.prod.yml` — confirmed via grep, zero matches for either
`celery-worker-plaso` or `celery-beat` as real service blocks (the former
appears only in a comment cross-referencing `docker-compose.dev.yml`, where
it does exist; the latter appears nowhere, including in Milestone LL's own
prose, which named it without ever actually adding it). Prod having no
scheduled-task/beat service and no Plaso worker at all is a separate,
pre-existing gap — flagged here, **not fixed** as part of this milestone
(out of scope for a secrets-exposure fix). This milestone's actual scope is
the 3 real services.

**Why Milestone LL's own fix pattern (a `sh` entrypoint script) doesn't
carry over**: `redis:7-alpine` has a real shell; `kronos-backend`'s own
image (`cgr.dev/chainguard/python:latest`, `docker/Dockerfile`'s runtime
stage) does not — confirmed directly (`docker run --rm --entrypoint sh
kronos-backend-secret-fix-test` → `"sh": executable file not found in
$PATH`). `docker/Dockerfile`'s own `ENTRYPOINT []` comment explains why: the
base image bakes in `ENTRYPOINT ["/usr/bin/python"]`, and clearing it
restores normal exec-form `CMD`/`command:` semantics (`$PATH` lookup, no
shell) — there is no shell to write a wrapper script for.

**Fix**, two mechanisms because `kronos-backend`/`celery-worker` and
`db-migrate` resolve their DSN through genuinely different code paths:

1. **`kronos-backend`/`celery-worker`** (both instantiate a bare
   `src.config.Settings()` — confirmed via `src/external/startup.py:95,435`
   and `src/external/celery_app.py:50`): `src/config.py`'s `Settings`
   now sets `model_config`'s real, current `secrets_dir` option
   (pydantic-settings 2.14.2 — the exact version this repo's dev venv has
   installed, confirmed via `python3 -c "import pydantic_settings;
   print(pydantic_settings.__version__)"`) from a new `KRONOS_SECRETS_DIR`
   env var. Unset (dev's real state, `docker-compose.dev.yml` untouched) is
   a complete no-op — `secrets_dir=None` disables the file-secrets source
   entirely, so plain env vars keep working exactly as before. Set in prod
   to `/run/secrets`, it resolves `database_url`/`redis_url`/
   `celery_broker_url`/`celery_result_backend` from real, field-named
   Docker secret files instead (`secrets_dir`'s own real lookup contract:
   one file per field, named after the field, case-insensitively — read
   directly from the installed `pydantic_settings/sources/providers/
   secrets.py` source, not assumed). A new `field_validator` closes the one
   gap that contract itself leaves open: a secret file that exists but is
   blank resolves to `""`, a syntactically valid string that would
   otherwise sail past pydantic's "field required" check — now raises a
   clear `ValidationError` instead.
2. **`db-migrate`** (`command: alembic upgrade head`) does not use
   `Settings()` at all (`migrations/env.py`'s own pre-existing docstring:
   deliberate, avoids requiring ~15 unrelated MinIO/OpenSearch/Keycloak/
   Vault fields for a migration-only run) — it reads `DATABASE_URL`
   directly from `os.environ`. Fixed by extracting that resolution into a
   new, pure `migrations/db_url.py::resolve_database_url()`, which adds a
   `DATABASE_URL_FILE` fallback mirroring the official `postgres` image's
   own `POSTGRES_PASSWORD_FILE` convention (already used elsewhere in this
   same compose file). Split into its own module specifically because
   `migrations/env.py` imports `alembic.context` at module level — an
   unconfigured proxy outside a real `alembic` invocation (confirmed:
   `import migrations.env` outside alembic raises `AttributeError`),
   making `env.py` itself unsafe to import from a unit test.

`docker-compose.prod.yml`: all three services now pass only a *path*
(`KRONOS_SECRETS_DIR` / `DATABASE_URL_FILE`) via `environment:`, never a
resolved connection string. Four new external secrets added:
`database_url`, `redis_auth_streams_url` (mounted with `target: redis_url`
— see README for why the secret *name* and mounted *filename* differ on
purpose), `celery_broker_url`, `celery_result_backend_url`. A real,
documented operational step (assembling each secret's full-DSN content from
the existing password secrets) is required of whoever deploys this — see
the PoC README's "Operational contract" section for the exact commands.

**Tests.** `tests/unit/test_config.py` (11 tests: plain-env-var path
unchanged, secrets_dir file resolution, env-vs-file priority, missing-dir/
missing-file/empty-file all raise clearly) and
`tests/unit/test_migrations_db_url.py` (10 tests: same shape, for the
`DATABASE_URL`/`DATABASE_URL_FILE` resolver). 21 new tests total, all
passing against the real installed pydantic-settings 2.14.2 — not mocked.

**Verification.**
- Full suite: **2025 passed, 2 skipped** (this branch's own real baseline —
  2004 passed/2 skipped, plus these 21 new tests, zero regressions;
  confirmed by diffing against the pre-change state via `git stash`).
  `ruff`/`black`/`mypy` clean on all 5 touched/added files. Pre-existing,
  unrelated lint debt (77 ruff errors / 30 files needing `black` reformat
  elsewhere in the repo) confirmed identical with and without this change
  via `git stash` — none of it is in the files this milestone touched.
- **Real Docker build + run** (not simulated): built the actual
  `docker/Dockerfile` image, ran a real disposable `postgres:16-alpine` +
  `redis:7-alpine` (distinctly named `kronos-poc-secretfix-*`, torn down
  after), and:
  - Ran the real `alembic upgrade head` command with `DATABASE_URL_FILE`
    pointed at a real secret file — 3 real migrations applied, 23 real
    tables created (confirmed via `psql \dt`).
  - Ran a script making the identical bare `Settings()` call
    `kronos-backend`/`celery-worker` make, with `KRONOS_SECRETS_DIR` set —
    it opened real `asyncpg`/`redis.asyncio` connections through all four
    resolved DSNs and got real `SELECT 1`/`PING` responses back.
  - `docker inspect --format '{{json .Config.Env}}'` on both real running
    containers: the real passwords appear **zero** times anywhere in the
    full inspect JSON for either container (explicit `grep -c` across the
    whole output, not just `Config.Env`).
- `docker compose -f docker/docker-compose.prod.yml config` with dummy
  values exported for every referenced env var: exit code 0, clean resolve
  (technique per Milestone LL's own "Verification performed" precedent).
- Everything disposable torn down immediately after capture; the shared dev
  stack (`docker-kronos-backend-1`, etc.) was never touched.

**Real, disclosed drift found along the way (not fixed here):**
`pyproject.toml` only floors `pydantic-settings>=2.3` — a fresh `docker
build` picked up `2.15.0` in the image versus this repo's dev venv's pinned
`2.14.2`. The `secrets_dir` API is identical in both (re-verified working
end-to-end against the 2.15.0-based built image), so this drift did not
cause a functional gap here, but it's a real, separate dependency-pinning
looseness worth its own future fix.

## Honest scope limit (same as Milestone LL's own, stated explicitly)

This closes the `docker inspect`/Docker-API-level exposure (`Config.Env`),
matching the actual scoped threat model: a principal with read-only,
inspect-level Docker access (not shell/exec). It does **not** — cannot —
prevent the resolved plaintext DSN from being visible in the running
process's own `/proc/PID/environ` once `Settings()` has legitimately read it
into memory to open a real connection; that requires actual shell/exec
access inside the container, a materially higher-privilege position than
`docker inspect`, out of scope here exactly as it was for Milestone LL.
