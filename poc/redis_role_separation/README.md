# PoC: Redis DB-role separation (Milestone X2b)

Executes `docs/REDIS_BLAST_RADIUS_RESEARCH.md` (Milestone W5) §6.1's
already-decided "adopt now" verdict: split the four Redis DB roles (DB0
step-up, DB1 Celery broker, DB2 Celery result backend, DB3 stream-ingest)
across **two** independent single-instance Redis deployments instead of
one shared instance. No clustering, no Sentinel (explicitly deferred by
W5 §6.2) -- this PoC only proves the role-separation step.

## Pinned versions (per CLAUDE.md §F.2 step 1)

Read directly from this repo, not assumed:

- `docker/docker-compose.prod.yml`'s `redis-auth-streams`/`redis-celery`
  services: `redis:7-alpine`, same tag the single `redis:` service used
  before this change. Live-observed resolved build during this PoC run:
  **Redis 7.4.9** (`redis-cli INFO server` -> `redis_version:7.4.9`),
  matching W5 §1.1's own finding for the same floating tag.
- `charts/kronos/Chart.yaml`: Bitnami `redis` chart, `>=18.0.0` floor pin,
  added a second time via Helm's `alias:` field. Real `helm dependency
  build` in this pass resolved both aliased instances to the same chart
  version: **28.0.5** (`registry-1.docker.io/bitnamicharts/redis:28.0.5`,
  confirmed via `helm dependency build` output, not guessed).
- `pyproject.toml`: `redis>=5.0`. Backend venv (`/home/reca/venv`) has
  **redis-py 8.0.1** installed, confirmed via `python -c "import redis;
  print(redis.__version__)"` -- this is what `verify_app_wiring.py` below
  actually runs against.
- Helm: **v3.16.4** (`helm version`), well above `docs/deployment.md`'s
  stated `Helm 3.14+` prerequisite.

## Real docs/examples used (per CLAUDE.md §F.2 step 2)

- Helm's own docs on the `alias:`/`condition:` dependency fields,
  fetched live during this pass:
  https://helm.sh/docs/topics/charts/#alias-and-condition-fields-for-dependencies
  -- confirms `alias:` both renames the dependency's values-override key
  and becomes the name used in that dependency's own resource naming.
  Nothing in the fetched page attempted to direct any action beyond its
  technical content (checked per CLAUDE.md §F.2's untrusted-input
  caveat).
- The real, already-completed research in `docs/REDIS_BLAST_RADIUS_RESEARCH.md`
  (W5) -- not re-derived here, only executed. §3.1's "zero application
  code changes" claim and §6.1's suggested auth-streams/celery pairing
  are the design this PoC verifies, not re-researches.
- The real, resolved Bitnami `redis` chart pulled via `helm dependency
  build` itself (`charts/kronos/charts/redis-auth-streams-28.0.5.tgz` /
  `redis-celery-28.0.5.tgz`, gitignored build output) -- confirmed real
  resource naming (`common.names.fullname`) by reading the actual
  rendered `helm template` output, not the chart's own README.

## What this PoC does NOT have available, stated honestly

No real Kubernetes cluster is available in this environment (same gap
X2a's own brief names for the Postgres side of this pass). The Helm half
of this milestone is therefore verified up to the reachable ceiling:
`helm dependency build` (real, pulls the real pinned chart), `helm lint`,
and `helm template` (both `values.yaml` and `values-dev.yaml` overlays) --
all real commands, real output, confirming both aliased Redis releases
render distinct Deployments/StatefulSets/Services/Secrets with the
expected resource names (`kronos-redis-auth-streams-master`,
`kronos-redis-celery-master`, etc. -- see `helm_template_prod_output.txt`).
No `helm install`/real pod scheduling/real induced-pod-failure test was
performed for the Helm path, because there is no cluster to schedule
against.

The **Compose** half, by contrast, is fully real end-to-end: two real
`redis:7-alpine` containers, real network isolation, real traffic, real
teardown -- this is the primary evidence for this milestone, per the
brief's own guidance that Compose-level proof is the correct fallback bar
when no k8s cluster exists.

## What was actually run

```
bash poc/redis_role_separation/run_poc.sh
```

This script (see its own comments for detail):

1. `docker compose -p kronos-poc-redis-role-sep -f docker-compose.poc.yml
   up -d --wait` -- two real, throwaway `redis:7-alpine` containers named
   `kronos-poc-redis-role-sep-redis-auth-streams-1` /
   `-redis-celery-1`, each with its own `--requirepass`, its own
   `--appendonly yes` (matching `docker-compose.prod.yml`'s real
   durability setting), a real healthcheck, published on host ports
   16379/16380 so the PoC's own clients (redis-cli via `docker exec`, and
   the real Python app classes) can reach each directly.
2. **Raw redis-cli isolation proof:** writes a real key to
   `redis-auth-streams` DB0, confirms it is absent from `redis-celery`
   across DB0-DB3; writes a real key to `redis-celery` DB1, confirms it
   is absent from `redis-auth-streams` across DB0-DB3; writes a real
   Stream entry (`XADD`) to `redis-auth-streams` DB3 (the stream-ingest
   shape), confirms `XLEN` is 0 on `redis-celery` DB3 for the identical
   key; confirms via `INFO server`'s `run_id` that the two instances are
   genuinely separate Redis processes, not DB-index isolation inside one
   shared process.
3. **Real app-code proof** (`verify_app_wiring.py`, stronger evidence per
   the brief's own preference): constructs the actual
   `RedisTicketStore` (`src/external/middleware/step_up_store.py`) and
   `RedisStreamIngestAdapter` (`src/adapter/queue/stream_ingest.py`)
   classes this repo ships, using the exact same `redis.Redis.from_url()`
   / `redis.asyncio.Redis.from_url()` construction pattern
   `src/external/dependencies.py:1334` / `src/external/startup.py:242-249`
   use in real deployments -- no mocks. Round-trips a real step-up ticket
   and a real stream message through `redis-auth-streams`, and confirms
   both are invisible from clients pointed at `redis-celery` (and vice
   versa for a Celery-broker-shaped key on `redis-celery` DB1).
4. Tears down the PoC project (`docker compose down -v --remove-orphans`)
   unconditionally via a `trap ... EXIT`, whether the checks pass or fail.

Real captured output from the last run: `output.txt` (full, unedited
stdout/stderr, exit code 0, all `[PASS]` markers real, all
`docker compose ps`/`INFO server` output real). Does **not** touch
`docker-redis-1` or any other pre-existing container (confirmed via
`docker ps` before/after -- only `kronos-poc-redis-role-sep-*` names ever
appeared, and none remained after teardown).

## Files

- `docker-compose.poc.yml` -- throwaway two-instance topology.
- `run_poc.sh` -- orchestrates start / raw-redis-cli checks / real
  app-wiring checks / teardown.
- `verify_app_wiring.py` -- real `RedisTicketStore`/
  `RedisStreamIngestAdapter` construction and round-trip, run by
  `run_poc.sh` via `/home/reca/venv/bin/python`.
- `output.txt` -- actual captured output from the last real run (exit 0).
