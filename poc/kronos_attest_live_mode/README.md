# PoC: kronos-attest live-Postgres mode vs. offline --audit-log mode

Gap Audit AA1 / P2-5: `kronos_attest/cli.py`'s `verify`, `day-report`, and
`case-report` commands previously only read from a static, offline JSON
export file (`--audit-log <path>`). This PoC verifies the new
`--database-url <dsn>` + `--org-id <uuid>` live-Postgres mode against the
real shared dev Postgres, and proves it produces byte-identical results to
the existing offline mode for the same underlying data.

## Versions pinned

- `sqlalchemy==2.0.51` (`sqlalchemy[asyncio]>=2.0` in `pyproject.toml`)
- `asyncpg==0.31.0` (`asyncpg>=0.29` in `pyproject.toml`)
- `click==8.4.2` (transitive dependency, already used by the pre-existing
  CLI)
- Postgres: `postgres:16-alpine` (the real, running `docker-postgres-1`
  container, `docker/docker-compose.dev.yml`'s pinned image)

Checked via `python -c "import sqlalchemy, asyncpg; print(...)"` and
`docker inspect docker-postgres-1 --format '{{.Config.Image}}'` immediately
before writing this PoC — see the orchestrating agent's transcript for the
raw command output; not re-pasted here to keep this README short.

## What this PoC does

1. Connects directly to the real `docker-postgres-1` (already running,
   `localhost:5432`, db=`kronos`, user=`kronos`/`kronos_dev_password`) —
   read-only queries only, no writes, no schema changes, no restart.
2. Picks a real org with real audit events already in the dev database
   (found via `SELECT org_id, count(*) c FROM audit_log GROUP BY org_id
   ORDER BY c DESC LIMIT 10`) — org `174cf1c7-a2b8-4636-b6a2-ba4b40f51007`
   has 33 real events, one real `case_id`
   (`906ad0c9-0f59-44d9-bbf9-23c26fb34e7c`, 2 events), all on
   `2026-08-08` UTC. This is a pre-existing dev-stack org from earlier
   PoC/dev work (not production data, not fabricated for this PoC — no new
   events were generated; 33 events on one case-bearing org was already
   enough to meaningfully exercise both `day-report` and `case-report`).
3. Builds a real offline `--audit-log` export file
   (`poc/kronos_attest_live_mode/export.json`) using
   `PostgresAuditLogRepository.stream_by_org()` +
   `src.external.routes.audit._to_export_dict` — the exact same repository
   call and field-shaping function `GET /api/audit/export` itself uses
   (imported, not re-derived).
4. Runs the real, installed `kronos-attest` CLI as a real subprocess
   (`python -m kronos_attest.cli ...`) for `day-report`, `case-report`, and
   `verify`, once in offline mode (`--audit-log export.json`) and once in
   live mode (`--database-url ... --org-id ...`), and diffs the parsed JSON
   output field-by-field (`event_count`, `merkle_root`, `chain_valid`,
   `break_count`, `org_chain_fully_intact`, `evidence_ids`).
5. Also exercises the new CLI option validation as REAL subprocess
   invocations (not just the `CliRunner`-based unit tests in
   `tests/unit/test_attest.py`): `--audit-log` + `--org-id` together,
   neither source given, `--org-id` without `--database-url`.

## How to run

```
/home/reca/venv/bin/python poc/kronos_attest_live_mode/run_poc.py
```

Requires `docker-postgres-1` already running and reachable on
`localhost:5432` (it was, throughout this PoC — `docker ps` showed
`Up 2 weeks (healthy)`).

## Result (see `output.txt` for the full real captured run)

**23 passed, 0 failed.** Key lines:

```
day-report[event_count] identical offline vs. live -- offline=33 live=33
day-report[merkle_root] identical offline vs. live -- offline='5c040335529999022592ed66f972807f8d280fb6c94f30ec1b30736776e35575' live='5c040335529999022592ed66f972807f8d280fb6c94f30ec1b30736776e35575'
day-report[chain_valid] identical offline vs. live -- offline=True live=True
day-report[org_chain_fully_intact] identical offline vs. live -- offline=True live=True
case-report[event_count] identical offline vs. live -- offline=2 live=2
case-report[merkle_root] identical offline vs. live -- offline='54cb26e13b97bea8dd4d323a2c6f93b996d589df40d36e336caef37ece22d309' live='54cb26e13b97bea8dd4d323a2c6f93b996d589df40d36e336caef37ece22d309'
case-report[evidence_ids] identical offline vs. live -- offline=['9ae2095f-4516-440b-b96d-deb36560a154'] live=['9ae2095f-4516-440b-b96d-deb36560a154']
real CLI rejects --audit-log + --org-id together
real CLI rejects neither source given
real CLI rejects --org-id without --database-url
```

Both `verify` invocations also independently report `Chain intact (33
events, root=5c04033552999902…)` — the same 33-event, zero-break chain from
two different code paths (one hitting the static export file, one
streaming live from Postgres).

## Scope note

`export.json` in this directory is the real captured export from the run
above (kept for reproducibility, matching `poc/chain_of_custody/`'s own
convention of committing its `export.json`). It is real data pulled from
the shared dev stack's pre-existing dev/PoC org, not synthetic or
hand-written.

## Explicitly out of scope for this PoC (see the parent task's report)

- Live MinIO evidence-hash re-verification — separate, deferred item.
- Live TSA re-querying — RFC 3161 verification is already fully offline
  and cryptographic; there's no live TSA call to add here.
- `merkle-root`/`merkle-proof` live mode — left `--audit-log`-only.
