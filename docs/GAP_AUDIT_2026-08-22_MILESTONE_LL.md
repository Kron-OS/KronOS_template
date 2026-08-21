# Gap Audit — Milestone LL (2026-08-22)

Continuation of `docs/GAP_AUDIT_2026-08-21_MILESTONE_JJ.md`/`_KK.md`'s
remaining, not-yet-actioned findings from the second multi-scenario
assessment (Task #14, round 2). This milestone closes items 1, 2, and 4
from that list, and resolves item 3 (found to be an operational
staleness issue, not a code defect, once investigated).

---

## 1. Case-scoped audit trail (JJ's item 3) — FIXED

**Finding.** `DetectionTriageService.transition()` correctly passes
`case_id=detection.case_id` to every audit log call
(`src/application/detection_triage.py` lines 62/78). `ContainmentAction
.execute()` and `DetectionSinkPushService.push()` did not — confirmed
via grep before any fix (zero `case_id` matches in either file) — meaning
containment/SIEM-sync audit events were invisible both to `kronos-attest
case-report` (strict `case_id` filter) and the live `GET /api/cases/{id}
/audit` route.

**Fix.**
- `src/application/detection_sink_push.py`: `push()` already receives real
  `Detection` objects (not just ids), so `case_id` is derived per-batch
  from a `detection_id -> case_id` map built from those real objects —
  only set when a batch is unambiguously all-one-case (today's only real
  caller, `SyncDetectionToSiemAction`, always pushes exactly one Detection
  per call, so this is always unambiguous in practice); a batch spanning
  multiple cases gets an honest `None` rather than a guessed value.
- `src/application/containment_action.py`: `ContainmentAction` doesn't
  look up Detection itself (by design — `RevokeKeycloakSessionAction`
  operates purely on Keycloak `session_id`/`user_id`, independently
  tenant-checked, never against Detection data). Instead, `execute()`
  reads an optional `case_id` from `params` (a new `_optional_case_id()`
  helper, best-effort, never blocking — mirrors how `detection_id` is
  already "audit context only" in the same params dict) and passes it to
  every audit log call.
- `src/external/routes/detections.py`: `revoke_session_for_detection()`
  now looks up the real `Detection` by `detection_id` (already present in
  the route as a path param) and adds `params["case_id"]` when found —
  an unknown/cross-org `detection_id` does not block the real containment
  action, exactly like `detection_id` itself already didn't.

**Tests.** New regression tests in `test_detection_sink_push.py` (case_id
populated for a single-detection batch; `None` for a batch spanning two
real, different case_ids), `test_containment_action.py` (case_id derived
from params when present; `None` when absent), and
`test_routes_detections.py` (a real HTTP-route-level test confirming the
real `Detection` lookup correctly threads `case_id` into the resulting
`CONTAINMENT_ACTION_ATTEMPTED`/`_EXECUTED` audit rows).

**Verification.** No new external integration surface — this reuses the
`case_id` column on `AuditEvent`, already proven real against Postgres by
`DetectionTriageService`'s own pre-existing usage. Full suite:
**2004 passed** (up from 1999 in Milestone JJ, matching 5 new tests), 0
failures. `ruff`/`black`/`mypy` clean on every changed file (one
pre-existing, unrelated `black`/`ruff` line-length issue in
`test_containment_action.py`, confirmed via `git stash` to predate this
change).

---

## 2. Redis prod secret CLI exposure (JJ's item 1) — FIXED

**Finding** (full writeup: `poc/redis_prod_secret_cli_exposure/README.md`):
`docker-compose.prod.yml`'s `redis-auth-streams`/`redis-celery` passed
their `requirepass` credential via `command:` argv interpolation —
`docker inspect --format '{{json .Config.Cmd}}'` returned the plaintext
password even though `docker top`/`ps aux` from inside the container did
not (Redis rewrites its own process title post-startup). Unlike this same
file's Postgres primary (`POSTGRES_PASSWORD_FILE`, a real Docker secret),
these two services never adopted that pattern.

**Fix.** New `docker/redis/redis-secret-entrypoint.sh` (mirrors
`docker/postgres/replica-entrypoint.sh`'s own established shape): reads
the real secret file path from `$REDIS_PASSWORD_FILE`, execs
`redis-server --requirepass "$REDIS_PASSWORD" --appendonly yes` with the
value resolved as a shell variable, never baked into the image's own
`Config.Cmd`/`Config.Entrypoint`. `docker-compose.prod.yml`: both services
now set `entrypoint: ["/bin/sh", "/redis-secret-entrypoint.sh"]`, mount
the script read-only, and read `REDIS_PASSWORD_FILE` pointing at a new
`redis_auth_streams_password`/`redis_celery_password` Docker secret (added
to the file's top-level `secrets:` block, `external: true`, matching
`db_password`/`replication_password`'s own pattern). Healthchecks updated
to read the same secret file (`redis-cli -a "$(cat ...)"`) rather than the
old `${REDIS_..._PASSWORD:-changeme}` env var interpolation.

**Verification performed (real, captured, CLAUDE.md §F).** Two real runs
against the pinned `redis:7-alpine` image (disposable, distinctly-named
`kronos-poc-*` containers, removed immediately after):
1. An inline `sh -c 'redis-server --requirepass "$(cat ...)" ...'` shape,
   confirming `docker inspect`'s `Config.Cmd` shows the unresolved
   `$(cat ...)` expression, never the plaintext value, while `redis-cli
   ping`/`AUTH` prove the real password is genuinely required and
   accepted; `docker top`/`/proc/1/cmdline` also checked (show only
   Redis's own self-rewritten `redis-server *:6379` title, unaffected
   either way).
2. **The actual final script file**, run with the real healthcheck test
   command from the compose file: `docker inspect
   .State.Health.Status` → `healthy`; `Config.Entrypoint`/`Config.Cmd`
   show only `["/bin/sh"]`/`["/redis-secret-entrypoint.sh"]` — no
   plaintext anywhere; `redis-cli ping` without auth →
   `NOAUTH Authentication required`; with the real password → `PONG`.

Full captured output in `poc/redis_prod_secret_cli_exposure/README.md`'s
own "Fix verification" section. `docker compose -f
docker/docker-compose.prod.yml config` (with dummy env vars for every
referenced variable) resolves both service blocks cleanly — confirmed the
YAML itself is valid, not just the underlying shell logic. `helm lint
charts/kronos` — 0 failures (unaffected by this Docker-Compose-only
change, checked for completeness since this milestone also touched
`values.yaml` for item 4).

**Related, explicitly NOT fixed here** (documented in the PoC's own
README): `kronos-backend`/`celery-worker`/`celery-beat` bake the same
resolved Redis (and Postgres) passwords into their own `environment:`
block via connection-string interpolation
(`REDIS_URL: redis://:${REDIS_AUTH_STREAMS_PASSWORD}@...`, `DATABASE_URL:
postgresql+asyncpg://kronos:${POSTGRES_PASSWORD}@...`) — `docker
inspect`'s `Config.Env` is exactly as visible to the same low-privilege
introspection principals as `Config.Cmd`. This predates this fix (the
Postgres `DATABASE_URL` line already has it) and is broader in scope
(every client service, both databases) — a real, separate candidate for
its own future milestone, not silently expanded into this one.

---

## 3. `db-migrate`'s "missing alembic" — investigated, found to be image staleness, not a code defect

**Original framing (Milestone KK):** "`kronos-backend:dev` image has no
`alembic` on `PATH` and no shell... real production risk if this image is
ever used for a genuinely fresh deploy."

**What was actually found.** `docker/Dockerfile` correctly sets
`ENV PATH=/opt/venv/bin:$PATH` and clears `ENTRYPOINT []` specifically so
`command:` overrides like `alembic upgrade head` work (the Dockerfile's
own comment already documents a past, real, fixed bug of this exact
shape: Chainguard's baked-in `ENTRYPOINT ["/usr/bin/python"]` swallowing
CMD overrides as arguments — `"can't open file '/app/uvicorn'"`).
`alembic>=1.13` is a real, listed dependency in `pyproject.toml`. The
`kronos-backend:dev` image tag actually in use, however, was **3+ weeks
old** — built long before the currently-running `kronos-backend`,
`celery-worker`, `celery-beat` containers were last (re)started, and
apparently stale relative to some later fix. Rebuilding the image fresh
(`docker compose -f docker/docker-compose.dev.yml build db-migrate`) and
re-running `alembic current`/`alembic upgrade head` against it worked
immediately and correctly — real output:
```
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
5a0779975c5a (head)
```
No `src/`/`Dockerfile`/`pyproject.toml` change was needed or made — the
Dockerfile, dependency list, and entrypoint clearing are all already
correct for a fresh build. This was purely a long-uptime dev-stack
image-staleness issue that had never surfaced because `db-migrate` (a
one-shot job, `restart: "no"`) had not been re-run since the image tag
went stale, until an unrelated `docker compose up -d nginx` (Milestone KK)
incidentally tried to recreate it.

**Action taken.** Rebuilt `kronos-backend:dev` (retags the image; the
already-running long-uptime containers are pinned to their own image ID
internally and were completely unaffected — confirmed via `docker ps`
before/after, no disruption). Ran the real `db-migrate` one-shot job
against the fresh image via `docker compose up -d --no-deps db-migrate`
(scoped to avoid re-triggering the dependency-graph cascade Milestone KK
already documented) — completed cleanly (`Exited (0)`), confirming the
compose-defined migration path itself now works end-to-end. Container
removed after (one-shot, matches the existing `restart: "no"` semantics).

**Recommendation, not yet actioned:** the long-running
`kronos-backend`/`celery-worker`/`celery-beat`/`celery-worker-plaso`
containers are still running on their original (older, but working)
image. There is no correctness issue today — but a planned rebuild+
recreate of these four services during a deliberate maintenance window
(not mid-autonomous-cycle) would bring the whole dev stack onto one
consistent, current image, closing the gap between "what's built" and
"what's actually running" before it causes confusion again.

---

## 4. Postgres sync-replica documentation gap (JJ's item 4) — documented

Added `docs/POSTGRES_MINIO_HA_RESEARCH.md` §1.6 ("Known limitation,
confirmed real: a dead sync standby blocks ALL primary writes
indefinitely"), a matching addendum to `docs/deployment.md`'s existing
cold-start note (this is the *steady-state* version of the same risk —
the replica dying *after* a successful install, not only before one), and
a code comment in `charts/kronos/values.yaml` at
`synchronousCommit`/`numSynchronousReplicas` pointing to both. No `docker/`
or `charts/` *behavior* change — this section exists to make sure the
tradeoff (already correctly adopted, per §1.2's own durability table) is
written down deliberately rather than discovered live during an incident.

**The deeper ops-policy question is explicitly left to the project
owner**, per this initiative's own established precedent for decisions it
cannot make unilaterally: accept the current block-until-safe behavior
as-is (consistent with this platform's audit-integrity-first design
goal), add a monitored `synchronous_commit` fallback policy for use during
a confirmed standby outage, or add `pg_stat_replication` alerting so an
operator knows *why* writes are hanging within seconds rather than via a
support ticket. All three options are named in §1.6; none is chosen here.

---

## Verification summary

- Full backend suite: **2004 passed, 2 skipped**, 0 failures (re-run
  after every code change in this milestone).
- `ruff check`/`black --check`/`mypy` clean on every changed `src`/`tests`
  file (pre-existing, unrelated lint debt in `test_containment_action.py`
  confirmed via `git stash`, not touched).
- `docker compose -f docker/docker-compose.prod.yml config` (dummy env
  vars for every referenced variable) resolves cleanly; `helm lint
  charts/kronos` — 0 failures.
- Real, captured `docker run`/`docker inspect`/`redis-cli` verification of
  the Redis secret-file fix against the pinned `redis:7-alpine` image
  (twice — an inline form, then the actual shipped script file with the
  real healthcheck command).
- Real, captured `alembic current`/`upgrade head` run against a freshly
  rebuilt `kronos-backend:dev` image, and the actual compose-defined
  `db-migrate` one-shot service run to completion (`Exited (0)`).
- Dev stack health independently re-confirmed before and after every
  Docker operation in this session (`docker ps` before/after each
  build/run; no container other than this session's own disposable,
  distinctly-named PoC containers was disrupted).

---

## Recommendation for the next wake-up cycle

Remaining real, not-yet-actioned items from this assessment round, in
priority order:

1. **Rebuild+recreate the long-running dev-stack backend/celery
   containers** (item 3 above) during a deliberate maintenance window, to
   close the drift between the image tag and what's actually running.
2. **Remaining frontend UX gaps** (larger scope, likely worth their own
   milestone): no UI anywhere for the `revoke-session`/`sync-to-siem`
   containment actions; `riskScore`/`riskFactors` computed server-side
   but never surfaced in the frontend `Detection` type or any UI.
3. **The broader client-side secret-in-`environment:` exposure** found
   while verifying item 2 above (every service's `REDIS_URL`/
   `DATABASE_URL`/etc. connection strings) — real, but bigger in scope
   than this milestone's Redis-server-specific fix; worth its own
   dedicated pass across the whole compose file rather than a partial fix.
4. The Postgres sync-replica ops-policy decision (item 4 above) remains
   open for the project owner — not a technical blocker, a deliberate
   choice to make when there's a human to ask.

With this milestone's items closed, the second multi-scenario assessment
(Task #14, round 2) that began with Milestone JJ is now fully worked
through: the most severe finding (JJ, approval-gate bypass) and every
concrete, small-to-medium finding it surfaced are either fixed and
verified or honestly documented as a real, open decision. The next fresh
full-repo gap audit (Milestone MM, or a third multi-scenario assessment)
is a reasonable next choice once the frontend UX items above are picked
up, whichever the next wake-up cycle judges more valuable.
