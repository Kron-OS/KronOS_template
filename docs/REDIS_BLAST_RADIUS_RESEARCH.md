# Redis Blast-Radius Research (P1-W7 / Milestone W5)

**Status:** research complete, 2026-08-16. Mirrors the structure and rigor
of `docs/POSTGRES_MINIO_HA_RESEARCH.md` (V10) — same discipline: pinned
versions, real vendor docs, a real minimum-viable topology sized against
named failure modes, an honest disruption-vs-benefit comparison, and an
explicit verdict with named trigger conditions. This document is the
direct execution of `docs/ASSESSMENT_SYNTHESIS_2026-08.md`'s **W5** item
(closing **P1-W7**, itself sourced from `docs/assessments/
scale_reliability_review.md` §3.1).

**Scope discipline:** this is a research document only. No `src/`,
`docker/`, or `charts/` file was modified to produce it. No multi-instance
Redis topology (Sentinel, Cluster, or a DB-role split) was stood up — per
the brief, a real, version-pinned, vendor-doc-cited sizing is the correct
bar for this pass, matching how the Postgres/MinIO and Kafka research
passes both worked.

---

## §0 Method

**What was checked, in order:**

1. `docs/ASSESSMENT_SYNTHESIS_2026-08.md`'s P1-W7 row and its W5 execution
   objective, plus `docs/assessments/scale_reliability_review.md` §3.1 in
   full (the real, four-role blast-radius finding this document exists to
   research a response to).
2. `docs/POSTGRES_MINIO_HA_RESEARCH.md` (V10) in full, as the explicit
   structural precedent this task mirrors — not re-derived below except by
   named cross-reference (§6.3).
3. `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` §0 in full, specifically the
   "verified starting facts" table's Redis-adjacent rows (the AOF-fsync
   durability-window finding and the dev-compose zero-persistence finding),
   as the explicit prior Redis-adjacent research this document does not
   relitigate (§6.3) — this task is about Redis's own *topology*, not
   about replacing Redis Streams with Kafka (already answered "not
   warranted" there) and not about re-deriving the fsync question (already
   answered there too).
4. Pinned versions and real wiring read directly from this repo, not
   assumed:
   - `docker/docker-compose.dev.yml:26`, `docker/docker-compose.prod.yml:54`,
     `docker/docker-compose.test.yml:18`: all three pin `redis:7-alpine`
     identically.
   - `charts/kronos/Chart.yaml`: `redis: version: ">=18.0.0"`, Bitnami
     chart, `condition: redis.enabled` — a floor pin only, same ambiguity
     V10 flagged for MinIO's `latest` tag (no `Chart.lock` exists in this
     repo to resolve it further; see §1.1 for how this was handled
     honestly rather than guessed).
   - `charts/kronos/values.yaml:255-270`: `redis.master.persistence.size:
     8Gi`, `resources.requests: 100m/128Mi`, `resources.limits: 500m/512Mi`
     — no `replica:` key, no `sentinel:` key present anywhere in this
     file, i.e. the chart today deploys the Bitnami `redis` subchart in
     its single-master shape.
   - `pyproject.toml:15-16`: `celery>=5.4`, `redis>=5.0` — both floor pins
     only, no lockfile in this repo to resolve an exact installed patch
     (confirmed: no `poetry.lock`/`uv.lock` at repo root, and celery/redis
     are not installed in this research environment to introspect
     `__version__` directly). Handled the same honest way as the chart
     version: cited against the current "stable" docs branch for the
     pinned major (Celery 5.x, redis-py 5.x+), flagged wherever a specific
     minor-version behavior might matter.
   - `src/config.py:31-38,121-122,137-140`: the real four DB-role config
     surface — `redis_url` (DB0, step-up), `celery_broker_url`/
     `celery_result_backend` (DB1/DB2), `stream_redis_db: int = 3` (DB3).
   - `docker/docker-compose.prod.yml:268,338-339,389,433-434`: the real
     resolved DSNs — `redis://:${REDIS_PASSWORD}@redis:6379/0` (step-up),
     `.../1` (broker), `.../2` (backend); DB3 has no compose-level env var
     shown because `stream_redis_db`'s default (`3`) is used directly by
     `Settings`, combined with the same `redis_url` host/port/password.
   - `src/external/middleware/step_up_store.py:113-159` (`RedisTicketStore`,
     built via plain `redis.Redis.from_url(...)` in
     `src/external/dependencies.py:1334`) and
     `src/external/startup.py:242-249` (`RedisStreamIngestAdapter` built
     via `redis.asyncio.Redis.from_url(...)`) read directly — both use the
     synchronous/asynchronous `.from_url()` constructor pattern, not a
     Sentinel-aware one; this is the concrete wiring point §3.3 checks
     against for "would Sentinel need custom wiring."
   - `src/external/celery_app.py:53-56`: `Celery(broker=..., backend=...)`
     built directly from `Settings`' resolved secret strings at import
     time — the real construction point §3.3/§3.4 check Sentinel/Cluster
     URL-scheme compatibility against.
5. Real vendor documentation fetched live for the pinned versions (Redis's
   own Sentinel and Cluster docs, Bitnami's `redis` chart README/ArtifactHub
   listing, Celery's current stable Redis broker/backend docs, redis-py's
   asyncio Sentinel module). URLs cited inline in §3. Treated as untrusted
   input per `CLAUDE.md` §F.2 — no fetched page contained anything
   resembling an embedded instruction; all fetched content was plain
   technical documentation. One inconsistency between two independently
   fetched summaries of the same Celery docs page is flagged honestly in
   §3.5 rather than silently resolved in whichever direction was more
   convenient.

---

## §1 The four roles, confirmed

| DB | Role | Real config source |
|---|---|---|
| 0 | Step-up (RFC 9470) ticket store — `RedisTicketStore`, `redis.Redis.from_url()` | `src/config.py:137-140`; `src/external/dependencies.py:1322-1335`; `src/external/middleware/step_up_store.py:113-159` |
| 1 | Celery broker — every parse/beat task in the platform | `src/config.py:121`; `src/external/celery_app.py:53-56`; `docker-compose.prod.yml:338,433` |
| 2 | Celery result backend | `src/config.py:122`; `docker-compose.prod.yml:339,434` |
| 3 | Stream-ingest backbone — `RedisStreamIngestAdapter`, `redis.asyncio.Redis.from_url()`; also the substrate `seal_pending_streams`' `list_active_streams()` discovers active (org, source) pairs from | `src/config.py:38`; `src/external/startup.py:242-249`; `src/adapter/queue/stream_ingest.py` |

**One instance, one container, one host, four roles distinguished only by
DB index** — confirmed across all three compose files and the Helm chart;
no document prior to `scale_reliability_review.md` §3.1 stated this
combined picture in one place (the Kafka roadmap looked only at DB3's
durability window; V10 explicitly scoped itself to Postgres/MinIO only).

### §1.1 Version pin, honestly stated

`redis:7-alpine` resolves, as of a live Docker Hub check during this
research pass, to the `7.4.9-alpine3.21` build line (manifest digest
`sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2`
per Docker Hub's tag listing at the time fetched) — i.e. Redis **7.4.x**,
not Redis 8. This is stated with the same honesty caveat V10 used for
MinIO's `latest` tag: `redis:7-alpine` is a **floating** tag (it will
silently move to a newer 7.x point release on the next `docker pull`),
so this is the resolved build observed during this research pass, not a
permanently pinned guarantee — a real gap for reproducibility that this
document flags but does not fix (out of scope; would be a `docker/`
change). The Bitnami `redis` Helm dependency (`>=18.0.0`) is a floor-only
semver range with no `Chart.lock` in this repo to resolve further; the
current latest published chart at research time was `18.6.3`
([artifacthub.io/packages/helm/bitnami/redis/18.6.3](https://artifacthub.io/packages/helm/bitnami/redis/18.6.3)),
cited as the closest real reference point for chart-schema behavior below,
not asserted as what this repo would actually resolve to on a fresh
`helm dependency update`.

---

## §2 Real, specific failure modes

Named concretely and mapped to which of the three guarantees each
threatens — evidence-intake dispatch, privileged-action step-up auth, and
new-telemetry landing — the same discipline V10 used for Postgres's
chain-of-custody integrity vs. availability split:

| # | Failure mode | Threatens | Severity/likelihood note |
|---|---|---|---|
| R1 | **Single-node hardware failure** (disk, PSU, host) — every compose/Helm deployment in this repo runs exactly one Redis process on one host's local disk/PVC (`docker-compose.prod.yml:56-57`'s `redis_data` volume; `charts/kronos/values.yaml:257-259`'s `master.persistence`), with all four DB roles multiplexed onto it. | All three: evidence-intake dispatch (DB1/DB2), step-up auth (DB0), new-telemetry landing (DB3) — simultaneously | This is `scale_reliability_review.md` §3.1's core finding: a wider *simultaneous* blast radius than Postgres's F1 or MinIO's M1 individually, precisely because those two each threaten exactly one guarantee while this single container threatens three unrelated ones at once. No automatic recovery path exists today — a human must provision a new Redis and, for DB1/2/3, tolerate real data loss (queued-but-undispatched Celery tasks, unconsumed stream entries) bounded only by the AOF-fsync window already researched in `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` §0 (not re-derived here). |
| R2 | **Single-AZ/datacenter outage.** Nothing in `docker-compose.prod.yml` or `charts/kronos/values.yaml` places Redis across failure domains — no `podAntiAffinity`/`topologySpreadConstraints` for the `redis` subchart exist in this repo's `values.yaml`, mirroring V10's identical finding for Postgres's F2. | Same three, same simultaneity | Same class as R1 at larger blast radius; the chart's single-master shape means even a multi-AZ *Kubernetes cluster* provides zero protection today because nothing asks for spread. |
| R3 | **AOF-fsync data-loss window on a hard crash (not graceful restart).** `docker-compose.prod.yml:55` sets `--appendonly yes` (durable), but the default `appendfsync everysec` policy still has a real, bounded (~1s) loss window on an actual OS/process crash. | Availability is unaffected (this is a durability-window question, not an outage question) — bounded data loss on DB1 (in-flight task) / DB3 (most-recent unconsumed stream entries) | **Already researched and explicitly scoped in `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` §0** — restated here only as a name-check per that document's own framing ("bounded by `SealingTriggerPolicy`'s own short intervals, not unbounded"), not re-derived. Notably, that prior research scoped itself to DB3 only; it did not separately consider DB1's Celery-task loss window, which is the same underlying `appendfsync everysec` mechanism but a functionally different consequence (a lost in-flight parse task vs. a lost stream entry) — named here as a small, honest gap in that prior pass's scope, not a new mechanism. |
| R4 | **Cross-role resource contention on the single shared instance** — a role-specific problem that has no Postgres/MinIO analogue at all, because those two components don't multiplex unrelated workloads onto one instance the way this Redis does. `charts/kronos/values.yaml:266-270`'s `500m`/`512Mi` limit was sized, per `scale_reliability_review.md`'s own finding (its §"resource sizing" table), before DB3's stream-ingest role existed — a large `collector_max_stream_length = 1_000_000`-entry backlog on DB3 for one or more (org, source) pairs competes for the *same* memory ceiling that DB1's broker queue and DB0's ticket TTLs depend on. Under `noeviction` (Celery's own documented recommendation, §3.5), a memory-pressured instance stops accepting new writes entirely rather than silently evicting — meaning a stream-ingest backlog spike can induce a full write-outage for step-up tickets and Celery task dispatch too, not just fail loudly for its own role. | Availability, cross-role (a DB3 problem causing a DB0/DB1 outage) | New finding in this pass, not previously named as a *blast-radius* mechanism (the scale review flagged the `512Mi` number as under-sized but did not connect it to this specific cross-role failure-propagation path). Real but not measured — no load test was run (out of this document's scope, matching `CLAUDE.md` §F's "run it and read the output" bar not being met here because no `docker/`/`charts/` topology change was made to test against); flagged as a concrete, plausible mechanism, not asserted as observed. |

**Which mechanisms does topology change actually address?** DB-role
separation (§3.2) directly addresses R1/R2/R4's *simultaneity* — even
with zero added redundancy, splitting roles across ≥2 single-instance
Redis processes means a hardware failure on one no longer takes the other
two roles down with it, and R4's cross-role memory contention becomes
structurally impossible once the roles don't share a process. Real
Sentinel/Cluster HA (§3.3/§3.4) addresses R1/R2's *availability* dimension
per role (survives a node loss without an outage) but does nothing for R4
on its own — a Sentinel-replicated single "everything" instance still has
the same cross-role contention problem, just with an extra failover
option once contention causes a crash. R3 is unaffected by any topology
option researched here (it is an `appendfsync` policy question,
orthogonal to node count — the same kind of "not what HA fixes" finding
V10 made for Postgres's F4 migration-locking risk).

---

## §3 Real HA/topology mechanisms researched, pinned to `redis:7-alpine` / Bitnami `redis` chart

### §3.1 DB-role separation across ≥2 single-instance Redis deployments (no clustering)

No official Redis/Bitnami/Celery documentation *mandates* this — it is a
deployment-topology choice this repo would make, not a documented Redis
feature — but two real, documented facts support it directly:

- **Celery's own official docs do not state a clear best-practice
  position on broker/backend sharing.** Checked directly against the
  current stable docs page
  ([docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/redis.html](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/redis.html))
  via two independent fetches in this pass: the page shows `broker_url`
  and `result_backend` as separate settings, both illustrated pointing at
  `redis://localhost:6379/0` in its own quick-start example, with **no
  explicit sentence recommending or discouraging sharing an instance/DB
  number between them**. This is itself a real finding worth stating
  honestly rather than inventing a citation for: an earlier web-search
  summary (not a direct page fetch) claimed the docs say "if result
  persistence is important, consider using another DB for your backend,"
  but a direct fetch of the same page could not locate that sentence —
  flagged here as a real inconsistency between an indirect and a direct
  source, resolved in favor of the direct fetch (no such explicit
  recommendation currently exists on the live stable docs page). What
  the docs *do* document, in the same page's **Caveats** section
  (`#caveats` anchor), are real, mechanistically-driven reasons the two
  roles behave differently under load: the **visibility-timeout**
  caveat ("If a task isn't acknowledged within the Visibility Timeout the
  task will be redelivered to another worker") interacts with this
  repo's own `task_acks_late=True` (`src/external/celery_app.py:97`,
  chosen so a crashed worker's task is retried rather than lost) — a
  long-running task combined with visibility-timeout redelivery is a
  broker-side behavior with no backend-side analogue; and the
  **key-eviction** caveat recommends `maxmemory-policy noeviction` or
  `allkeys-lru` specifically because Redis silently dropping a broker key
  under memory pressure causes lost tasks, a failure mode that doesn't
  apply the same way to result-backend keys (which have their own
  `result_expires` TTL semantics). These are real, documented, distinct
  operational characteristics per role — not a stated "never share them"
  rule, but a real basis for the intuition that they are different
  workloads worth separating, independent of any HA question.
- **Sentinel deployment guidance (§3.3) reinforces the same intuition
  from a different angle**: Redis's own Sentinel docs discuss "monitored
  masters" as the unit of failover, and a single master serving four
  unrelated roles is one failover event away from all four roles
  failing over together, whether or not that's operationally desirable
  (e.g. a planned maintenance failover for the stream backbone would
  also bounce step-up auth and the Celery broker, even if only DB3 needed
  the maintenance).

**Real wiring cost of DB-role separation, checked directly against this
repo's actual code, not assumed:** `src/config.py` already models each
role as an independent DSN (`redis_url`, `celery_broker_url`,
`celery_result_backend`, plus `stream_redis_db` layered on `redis_url`'s
host/port) — meaning the **application code requires zero changes** to
point different roles at different hosts; this is purely an environment-
variable/compose-service/Helm-values change (a second `redis` service
block in compose, a second Bitnami `redis` subchart instance — or a
second, independently-templated `Deployment` — in Helm, and updated DSNs
in `docker-compose.prod.yml`'s `environment:` blocks and
`charts/kronos/values.yaml`). This is the cheapest topology change
researched in this entire document, materially cheaper than V10's
"replication-only" Postgres step, because it requires no new replication
mechanism at all — just two independent single points of failure instead
of one shared one.

### §3.2 Redis Sentinel

Per the current official Redis Sentinel documentation
([redis.io/docs/latest/operate/oss_and_stack/management/sentinel/](https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/)),
fetched directly in this pass:

- **"You need at least three Sentinel instances for a robust
  deployment"** and **"please deploy at least three Sentinels in three
  different boxes always"** — quoted verbatim from the official docs.
  This is structurally the same shape of finding V10 made for Postgres's
  Patroni+etcd option: genuine automatic failover needs a real,
  odd-numbered consensus quorum (Sentinel's own majority-vote failover
  authorization), not just 2 nodes.
- **Real minimum topology for one monitored master with automatic
  failover:** 1 master + 1 replica (2 Redis processes) + 3 Sentinel
  processes = **5 real processes minimum** — the exact same number V10
  derived for Postgres's Patroni+etcd option, and not a coincidence: both
  are "2 data nodes + a 3-node consensus layer" shapes.
- **Bitnami chart support, confirmed real and current**: the `redis`
  chart (pinned `>=18.0.0`, checked against `18.6.3`'s current
  documentation) supports Sentinel natively via
  `architecture: replication` + `sentinel.enabled: true` +
  `sentinel.quorum`, deploying Sentinel as a sidecar container inside the
  same pods as the Redis master/replica StatefulSets — this repo would
  **not** need a new Helm chart dependency the way MinIO's distributed
  mode would (V10 §2.2's "wholly new component" finding does not apply
  here); it is a `values.yaml`-only change to the existing dependency,
  much closer to Postgres's `readReplicas.replicaCount` case than to
  MinIO's Operator case.
- **Client-library support, checked against the real question the brief
  asked ("does the client library actually support Sentinel-aware
  connections out of the box, or would that need custom wiring?"):**
  redis-py (`pyproject.toml:16`'s `redis>=5.0`) ships **both** a
  synchronous (`redis.sentinel.Sentinel`) and an asyncio-native
  (`redis.asyncio.sentinel.Sentinel`) Sentinel client, confirmed via
  direct inspection of the current redis-py docs/source
  ([github.com/redis/redis-py/blob/master/redis/asyncio/sentinel.py](https://github.com/redis/redis-py/blob/master/redis/asyncio/sentinel.py);
  [redis.readthedocs.io/en/stable/connections.html](https://redis.readthedocs.io/en/stable/connections.html)),
  with `master_for()`/`slave_for()` helpers that "detect failover and
  reconnect Redis clients automatically." **The library supports it out
  of the box — but this repo's actual client construction does not use
  that API today**, confirmed by direct read: `src/external/dependencies.py:1334`
  (`redis.Redis.from_url(url, ...)` for the step-up ticket store) and
  `src/external/startup.py:249` (`AsyncRedis.from_url(_stream_redis_url)`
  for the stream-ingest adapter) both use the plain `.from_url()`
  constructor. Adopting Sentinel would require real, small, localized
  code changes at exactly these two call sites (swap `.from_url()` for a
  `Sentinel(...).master_for()`/`.slave_for()` call, sourced from a list of
  Sentinel host:port pairs instead of one Redis DSN) — not zero-code, but
  bounded to two files, not a framework-wide rewrite.
- **Celery's own Sentinel support, checked against the current stable
  docs** (same page as §3.1): Celery has first-class Sentinel support via
  a `sentinel://` URL scheme for `broker_url`
  (`'sentinel://host1:26379;sentinel://host2:26379;...'`) plus
  `broker_transport_options = {'master_name': "..."}`, and a parallel
  `result_backend_transport_options = {'master_name': "..."}` for the
  result backend. This means `src/external/celery_app.py:53-56`'s direct
  `Celery(broker=..., backend=...)` construction from `Settings`' plain
  DSN strings would need a real (small, bounded) change — sourcing a
  Sentinel connection string and transport options from `Settings`
  instead of a single Redis URL — but the mechanism itself is native to
  Celery, not something requiring a third-party plugin (the `celery-
  redis-sentinel` PyPI package that surfaced in this research's own
  search results appears to predate or duplicate Celery's now-built-in
  support and was not needed for this finding).

### §3.3 Redis Cluster

Per the official Redis Cluster specification
([redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/](https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/))
and scaling guide
([redis.io/docs/latest/operate/oss_and_stack/management/scaling/](https://redis.io/docs/latest/operate/oss_and_stack/management/scaling/)):
a functional cluster requires **a minimum of 3 master nodes** (consensus/
majority requirement, structurally identical in shape to Sentinel's
3-Sentinel quorum and Kafka's 3-node minimum already rejected in
`docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` §0), with Redis's own real-world
recommendation being **6 nodes** (3 masters + 3 replicas) for genuine
node-fault tolerance — the same "documented floor vs. real-world
recommended floor" gap V10 found for MinIO's 2-drive-technical-floor vs.
4-node-real-world-floor.

**This is where the brief's own explicit caveat proved decisive, and
rules Cluster out independent of the node-count cost:** Celery/Kombu (the
messaging library underneath Celery) has **no supported Redis Cluster
broker integration** — confirmed via multiple real, current, open GitHub
issues against the `celery/celery` repository: issue #2852 ("FR:
Integrate Redis Cluster as broker," open since 2015, still unresolved and
explicitly noting the fix would need to happen in Kombu first, not
Celery itself), issue #8276 ("The message queue of the framework does not
seem to support Redis clusters," 2023), and discussion #8333 confirming
Redis Cluster is not supported for Celery's broker/backend as of the
current stable release line. **This directly answers the brief's own
named question** ("does Celery's own docs have real documented caveats
with Redis Cluster? check Celery's own docs") — the caveat is not
documented as a caveat *in Celery's own docs* (the official Redis-broker
page is silent on Cluster entirely, confirmed by direct fetch), but the
real-world unsupported status is confirmed in Celery's own issue tracker,
which is the more authoritative real signal than an absence of
documentation would be on its own. **Redis Cluster is therefore not a
viable option for DB1/DB2 (the Celery broker/backend roles) at all**,
independent of whether its 3-6 node cost would otherwise be justified —
the same kind of hard technical disqualifier V10 never needed for
Postgres/MinIO (both of those options were cost/benefit questions, not
compatibility questions). Cluster would remain *technically* usable for
DB0 (step-up tickets, a simple key-value `SET`/`GETDEL` workload with no
Celery dependency) and DB3 (Redis Streams are cluster-compatible in
principle, keys hash-sharded by slot), but adopting Cluster for only two
of the four roles while Sentinel or single-instance serves the other two
adds a second, structurally different HA mechanism to operate
side-by-side with whatever DB1/DB2 uses — a real, added operational
complexity cost this document flags but does not recommend, given §3.2's
Sentinel option already covers all four roles uniformly with a smaller
node-count floor (5 vs. Cluster's 6) and no Celery-compatibility
disqualifier.

---

## §4 Real minimum viable topology

| Ambition | Nodes/processes | What it buys | What it doesn't |
|---|---|---|---|
| DB-role separation only, no clustering | 2 single-instance Redis processes (e.g. A: step-up + stream-ingest; B: Celery broker + backend) | Removes R1/R2/R4's *simultaneity* — a hardware failure or memory-contention event on one no longer takes all three guarantees down together | Zero redundancy per role — each instance is still its own unmitigated single point of failure for the roles it hosts |
| DB-role separation + Sentinel HA on each split instance | 2 × (1 master + 1 replica) + 3 shared Sentinel processes = **7 processes** (Sentinel processes can monitor multiple masters, so 3 Sentinels suffice for both split instances, not 3 per instance) | R1/R2 survivability *per role-group*, automatic failover, zero simultaneity | Meaningfully more operational surface than either option alone — a new stateful consensus layer (Sentinel) this platform has never operated, mirroring V10's own etcd-for-Patroni caveat almost exactly |
| Single instance + Sentinel HA, no role separation | 1 master + 1 replica + 3 Sentinel = **5 processes** | R1/R2 survivability for the combined instance | Does **not** fix R4 (cross-role contention) or the "one failover event bounces all four roles" characteristic named in §3.1 — HA without role separation is a strictly incomplete answer to the review's own finding |
| Redis Cluster (any role split) | 3 nodes minimum (documented floor), 6 recommended (real-world floor) | Would be moot for DB1/DB2 in any case — **disqualified for the Celery broker/backend roles by Celery/Kombu's own unsupported status** (§3.3), not by cost | N/A — ruled out on compatibility grounds before the cost question is even reached |

Unlike Postgres (useful at 2 nodes per V10 §1.2) and roughly like MinIO's
real 4-node floor (V10 §2.3), Redis's genuine *automatic-failover* floor
is 5 processes — but unlike MinIO, Redis's **DB-role-separation** option
(§3.1) is a real, separately-adoptable, much cheaper step that has no
Postgres or MinIO analogue at all, because those two components don't
multiplex unrelated guarantees onto one instance the way this Redis does.
This is the single most important structural difference this document
found relative to both prior research passes.

---

## §5 Disruption vs. benefit comparison

### §5.1 DB-role separation across ≥2 instances

**Cost:** one more container/pod/PVC to run, monitor, and secure (a
second `REDIS_PASSWORD`-equivalent secret, a second healthcheck, a second
line in whatever alerting exists); `docker-compose.prod.yml` needs a
second `redis` service block and every DSN referencing DB1-DB3 (or
whichever split is chosen) repointed at the new host; `charts/
kronos/values.yaml` needs either a second Bitnami `redis` subchart alias
or a hand-templated second Deployment (the chart's dependency mechanism
supports subchart aliasing for exactly this, so this is not a new
dependency, just a second instance of the existing one). No source-code
changes are required (`src/config.py` already models each role as an
independent DSN, confirmed in §3.1).

**Benefit:** directly closes R1/R2/R4's *simultaneity* — the concrete,
named, wider-than-Postgres-or-MinIO blast radius `scale_reliability_review.md`
§3.1 raised as the reason this research pass exists at all. This is a
real, structural risk reduction, not a marginal one: today, one bad host
takes down evidence-intake dispatch, privileged-action auth, *and* new-
telemetry ingestion in the same instant; after this change, it takes down
at most two of those three (whichever pairing is chosen), and a sensible
pairing (e.g. auth+streams on one instance, broker+backend on the other,
per the brief's own suggested split) means the platform's two most
customer-visible failure modes — "I can't do a privileged action" and "my
new alert data isn't landing" — become independently recoverable from
"evidence processing is stuck."

**Verdict lean:** high benefit, low cost, no code changes — the cheapest,
highest-value item in this entire document.

### §5.2 Real Sentinel/Cluster HA on top of however many instances are chosen

**Cost, Sentinel (the only real Celery-compatible option per §3.3):** a
wholly new stateful service class this platform has never operated
(Sentinel processes, quorum-tuned, "at least three... in three different
boxes" per Redis's own docs) — the same category of new operational
surface V10 flagged for Patroni+etcd, though smaller in absolute node
count (Sentinel's 3 vs. etcd's 3, but Sentinel is a lighter, Redis-native
process rather than a general-purpose consensus store, arguably a smaller
new-skillset cost than etcd would be). Client-side, real code changes at
the two identified `.from_url()` call sites (§3.2) plus
`src/config.py`/`src/external/celery_app.py` to source Sentinel
connection strings and `master_name`/transport-options instead of plain
DSNs — bounded, but not zero, unlike §5.1's role-separation step.

**Cost, Cluster:** moot for DB1/DB2 (disqualified by compatibility, not
cost, per §3.3); even limited to DB0/DB3 only, it would introduce a
second, structurally different HA mechanism running alongside whatever
DB1/DB2 uses (single-instance or Sentinel) — real added complexity with
no offsetting benefit over just using Sentinel uniformly across all
roles, since Sentinel already covers DB0/DB3's simple key-value/stream
workloads just as well as Cluster would, at a smaller total node count.

**Benefit:** survives a single Redis node/process failure without a full
outage, on top of whatever role-split §5.1 already achieved — a real,
further risk reduction, but qualitatively different from §5.1's benefit:
§5.1 fixes *simultaneity* (three guarantees failing together), while
Sentinel fixes *recoverability* (any one guarantee's own outage duration).
Both are real, but they are answering different questions, and (per §4)
§5.1 is available today at effectively zero disruption while §5.2 is not.

**Verdict lean:** real benefit, meaningfully higher cost (new service
class + bounded code changes), and — critically — **this repo has no
documented evidence today that recoverability time (not just
simultaneity) is a live problem**, the same absence-of-evidence V10 used
to defer Postgres's own automatic-failover step.

---

## §6 Verdict

### §6.1 DB-role separation: **adopt now, in whatever form is scoped as a follow-up item**

Split the four DB roles across at least 2 single-instance Redis
deployments — no clustering, no Sentinel, just two (or more) independent
instances. This is justified on the same "cheap, no new service class,
bounded config-only change" grounds V10 used to recommend Postgres's
replication-only step, and is in fact **cheaper than that step**: it
requires zero application code changes (§3.1's `src/config.py` finding),
zero new replication mechanism, and zero new Helm dependency — purely a
second instance of something this platform already runs, with `Settings`'
existing per-role DSN fields simply pointed at two hosts instead of one.
A sensible default split, following the brief's own suggested shape: one
instance for step-up tickets (DB0) + stream-ingest (DB3) — the two
customer/telemetry-facing roles — and a second instance for the Celery
broker (DB1) + result backend (DB2) — the internal task-plumbing roles,
which per §5.1 also directly resolves R4's cross-role memory-contention
mechanism as a side effect, since the roles most likely to spike memory
(a large stream backlog) no longer share a ceiling with the roles most
sensitive to a memory-pressure write-outage (step-up tickets, task
dispatch).

### §6.2 Real Sentinel/Cluster HA: **defer, named trigger conditions below — Cluster specifically ruled out for DB1/DB2 regardless of trigger**

**Do not adopt Sentinel now.** The cost (a new 3-process consensus
service class, bounded but real code changes at the two identified
`.from_url()` sites plus `celery_app.py`/`config.py`) is not justified by
any evidence in this repo today that per-role *recoverability time* (as
opposed to §6.1's *simultaneity*) is a live, observed problem — the exact
same absence-of-evidence reasoning V10 used to defer Postgres's automatic
failover. **Trigger conditions that would reopen this, mirroring V10's
own trigger-condition style:** (a) a real customer/production deployment
with a contractual or regulatory uptime SLA on evidence-intake
availability or step-up-gated privileged actions specifically (not just
data durability); (b) a real incident in this repo's own operational
history where a Redis outage's recovery time (not just its simultaneity)
caused a missed detection, a stalled evidence pipeline with measurable
customer impact, or a chain-of-custody dispute; (c) the platform moving
to a real multi-region/multi-AZ production posture, where R2 (single-AZ
outage) stops being a theoretical failure domain and Sentinel's
automatic cross-node failover becomes operationally load-bearing rather
than a nice-to-have.

**Do not adopt Redis Cluster for DB1/DB2 at all, ever, under the current
Celery/Kombu architecture** — this is a compatibility disqualifier, not a
cost/benefit judgment call, and would not be reopened by any of the
trigger conditions above; it would only be reopened by Kombu itself
shipping real Redis Cluster broker support (tracked upstream, unresolved
since 2015 per §3.3) or this platform migrating off Celery entirely
(out of scope for anything in this initiative). Cluster remains
theoretically available for DB0/DB3 alone but is not recommended even
then (§5.2) — if Sentinel is ever adopted per a trigger condition above,
apply it uniformly across all four roles rather than introducing Cluster
as a second HA mechanism for a subset of them.

### §6.3 Priority relative to V10's own Postgres-now/MinIO-later verdict: **Redis's role-separation step is real, adopt-now work — comparable in cost to Postgres's own cheap step, and arguably higher-urgency given the wider blast radius, but the two are not in conflict and should both proceed**

Stated as a real, reasoned opinion, per the brief's explicit ask not to
just present options: **the DB-role-separation half of this verdict
(§6.1) deserves the same "adopt now" priority V10 gave Postgres's
replication step, and arguably a marginally higher one**, for a reason
V10 itself could not have weighed (it explicitly did not cover Redis):
`scale_reliability_review.md` §3.1's blast-radius finding is not
hypothetical in the way Postgres's F1/F2 (hardware/AZ failure) or MinIO's
M1 (hardware failure) are — those are failure modes that *haven't
happened yet* in this repo's operational history, whereas Redis's
combined-role design is a **standing, present-tense architectural fact**
that guarantees simultaneity the moment *any* one of R1/R2/R4 occurs, not
a probabilistic tail risk gated behind a hardware failure. Postgres's
replication step protects against an *event*; Redis's role-separation
step removes a *standing design property* that amplifies the blast
radius of any such event across three unrelated guarantees at once. Both
are real, both are cheap, and — importantly — **they are not competing
for the same engineering attention or infrastructure budget**: Postgres's
step is a `docker-compose.dev.yml`/`prod.yml` + `values.yaml` change to
an existing dependency; Redis's role-separation step is the same shape of
change to a different existing dependency. There is no honest reason to
sequence one strictly before the other; both should be scoped as
follow-up items from their respective research passes independently.

**Where this verdict does *not* out-urgency MinIO's still-deferred
question:** MinIO's M3 (silent bit-rot on WORM-locked evidence, zero
current detection) remains, on its own terms, the single most severe
*integrity* gap named across all three research passes — it is about
data that may already be silently wrong with no way to know, a
categorically different and more severe kind of risk than anything
Redis's blast radius raises (Redis's failure modes are all
*availability*-class: things stop working, loudly, recoverably by a
human; nothing about Redis's design threatens silent, undetectable
corruption of already-committed evidence the way M3 does). This document
does not claim Redis's finding outranks MinIO's bit-rot gap — it claims
Redis's **role-separation** step (not full HA) is comparably cheap to
Postgres's already-approved step and should proceed on the same "cheap,
adopt now" logic, independent of and without displacing MinIO's own
still-open, still-more-severe M3 question.

---

## §7 Next steps if this is picked up (objectives only, not full agent briefs)

Per the Gap Audit / V10's own convention:

1. **DB-role separation (adopt now, per §6.1).** Split `docker-compose
   .dev.yml`/`.prod.yml` and `charts/kronos/values.yaml`'s single `redis`
   service/subchart into two independent single-instance deployments,
   repointing `REDIS_URL`/`CELERY_BROKER_URL`/`CELERY_RESULT_BACKEND` DSNs
   per the suggested split in §6.1 (step-up + stream-ingest on one
   instance, Celery broker + backend on the other) — or a different split
   if a future review identifies a better pairing. Verification-first
   (`CLAUDE.md` §F) applies: a real `poc/redis_role_separation/` PoC
   should demonstrate the full evidence-intake pipeline and a real
   stream-ingest → seal → normalize → sync cycle both working correctly
   against the split topology, plus a real induced-outage test (kill the
   broker/backend instance, confirm step-up tickets and stream-ingest are
   unaffected, and vice versa) before any `docker/`/`charts/` file is
   touched for real. Explicitly out of scope for this item: any Sentinel/
   Cluster HA work (deferred per §6.2).
2. **Redis Sentinel HA (deferred, only if a §6.2 trigger condition is
   met).** If reopened, a real `poc/redis_sentinel/` PoC standing up a
   real 1-master/1-replica/3-Sentinel topology (Bitnami chart's
   `architecture: replication` + `sentinel.enabled: true` locally, or the
   compose equivalent), updating the two identified `.from_url()` call
   sites (`src/external/dependencies.py:1334`,
   `src/external/startup.py:249`) plus `src/config.py`/
   `src/external/celery_app.py`'s broker/backend construction to use
   Sentinel-aware connections, and a real induced-failover test (kill the
   monitored master, confirm automatic promotion, confirm zero step-up-
   ticket/Celery-task loss for anything already durably written) before
   any `docker/`/`charts/`/`src/` file is touched for real.
3. **Not a real item, flagged only:** the `redis:7-alpine` floating-tag
   reproducibility gap named in §1.1 (the same class of gap V10 flagged
   for MinIO's `latest` tag) is a real, small, separately-fixable issue
   (pin to a specific digest or `7.4.9-alpine3.21`-style explicit tag)
   independent of anything else in this document — worth a short,
   separate fix if reproducible builds become a priority, not bundled
   into either item above.
