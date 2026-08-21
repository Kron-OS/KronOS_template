# Postgres / MinIO HA Research Pass (P1-16 / V10)

**Status:** research complete, 2026-08-14. Mirrors the structure and rigor
of `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` §0's Kafka/Redpanda research —
same discipline: pinned versions, real vendor docs, a real minimum-viable
topology sized against named failure modes, an honest disruption-vs-benefit
comparison, and an explicit verdict with named trigger conditions.

**Scope discipline:** this is a research document only. No `src/`,
`docker/`, or `charts/` file was modified to produce it. No multi-node
Postgres/MinIO cluster was stood up — per the brief, a real, version-pinned,
vendor-doc-cited sizing is the correct bar for this pass, matching how the
Kafka research itself worked.

---

## §0 Method

**What was checked, in order:**

1. `docs/GAP_AUDIT_2026-08.md` P1-16 entry (full row + §3 V10 objective +
   §4 "explicitly not conflated" note distinguishing this from the
   accepted Redis AOF-fsync gap).
2. `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` §0 in full, as the explicit
   structural precedent this task mirrors.
3. Pinned versions read directly from this repo (not assumed):
   - `docker/docker-compose.dev.yml`, `docker/docker-compose.prod.yml`,
     `docker/docker-compose.test.yml`: `postgres:16-alpine` (all three,
     identical), `minio/minio:latest` (all three — the repo pins `latest`
     on purpose; `poc/minio/README.md` already resolved this to a real
     pulled build, `RELEASE.2025-09-07T16-13-09Z`, used as the pinned
     reference point below since it's the most recent real-verified pull
     in this repo).
   - `charts/kronos/Chart.yaml`: `postgresql: ">=15.0.0"` (Bitnami chart
     version, not Postgres engine version) from `charts.bitnami.com/bitnami`,
     `condition: postgresql.enabled`. **MinIO has no Helm dependency entry
     at all** — `charts/kronos/values.yaml:150-153` confirms MinIO is
     referenced purely by `endpoint: minio:9000`, assumed pre-provisioned
     externally, the same pattern already used for OpenSearch/Keycloak/Vault
     (no Deployment/Service template exists for it in this chart).
   - `charts/kronos/values.yaml:221-239`: Bitnami `postgresql` subchart
     configured with only a `primary:` block (`persistence.size: 50Gi`,
     `resources` requests/limits) — no `readReplicas:` key present, i.e.
     the chart today deploys exactly one Postgres pod, same as compose.
4. Existing PoC evidence already in this repo, read before assuming
   nothing existed: `poc/postgres/README.md` + `output.txt` (18/18,
   real concurrent-writer hash-chain + tamper-detection proof against
   `postgres:16-alpine`) and `poc/minio/README.md` + `output.txt`
   (real WORM/Object-Lock rejection proof against a real pulled MinIO
   server). Both are **single-node** proofs — neither exercised
   replication, failover, or distributed/erasure-coded mode. Nothing in
   either PoC is HA evidence; they are correctly cited below only as
   failure-mode/durability-guarantee context, not as HA verification.
5. `src/domain/audit.py`, `src/domain/evidence.py` read directly for the
   real, in-repo language describing the hash-chain and WORM guarantees
   (`AUDIT_HASH_CHAIN_TAMPERED` event type; `EvidenceState`'s WORM/legal-hold
   comment citing `Project_Specifications.md` §2).
6. `docker/docker-compose.prod.yml` read in full for both services' real
   config (volumes, secrets, healthchecks) — notably: **Keycloak in prod
   also points `KC_DB_URL` at the same single Postgres instance**
   (`jdbc:postgresql://postgres:5432/kronos`, `docker-compose.prod.yml:99`),
   meaning a Postgres outage in this deployment topology is not scoped to
   "audit trail temporarily unavailable" — it takes authentication down
   with it.
7. `src/config.py:131-133` (`max_upload_bytes = 5_368_709_120` — 5 GiB,
   comment citing `poc/clamav/run_poc_large_file.py`) and `CLAUDE.md`
   §A.5 ("scales to 100+ GB evidence files" design goal) read directly —
   both cited below as-is, not paraphrased from memory.
8. Real vendor documentation fetched live for the pinned versions (not
   "latest" in the sense of unpinned — Postgres 16 docs specifically,
   MinIO's current distributed-mode README, Bitnami's own chart
   README distinguishing `postgresql` from `postgresql-ha`). URLs cited
   inline in §1/§2. Treated as untrusted input per `CLAUDE.md` §F.2 — no
   fetched page contained anything resembling an embedded instruction;
   all fetched content was plain technical documentation.

---

## §1 Postgres

### §1.1 Real, specific failure modes

Named concretely, not generically, and mapped to which of KronOS's two
Postgres-dependent guarantees each one threatens (chain-of-custody
integrity vs. chain-of-custody *availability* — these are different
properties and a single-instance Postgres threatens both, but via
different mechanisms):

| # | Failure mode | Threatens | Severity/likelihood note |
|---|---|---|---|
| F1 | **Single-node hardware failure** (disk, PSU, host) — the container's `postgres_data` volume (`docker-compose.prod.yml:37`) lives on exactly one host's local disk in every compose/Helm deployment this repo ships. | Availability (total outage) + potential integrity loss if the volume itself is on failing media | Highest-likelihood real-world failure mode for any single-node deployment; unbounded outage duration (no automatic recovery path exists today — a human must provision a new host and restore from backup, if one exists). |
| F2 | **Single-AZ/datacenter outage** — nothing in `docker-compose.prod.yml` or `charts/kronos/values.yaml` places Postgres across failure domains; it is one pod/one container, full stop. | Availability | Same class as F1 at larger blast radius; the Helm chart's `primary:` block has no `podAntiAffinity`/`topologySpreadConstraints` for Postgres at all — even a multi-node *Kubernetes cluster* wouldn't protect against this today because the chart doesn't ask for spread. |
| F3 | **Disk corruption / bitrot** on the single data volume, not caught until a query fails or `verify_chain()` is run. | Integrity (a chain break from corruption is silent until detected — categorically different from F1/F2's *loud*, immediate outage) | `poc/postgres/README.md` result 4 confirms `AuditLogService.verify_chain()` *detects* a tampered/corrupted row after the fact via hash mismatch — but detection is not recovery. With no replica, a corrupted row has no independent copy to restore from; the chain is provably broken with no way to reconstitute the lost row's true content. This is the most legally consequential of the four failure modes: F1/F2 are "the system was down," F3 is "the custody record itself may now be permanently unable to prove what it once proved." |
| F4 | **A bad migration or `ALTER TABLE` locking the table under load** — `docs/DATABASE_MIGRATIONS.md`'s own Alembic adoption (P1-12, closed) means schema changes are now routine, not ad hoc; a lock-heavy migration (e.g. adding a `NOT NULL` column or index without `CONCURRENTLY` on a large `audit_log`/`evidence` table) blocks all writers for the migration's duration. | Availability (self-inflicted, not hardware-caused) | Real and repo-relevant precisely *because* Alembic migrations are now a normal part of the workflow (unlike F1/F2/F3 which are infrastructure-driven); a synchronous streaming replica does **not** fix this on its own (replicas apply the same DDL), it needs migration discipline (`CONCURRENTLY`, batched backfills), which is an orthogonal fix to HA. Noted here for completeness per the brief's own example, but correctly out of scope for "adopt HA" — see verdict. |

**Which failure modes does HA actually address?** F1 and F2 (availability)
are what streaming replication + failover genuinely fixes. F3 (corruption)
is partially addressed as a side effect — a healthy replica gives an
independent copy to fail over to or restore from, which a solo instance
cannot offer — but replication does not *detect* corruption any faster
than `verify_chain()` already does today; async replication can even
propagate a corrupted write to the replica before it's detected. F4 is not
an HA problem at all; it's a migration-discipline problem, correctly
excluded from this recommendation's scope.

### §1.2 Real HA mechanism, pinned to `postgres:16-alpine`

**Core mechanism — streaming replication.** PostgreSQL 16's built-in
physical streaming replication (`wal_level=replica`, `max_wal_senders`,
`synchronous_standby_names`) is unchanged in its fundamentals from earlier
majors; nothing about the 16.x pinned version requires a different
mechanism than what's documented at
[postgresql.org/docs/16/runtime-config-replication.html](https://www.postgresql.org/docs/16/runtime-config-replication.html)
and
[postgresql.org/docs/16/runtime-config-wal.html](https://www.postgresql.org/docs/16/runtime-config-wal.html).

**Sync vs. async — the real durability/latency tradeoff, per the official
16 docs (`synchronous_commit`):**

| Mode | Durability guarantee | Cost |
|---|---|---|
| `off` | OS/DB crash can lose recently-committed transactions (the current, unstated default behavior of this repo's single-node deployment — worse than plain `on` because even *local* durability isn't waited on) | None — no wait |
| `local` | Local WAL flush only; **no replication safety at all** — a synchronous standby's own data is not covered | Small |
| `remote_write` | Standby acknowledges receipt+filesystem write; **not safe against the standby's own OS-level crash** (buffered writes can still be lost) | Medium |
| `on` (Postgres default once a sync standby is named) | Transaction is not lost unless **both** primary and all synchronous standbys suffer storage corruption | Larger commit-latency cost, real network-RTT-bound |
| `remote_apply` | Standby has received **and replayed** the WAL, so it's query-visible on the standby too — strongest guarantee | Largest commit-latency cost |

For an audit trail whose entire compliance value proposition is
"tamper-evident, unbroken, hash-chained" (`CLAUDE.md` §A.2;
`src/domain/audit.py`'s `AUDIT_HASH_CHAIN_TAMPERED` event exists
specifically to name this threat), `synchronous_commit=on` with one
synchronous standby is the correct minimum — `remote_write` is explicitly
documented as not safe against exactly the kind of OS-level crash this
research is trying to protect against (F1), so it would be adopting HA
while still leaving the standby's own durability window open.

**Failover orchestration — the real minimum-node-count question.** Postgres
core has zero opinion about *automatic* failover; `pg_ctl promote` is a
human/script action. The two real, self-hostable options for a Docker
Compose/Helm deployment, both checked against their real current docs:

- **Patroni** (+ a distributed consensus store — etcd, Consul, or
  Kubernetes' own API via the `kubernetes` DCS backend) — confirmed via
  current community write-ups: the minimum cluster for *genuine automatic*
  failover (no human in the loop, split-brain-safe) is **2 Postgres nodes
  (1 primary + 1 sync standby) + 3 etcd nodes**, because etcd's Raft
  consensus itself requires an odd-numbered quorum of at least 3 to
  tolerate any node loss without losing the ability to elect a leader.
  That is **5 real processes/nodes minimum**, not 2 — a 2-node
  Postgres-only cluster with no consensus layer cannot safely
  auto-decide who's primary during a network partition (classic
  split-brain risk), which is precisely the failure mode automatic
  failover exists to avoid.
- **repmgr** — simpler, but its own documented design explicitly requires
  a human or an external trigger (`repmgrd` can automate promotion but
  is widely documented as less split-brain-safe than a real consensus
  layer, and Bitnami's own `postgresql-ha` chart pairs it with Pgpool-II
  specifically to add connection routing/failover awareness on top).
- **Bitnami chart reality check** (since `charts/kronos/Chart.yaml`
  already depends on `bitnami/postgresql`): Bitnami ships **two separate
  charts** — `postgresql` (what this repo already depends on: standalone,
  or `readReplicas.replicaCount` for basic async streaming replication,
  **no automatic failover**) and a distinct `postgresql-ha` chart (adds
  `bitnami/postgresql-repmgr` + Pgpool-II specifically to get automatic
  failover). Adopting even the *minimum* HA posture — replicas without
  auto-failover — means changing which Bitnami chart this repo depends on
  is **not** required (the existing `postgresql` chart's
  `readReplicas.replicaCount: 1` is sufficient for that scoped step); only
  the *auto-failover* step would require swapping to `postgresql-ha` (or
  hand-rolling Patroni), a materially bigger change.

**Real minimum topology, split by ambition:**

| Ambition | Nodes | What it buys | What it doesn't |
|---|---|---|---|
| Replicated, no auto-failover | 1 primary + 1 sync standby (2 Postgres nodes) | F1/F2 survivability *with a human running `pg_ctl promote`/pointing the app at the new primary* | Zero-touch recovery; an outage still has a human-latency floor |
| Full automatic failover | 1 primary + 1 sync standby + 3-node etcd (or reuse Kubernetes' own API as DCS, still needs Patroni's k8s-mode) = 5 real components | Zero-human-in-the-loop recovery | Meaningfully more operational surface — an etcd cluster is a new stateful service this platform doesn't operate today, itself a new single point of *complexity*, not failure |

### §1.3 Real cost of the minimum viable topology

Using this repo's own already-configured Helm resource footprint as the
baseline (`charts/kronos/values.yaml:233-239`: `250m`/`512Mi` request,
`1000m`/`2Gi` limit per Postgres pod) — a second (replica) pod at the same
sizing roughly **doubles Postgres's own resource footprint** (from ~0.25
vCPU/512Mi requested to ~0.5 vCPU/1Gi requested; ~50Gi persistent volume
becomes ~100Gi across two PVCs). This is a linear, well-understood cost,
unlike Kafka/Redpanda's *categorical* minimum-3-node requirement — Postgres
replication genuinely starts useful at 2 nodes, not 3, which is a real
structural difference from the Kafka precedent worth naming plainly. Adding
full automatic failover (Patroni + 3-node etcd) adds a wholly new stateful
service class this platform has never operated (etcd), a nontrivial new
operational burden independent of raw resource cost.

### §1.4 Disruption vs. current deployment

- **Compose (`docker-compose.dev.yml`/`prod.yml`):** adding a streaming
  replica is a genuinely bounded compose-file change — a second
  `postgres:16-alpine` service, a `primary_conninfo`, `pg_basebackup`
  bootstrap step, and (for sync mode) `synchronous_standby_names` on the
  primary. No application code changes are required for the
  replica-without-failover step, since the app's own connection string
  (`postgres:5432`) is unaffected — the standby is passive.
- **Helm:** the `postgresql` Bitnami chart this repo already depends on
  supports `readReplicas.replicaCount` natively — this is a values.yaml
  change, not a new dependency, for the replication-only step. Automatic
  failover would require either switching to `bitnami/postgresql-ha`
  (a real dependency swap in `Chart.yaml`, plus reconciling
  `values.yaml`'s existing `postgresql:` keys against the HA chart's
  different schema) or hand-building Patroni + etcd manifests — both
  materially bigger than anything in this initiative's Kafka question.
- **Real, repo-specific complication not present in the Kafka case:**
  Keycloak shares this same Postgres instance in prod
  (`docker-compose.prod.yml:99`). Any HA topology change to Postgres
  must account for Keycloak's own connection behavior on failover (does
  `KC_DB_URL` reconnect cleanly to a promoted standby, or does it need a
  connection-string change / a proxy layer like PgBouncer/Pgpool in
  front?). This is real added scope the Kafka research never had to
  consider, because nothing else in this stack depended on Redis/Kafka
  the way Keycloak depends on Postgres.

### §1.5 Verdict — Postgres: **scoped middle ground, adopt the replication half now, defer automatic failover**

- **Adopt now:** real Postgres 16 streaming replication,
  `synchronous_commit=on` with exactly one synchronous standby (2 nodes
  total). This directly closes F1 (single-node hardware failure) and F2
  (single-AZ outage) for the *data-loss* dimension — a sync standby by
  definition holds every committed transaction the primary has — even
  without automatic failover, because a human-executed promotion still
  recovers with zero committed data loss, just non-zero downtime. This is
  the highest-value, lowest-disruption slice: no new service class, a
  values.yaml-only change in Helm, a bounded compose-file change in
  Docker, zero application code changes.
- **Defer automatic failover (Patroni+etcd or `postgresql-ha`+repmgr)
  until a real trigger condition:** the honest reason to defer is the same
  shape of reasoning the Kafka research used — the *operational cost* of
  adding a wholly new consensus service (etcd) that this platform has
  never run, to save the last-mile "a human clicks a button" step, is not
  justified by evidence of an actual deployment requiring zero-touch
  recovery today. **Trigger conditions that would reopen this:**
  (a) a real customer/production deployment with a contractual or
  regulatory *uptime* SLA on evidence-intake availability (not just
  data-durability — this repo has no evidence of one today); (b) a real
  incident in this repo's own operational history where a human-latency
  gap during Postgres recovery caused missed evidence or a chain-of-custody
  dispute; (c) the platform moving to multi-region/multi-AZ deployment,
  where auto-failover materially changes the operational model rather than
  just adding a button-click step.
- **Do not bundle F4 (bad-migration table locks) into this HA work** —
  it is a real, separate migration-discipline issue (`CONCURRENTLY`,
  batched backfills), unaffected by replica count.

### §1.6 Known limitation, confirmed real (Gap Audit Milestone LL): a dead sync standby blocks ALL primary writes indefinitely

This section was missing from the original §1.5 verdict and its own
adoption (`docker-compose.prod.yml`'s `synchronous_standby_names` naming
exactly one replica, `synchronous_commit=on`) — the table in §1.2 states
the *durability* tradeoff of `synchronous_commit=on` correctly, but does
not spell out its *availability* consequence, which a second multi-scenario
assessment's scale/reliability review found and reproduced directly:
**with exactly one named synchronous standby and no configured timeout,
a primary whose sole sync standby is unreachable does not degrade — it
blocks every write transaction indefinitely.** Confirmed via a real PoC
(`poc/postgres_sync_replica_failure/`): a 12-second-bounded `INSERT`
against the real primary timed out (exit 124) while the sync standby was
down; a concurrent read confirmed the row was never committed; both
blocked inserts completed immediately once the standby reconnected. This
is exactly what PostgreSQL 16's own docs describe as `synchronous_commit
=on`'s behavior when no standby can acknowledge — it is not a bug in this
repo's configuration, it is the documented, correct behavior of the
adopted mode, simply not previously written down here or in
`docs/deployment.md`/`charts/kronos/values.yaml`.

**Why this matters operationally, beyond the abstract tradeoff already in
§1.2's table:** F1/F2 (single-node hardware failure / single-AZ outage)
were adopted against on the premise that a human-executed promotion
"recovers with zero committed data loss, just non-zero downtime" (§1.5).
That framing is accurate for the *standby* dying. It is incomplete for the
*network path to the standby* degrading (not dying outright) — e.g. a
transient partition, a slow/overloaded standby, or a misconfigured
security group — during which the primary is fully up but **every write
anywhere in the system blocks**, including evidence intake, chain-of-
custody audit rows, and detection triage, with no operator-visible signal
beyond "requests are hanging," not "the database is down." A monitoring
setup that only alerts on primary-down would miss this failure mode
entirely.

**This is a real, project-owner-level decision this initiative cannot
make unilaterally (established precedent: V9's log-type prioritization,
the prod OpenSearch demo-cert decision) — options, not a recommendation:**

1. Accept the current behavior as-is (this deployment's compliance value
   proposition is explicitly built on zero data loss over uninterrupted
   availability — CLAUDE.md §A.2 — so "block until safe" may be the
   *correct* choice, not an oversight to fix).
2. Add a statement timeout / `synchronous_commit` fallback policy (e.g.
   monitor `pg_stat_replication` and have an operator or automation
   demote to `synchronous_commit=local` temporarily during a confirmed
   standby outage) — trades the durability guarantee for availability
   during an incident, which needs an explicit, written runbook and
   alerting, not a silent default.
3. At minimum, add alerting on `pg_stat_replication` showing the sync
   standby unreachable/lagging, so an operator knows *why* writes are
   hanging within seconds rather than discovering it via a support
   ticket about a hung upload.

No code or config change is made here — this section exists so the
tradeoff is written down and the decision is made deliberately, not
discovered live during an incident.

---

## §2 MinIO

### §2.1 Real, specific failure modes

| # | Failure mode | Threatens | Severity/likelihood note |
|---|---|---|---|
| M1 | **Single-node hardware failure** — `docker-compose.prod.yml:65` mounts one `minio_data` volume on one host; `charts/kronos/values.yaml` doesn't deploy MinIO at all (external endpoint only), so *whatever* actually runs it in a real k8s deployment is entirely undocumented by this repo today. | Availability + potential data loss if the volume's media fails outright | This is the platform's **evidence** store — `CLAUDE.md`'s own design goal is "scales to 100+ GB evidence files" (§A.5) and `src/config.py:133`'s real `max_upload_bytes = 5_368_709_120` (5 GiB) ceiling on any *single* upload. A single-node MinIO failure mid-upload of a multi-GB forensic image is not just an availability blip — `poc/minio/README.md` confirms `promote_to_evidence_bucket` uses a real `copy_object` step *after* the presigned-PUT completes; a disk failure between those two steps could leave an object in quarantine with no evidence bucket copy and no independent replica to recover from. |
| M2 | **Disk running out of space mid-write during a large forensic-image upload** — named explicitly in the task brief as a real scenario worth checking, not hypothetical: a multi-GB EWF/E01 upload approaching the 5 GiB ceiling on a single-disk backend has no failover target if that disk fills. | Availability (upload fails) — not integrity, since MinIO/S3 semantics mean a failed multipart upload simply never completes (no partial/corrupt object is exposed as "committed") | Real but self-inflicted-by-undersizing risk, not really an *HA* gap — erasure coding does not solve "the disk is full," capacity planning does. Distributed mode's real value here is different: it adds usable capacity headroom by pooling across nodes' drives, but that's a capacity-planning benefit, not a redundancy one. Named here per the brief but correctly weighted lower than M1/M3 below in the verdict. |
| M3 | **Silent bit rot / disk corruption on evidence data**, undetected until read-back or a legal-discovery request. | Integrity — for WORM-locked evidence this is the direct MinIO analogue of Postgres's F3: a court-admissibility-critical byte sequence with no independent copy to verify or restore from if the single copy silently degrades. | MinIO's own erasure coding includes real per-shard bitrot protection (BitrotVerify with HighwayHash/SHA256 checksums per erasure-set) that a **single-node, single-drive** deployment does not get at all — single-node MinIO has no erasure set, so this protection is currently fully absent, not just "not redundant." This is arguably the single strongest MinIO-specific argument for this research pass, stronger than the availability argument alone. |
| M4 | **Single-AZ/datacenter outage** | Availability | Same class as Postgres's F2; nothing in this repo's deployment topology spreads MinIO across failure domains, and (per §0.3) the Helm chart doesn't even deploy MinIO, so there is currently no k8s-native answer to this question at all in this repo. |

### §2.2 Real HA mechanism, pinned to the resolved `minio/minio` build

**Distributed/erasure-coded mode**, per the current official MinIO
distributed-mode README
([github.com/minio/minio/blob/master/docs/distributed/README.md](https://github.com/minio/minio/blob/master/docs/distributed/README.md)):

- Invocation is `minio server http://host{1...n}/export{1...m}` — the
  literal three-dot ellipsis syntax the docs explicitly warn must not be
  confused with shell brace-expansion's two-dot form (`{1..n}`), which
  the shell would expand itself and silently break MinIO's own erasure-set
  ordering. This is a real, concrete gotcha that would need to be gotten
  right in whatever compose/Helm change implements this.
- **Erasure-coding sets span 2–16 drives**; the total drive count must be
  a multiple of one of those valid set sizes. Two drives is the
  documented technical floor for erasure coding to engage at all, but
  the docs' own real-world guidance and the current community operational
  consensus (echoed by MinIO's own object-storage architecture docs) is
  that genuine multi-node fault tolerance — surviving a **node**, not just
  a **drive**, failure — needs **at least 4 nodes**, each contributing
  drives to the same erasure set, so a whole-node loss still leaves the
  erasure set with a majority of its shards.
- **Quorum**: with `m` servers and `n` drives per server, MinIO documents
  data safety as long as `m/2` servers or `m*n/2` drives remain online —
  i.e. up to just under half the fleet can be lost without an outage.
- **Kubernetes reality specific to this repo**: `charts/kronos/` has *no*
  MinIO Deployment/StatefulSet/Tenant resource today (§0.3) — it only
  references an external `minio.endpoint`. The real, current
  Kubernetes-native way to run distributed MinIO is the **MinIO Operator**
  (a separate Helm chart, `minio-operator/operator`, managing a `Tenant`
  CRD) — adopting distributed MinIO in this repo's Helm deployment path
  is not a values.yaml tweak, it is **onboarding an entirely new
  component this chart has never included**, a materially bigger change
  than Postgres's `readReplicas.replicaCount` case.

**Object Lock / WORM compatibility with distributed mode** — this was a
named open question in the task brief ("confirm real compatibility, don't
assume"). Real finding: **official MinIO documentation does not present
Object Lock as deployment-mode-restricted anywhere it was checked**
(`docs.min.io/aistor/administration/object-locking-and-immutability/`) —
retention modes, legal holds, and versioning interplay are documented as
general bucket-level features, with no stated single-node-only or
distributed-only restriction found in the fetched documentation. This is
consistent with Object Lock being implemented at the object/version
metadata layer (as `poc/minio/README.md` result 7 already confirmed for
single-node: Object Lock auto-enables bucket versioning, and retained
versions reject `DeleteObject`) rather than at the storage-topology layer
— there is no documented reason erasure coding would change that
enforcement. **Caveat, stated honestly rather than overclaimed:** this is
an absence-of-contrary-evidence finding from the docs actually fetched in
this pass, not a real multi-node run confirming it — per the brief's own
"a real, cited, version-accurate sizing from official docs is the right
bar" allowance (a full distributed-mode Object-Lock proof would need a
real 4-node cluster, out of scope for this research pass), this is flagged
as the one open item a future adoption PoC (§4) must verify with an actual
run, not assume from this document alone.

### §2.3 Real minimum viable topology

| Ambition | Nodes/drives | What it buys | What it doesn't |
|---|---|---|---|
| Drive-level bitrot protection only, single node | 1 node, ≥2 local drives (`minio server /data1 /data2 /data3 /data4` on one host) | M3 (bitrot detection/self-heal within that host) | M1/M4 (the whole host is still a single point of failure) |
| Genuine node-fault-tolerant distributed mode | **4 nodes minimum** (matches the docs' real-world guidance above), each with local drives forming one erasure set | M1, M3, M4 — survives a full node loss, not just a drive loss | Nothing structurally — this is the real minimum for the property being sought |

Unlike Postgres (useful at 2 nodes), MinIO's genuine node-fault-tolerant
floor is **4**, the same order of magnitude as Kafka/Redpanda's real
3-node minimum that the Kafka research already weighed and found not
worth it for that component. This is a real, structural point of
similarity to the Kafka case that the brief asked to check honestly rather
than assume away.

### §2.4 Real cost of the minimum viable topology

No resource-request baseline exists for MinIO in `charts/kronos/values.yaml`
today (it isn't deployed by the chart at all), so there is no existing
in-repo number to double the way Postgres's §1.3 could. Order-of-magnitude
estimate from the fetched MinIO docs' own reference topology (4 nodes ×
4 drives, EC:4 parity): **~4x the compute/host footprint** of today's
single MinIO container, plus **~33% storage overhead** (parity blocks,
per the EC:4 usable-capacity math in the fetched docs) on top of that 4x
raw-capacity multiplication — i.e., meaningfully more than double the
*effective* storage cost for the same usable evidence-retention capacity,
before even counting the new MinIO Operator component itself.

### §2.5 Disruption vs. current deployment

- **Compose:** bounded but nontrivial — four `minio` service blocks
  instead of one, each needing the ellipsis-syntax multi-host argument
  wired correctly (a real, named footgun per §2.2), CORS/presigned-URL
  endpoint reasoning (`docker-compose.prod.yml`'s existing
  `MINIO_API_CORS_ALLOW_ORIGIN` comment already flags that MinIO isn't
  published externally yet) revisited for a 4-node backend, and a load
  balancer/ingress point in front of the 4 nodes for the application to
  target (today the app talks to one `minio:9000` hostname directly).
- **Helm:** materially the biggest single piece of new scope in this
  entire research pass — `charts/kronos/` would need to **add** the MinIO
  Operator as a genuinely new dependency (not swap an existing one, as
  Postgres's `postgresql-ha` option would be) plus author a `Tenant` CRD
  manifest, then rewire `minio.endpoint` to point at the Operator-managed
  service. Nothing in this chart today provides a template to extend.
- **Net comparison to Postgres:** MinIO's HA adoption is strictly more
  disruptive than Postgres's on every axis checked here — node-count floor
  (4 vs 2), Helm-chart ownership (new component vs. values.yaml change),
  and storage-cost multiplier (4x+ raw vs 2x).

### §2.6 Verdict — MinIO: **defer, but with the most narrowly-scoped, highest-priority trigger condition of anything in this document**

- **Do not adopt full 4-node distributed/erasure-coded MinIO now.** The
  disruption is real and large (§2.5) — a wholly new Helm-chart component,
  a real multi-host compose topology change, and a >2x effective storage
  cost — and nothing in this repo's current deployment evidence (a
  single-tenant dev/PoC-stage platform, per every other document in this
  initiative) demonstrates that cost is justified *today*.
- **However — name the honest asymmetry with Postgres plainly, since the
  brief asked to confirm or challenge the gap audit's framing rather than
  accept it uncritically:** M3 (silent bit rot on WORM-locked evidence,
  with **zero** current detection or recovery capability, since single-node
  MinIO has no erasure set at all) is arguably a *more* severe integrity
  gap than anything on the Postgres side, because Postgres at least has
  `verify_chain()` actively detecting tamper/corruption today
  (`poc/postgres/README.md` result 4, a real-verified capability) — MinIO
  has no equivalent detection mechanism running against single-node
  storage at all. The gap audit's framing (P1-16: "the components the
  platform's actual custody guarantee depends on") is confirmed accurate
  for *why this matters*, but the researched *cost* side of the equation
  is genuinely higher for MinIO than for Postgres, which is why this
  verdict is not a mirror of Postgres's "adopt the cheap half now" —
  there isn't a comparably cheap half on MinIO's side to adopt now
  (2-node MinIO both fails to meet the real node-fault-tolerance floor of
  4 *and* still requires the same new Helm-Operator component as 4-node
  would).
- **Trigger conditions that would reopen this:** (a) any real production
  or customer deployment where evidence retention is expected to
  outlive a single disk's realistic MTBF window without a documented
  backup/restore runbook (this repo does not currently have one — that
  absence is itself worth flagging as a nearer-term, cheaper fix, see §4);
  (b) a real, observed bitrot/corruption event on any evidence object in
  this repo's own dev/prod usage (would immediately validate M3 as a live,
  not theoretical, risk); (c) the platform moving to a real multi-tenant
  production posture with contractual evidence-retention/availability
  commitments, mirroring Postgres's own trigger (c) above but for storage
  specifically.
- **Cheaper interim mitigation worth naming even though it's not full
  HA** (not a "do this instead" replacement for the trigger conditions
  above, just the honest cheapest real step available today): MinIO
  supports **bucket replication** (a different, lighter mechanism than
  distributed/erasure-coded mode — async object-level replication to a
  second, independent single-node MinIO instance) which would address
  M1/M4 (a second independent copy exists) without the 4-node
  node-fault-tolerance requirement or the new Operator dependency. This
  was not deep-dived in this pass (out of the scope the brief defined —
  the brief asked specifically about distributed/erasure-coded mode) but
  is flagged in §4 as a legitimately smaller, separately-evaluable next
  question if disaster-recovery (not node-fault-tolerance) is the actual
  near-term priority.

---

## §3 Cross-cutting comparison against the Kafka precedent

**Does the same "not warranted" logic that closed the Kafka question apply
here?** Checked honestly, component by component, not accepted or
rejected wholesale:

- **The gap audit's core claim — real, confirmed.** Real research effort
  went into a 3-node-minimum Kafka/Redpanda cluster for the
  *stream-ingest* layer, correctly concluded not worth it, while
  Postgres/MinIO — the layers the *actual* durable custody guarantee
  depends on once a batch is sealed (`src/application/batch_sealing.py`;
  Kafka roadmap §0's own table: "Sealed batches ... durable via WORM MinIO
  + mandatory RFC3161 TSA + Postgres + Merkle root — independent of Redis
  once sealed") — were left completely unaddressed. This research pass
  confirms that prioritization inconsistency was real, not confirms it
  away.
- **Where the situations diverge, honestly:**
  - **Postgres's minimum useful HA step is *cheaper* than Kafka's ever
    was** — 2 nodes vs. Kafka's hard 3-node floor, and (per §1.4) fits
    inside the existing Bitnami chart dependency with a values.yaml
    change, not a new dependency. This makes Postgres's "adopt now"
    slice of the verdict *more* justified than anything in the Kafka
    research, not just equally justified — the disruption-vs-benefit
    balance genuinely tips further toward adoption here than it ever did
    for Kafka.
  - **MinIO's real minimum node-fault-tolerant floor (4 nodes) is exactly
    the same order of magnitude as Kafka's rejected 3-node floor**, and
    its Helm-chart disruption is *larger* than Kafka's would have been
    (Kafka would also have been a new chart dependency, but MinIO's
    change additionally reworks the application's storage endpoint
    topology, presigned-URL flow, and CORS story — more surface area
    than a new message broker sitting behind an existing ABC the way
    `StreamIngestAdapter` was already designed to swap Redis for Kafka
    "with zero changes to any caller"). The same "not warranted yet"
    logic that closed Kafka genuinely does apply to MinIO's full
    4-node distributed mode today — this is not a rubber-stamp of the
    gap audit's framing, it's an independent re-derivation landing in
    the same place for a different, storage-specific reason (§2.6).
  - **The one place this research pass departs from a clean "gap audit was
    right, Kafka logic transfers 1:1" story**: MinIO's *bitrot-detection*
    gap (M3) has no Kafka-side analogue at all — Kafka's rejected gap was
    about ingest-layer replay/redelivery granularity, a bounded,
    already-mitigated risk (Redis AOF fsync window, `docs/GAP_AUDIT_2026-08.md`
    §4's own explicit non-conflation note). MinIO's M3 is a *currently
    fully unmitigated* integrity gap on the platform's actual
    court-facing evidence bytes, with no equivalent to `verify_chain()`
    running against it today. That's real new information this pass
    surfaces beyond what the gap audit's one-line framing captured, which
    is why §2.6 flags MinIO bucket replication (lighter than full
    erasure-coded HA) as a legitimately separate, cheaper follow-up
    question rather than folding the whole MinIO question into a flat
    "defer, same as Kafka."
- **Overall:** the custody-critical nature of these two components does
  change the calculus relative to Kafka, but **asymmetrically between the
  two** — it justifies adopting Postgres's cheap replication step now
  (Kafka never had an equally cheap step to adopt), while for MinIO it
  sharpens *which* gap is most urgent (M3, not the full node-fault-
  tolerance question) without changing the "full distributed mode: not
  yet" verdict itself.

---

## §4 Next-item objectives (for verdicts landing on "adopt" or "adopt with scoping")

Per the Gap Audit's own §3 convention — objectives only, not full agent
briefs, for the orchestrator to turn into a dispatch later:

1. **Postgres streaming replication (adopt now).** Add one synchronous
   streaming standby to both `docker-compose.dev.yml` and
   `docker-compose.prod.yml` (`synchronous_commit=on`,
   `synchronous_standby_names` naming exactly one standby), and set
   `readReplicas.replicaCount: 1` on the existing `bitnami/postgresql`
   Helm dependency in `charts/kronos/values.yaml`. Verification-first
   (CLAUDE.md §F) applies: a real `poc/postgres_replication/` PoC must
   demonstrate a real primary-to-standby failover with `pg_stat_replication`
   showing `sync_state=sync` beforehand, and a real `pg_ctl promote` with
   zero committed-transaction loss confirmed via `verify_chain()` against
   both instances post-promotion, before any `docker/`/`charts/` file is
   touched. Explicitly out of scope for this item: Patroni/etcd automatic
   failover (deferred per §1.5's named trigger conditions) and any
   migration-locking (F4) fix.
2. **MinIO bucket replication (separately evaluable, smaller, if
   disaster-recovery is prioritized ahead of full node-fault-tolerance).**
   A real PoC (`poc/minio_replication/`) standing up two real single-node
   MinIO containers and configuring MinIO's native bucket replication
   between them, verifying a real WORM-locked object replicates correctly
   (retention metadata included, not just bytes) and that replication
   lag/consistency behavior is understood — before any decision to wire
   this into `docker-compose.prod.yml`. This is explicitly *not* the same
   as §2's rejected 4-node distributed/erasure-coded mode; do not conflate
   the two in a future dispatch brief.
3. **Not yet an item, flagged only:** a documented Postgres/MinIO
   backup-and-restore runbook (independent of live replication) was
   identified in §2.6 as a real, currently-absent, and likely *cheaper*
   mitigation for both components' worst-case data-loss scenarios than
   either HA topology above — worth a short, separate audit of whether
   one already exists informally before scoping a dedicated item.
