# PoC: OpenSearch Security Analytics native threat-intel feature — version check

**Roadmap item:** M5/F2 ("IOC ingestion and matching, using SA's own
threat-intel feature where it fits").

## Versions pinned in this repo (CLAUDE.md SS F.2 step 1)

| Compose file | OpenSearch image tag |
|---|---|
| `docker/docker-compose.dev.yml` (the live dev cluster, `docker-opensearch-1`) | `opensearchproject/opensearch:2.11.1` |
| `docker/docker-compose.test.yml`, `docker-compose.prod.yml` | `opensearchproject/opensearch:2.13.0` |

## What was checked, and how

1. Ran `run_poc.sh` against the REAL, already-running dev container
   (`docker-opensearch-1`, reachable at `https://localhost:9200`, same
   admin credentials `SecurityAnalyticsDetectorProvisioner`
   (`src/adapter/opensearch/detector_provisioner.py`) already uses).
2. Confirmed the real cluster is genuinely 2.11.1 (not an assumption) and
   that `opensearch-security-analytics 2.11.1.0` IS installed.
3. Probed the threat-intel REST namespace directly:
   `GET /_plugins/_security_analytics/threat_intel/sources` (and an
   alternate spelling) — both returned **HTTP 400, "no handler found for
   uri"**. This is OpenSearch's own message for "no REST action is
   registered at this path at all" — categorically different from a 404
   ("resource not found but the route exists") or an empty result. The
   route simply isn't compiled into this plugin build.
4. Control check, same cluster: `POST
   /_plugins/_security_analytics/detectors/_search` (a real, known-working
   SA endpoint this codebase already depends on) returned a normal **HTTP
   200** with a real (empty) hits array — proving the SA plugin itself is
   alive and the 400s above are specific to the threat-intel path, not a
   general SA outage.

See `output.txt` for the full, real captured request/response pairs.

## Why this isn't a maturity/fit judgment call — it's a version-gap fact

Checked against the real upstream project
(`opensearch-project/security-analytics` on GitHub — official repo, per
CLAUDE.md SS F.2 step 2):

- Threat-intel work was originally targeted at the **2.11** release
  itself. PR **#717** ("Revert Threat Intel Changes for 2.11") was merged
  into the `2.11` base branch on **2023-11-08** — i.e. the feature was
  pulled back out of 2.11 before that line even shipped (2.11.1's own
  build date is 2023-11-29, three weeks later).
- Real feature work (source-config CRUD, monitor implementation, REST
  APIs) resumes visibly in the PR history starting **May–June 2024** (e.g.
  #1051 "Threat Intel Feature Branch", #1057/#1058/#1066 index/search/
  delete REST APIs for the monitor, all June 2024).
- Every backport PR found for later threat-intel fixes (e.g. #1406 "Add
  validation for threat intel source config") backports only as far back
  as **2.15** — no `[Backport 2.11]` or `[Backport 2.13]` variant exists
  for any threat-intel PR searched.

Net: the feature does not exist in **either** OpenSearch version this repo
pins (2.11.1 or 2.13.0) — it was reverted before 2.11 shipped and the real
implementation only landed roughly a year later, starting around 2.15/2.16.
A future OpenSearch upgrade (2.15+) would be the natural point to revisit
using SA's native feature instead of (or alongside) the KronOS-native path
below.

## Untrusted-content handling note (CLAUDE.md SS F.2 step 2)

GitHub API/raw content and the OASIS spec page were fetched and read only
for their technical content (plugin version numbers, PR metadata, STIX
pattern syntax). Nothing in any fetched page attempted to direct further
action, so there was nothing to flag.

## Design decision this PoC drives

See `src/domain/ioc_feed.py`'s own module docstring and
`docs/NEXTGEN_SOC_ROADMAP.md`'s F2 STATUS note: since the native feature
is unavailable on every pinned version, F2 is implemented as a
KronOS-native IOC enrichment path reusing the F1 `Enricher`/
`EnrichmentPipeline` mechanism exactly as designed for this kind of
extension — see `poc/threat_intel_stix_ingest/` for that path's own real,
captured PoC run.

## How to re-run

```bash
./run_poc.sh > output.txt 2>&1
```

Requires the dev stack's `opensearch` container already running
(`docker compose -f docker/docker-compose.dev.yml up -d opensearch`) and
reachable at `https://localhost:9200` with `admin:admin` credentials (dev
defaults per `docker/docker-compose.dev.yml`).
