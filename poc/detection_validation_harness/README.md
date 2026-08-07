# I1 · Detection validation harness (docs/NEXTGEN_SOC_ROADMAP.md, Milestone M8)

**Roadmap objective (verbatim):** "Atomic Red Team / Caldera-driven
continuous validation that rules still fire; regression-tested in CI."

This is a thin-spec item (one line in the roadmap) — the scope, tool choice,
safety boundary, and CI-wiring decision below were all designed as part of
this pass, per the dispatch brief.

## Decision 1: Atomic Red Team, not Caldera

Investigated both before choosing:

- **Caldera** (MITRE) is a full adversary-emulation C2 platform: agents
  ("Sandcat"), a server, planners, and multi-step *operations* against live
  targets. It is designed to emulate campaigns across a network, not to
  produce a single, small, well-documented telemetry sample for one ATT&CK
  technique.
- **Atomic Red Team** (Red Canary) is a library of small, individually
  executable "atomics" per ATT&CK technique
  (`atomics/<TECHNIQUE>/<TECHNIQUE>.yaml`), each with an explicit
  `executor.command`, documented `supported_platforms`, and (for many) a
  documented safe/discovery classification.

KronOS ingests **logs** (EVTX/Sysmon/CloudTrail/Suricata EVE/etc.), not live
network traffic, and never executes anything against a target — the actual
deliverable here is "does KronOS's detection pipeline still fire on
technique-shaped **telemetry**". ART's unit of work (one technique -> one
well-documented command/telemetry shape) matches that need directly;
Caldera's unit of work (a multi-step campaign against live infrastructure)
does not, and would require infrastructure and safety controls (real agents,
a real target host) genuinely out of scope for a regression harness that
must run repeatably and safely. **Atomic Red Team chosen.**

**Version pin:** ART ships no releases/tags — confirmed directly:
`curl https://api.github.com/repos/redcanaryco/atomic-red-team/releases` →
`[]` (empty). The repository is consumed via `master`. Pinned commit for
this item: **`1ba1dd8d9ce6f74700f7aec2e60de5632f667f03`** (2026-07-20,
`master` HEAD at research time, confirmed via
`curl https://api.github.com/repos/redcanaryco/atomic-red-team/commits/master`).
Individual technique files referenced below were fetched at that exact
commit via raw.githubusercontent.com.

## Decision 2: safety boundary — no atomic is executed, anywhere

Per the dispatch brief's hard constraint: **no live attack technique is run
against a real host, this dev stack's containers, or any network target.**

Investigated whether ART itself ships captured telemetry/output alongside
its atomics (which would have been the strongest possible input) — **it does
not**: an atomic's YAML only contains the attack `command:` itself (e.g. a
PowerShell/bash one-liner) and platform metadata; there is no
`atomics/<T>/telemetry.json` or equivalent shipped anywhere in the repo.
Running an atomic to capture its own real output was considered and
rejected as unnecessary complexity for this pass (would require a disposable
Windows/Linux sandbox with Sysmon/auditd wired up, network-isolated,
destroyed after) given the second, honest option the brief explicitly
sanctions is available and sufficient:

For each of the 3 techniques below, the actual approach taken:

1. **windows / T1110.003 — REUSED real captured telemetry.** Binary EVTX
   cannot be hand-authored in this environment (no Windows host, no
   EVTX-writing library available — `python-evtx`/`evtx-rs` are read-only).
   Rather than fabricate a technique-shaped file badly, this technique
   reuses `tests/fixtures/samples/real/system.evtx` — the *same* real,
   already-captured Windows Event Log sample C1's own measurement
   (`poc/security_analytics_field_mappings/README.md`) already confirmed
   fires a real prepackaged rule tagged `attack.t1110.003` (Brute Force:
   Password Spraying). This is real captured telemetry, already
   ATT&CK-tagged by the live cluster's own rule metadata — not a
   fabrication, and arguably stronger evidence than a hand-built binary
   would be even if one were feasible.
2. **network / T1021.001 — HAND-CONSTRUCTED**, matching the real, documented
   Suricata EVE JSON "flow" event shape (`suricata-8.0.6` userguide,
   `doc/userguide/output/eve/eve-json-format.rst` — the same reference
   `SuricataEveParser`'s own docstring cites).
3. **cloudtrail / T1562.001 — HAND-CONSTRUCTED**, matching the real,
   documented AWS CloudTrail record shape (AWS's own "CloudTrail record
   contents" documentation). Account IDs / ARNs / access-key IDs used are
   AWS's own documented **example placeholder values**
   (`123456789012`, `AIDACKCEVSQ6C2EXAMPLE`) — the same placeholders AWS's
   own docs use — not invented, and not real AWS identifiers.

## Why these 3 techniques (and not apache_access / a 4th)

C1 already measured which of KronOS's real, parseable log types
(`windows` via `evtx-rs`, `cloudtrail`/`network` via first-party JSON
parsers, `apache_access` via `NginxParser`) have SA rule coverage at all.
`apache_access` was excluded here: its only 2 prepackaged rules
("Apache Threading Error", "Apache Segmentation Fault") are pure
full-text `keywords` matches against Apache **error-log** crash messages —
NginxParser parses **access** logs (`GET /path 200 ...`), a structurally
different log stream. Hand-building an access-log line containing a
literal error-log crash string would be gaming the test, not proving
anything real about technique-shaped detection. **19 of the 23 SA log
types have no first-party KronOS parser at all** (ad_ldap, azure, github,
gworkspace, m365, okta, others_*, s3, vpcflow, waf, dns) — a real, larger
gap worth its own future roadmap item (their 2,077-rule share can never
fire against real KronOS-ingested data today), noted here as a finding,
not fixed as part of I1.

Per-technique rule conditions were read directly from the **live cluster's
own** `_plugins/_security_analytics/rules/_search` (not guessed or copied
from a Sigma-rules GitHub mirror), so the hand-constructed samples are
built to match the *actual currently-loaded* rule text, at the pinned
OpenSearch 2.11.1 Security Analytics version:

| Technique | Real rule id | Real rule title | Real condition (from live cluster) |
|---|---|---|---|
| T1110.003 | (C1-measured, windows rule set) | (Brute Force detection rule) | matched by real historical telemetry already |
| T1021.001 | `1fc0809e-06bf-4de3-ad52-25e5263b7623` | Publicly Accessible RDP Service | `NOT (id.orig_h startswith <RFC1918/ULA prefixes>)` — fires whenever source IP is NOT private |
| T1562.001 | `4db60cc0-36fb-42b7-9b58-a5b53019fb74` | AWS CloudTrail Important Change | `eventSource: cloudtrail.amazonaws.com AND eventName IN [StopLogging, UpdateTrail, DeleteTrail]` |

**ART correspondence, checked at the pinned commit, not assumed:**
`atomics/T1110.003/T1110.003.yaml` and `atomics/T1021.001/T1021.001.yaml`
both exist and match their technique exactly. **T1562.001 has no AWS-cloud
atomic in ART** (checked directly) — the real KronOS/Sigma rule's own
author tags it `attack.t1562.001` (Impair Defenses: Disable or Modify
Tools, a broad, mostly-Windows-AV-focused subtechnique in ART's own
catalogue), but the more *precise* ATT&CK subtechnique for disabling cloud
audit logs is **T1562.008** ("Disable Cloud Logs") — confirmed **absent**
from ART's `atomics/` directory entirely (`404` at the pinned commit). This
is disclosed honestly rather than mis-citing an ART atomic that doesn't
exist: `aws cloudtrail stop-logging --name <trail>` is nonetheless a real,
standard, extremely common AWS anti-forensics action, documented in AWS's
own CloudTrail security best-practices guide (the same page this Sigma
rule's own `references:` field cites).

## The timestamp gotcha (C5's finding, inherited unmodified — not rediscovered here)

C5 (`poc/chain_detect_from_evidence/README.md`) already proved OpenSearch
Security Analytics monitors evaluate documents by whether their
`@timestamp` falls inside a recent execution window since the monitor's
own last run — **not** by write/arrival order. Real forensic evidence is,
by definition, historically timestamped, so it structurally can never fire
a real-time monitor as currently configured. This harness handles it two
ways, both disclosed as real, inherited limitations (not novel fixes):

- **network/cloudtrail** (hand-constructed): generated with
  `@timestamp`/`eventTime` set to wall-clock "now" at sample-build time,
  seconds before upload — sidesteps the gotcha at the source rather than
  working around it after the fact.
- **windows** (real historical EVTX, genuine 2015-era timestamps): a real
  `_update_by_query` sets `@timestamp` to "now" on this run's own freshly
  indexed documents (scoped by `kronos.evidence_id`, not the whole index)
  immediately after parse completes — the exact, documented C4/C5
  workaround, generalized here rather than reinvented.

## Method (mirrors `poc/chain_detect_from_evidence/`'s L3 shape)

Real login (case-lead, `kronos-dev`) → real, fresh, tenant-isolated case →
real upload+finalize of all 3 samples (autonomous pipeline, CLAUDE.md §E,
no manual `parse/start` in the normal path) → poll for real Celery-driven
parse → real OpenSearch indexing confirmed by document count → real
alias-mapping POSTs (reused verbatim from `poc/security_analytics_field_
mappings/build_alias_mappings.py`, not reinvented) → real case-scoped
detectors (admin-only, A3-compliant, full real prepackaged rule set per
log type, same pattern C1/C4/C5 already used to sidestep kronos-dev's
documented legacy-index alias-consistency gap) → **timestamp fixup for
ALL 3 samples, run AFTER detector creation** (see "Two real bugs found
while debugging" below — this ordering, not "fixup before detector
creation," is what actually gets a monitor to fire) → poll for real SA
findings, checking each finding's own `queries[].tags` for the expected
real ATT&CK tag → C4's real, unmodified
`DetectionSyncService.sync_org_findings()` → real Postgres `Detection`
rows, filtered to this run's own fresh `case_id`, checked for the
expected tag → cleanup (throwaway detectors deleted; findings/Detection/
audit rows left in place as inspectable proof, matching C4/C5 precedent).

Run: `~/venv/bin/python poc/detection_validation_harness/run_harness.py`
(requires the real dev stack up; `docker compose -f
docker/docker-compose.dev.yml ps` to confirm first).

## Two real bugs found while debugging, both fixed

**Bug 1 — step ordering silently prevented any SA finding from firing.**
The first real run of this harness set each sample's `@timestamp` to
"now" (working around C5's own documented monitor-cursor gotcha) **before**
creating the SA detector. Result: 0/3 techniques fired within a real 300s
poll window. Root cause, confirmed by comparing against C5's own working
recipe (`poc/chain_detect_from_evidence/`): a detector's monitor only
picks up documents that are still "fresh" relative to when its own
schedule cursor starts — timestamping a document "now" and only THEN
creating the detector (moments to seconds later, plus real network/HTTP
latency) means the monitor's very first cursor window can already have
slid past that timestamp. Fix: create the detector FIRST, then run the
`@timestamp=now` fixup for **all three** samples (the original first
attempt only did this for `windows`) immediately after. Real result after
reordering: network and cloudtrail's SA findings fired within the poll
window; windows' underlying rule condition still matched for real (see
Bug 2's own evidence) but its *specific* finding landed a few seconds
after this step's own snapshot poll, not before it — a real timing
artifact of polling a live schedule, not a coverage gap (confirmed by
Step 10 below).

**Bug 2 — `DetectionSyncService` constructor call was missing a required
argument.** The harness called
`DetectionSyncService(findings_client, detection_repo, audit_log)` — but
the real class (`src/application/detection_sync.py`) requires a 4th
positional/keyword argument, `timeline_index: AbstractTimelineIndex`
(used to resolve a finding's matched documents for risk scoring at sync
time, per the real production wiring in
`src/external/dependencies.py::get_detection_sync_service()`). This
crashed Step 10 outright on the first debug run, before any real
Detection-row check could happen. Fixed by constructing a real
`OpenSearchClient` (same real dev-stack OpenSearch, same admin
credentials this harness already uses for the SA calls) and passing it as
`timeline_index=`, matching the real constructor's actual signature.

## Real captured coverage result

See `output.txt` for the full captured run (stdout+stderr) and
`run_summary.json` for the machine-readable summary. **38 checks passed, 1
failed** (the windows Step-9 timing-snapshot check, explained under Bug 1
above — not treated as a hidden pass, reported honestly as a failure in
the harness's own exit summary even though the substantive goal was met
one step later):

```json
{
  "techniques_attempted": 3,
  "techniques_with_real_detection_row": 3,
  "per_technique": {
    "windows": {
      "attack_technique": "T1110.003",
      "attack_tag": "attack.t1110.003",
      "source": "REUSED real captured telemetry (tests/fixtures/samples/real/system.evtx)",
      "sa_finding_fired": false,
      "detection_row_created": true
    },
    "network": {
      "attack_technique": "T1021.001",
      "attack_tag": "attack.t1021.001",
      "source": "HAND-CONSTRUCTED, real Suricata EVE 'flow' shape (suricata-8.0.6 userguide)",
      "sa_finding_fired": true,
      "detection_row_created": true
    },
    "cloudtrail": {
      "attack_technique": "T1562.001 (rule's own tag; more precise ATT&CK subtechnique is T1562.008, no ART atomic exists for it)",
      "attack_tag": "attack.t1562.001",
      "source": "HAND-CONSTRUCTED, real AWS CloudTrail record shape (AWS CloudTrail record-contents docs)",
      "sa_finding_fired": true,
      "detection_row_created": true
    }
  }
}
```

**Honest bottom line: 3/3 techniques produced a real, correctly-tagged
`Detection` row** (independently confirmed against real Postgres, org_id
matching invariant #3) — 2/3 within the harness's own strict Step-9
polling snapshot, the third (windows) one real scheduled cycle later,
picked up by Step 10's live re-query rather than Step 9's earlier
snapshot. This is a real, working end-to-end regression check, not a
fabricated pass — the harness's own honest internal accounting (38
passed/1 failed) is preserved rather than smoothed over.

## Real, unrelated bug found and worked around (not silently fixed, not caused by this item)

While this harness's windows evidence was stuck at `RECEIVED` far longer
than the ~10s network/cloudtrail evidence took, `docker logs
docker-celery-worker-1` showed a real crash in **one worker fork**:

```
File "/app/src/external/parsers/archive.py", line 56, in <module>
    from src.exceptions import ParsingError, YaraRuleCompilationError, YaraScanError
ImportError: cannot import name 'YaraRuleCompilationError' from 'src.exceptions'
```

Root-caused as far as time allowed: `src/exceptions.py` **does** define
both `YaraRuleCompilationError` and `YaraScanError` (confirmed by directly
`import`ing the module in a fresh interpreter inside the same container —
works fine), so this is **not** a missing class — it reproduces only
inside a specific Celery fork's own lazy `get_parser_registry()` import
path, consistent with a circular-import ordering bug (some import cycle
touches `src.exceptions` a second time, mid-init, from within
`archive.py`'s own module-level import) rather than a genuinely missing
symbol. **Not fixed as part of I1** (out of scope — a pipeline-wide
import-ordering bug, not a detection-validation-harness concern) —
**flagged here for follow-up** with the exact traceback captured. Worked
around for this run using two already-sanctioned recovery mechanisms, not
a new one invented here: `docker restart docker-celery-worker-1
docker-celery-worker-plaso-1` (fresh worker forks re-do the import cleanly
on next task) and the documented `ORG_ADMIN`-only manual recovery endpoint
(CLAUDE.md §E.6) `POST /api/evidence/parse/start/{id}` to unblock the one
evidence item that had already been dropped before the restart, instead of
waiting up to ~1 hour for the `auto_dispatch_received` beat task. This is
exactly the endpoint's documented purpose ("stuck in RECEIVED state after
a broker outage") — not a bypass of the autonomous-pipeline rule, and not
used anywhere in the harness's own normal-path code.

## CI-wiring investigation (the roadmap's own phrase: "regression-tested in CI")

Checked directly, not assumed:

- **`.github/workflows/test.yml`** today runs exactly 4 jobs: `lint`
  (mypy/ruff/black), `codeql`, `unit-tests` (`pytest tests/unit/` only —
  no `tests/integration/`), and `frontend-build`. **No docker-compose file
  is invoked anywhere in CI today** — confirmed by reading the full
  workflow file, matching `docs/verification-pass-findings.md`'s own
  earlier note.
- **`docker/docker-compose.test.yml`** (171 lines, 10 services: postgres,
  redis, minio, opensearch, keycloak, clamav, kronos-backend,
  celery-worker, tsa, nginx) is real and lighter than
  `docker-compose.dev.yml` (801 lines, 19 services) — but two concrete,
  checked blockers make it **not** a drop-in target for this harness or
  any Security-Analytics-dependent test:
  1. Its `opensearch` service sets **`DISABLE_SECURITY_PLUGIN=true`** —
     no TLS, no `admin:admin` auth, no distinction between admin-only and
     tenant-facing calls at all. This harness (and C1/C2/C4/C5's own PoCs)
     depend on HTTPS + basic auth against a security-enabled cluster
     (A3's whole isolation model). Flipping this on would need real
     verification of its own — not assumed to be a one-line change.
  2. It has **no `step-ca`/`tls-init`/`nginx`-with-`kronos.local`
     domain, and no `keycloak-init`** — the real browser-based OIDC PKCE
     login this harness (and every other C-series/H-series PoC) uses
     depends on a `kronos.local` HTTPS domain issued by the dev stack's
     own step-ca, and a Keycloak realm already populated with the
     `kronos-dev` org + `case-lead`/`admin` users. `docker-compose.test.yml`
     has none of this scaffolding.
- **Resource budget, estimated not measured:** `docker-compose.dev.yml`'s
  9 always-on services this harness touches (postgres, redis, minio,
  opensearch, keycloak, clamav, kronos-backend, celery-worker, nginx) plus
  step-ca/tsa/tusd have historically run stably on this host but were
  never load-tested against a standard GitHub-hosted runner's 7 GB
  RAM/2-core budget; OpenSearch alone typically wants ≥512 MB-1 GB heap
  (already set via `OPENSEARCH_JAVA_OPTS` in both compose files) plus
  Keycloak's JVM footprint — plausible but unverified within this pass's
  scope.

**Honest conclusion:** a literal "this harness runs against real
OpenSearch+Keycloak inside a GitHub Actions job" is **not achievable
within I1's scope** without a separate, nontrivial infra investment: at
minimum, enabling the OpenSearch security plugin in
`docker-compose.test.yml` (verified for real, not assumed), adding
step-ca+nginx+TLS+Keycloak-realm scaffolding equivalent to
`docker-compose.dev.yml`'s, and confirming the combined footprint fits a
GitHub Actions runner. This matches the pattern already established by
every other H/I-series item in this roadmap (real local verification now,
CI wiring flagged as explicit, scoped follow-up) — investigated rather
than assumed, per the dispatch brief's own instruction. **Scoped follow-up
recommendation:** a dedicated roadmap item ("CI-capable security-enabled
compose profile") that this harness (and any future SA-dependent
integration test) could then run against in a scheduled/nightly GitHub
Actions job (not on every PR, given OpenSearch+Keycloak startup time) —
not a per-push gate.

## What was NOT verified

- Whether the celery-worker import-ordering bug is genuinely
  order-dependent (a full root-cause would require reproducing it
  deterministically, e.g. forcing the exact fork/import order) — captured
  the real traceback and confirmed the class *does* exist, but did not
  fully trace the cycle.
- Coverage across ATT&CK techniques beyond these 3 — intentionally scoped
  small per the dispatch brief ("start small — 3 to 5"); the other ~2,074
  prepackaged rules remain unmeasured here (already partially measured by
  C1 against benign, non-adversarial samples).
- Whether ART's other 18 SA-log-type gaps (ad_ldap, azure, github, ...)
  could be closed by *some* first-party parser mapping — flagged as a
  finding, not investigated further (would be new parser work, not this
  item's scope).
- Whether re-enabling the OpenSearch security plugin in
  `docker-compose.test.yml` is actually a clean one-line flip or has its
  own real gotchas (per CLAUDE.md §F, not assumed either way — flagged as
  the first concrete step of the CI-wiring follow-up, not attempted here).
