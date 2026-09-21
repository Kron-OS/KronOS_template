# KronOS — Current Status

**Last updated:** 2026-09-21
**This is the only status document.** It is a living file, edited in
place — not appended to, not superseded by a new dated copy. If you are
about to write `docs/GAP_AUDIT_<date>_MILESTONE_<X>.md`, a new
"HANDOFF"/"PROGRESS"/"PRODUCT_STATUS" doc, or any other dated
current-state snapshot: don't. Update this file's relevant section
instead. See `docs/archive/status-history/README.md` for why this rule
exists — the short version is that the previous approach produced 93
gap-audit docs and three separate, overlapping "the real status" attempts,
none of which superseded the others.

**Companion file:** `DECISIONS.md` — append-only log of *why* things are
the way they are. This file (`STATUS.md`) says what's true now; that file
says why it became true and doesn't need updating when it's still true.

**How to keep this honest:** every claim below should be traceable to
something real — a passing test, a `poc/*/README.md` with captured
output, a real E2E spec, or code actually read in the pass that touched
it — not "should work." When you finish a piece of work, update the
relevant bullet here (move it between sections, add/remove a line) as
part of being done, the same way you'd run tests before calling something
finished. Content below not touched in a given session should be assumed
accurate as of its own last-verified date, not silently re-warranted —
if you're not sure a still-listed item is still true, say so rather than
deleting or keeping it silently.

---

## 1. What's built and verified

### Evidence intake & forensic parsing
Real, resumable, hash-verified upload pipeline (client magic-byte
pre-check → presigned MinIO upload → server-side validate/scan(ClamAV)/
hash/promote → autonomous parse → OpenSearch indexing), fully
server-driven after the client's initial call (`CLAUDE.md` §E). Parsers
with real, verified coverage: evtx-rs (fast EVTX), Plaso (heavy —
Prefetch/registry/journald/SQLite and now the sole EVTX handler, see
`DECISIONS.md`), Suricata EVE JSON, Chrome History, AWS CloudTrail,
nginx/Apache logs, ZIP/tar/EWF container recursion (including nested
containers). `VolatilityModule` (memory forensics) now handles **both
Windows and Linux** images — real OS-family detection
(`VolatilityLauncher.detect_os_family()`, the OS-agnostic `banners.Banners`
plugin) picks the right curated eager plugin set per file automatically,
real-verified end-to-end against both a real Windows sample (`cridex.vmem`)
and a real self-generated Linux sample (Ubuntu 22.04, LiME capture) in the
same run — see `poc/volatility_linux_module/README.md` and
`reviews/Volatility_Linux_Plugin_Research.md`. Linux images now also
dual-emit real `TimelineRecord`s (not just `StructuredArtifact`s) via
`linux.pslist.PsList`'s "CREATION TIME" column, **conditional on the
image's ISF having been built by `dwarf2json` rather than `btf2json`** —
real-verified both ways against the identical kernel build/memory capture
(`poc/volatility_linux_boottime/README.md`): a `dwarf2json`-built ISF gave
all 105 real sample rows a real timestamp; the codebase's own
`btf2json`-built sample ISF gives every row `null` (handled honestly, zero
records, not a crash — see known gaps below). One further named, real
caveat in §2 below (an ISF-tool compatibility gap for one bonus plugin,
`hidden_modules`).

### Volatility remote ISF lookup — fixed 2026-09-20
Real, reproduced bug found via a real user-uploaded 4GB memory image
(`memory.vmem`, Ubuntu `6.5.0-41-generic`): every plugin failed with
`UnsatisfiedException` even though OS-family detection correctly
identified Linux. Root cause: this worker calls volatility3's framework
API directly, never its CLI (`vol.py`) — the only other code that ever
sets `volatility3.framework.constants.REMOTE_ISF_URL` — so remote symbol
lookup was never attempted at all, regardless of this container's real
network access; only a memory image whose exact kernel/PDB build already
had a manually pre-installed local ISF could ever be analyzed. Fixed by
wiring `Settings.volatility_remote_isf_url` (default: volatility3's own
project's real, CI-verified remote ISF index, see
`github.com/volatilityfoundation/volatility3` PR #1316) through
`VolatilityLauncher`/the worker script's new `--remote-isf-url` flag,
covering both the eager multi-plugin run and the on-demand curated-plugin
picker. Real-verified end-to-end, twice: first a direct PoC against the
worker module's own multi-plugin function
(`poc/volatility_remote_isf/README.md`), then the real production Celery
pipeline against the same real evidence file after rebuilding
`celery-worker-plaso` — `linux.psscan.PsScan` went from `UnsatisfiedException`
to 1493 real process rows, now persisted as a real `StructuredArtifact`
in Postgres via the actual `kronos.parse_artefact_heavy` task, not a
standalone script. Empty string disables (fully offline/air-gapped
deployments); see `DECISIONS.md` for the real network/sandboxing tradeoff
this accepts. One further real, disclosed finding from the same
verification, **not fixed by this change**: most linked-list-walk plugins
(`pstree`/`pslist`/`psaux`/`bash`/`malfind`/`library_list`/`lsof`/`lsmod`)
still return zero rows against this exact file even with symbols now
resolved, while pool-scan-based `psscan` recovers real data — likely tied
to this being a bare `.vmem` with no paired `.vmss`/`.vmsn` snapshot
metadata (volatility3 itself warns about exactly this), affecting
KASLR/DTB-shift calculation for the walk-based plugins specifically. Not
investigated further; a separate, real gap, tracked below, not silently
folded into "fixed."

### Volatility companion-file (.vmss/.vmsn) support — built 2026-09-20
Closes the gap above: a VMware `.vmem` can now be linked to an
already-uploaded `.vmsn`/`.vmss` evidence item and re-parsed with it
staged correctly, recovering the walk-based-plugin rows the remote-ISF
fix alone could not. New: `Evidence.companion_evidence_id` (nullable,
generic, not VMware-specific — domain layer, migration
`a1f4c9e2b6d7_add_evidence_companion_evidence_id`, applied to the real
dev Postgres, confirmed via `alembic current` and a direct `\d evidence`
check), `Evidence` FSM gains `COMPLETE → PARSING` as a real, deliberate
re-entry point (only reachable via the new service method, never a bare
retry), `ParsingOrchestrationService.attach_companion_and_reparse()`,
`POST /api/evidence/{id}/companion`, and `VolatilityModule`'s new
`CompanionFileResolver` (downloads the companion, stages it next to the
primary temp file under a matching basename — the exact filesystem
adjacency volatility3's own `VmwareStacker` requires, confirmed by
reading `volatility3/framework/layers/vmware.py` directly). Frontend:
`EvidenceDetailDrawer` gained an "Attach companion file" picker (offered
whenever `canAttachCompanion` — COMPLETE or ERROR — and other evidence
exists in the case) and a "Companion file" display row once linked.
Real, decisive verification, not assumed, per `CLAUDE.md` §F/§G.5, in
layers:
- **Plugin level**: `poc/volatility_vmware_companion/README.md` — the
  project owner's own real `memory.vmsn` staged correctly alongside the
  same 4GB `memory.vmem` from the remote-ISF fix above.
  `linux.pstree.PsTree` went from 0 rows to a full real process tree;
  `linux.pslist.PsList` went from 0 rows to 344 real rows with real
  `CREATION TIME` values (this ISF is `dwarf2json`-built, so this also
  unlocks real dual-emitted `TimelineRecord`s for this specific image).
  Also surfaced and fixed two real bugs found only by running this for
  real inside `celery-worker-plaso`: `get_evidence_repository()` is never
  configured inside a Celery worker process (mirrors
  `_build_task_resources()`'s own fresh-engine-per-task pattern instead),
  and the companion-staging step used to run outside the primary temp
  file's own `try`/`finally`, leaking it on a staging exception.
- **Backend**: full unit suite (2088 tests) and the companion-specific
  domain/orchestration/route/parser tests (164 tests) pass; the migration
  is live-applied to the real dev Postgres (not just `alembic upgrade
  --sql`).
- **End-to-end, real browser**: `frontend/e2e/evidence-companion-attach.spec.ts`
  (new) — real Keycloak login, uploads two small real fixtures
  (`apache_access.log`, `linux_auth.log`) rather than the 4GB image
  (avoids the real OOM risk the plugin-level PoC found — see its "OOM
  risk" section — while exercising the identical generic route/
  service/FSM/audit path), attaches one as the other's companion through
  the real UI, confirms the real server-side reparse via a fresh
  independent GET (not the transient UI state text — apache log parsing
  is fast enough to legitimately skip past the intermediate `Parsing`
  render between two 500ms polls), and confirms the drawer shows the
  linked companion filename afterward. Run live twice, both green
  (~45s and ~40s). `frontend/e2e/pages/CaseDetailPage.ts` gained
  `openEvidenceDrawerAnyState()` alongside this — the existing
  `openEvidenceDrawer()` waits on the Retry button, which only renders
  for a retryable ERROR row, not a COMPLETE one.
- **Frontend unit**: `EvidenceDetailDrawer.test.tsx`'s new
  companion-attach describe block (7 tests) passes; `tsc -b --noEmit` and
  the full `vitest run` suite (143 tests) are both clean.

Not yet done: no coverage of `canAttachCompanion` being offered from an
ERROR (not COMPLETE) row specifically — same underlying gate and service
method, judged low-risk, not a gap worth naming further.

**Two further real bugs found and fixed running the real 4GB companion
pair through the actual production Celery pipeline (beyond the two named
above), plus full end-to-end success — 2026-09-20/21:**
- **Two Linux plugins are pathologically slow on real data.** Real,
  isolated per-plugin timing (fresh subprocess each, no cumulative
  memory pressure from other plugins) against the real 4GB image:
  `linux.malware.malfind.Malfind` took 304s; `linux.library_list.LibraryList`
  didn't finish within a 320s budget at all. Both removed from
  `LINUX_DEFAULT_PLUGINS` — same real, measured reasoning `windows.consoles`
  was already excluded from `DEFAULT_PLUGINS` for. Both remain available
  via the on-demand curated-plugin picker.
- **The real root cause of persistent "still doesn't finish" failures:
  an O(n²) artifact-batching bug**, not Volatility itself. Even after
  removing the two slow plugins, a real run still hit
  `SoftTimeLimitExceeded` — but the scan itself now completed in ~7
  minutes. Process-of-elimination timing (a real 7MiB Postgres JSONB
  insert of the exact production content took 17.6ms, ruling out the
  database) found `rows_to_artifacts()`'s batching loop re-serialized
  the *entire growing batch* to JSON on every row to measure its size —
  O(n²) overall, invisible against every plugin this module had ever
  been verified against before (a few hundred rows), but a real
  companion-linked `linux.lsof.Lsof` result correctly recovered 24,562
  real rows (only possible *because* the companion fix works), turning
  the quadratic cost into a 30+ minute silent hang inside one Python
  loop with zero intermediate logging. Fixed to O(n) (compute each row's
  own size once, keep a running total). Regression test:
  `test_batching_is_linear_not_quadratic_in_row_count` (25,000 rows,
  asserts under 5s — the old code would not finish within any reasonable
  test timeout).
- `kronos.parse_artefact_heavy`'s Celery time limits and
  `VolatilityModule`'s own internal timeout raised to a realistic budget
  for genuine forensic tooling processing genuine large datasets
  (bounded, not infinite) — see `celery_app.py`'s own comment for the
  two real incidents this tracks.
- **Final, complete, real, end-to-end success**: with all four fixes
  applied, the real production task succeeded in 513s against the real
  4GB `.vmem` + `.vmsn` pair — evidence reached `COMPLETE`, `parse()`
  dual-emitted 344 real `TimelineRecord`s, and `extract_artifacts()`
  persisted real, correct `StructuredArtifact`s for every plugin in the
  trimmed eager set (`pstree`, `psscan` 1493 rows, `pslist` 344, `psaux`
  344, `bash` 28, `lsof` 24,562 rows split across multiple 7MiB-capped
  artifacts, `lsmod`, `hidden_modules`). Full account, including the
  per-plugin timing table and a real Celery-retry race condition also
  found along the way, in `poc/volatility_vmware_companion/README.md`.

### Timeline & search
OpenSearch, ECS + `kronos.*` schema, per-case-per-month index rollover
under ISM. Dashboards field discovery verified live against real Plaso
output.

### Multi-tenancy, auth, audit
Keycloak 26+ Organizations, JWT + step-up (aal2) auth, per-tenant data
isolation. Append-only, hash-chained audit log
(`row_hash = SHA256(prev_row_hash || canonical_json(event))`) on every
mutation. RBAC trilogy (`assert_case_lead_or_admin` and friends) closed,
including case-member add/remove and mid-session role changes.

### Connector marketplace (`/admin/connectors`) — built 2026-09, this initiative
Per-org, self-service connector configuration replacing single-global
`Settings`-driven config. All 7 phases of the build (Vault wiring →
domain/application layer → Postgres+Vault adapters → Defender POLL
per-org rewiring → sink fan-out (Splunk HEC/CEF syslog/Sentinel) → PUSH
connector UI (Wazuh/Suricata/Zeek) → global-Settings cleanup) are done
and were verified against the real dev stack, not just unit-tested — see
`docs/CONNECTOR_MARKETPLACE_VERIFICATION.md`. Real, working:
- Per-org credential storage in a dedicated Vault KV-v2 mount
  (`kronos-connectors`) + AppRole, never the shared KES token.
- Circuit breaker: 5 consecutive failures auto-disables a connector
  (`auto_disabled_at`, distinct from the user-controlled `enabled` flag).
- Reversible disable/enable vs. permanent delete (see `DECISIONS.md`).
- A real, previously-unverified bug (step-up ticket never minted by the
  marketplace frontend, mutations silently hung) was found and fixed
  2026-09-19 via a real Playwright run — see `DECISIONS.md`'s connector
  marketplace section. Fix: `frontend/src/lib/stepUpTicket.ts`.
- Real Playwright E2E coverage: Suricata PUSH key
  generate/reveal-once/revoke
  (`frontend/e2e/connector-marketplace-suricata-push.spec.ts`) and
  CEF-syslog SINK configure/disable/enable/remove
  (`frontend/e2e/connector-marketplace-cef-syslog-sink.spec.ts`), both
  run live against the dev stack including the real step-up MFA redirect.
- **All 7 marketplace connectors now have real, passing E2E coverage** —
  Wazuh/Zeek PUSH panels
  (`frontend/e2e/connector-marketplace-push-panels.spec.ts`) and Splunk
  HEC/Sentinel/Defender POLL config forms
  (`frontend/e2e/connector-marketplace-poll-sink-forms.spec.ts`), added and
  run live against the dev stack 2026-09-20 alongside the pre-existing
  Suricata PUSH and CEF-syslog SINK specs (all 7 re-run together, all
  green). Config-form saves use well-formed fake credentials, not live
  Splunk/Sentinel/Graph calls — confirmed by reading
  `admin_connector_config.py`'s `set_connector_config`, which only
  validates and persists to Postgres/Vault, never dials out on save.
  **A real bug was found and fixed by this run**: `ConnectorConfigForm.tsx`
  and `PushConnectorKeyPanel.tsx`'s modal had no `max-height`/scroll — the
  Microsoft Sentinel form (8 parameters) overflowed the fixed-position
  overlay with no way to reach the Save button, a real, reproducible
  usability bug on any viewport shorter than the rendered form (not a test
  artifact — confirmed via screenshot, then fixed with `max-h-[90vh]
  overflow-y-auto` on both modals' inner container, rebuilt into the nginx
  image, and re-verified green).
- A real bug in stream ingestion was found and fixed in the same
  initiative: `StreamSourceNormalizerRegistry` was keyed on a connector
  *instance's* `source_id` (e.g. `wazuh-manager-1`) instead of its
  `source_type` (`wazuh`) — affected both arbitrary-named PUSH instances
  and the Defender POLL rewrite. Fixed with regression tests and a live
  end-to-end re-verification.

### Evidence-upload TLS-origin bug — fixed 2026-09-19
Presigned upload URLs used to point at `https://kronos.local:9444`
(nginx→MinIO), a different browser *origin* than the main app purely
because the port differed — a browser that had only trusted the main
site's cert got a silent, undiagnosable "Network error" on every upload
(real HAR showed `status: 0` on both the CORS preflight and the PUT; the
old repro tooling, curl `-k`/Playwright `ignoreHTTPSErrors`, couldn't
catch it since both bypass cert validation entirely). Fixed by proxying
MinIO's real bucket-prefixed paths (path-style S3 addressing) through the
main `:443` origin itself (`docker/nginx/nginx-lan-https.conf.template`'s
`location ~ ^/kronos-evidence-`) instead of a dedicated port, and pointing
`MINIO_PUBLIC_ENDPOINT`/`MINIO_PUBLIC_URL` at `https://kronos.local` (no
port). Port `9444` is fully retired (nginx server block removed, no
longer published in `docker-compose.dev.yml`). Verified for real: a
Python script logging in through real Keycloak (`https://kronos.local:8443`)
and performing a real presign→PUT→finalize upload with the real step-ca
root CA trusted and **no cert-validation bypass anywhere** (`verify=<real
root_ca.crt>`, not `-k`/`verify=False`) — presigned URL confirmed to carry
no port, PUT returned 200, finalize returned 202. Backend unit tests
(209 relevant) and the real `evidence-upload.spec.ts` Playwright spec both
still pass. See `DECISIONS.md`'s connector/infra section for the full
rationale.

### nginx request buffering made large evidence uploads look stuck — fixed 2026-09-20
Real, reproduced bug found via a real user report: a multi-GB PUT to
`location ~ ^/kronos-evidence-` (the same-origin MinIO proxy above) sat at
0% with no visible progress. Confirmed live in nginx's own error log --
`"a client request body is buffered to a temporary file"` -- nginx's
default `proxy_request_buffering on` writes the ENTIRE request body to
`/var/cache/nginx/client_temp/` before forwarding any of it to MinIO, so a
multi-GB upload is serialized behind a second full disk write+read on top
of the browser's own transfer, degrading sharply under real disk
contention (this host's own dev stack + concurrent work already keeps the
disk busy). Not a total stall -- the two uploads that triggered this report
did eventually complete end to end (confirmed: both evidence items reached
`COMPLETE`, one after several minutes) -- but indistinguishable from a
genuine hang within any reasonable UI-watching timeframe. Fixed with
`proxy_request_buffering off;`, verified with a real 1GiB presigned PUT
through the real nginx container before asking the user to retry: 23s
(~44MB/s) with no buffering warning in the log, vs. multi-minute
buffered transfers for similarly-sized real uploads before the fix.

### Large-file client-side hash mismatch bug — fixed 2026-09-20
Every real multi-GB evidence upload (this platform's own memory-forensics
use case) was terminally failing intake with `hash_mismatch`, every time,
not intermittently. Root cause: `computeSHA256()`
(`frontend/src/store/uploads.ts`) called `crypto.subtle.digest()` over a
single `file.arrayBuffer()` — for a multi-GB file that requires the
*entire* file materialized as one in-memory `ArrayBuffer`, which silently
produced a hash over truncated/corrupted bytes well below any visible
browser error, while the real presigned PUT (`xhr.send(file)`) streams the
actual full file straight from disk. The two never matched, so the
server's real streamed-from-storage hash (`_run_hash`,
`src/application/evidence_intake.py`) always disagreed — and
`hash_mismatch` is backend-terminal (`is_retryable_error_reason()`), so
the affected evidence item could never be retried in place, only
re-uploaded fresh after the client fix. Fixed by hashing in fixed-size
(32 MiB) chunks via `@noble/hashes`' incremental `sha256.create()` (Web
Crypto's `SubtleCrypto` has no chunked/streaming digest API), keeping peak
hashing memory bounded regardless of file size. Verified with a real unit
test computing the hash of a real 75 MiB file (crossing the chunk boundary
twice) and comparing against a one-shot digest over the same bytes —
not just re-testing the old tiny fixture. Rebuilt and redeployed to the
dev nginx image the same session.

### Intake `ReadTimeoutError` on large evidence under resource contention — fixed 2026-09-22
Real user report: `intake_failed:ReadTimeoutError` during validation/
scanning/hashing on large evidence, worse on a lower-RAM host running the
whole stack at once. Root cause: `S3EvidenceStorage`/`S3DerivedArtifactStorage`/
`S3SealedBatchStorage` (`src/adapter/storage/`) each construct their boto3
`Config` with `read_timeout=60`. `_run_scan`/`_run_hash`
(`src/application/evidence_intake.py`) each stream a multi-GB evidence
object *in full* via `_s3_stream`'s manual `body.read(chunk_size)` loop —
botocore's own `retries={"max_attempts": 3}` wraps only the initial
`get_object` call, not a `StreamingBody.read()` mid-stream, so any single
64 KiB read that stalls past 60s (real cause: MinIO's own available-RAM-
sized concurrent-request throttling — see the companion-file section above
for the verified mechanism — or plain disk contention under several large
uploads/scans in flight at once) raises `ReadTimeoutError` straight into
application code with no retry. 60s was sized for small compliance-log
evidence, never revisited for this platform's own multi-GB memory-dump use
case. Fixed by raising `read_timeout` to 300s in all three clients, matching
the `proxy_read_timeout 300s` this codebase already uses for the same
evidence-upload path in nginx. `connect_timeout=10` left unchanged — the
failure is specifically a read timeout on an already-open connection, not a
slow connect.

### Frontend E2E (`frontend/e2e/`)
Real browser tests against the live dev stack (`https://kronos.local`),
not mocked — evidence upload through to `COMPLETE` via SSE, admin
quota/invite/role-change step-up flows, connector marketplace (above).
Page-object pattern (`KronosPage` base + per-page subclasses),
`DEV_USERS` fixture for the three static dev accounts. `workers: 1` —
there is a documented Keycloak concurrent-login race, don't parallelize.

**Two-simultaneous-dependency-failure fault injection — added 2026-09-20**
(`evidence-dual-dependency-outage.spec.ts`): stops ClamAV *and* OpenSearch
together (dev stack), confirms upload deterministically lands on
`ERROR/intake_failed` (the ClamAV gate, unaffected by OpenSearch also being
down), restores ClamAV only and confirms retry correctly fails a *second*
time at `ERROR/ingest_failed` (the parse/OpenSearch stage, not a hang or a
misattributed repeat of the first error), then restores OpenSearch and
confirms full recovery to `COMPLETE` — three real stop/restart cycles, one
spec, real-verified green (`~7.2min`, `CLAUDE.md` §F). Writing this spec
surfaced and fixed two real, previously-hidden bugs in shared E2E
infrastructure (not the app pipeline — see `DECISIONS.md`):
`KronosPage.pollLiveText`'s seed-guard returned `null` instead of a
genuine second terminal reading whenever a row legitimately cycled back to
the *same* terminal value as its seed (every prior spec only ever seeded a
*different* value than it waited for, so this never fired before); and
`EvidenceDetailDrawer`'s Retry button doesn't close the drawer, so a second
`openEvidenceDrawer()` in the same test was blocked by the still-mounted
backdrop (fixed with a new `closeEvidenceDrawer()` page-object helper).

### CI / test suite
`~/venv/bin/python3 -m pytest tests/` runs the full unit+integration
suite in-process. As of the last full run this initiative is aware of:
2000+ tests passing, ~90% coverage gate. Python 3.14 works fine on this
host (an older `asyncpg`/`greenlet` deadlock is no longer reproducible).

---

## 2. Known gaps (real, named, not hidden)

- **"Firecracker microVM" isolation is not actually Firecracker.** Heavy
  parsing (Plaso, Volatility) runs as a sandboxed subprocess in a
  container, not inside a real Firecracker microVM, despite naming in
  the code. Functionally correct; the isolation boundary is weaker than
  the documented target.
- **SIEM integrations (Wazuh/Falco/fluent-bit) are configured but not
  wired in.** Each has a standalone compose file; none is referenced by
  any shipped `docker-compose.{dev,test,prod}.yml` profile, and no rule
  has ever fired against a real event. This is a standing product-scope
  decision, not an oversight — see `DECISIONS.md`.
- **No real Kubernetes deployment has been attempted.** `helm lint`/
  `helm template` pass clean; a real `helm install` against a real
  cluster has not been tried.
- **No workflow in this repo has ever executed on GitHub's own
  infrastructure.** All CI-equivalent coverage is real and locally
  verified, but GitHub only evaluates `schedule:`/other triggers from the
  default branch, and this work has never merged to `main`.
- **`linux.malware.hidden_modules.Hidden_modules` may `scan_error` on some
  real orgs' images.** Real, understood cause (`poc/volatility_linux_module/`):
  this plugin checks an ISF metadata field that only `dwarf2json`-produced
  symbol tables set — an org whose Linux ISF was built via `btf2json` (a
  real, valid, faster alternative for kernels with `CONFIG_DEBUG_INFO_BTF=y`)
  will see this one plugin fail while the other 8 in the Linux eager set
  succeed normally (same "one bad plugin doesn't sink the run" handling
  every other multi-plugin outcome already gets). Not urgent, named.
- ~~A bare `.vmem` with no co-located `.vmss`/`.vmsn` leaves most
  linked-list-walk Linux plugins returning zero rows~~ — **fixed
  2026-09-20**, see "Volatility companion-file (.vmss/.vmsn) support" in
  §1 above. No longer a gap.
- **Linux memory images only dual-emit `TimelineRecord`s when the image's
  ISF was built by `dwarf2json` — a `btf2json`-built ISF still gets none.**
  No longer a flat "not built" gap (fixed 2026-09-20, see `DECISIONS.md`'s
  Volatility section and `poc/volatility_linux_boottime/README.md`'s "Part
  2"): `linux.pslist.PsList`'s "CREATION TIME" column is real-verified to
  give all rows a real timestamp when a `dwarf2json`-built ISF resolves
  `tk_core`/`timekeeper` correctly, but this codebase's own
  `btf2json`-built self-generated sample (and any org's BTF-only kernel)
  leaves that symbol untyped, so every row's CREATION TIME is `null` —
  same ISF-metadata gap already named below for `hidden_modules`, handled
  the same honest way (zero records, not a crash). Not urgent to fix
  further: most distro kernels have a `dwarf2json`-compatible debug
  package available, and the alternative (a `timekeeper`-independent
  wall-clock anchor) has its own real accuracy caveats.
- **Dev OpenSearch's shard ceiling was raised (1000 → 2000) as a
  workaround, not fixed.** Root cause (ISM creates a new index per case
  per month, never deleted) is still real; the ceiling will be hit again
  eventually. See `DECISIONS.md`.
- **Vault runs in `-dev` mode (in-memory, unsealed) on the dev stack.**
  Acceptable for dev only. Production deployment of the connector
  marketplace (or KES) is blocked on real sealed/persistent Vault — this
  is a hard requirement, not a nice-to-have.
- **Per-org Vault ACL isolation is application-layer discipline, not
  Vault-enforced.** The connector-secrets Vault policy is static, not
  templated per org-id token claim. The actual collision boundary today
  is "`org_id` always comes from `TenantContext`, never client input" —
  correct and tested, but a compromised backend process could in theory
  read another org's path. Stronger per-org Vault ACLs are a named,
  deferred hardening, not implemented.
- **Track D (third-party/customer-supplied parser modules) has not
  started.** Gated behind first-party modules being solid, per
  `reviews/Extensibility_Architecture_Proposal.md`.
- **A few named, small test-coverage gaps**: `StatusPill`'s transient
  pipeline states have no visual-regression coverage (deliberately scoped,
  not an oversight — see `visual-regression-pills.spec.ts`'s own docstring).
  Two-simultaneous-dependency-failure fault injection is now covered — see
  below, no longer a gap.
- **CEF-over-syslog egress connector still uses a raw outbound TCP/UDP
  socket** (`SyslogIntegrationSink`, `src/adapter/integration_sink/syslog_sink.py`
  — confirmed by direct read 2026-09-21, not assumed), not fluent-bit. The
  project owner flagged a raw outbound socket as fragile in real infra and
  asked to move this transport to fluent-bit (already the verified
  log-shipping reference for PUSH connectors — see the dev-stage fluent-bit
  PoC in `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md`). **Blocked on one
  unanswered product decision, asked but not yet resolved**: should
  per-org destination config stay self-service (today's model —
  `connector_configs` in Postgres/Vault, one row per org) or become a
  shared/ops-managed fluent-bit route? Do not pick either silently —
  this is exactly the kind of multi-tenancy-shaped call CLAUDE.md's
  verification-first process defers to the project owner. See TaskList
  for the tracked pending item.

## 3. Explicitly out of scope (standing product decisions — don't re-litigate without a fresh instruction)

- No SIEM wiring for now.
- No v2 features for now (advanced timeline search, case collaboration/
  comments, non-Sigma detection rules, DFIR report generation, broader
  API rate limiting).
- `audit.py`'s export/verify/merkle-proof routes deliberately have no web
  UI — they feed the standalone `kronos-attest` CLI by design.

See `DECISIONS.md` for the reasoning behind each.

---

## 4. Operational facts worth not re-deriving

- Docker Compose commands against the dev stack need `-p docker`
  explicitly (e.g. `docker compose -p docker -f docker/docker-compose.dev.yml
  build nginx`) — the project name doesn't default correctly on this host.
  Container names: `docker-kronos-backend-1`, `docker-nginx-1`, etc.
- `kronos-backend` auto-reloads on source changes (volume-mounted `src/`,
  `uvicorn --reload`) — a backend Python change needs no manual restart.
  A **frontend** change needs a manual `docker compose ... build nginx`
  + `up -d nginx` — it's a static build baked into the nginx image, not
  live-mounted.
- OpenSearch: real, live, 2.11.1, `https://localhost:9200`
  (`admin`/`admin`, self-signed cert). Keycloak: real, live, 26.2,
  `https://kronos.local:8443` externally. Dev users: `case-lead`,
  `analyst`, `admin` (`frontend/e2e/fixtures.ts`'s `DEV_USERS`). `admin`
  requires TOTP for both ordinary login (`CONFIGURE_TOTP` required
  action) and step-up (aal2) — these are different Keycloak flows; a
  normal TOTP login does not imply aal2.
- Step-up (MFA) is a full browser redirect (`keycloak.login({acrValues:
  'aal2', prompt: 'login'})`), not an in-page refresh — the original
  in-flight mutation is abandoned and must be manually retried after
  returning; local form state is stashed/restored via
  `frontend/src/lib/stepUpFormPersistence.ts` but never auto-resubmitted.
  Some routes additionally require a one-time `X-Step-Up-Ticket` on top
  of aal2 (see `DECISIONS.md`) — check which bar a route actually
  enforces before assuming the aal2-only pattern.
- The dev-seeded `admin` user's TOTP secret lives in
  `poc/auth_flow/dev_totp_secrets.py` and `frontend/e2e/stepup.ts` — both
  must be updated together if the credential is ever re-registered (see
  `DECISIONS.md`).
