# KronOS — Project Status

**Last updated:** 2026-07-24
**Supersedes:** the previous version of this file (dated 2026-06-26), which
is now known-stale — several of its "✅ COMPLETE" claims were never
independently run against real dependencies (see `CLAUDE.md` §F, added
after that date) and at least one of its own facts was already wrong at
publish time (§7.1 claimed "14 services"; `docker/docker-compose.dev.yml`
has 18).

## How this document was built, and how to keep it honest

Per the project's verification-first rule (`CLAUDE.md` §F), nothing below
is marked done because a doc says so. Every checklist item links to the
artifact that proves it — a `poc/*/README.md` with real captured output, a
git commit, a test file, or a config file actually inspected in this pass —
and, where two documents disagreed, the more recent, more-verified one wins
and the older one is flagged. Two structural conflicts worth knowing about
before reading the checklists:

- **`roadmap.md` under-claims.** Every checkbox in `roadmap.md` §2–§9 is
  still unchecked (`- [ ]`), because that file was written *before* most of
  the work and has never been updated — but large parts of §2, §3, §4, §5
  are, in fact, built and independently verified (see below). Don't read
  an unchecked `roadmap.md` box as "not started."
- **The old `PROGRESS.md` over-claimed.** It marked §5 (Security) and §6
  (SIEM) "✅ COMPLETE" for the mere existence of config files that were
  never brought up against a real container. `reviews/Static_Compliance_Pentest_Review.md`
  (2026-07-05) later found 10 Critical + 5 High compliance gaps in exactly
  that "complete" code, most now fixed (§0 remediation log in that file) —
  but not all, see the Remaining checklist below.

**Test suite provenance:** this pass attempted a fresh local
`pytest tests/unit/` run to independently confirm the current count. The
only Python available on this host is 3.14.4; the repo's CI
(`.github/workflows/test.yml`) and every prior verification pass pin
**3.11**, and the ad hoc 3.14 venv deadlocked inside `asyncpg`/`greenlet`
native code during collection (a known class of interpreter-version
incompatibility, confirmed via `SIGABRT` C-stack dump — not a repo bug).
Rebuilding a 3.11 toolchain from source was judged out of scope for this
document. The counts cited below are therefore the last real, captured
numbers from `docs/verification-pass-findings.md` (itself produced by
actually running the suite), not re-derived here — flagged so this gap is
visible rather than silently papered over.

---

## Part 1 — What Works Right Now (independently re-verified)

Each row was actually run against the real dependency at the pinned
version, with captured output — not inferred from source reading alone.

| Area | Verified | Evidence |
|---|---|---|
| Backend unit+integration suite | 581 unit tests / 84.10% coverage, 117 integration tests, green; ruff/mypy 0 findings | [`docs/verification-pass-findings.md`](docs/verification-pass-findings.md) §"Suricata module" entry, row 25 area |
| Frontend build | `npm run build` — 185 modules, succeeds | run in this pass; also [`docs/verification-pass-findings.md`](docs/verification-pass-findings.md) §4 |
| Frontend unit tests | `npm run test` — 33/33 pass | run in this pass; also [`docs/verification-pass-findings.md`](docs/verification-pass-findings.md) §4 |
| Frontend lint | 1 benign warning, 0 errors | [`docs/verification-pass-findings.md`](docs/verification-pass-findings.md) §4 |
| Full autonomous ingestion pipeline (§E rules) | Real login → upload/finalize → autonomous `RECEIVED→PARSING→COMPLETE` → real OpenSearch docs, 5 parsers, 223 docs, zero client intervention | [`poc/full_ingestion_test/`](poc/full_ingestion_test/README.md) |
| KAPE ZIP + E01 container ingestion | Real KAPE-shaped `.zip` + real `.E01`, 631 docs, correct `source_path`/`container_sha256` | [`poc/kape_ingestion_test/`](poc/kape_ingestion_test/README.md) |
| Plaso parsing (real, not stub) | Real `log2timeline`/`psort` subprocess, real Windows EVTX/Prefetch/registry output landing in OpenSearch | [`poc/plaso_opensearch/`](poc/plaso_opensearch/README.md), [`poc/plaso/`](poc/plaso/README.md) |
| MinIO Object Lock / WORM | Root-proof compliance-mode lock confirmed | [`poc/minio/`](poc/minio/README.md) |
| Vault → KES → MinIO SSE-KMS | Full encrypted-WORM chain works after fixes | [`poc/vault_kes_minio/`](poc/vault_kes_minio/README.md) |
| Keycloak JWT auth + Organizations | Real Keycloak 26.2, `aud`-bypass bug found+fixed | [`poc/keycloak/`](poc/keycloak/README.md) |
| Celery ↔ Redis dispatch | Real task round-trip | [`poc/celery_redis/`](poc/celery_redis/README.md) |
| RFC 3161 timestamping | Real local TSA responder, request/verify round trip | [`poc/rfc3161/`](poc/rfc3161/README.md) |
| Chain-of-custody CLI (`kronos-attest`) | Postgres → Merkle → real RFC3161 → CLI, end to end | [`poc/chain_of_custody/`](poc/chain_of_custody/README.md) |
| Cross-org tenant isolation (Postgres+OpenSearch+JWT) | Severe wiring bug found+fixed (`PostgresCaseRepository` never wired) | [`poc/multi_tenancy/`](poc/multi_tenancy/README.md) |
| Audit hash-chain tamper detection | Concurrency-safe, correct | [`poc/postgres/`](poc/postgres/README.md) |
| ClamAV scanning in intake path | Real EICAR detection | [`poc/clamav/`](poc/clamav/README.md) |
| PKCE login + step-up (aal2/TOTP) MFA | 6/6 real logins against the actual shipped realm, conditional-LoA bug found+fixed | [`poc/auth_flow/step_up_conditional_fix/`](poc/auth_flow/step_up_conditional_fix/README.md) |
| OpenSearch DLS multi-tenant isolation | Real Keycloak flat `org_id` claim → real DLS, zero-touch new-member scaling | [`poc/keycloak_opensearch_dls/`](poc/keycloak_opensearch_dls/README.md) |
| OpenSearch Dashboards SSO + per-org tenants | 11/11 checks, 8 bugs found+fixed, wired into the real dev stack | [`poc/opensearch_dashboards_sso/`](poc/opensearch_dashboards_sso/README.md) |
| Celery beat orphan-sweep + daily anchor tasks | Against real seeded-stale Postgres rows | [`poc/celery_beat/`](poc/celery_beat/README.md) |
| nginx CSP/CORS + Helm ConfigMap | Missing Helm ConfigMap bug found+fixed | [`poc/nginx/`](poc/nginx/README.md) |
| Dashboards embed URL route | Verified against real Dashboards 2.11.1 source | [`poc/dashboards_embed/`](poc/dashboards_embed/README.md) |
| `SuricataEveParser` (first Section G module) | Real `eve.json` (OISF golden fixture + userguide sample), 6/6 events, correct monthly-index split, real alert fields | [`poc/suricata/`](poc/suricata/README.md) |
| `docker compose config` (all 3 files) | Parses structurally clean | [`docs/verification-pass-findings.md`](docs/verification-pass-findings.md) §4 |
| `helm lint charts/kronos` | 0 charts failed (after the missing-ConfigMap fix) | [`docs/verification-pass-findings.md`](docs/verification-pass-findings.md) §4 — **not re-run this pass**, `helm` isn't installed on this host; see Remaining §7 |

**Known-open bugs/gaps** (found, not yet fixed):
- `/silent-check-sso.html` nginx location genuinely lacks `X-Frame-Options`/HSTS (own CSP mitigates) — [`poc/nginx/README.md`](poc/nginx/README.md), flag D.
- Dashboards embed URL never sets an index-pattern app-state; real behavior needs a browser, not static analysis — [`poc/dashboards_embed/README.md`](poc/dashboards_embed/README.md), flag E. See Remaining §2.

---

## Part 2 — Done Checklist (shipped, sourced)

### 2.1 Backend Core (Phases 1–5)
- [x] Domain models, DI container, audit hash chain, exception hierarchy — `CLAUDE.md` §A, [`src/domain/`](src/domain/)
- [x] Evidence intake (UPLOADING→RECEIVED), validators, ClamAV, hashing — verified live, see Part 1
- [x] Parser framework (`ForensicParser` ABC, `ParserRegistry`) — [`src/application/parsing.py`](src/application/parsing.py), [`src/application/parser_registry.py`](src/application/parser_registry.py)
- [x] Timeline ingestion into OpenSearch, ECS schema, ISM rollover — verified live, see Part 1
- [x] Multi-tenancy (Keycloak JWT, RBAC, step-up, DLS) — verified live, see Part 1

### 2.2 Ingestion Pipeline Autonomy (`CLAUDE.md` §E)
- [x] Fully autonomous `finalize→dispatch→parse→ingest→COMPLETE` chain, zero client sequencing — [`poc/full_ingestion_test/`](poc/full_ingestion_test/README.md)
- [x] `auto_dispatch_received` beat-task recovery path — [`poc/celery_beat/`](poc/celery_beat/README.md)
- [x] `stream_all_by_state` confirmed system-task-only in current call sites — spot-checked in this pass, [`src/adapter/repository/evidence.py`](src/adapter/repository/evidence.py)

### 2.3 Container/Disk-Image Ingestion (KAPE Track C)
- [x] `ZipArchiveParser` — recursive re-dispatch, zip-bomb per-member cap — [`src/external/parsers/archive.py`](src/external/parsers/archive.py), commit `44a9089`
- [x] EWF/E01 whole-image routing through `PlasoParser` (dfVFS auto-detect) — same commit
- [x] `KronosProvenance.source_path`/`container_sha256` — same commit
- [x] End-to-end verified against real KAPE zip + real E01 — [`poc/kape_ingestion_test/`](poc/kape_ingestion_test/README.md)

### 2.4 Unified Data-Source Module System (Section G, new)
- [x] Architecture + flowchart — [`reviews/Data_Source_Module_System.md`](reviews/Data_Source_Module_System.md)
- [x] DFIR artifact landscape catalogue (Linux/memory/mobile/network/cloud/container/macOS/email) — [`reviews/DFIR_Artifact_Landscape.md`](reviews/DFIR_Artifact_Landscape.md)
- [x] `StructuredArtifact` domain type + `structured_artifacts` Postgres table + `ArtifactIngestService` — [`src/domain/artifact.py`](src/domain/artifact.py), [`src/application/artifact_ingest.py`](src/application/artifact_ingest.py)
- [x] Wired into both `ParsingOrchestrationService.execute_parse()` and the real Celery per-task path (`celery_runtime.py`) — the fix for a silent-no-op-in-production bug caught before shipping
- [x] CLAUDE.md §G — module-authoring rules and checklist
- [x] First module built end-to-end under the new process: `SuricataEveParser` — [`poc/suricata/`](poc/suricata/README.md), commit `476706a`

### 2.5 Chain of Custody & Attestation
- [x] RFC 3161 timestamping wired to real transitions — [`poc/rfc3161/`](poc/rfc3161/README.md), [`poc/chain_of_custody/`](poc/chain_of_custody/README.md)
- [x] Daily Merkle root + anchor (UTC-date bug found+fixed) — [`poc/celery_beat/`](poc/celery_beat/README.md)
- [x] `kronos-attest verify`/`merkle-root`/`merkle-proof`/`day-report` — verified — [`poc/chain_of_custody/`](poc/chain_of_custody/README.md)
- [ ] `kronos-attest case-report` — still only replays an offline JSON export, does not live-re-read MinIO/Postgres/TSA (COMP-2) — see Remaining §4

### 2.6 Security Layer (dev-mode)
- [x] Internal PKI (step-ca) config — [`docker/pki/`](docker/pki/)
- [x] mTLS-adjacent SSE-KMS chain (Vault+KES+MinIO) — verified, [`poc/vault_kes_minio/`](poc/vault_kes_minio/README.md)
- [x] Step-up MFA actually conditional on `acr_values` (was previously unconditional — real Keycloak 26.2 bug) — [`poc/auth_flow/step_up_conditional_fix/`](poc/auth_flow/step_up_conditional_fix/README.md), commit `c7601ce`
- [x] `docker-compose.{dev,test}.yml` parse cleanly, Keycloak realm imports cleanly (256-char column-limit regression found+fixed) — [`docs/verification-pass-findings.md`](docs/verification-pass-findings.md) row 17
- [x] Static compliance/pentest pass (19+18+15 findings across Auth/Evidence/Audit/Infra/Frontend/Compliance) triaged; most Critical/High fixed in three parallel workstreams — [`reviews/Static_Compliance_Pentest_Review.md`](reviews/Static_Compliance_Pentest_Review.md) §0
- [ ] Several dev-mode-triaged-but-still-open + everything explicitly prod-mode-deferred — see Remaining §3–§4

### 2.7 Frontend SPA
- [x] Vite+React 19+TanStack Router scaffold, Zustand, Tailwind v4+shadcn/ui — [`frontend/`](frontend/), confirmed via real `npm run build`
- [x] Cases/evidence list, detail drawer, status pills, error catalogue — [`frontend/src/pages/`](frontend/src/pages/), [`frontend/src/components/`](frontend/src/components/)
- [x] Uppy resumable upload (S3-multipart) — [`frontend/package.json`](frontend/package.json) deps confirmed real
- [x] SSE evidence-status hook — [`frontend/src/hooks/useEvidenceSSE.ts`](frontend/src/hooks/useEvidenceSSE.ts)
- [x] Auth token-storage/refresh-proxy and RBAC gaps found by `Static_Compliance_Pentest_Review.md` (FE-1/FE-2/FE-3) fixed — see that file §0
- [ ] **No browser-level verification has ever been run** — build+unit-test-green is not the same as "works in a real browser end to end." See Remaining §2.

### 2.8 CI/CD
- [x] `test.yml` — lint (mypy/ruff/black), CodeQL security scan, unit tests with `--cov-fail-under=80`, frontend build — [`.github/workflows/test.yml`](.github/workflows/test.yml)
- [x] Confirmed CI does **not** run `docker-compose.test.yml` or any integration test against real services — it only runs `tests/unit/` and a frontend build; the `poc/` real-service verification described above happens in local/manual passes, not CI
- [x] `ruff`/`mypy` both at 0 findings — [`docs/verification-pass-findings.md`](docs/verification-pass-findings.md) §5 P2

---

## Part 3 — Remaining / Known Gaps (checklist, sourced)

### 3.1 Paused by explicit user instruction
- [ ] **Volatility3 memory-forensics module** — research complete (version `volatility3==2.28.0` pinned, sample source found, detection strategy scoped as open question), zero code written. **Paused: wait for the account Claude spend limit to reset/be raised before resuming** — [`reviews/DFIR_Artifact_Landscape.md`](reviews/DFIR_Artifact_Landscape.md) §2

### 3.2 Verification work still open (not bugs — unfinished PoCs)
- [ ] `poc/frontend_browser` — real Playwright pass: keycloak-js login + React app + Dashboards iframe embed, live in a browser. Would also resolve the embed index-pattern question (flag E above) — [`docs/verification-pass-findings.md`](docs/verification-pass-findings.md) §5, item 10
- [ ] Fresh local `pytest` run under the pinned Python 3.11 — this host only has 3.14 available and a 3.14 venv deadlocked in `asyncpg`/`greenlet` native code; needs a proper 3.11 toolchain (pyenv/deadsnakes/container) to re-confirm current counts locally rather than relying on the last captured run
- [ ] `helm lint`/`helm template` re-run — `helm` binary isn't installed on this host; last real run (recorded in `docs/verification-pass-findings.md`) passed after the ConfigMap fix, but that was a different session/environment and hasn't been re-confirmed here
- [ ] Real Kubernetes deployment of `charts/kronos/` — `helm lint` passing is not the same as a real cluster `helm install` — never attempted per any evidence found in this repo

### 3.3 Compliance gaps from `Static_Compliance_Pentest_Review.md`, confirmed still open
(Cross-referenced against `docs/verification-pass-findings.md`'s later fixes — these specific IDs are **not** in either doc's "fixed" list.)
- [ ] **COMP-2** — `kronos-attest case-report` doesn't live-re-read MinIO/Postgres/TSA, only replays an offline export — [`reviews/Static_Compliance_Pentest_Review.md`](reviews/Static_Compliance_Pentest_Review.md) §F, confirmed still open in `docs/verification-pass-findings.md` §"Deferred for other reasons"
- [ ] **COMP-9** — SIEM cold-archive mirroring: bucket provisioned, nothing mirrors Wazuh alerts into it (needs a live Wazuh instance to build/test, never available in any session so far) — same source
- [ ] **COMP-10** — Merkle-anchor domain-separation weakness (hardening, not a break) — `reviews/Static_Compliance_Pentest_Review.md` §F, not in the fixed list
- [ ] **COMP-11** — no `evidence.download` audit event type exists; reads of WORM objects can't be logged — same, not in the fixed list
- [ ] **Prod-mode items explicitly deferred by user instruction, scope limited to dev-mode:** INFRA-001/002/003/007/010/017/019, COMP-6 (MinIO active-active replication), COMP-12 (Vault backup automation / prod running in `-dev` mode) — all specific to `docker-compose.prod.yml`; "will be rebuilt from dev later rather than patched in place" per that review's own remediation note
- [ ] **INFRA-013/016** — real TLS certs / a real signing key are inherently deployment-target concerns, confirmed unfixable in a dev-only pass

### 3.4 SIEM / Observability — config exists, never actually exercised
- [ ] Wazuh, Falco, and Fluent-bit each have a standalone `docker/{wazuh,falco,fluent-bit}/docker-compose.*.yml` — **none of these three files is referenced by `docker-compose.{dev,test,prod}.yml`**, confirmed by inspection in this pass. No PoC in `poc/` exercises any of them against a real event. The custom Wazuh rule pack's field-mismatches found in `Static_Compliance_Pentest_Review.md` (COMP-7) were fixed for the *string values*, but the rules have still never fired against a real Wazuh instance.
- [ ] `docs/runbooks/siem-alert-response.md` — procedures for alerts that have never been shown to fire

### 3.5 Advanced parsing / Celery DAG — largely further along than `roadmap.md` shows, gaps remain
- [x] (Contrary to `roadmap.md`'s unchecked boxes) Plaso via `FirecrackerLauncher`-as-subprocess is real and verified — see Part 1
- [ ] True Firecracker microVM isolation (`network=none`, hardened rootfs) vs. the current subprocess-in-container approach — not verified either way in this pass; `roadmap.md` §3.1/§5.3 describes the target, current PoCs only confirm the subprocess path produces correct output, not that it runs inside an actual microVM sandbox
- [ ] gVisor `runsc` runtime for the fast-parse queue — referenced in `charts/kronos/values.yaml` RuntimeClass names, never confirmed against a real gVisor-enabled node

### 3.6 v2 Features (deferred by product decision, not a gap)
- [ ] Advanced timeline search (full-text, saved searches) — [`roadmap.md`](roadmap.md) §9
- [ ] Case collaboration (comments, activity feed) — same
- [ ] Automated forensic detection rules — same
- [ ] DFIR report generation (HTML/PDF/XLSX) — same
- [ ] API rate limiting / token-based integrations — same

### 3.7 Presentation/analysis layer for `StructuredArtifact` (explicitly out of scope by product direction)
- [ ] No UI or query surface for non-timeline artifact `content` yet — deliberate, "on réfléchira plus tard" — [`reviews/Data_Source_Module_System.md`](reviews/Data_Source_Module_System.md) §9

---

## Part 4 — Notes for the Next Person Updating This Document

- Update this file, not `roadmap.md` or the old-style per-phase completion tables, when new work lands — this is now the single source of truth for "what's actually true," cross-checked against code/PoCs rather than restated from other docs.
- When you close an item from Part 3, move it to Part 2 with the commit/PoC that proves it, and add a Part 1 row only if you (or an automated run) actually executed it against the real dependency.
- If you find another doc (a `reviews/Part_N_Review.md`, `docs/SECURITY_AUDIT.md`, etc.) making a claim that contradicts this file, this file wins only if its claim is itself sourced to a real run — otherwise, re-verify before trusting either.
