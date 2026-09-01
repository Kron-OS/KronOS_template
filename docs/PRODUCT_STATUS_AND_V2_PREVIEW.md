# KronOS — Product Status & v2 Preview

**Purpose of this document:** a single, honest, product-level snapshot —
what KronOS actually does today (verified, not aspirational), what's
planned for v2, and what's genuinely still missing or rough. Written to
give a reader (technical or not) an accurate preview of the tool without
having to read `PROGRESS.md`'s full sourced checklist, `roadmap.md`'s
original design doc, `docs/NEXTGEN_SOC_ROADMAP.md`'s deep technical
backlog, or the ~30-entry `docs/GAP_AUDIT_2026-08-28_MILESTONE_*.md`
trail this document distills.

**How this was produced:** every claim below is sourced to real,
independently-verified work — a `poc/*/README.md` with captured output,
a passing test, a real E2E spec, or a specific, cited gap-audit doc — not
inferred from what "should" work. Where something is uncertain or
unverified, it's stated as such below, not rounded up.

---

## 1. What KronOS does today (v1)

KronOS is a forensically-sound, multi-tenant evidence-management and
timeline-analysis platform, moving toward a broader next-gen SOC/CERT
incident-response platform. As of this document, the following is real,
built, and verified:

### Evidence intake & forensic parsing
- Upload evidence (any file) through a real, resumable, hash-verified
  pipeline: client-side magic-byte pre-check → presigned MinIO upload →
  server-side validate/scan (ClamAV)/hash/promote → autonomous parse →
  OpenSearch indexing — entirely server-driven after the client's initial
  upload call, per the platform's own non-negotiable pipeline-autonomy
  rule (`CLAUDE.md` §E).
- **Every parser this platform ships has real, verified coverage**,
  fast-path and heavy-path alike:
  - FAST tier (evtx-rs, nginx/Apache logs, Suricata EVE JSON, Chrome
    History, AWS CloudTrail) — each has a dedicated, CI-wired real
    browser E2E test using genuine forensic sample data.
  - HEAVY tier (Plaso — Prefetch/registry/journald/SQLite via
    `log2timeline`; ZIP/tar container recursion including a real,
    reproduced incident where a `.E01`-named file was actually a tar
    archive; EWF/E01 raw disk-image whole-image parsing; Volatility3
    memory-forensics, pstree/psscan) — each verified against real
    forensic artifacts (real Windows Prefetch, a real EWF image built
    with `ewfacquirestream`, a real memory dump), CI-wired where the
    fixture size allows it (Volatility's own 512 MiB sample is
    deliberately never committed — verified via a real, re-runnable PoC
    script instead).
- A real, found-and-fixed bug class along the way: `CloudTrailParser`
  used to break on a real, common AWS event shape (service-linked events
  where `sourceIPAddress` is a hostname, not an IP) — found only because
  a synthetic test fixture was swapped for a genuinely real one.

### Chain of custody & forensic integrity
- Append-only audit log with a real SHA-256 hash chain per row.
- Daily Merkle-tree anchoring with **real RFC 6962-style domain
  separation** (closing a CVE-2012-2459-class weakness), cross-validated
  between the backend's own implementation and the standalone
  `kronos-attest` CLI's independently-packaged copy.
- Real RFC 3161 trusted timestamping.
- `kronos-attest` — a standalone attestation CLI that can verify a case's
  full chain **live**, re-reading Postgres/MinIO/the TSA directly (not
  just replaying a static offline export), with real evidence byte-level
  re-hashing against MinIO to catch tampering.
- A real, `evidence.download` audit event closes the "was every WORM
  read logged, not just writes" compliance gap.

### Multi-tenancy, RBAC & security
- Keycloak 26+ Organizations for tenant isolation; per-tenant OpenSearch
  Document-Level Security; real cross-org isolation verified via a fresh
  org + fresh member navigating directly to another org's case (a real
  404, not a client-side redirect that only looks safe).
- **Every RBAC/authz boundary the platform defines has real, live
  end-to-end proof, on both the denial and the grant side**: a pure role
  check, an ownership/membership check for read access, and a stricter
  ownership check for mutating actions (add member, delete, legal hold) —
  each independently verified with a real, distinct account, not just
  read off the route decorator.
- Step-up (RFC 9470, `acr=aal2`) MFA for sensitive actions, real TOTP.

### Frontend
- A real React 19 + TanStack Router SPA: case/evidence management, live
  SSE-driven status updates (with a real, found-and-fixed reconnect race
  affecting both the parse-retry and intake-retry paths), detection
  triage, an embedded OpenSearch Dashboards timeline view, org
  administration.
- **Automated accessibility coverage**: a real `@axe-core/playwright`
  WCAG scan across every real page, CI-wired — 3 real violations (two
  color-contrast failures, one missing accessible name on an admin
  control) were found and fixed this way, not by manual review.
- **Automated visual regression** on the status/triage pill components
  specifically (the ones that encode meaning purely through color),
  proven to actually catch a real accidental color-class change.
- **Resilience**: a real backend-unreachable scenario and a real
  mid-upload SSE-drop scenario both confirmed to degrade gracefully
  (error banners, automatic reconnect/poll fallback) rather than freezing
  or crashing — both already worked correctly when finally tested, a
  genuine (not assumed) confirmation.

### CI & verification discipline
- A real, maintained Playwright E2E suite (`frontend/e2e/`), not a
  scattering of one-off scripts — every scenario in
  `docs/PLAYWRIGHT_E2E_TEST_PLAN.md`'s own catalogue (§3.1 through §3.8)
  now has real, committed coverage.
- A verification-first discipline (`CLAUDE.md` §F) enforced throughout:
  no integration is called "done" without being run against a real
  dependency with captured, inspected output. This discipline has itself
  repeatedly found real bugs a code review alone would have missed — a
  15-second case-creation hang, a silent empty-timeline bug (Dashboards
  hardcoded a 30-day window against forensic data that's always older),
  a production deployment gap (the HEAVY-tier Celery queue had zero
  consumer in `docker-compose.prod.yml`), among others.

---

## 2. What's planned for v2

These are deliberately **not** built yet — a product decision, not an
oversight, per `roadmap.md` §9:

- **Advanced timeline search** — full-text search across ingested
  timeline data, saved/reusable searches.
- **Case collaboration** — comments, an activity feed, more collaborative
  investigation workflows beyond the current case-membership model.
- **Automated forensic detection rules** — rules that fire directly off
  parsed timeline data (distinct from the existing OpenSearch Security
  Analytics detector pipeline, which already runs 2,000+ prepackaged
  Sigma rules against ingested logs — see
  `docs/NEXTGEN_SOC_ROADMAP.md` for that separate, already-substantially-built
  effort).
- **DFIR report generation** — HTML/PDF/XLSX case reports for external
  handoff (distinct from `kronos-attest`'s own machine-readable
  attestation report, which exists today).
- **API rate limiting / token-based integrations** — programmatic,
  non-interactive API access for external tooling.
- **A presentation/analysis layer for non-timeline forensic artifacts**
  (`StructuredArtifact` — e.g. Volatility's process trees/listings).
  The data is captured and stored safely today; there is deliberately no
  read API or UI for it yet (`CLAUDE.md` §G.2's own stated direction:
  "capture and store safely now, design presentation/analysis later").
  When this gets built, the natural shape is a
  `GET /api/cases/{id}/evidence/{evidence_id}/artifacts` read endpoint
  plus a per-`kind` rendering layer (a process-tree view, a table for
  scan listings, etc.) — not designed yet, deliberately, since no
  consumer exists to design against.

---

## 3. Known limitations (honest gaps, not hidden)

### Verification infrastructure

- **No workflow on this branch has ever executed on GitHub's own
  infrastructure.** Every piece of CI-wired coverage described in §1 is
  real, locally-verified against real dependencies — but GitHub only
  evaluates a workflow's `schedule:` trigger from the *default* branch,
  and every workflow here (including `push`/`pull_request` triggers)
  only fires for `main`, which this work has never been merged into. The
  job definitions are correct and proven to work when run; none of them
  has an independent, automatic confirmation on GitHub's own runners
  yet. Closing this needs either a manual `workflow_dispatch` by someone
  with repo access, or a merge to `main`.
- A handful of specs are real but deliberately **not** CI-wired, each for
  a stated, specific reason rather than being forgotten: the Dashboards
  embed spec (the CI compose profile's own `opensearch-dashboards`
  service is a DNS-only stub, no real Dashboards content to assert
  against there), the pill visual-regression spec (real font-rendering
  can differ between this host and a GitHub Actions runner's default
  system font, and there's no real GHA run yet to generate a trustworthy
  CI-side baseline against), and the Volatility memory-forensics pipeline
  (the real fixture is 512 MiB and is deliberately never committed to
  the repo — verified via a real, re-runnable script instead of an
  automated test).
- One test-stack-profile spec (a CI-wired twin of the intake-stage retry
  test) is code-complete and config-validated but has not actually been
  run end-to-end against a real isolated test-stack instance — a real,
  measured host memory constraint (not a code problem) stopped that dry
  run.

### Architecture gaps vs. documented design intent

- **"Firecracker microVM" isolation is not actually a Firecracker
  microVM.** Despite the name in the code, heavy parsing (Plaso,
  Volatility) runs as a sandboxed *subprocess in a container*, not
  inside a real Firecracker microVM. Functionally verified correct;
  the isolation boundary is real (container-level sandboxing) but weaker
  than the documented target.
- **SIEM integrations are configured but never wired in or exercised.**
  Wazuh, Falco, and Fluent-bit each have a standalone Docker Compose
  file, but none is referenced by any of the shipped
  `docker-compose.{dev,test,prod}.yml` profiles, and no rule has ever
  fired against a real event. This is also why one compliance
  requirement (cold, write-once SIEM archive mirroring) remains open —
  it needs a live Wazuh instance to build and test against, which has
  never been available in any verification session so far.
- **No real Kubernetes deployment has ever been attempted.** The Helm
  chart passes `helm lint`; a real `helm install` against a real cluster
  has not been tried.

### Coverage gaps, named and tracked (not urgent, not hidden)

- `StatusPill`'s transient pipeline states (uploading, scanning, hashing,
  etc.) have no visual-regression coverage — they're sub-second-to-
  few-second states with no deterministic way to freeze the real
  pipeline on them yet without meaningfully heavier fault-injection
  machinery per state.
- The stricter case-lead ownership RBAC check's own ALLOW branch (a
  case-lead successfully mutating a case they genuinely own) is
  implicitly exercised by an existing spec's own setup step, but has
  never been asserted on as its own explicit scenario.
- Two simultaneous dependency failures, or a degraded-but-not-fully-down
  dependency (a slow response rather than a hard connection refusal),
  have no test coverage — every existing fault-injection spec targets
  exactly one dependency, fully down.

### Tooling/environment gaps on the current verification host

- This host only has Python 3.14 available; the project's own CI still
  pins Python 3.11. A 3.14 venv on this host *used to* deadlock inside
  native `asyncpg`/`greenlet` code during test collection (a real,
  observed `SIGABRT`) — that is **no longer reproducible**: re-verified
  2026-09-01 (Milestone PPPP) with a fresh full-suite run,
  `2056 passed, 2 skipped in 29.87s`, coverage gate passed at 90.39%.
  Whatever native-wheel mismatch caused the original deadlock was
  evidently resolved by a later `pip install`/venv rebuild between
  sessions. A real Python 3.11 toolchain is still not installed on this
  host, so CI's own pinned-version behavior can't be independently
  reproduced locally, but a fresh local `pytest` run is no longer blocked.
- ~~The `helm` binary is not installed on this host~~ — corrected
  2026-09-01 (Milestone PPPP): it IS installed (`/usr/local/bin/helm`,
  `v3.16.4`); the prior claim was stale. Re-confirmed both `helm lint
  charts/kronos` (clean, one informational note only) and `helm template
  kronos charts/kronos` (real, clean render, 57 resources across 11
  kinds) live on this host. What's still genuinely true: a real `helm
  install` against a real Kubernetes cluster remains unattempted — no
  cluster is available in this verification environment.

### Explicitly out of scope by prior product/user decision

- Production-mode hardening (MinIO active-active replication, Vault
  backup automation, several infrastructure-hardening items specific to
  `docker-compose.prod.yml`) — explicitly deferred: "will be rebuilt
  from dev later rather than patched in place."
- Real TLS certificates and a real code-signing key are inherently
  deployment-target concerns, not something a dev-mode verification pass
  can meaningfully close.

---

## 4. The honest one-paragraph summary

KronOS's core forensic pipeline — intake, every parser it ships,
chain-of-custody, RBAC, and the frontend that drives all of it — is real,
built, and has been verified against real dependencies repeatedly, with a
track record of that verification process itself catching genuine,
previously-unknown bugs rather than rubber-stamping assumptions. What's
missing is concentrated in three honest categories: features deliberately
deferred to v2 (search, collaboration, reporting, rate-limiting), SIEM/
Kubernetes integrations that are scaffolded but not yet wired in or
exercised against anything real, and one structural gap in the
verification story itself — none of this has yet been independently
confirmed by GitHub's own CI infrastructure, only by real, repeated,
locally-run verification.
