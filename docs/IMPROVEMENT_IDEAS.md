# KronOS — Ideas to Make the Tool More Valuable, Powerful, and Beautiful

**Status:** brainstorm/prioritization list, not a commitment or a roadmap —
same spirit as `reviews/DFIR_Artifact_Landscape.md`'s own §11
("impact vs. effort, not a commitment"). Grounded in what's actually built
(M0-M8 closed, six parsers, real SOC detection/response stack) and in gaps
this repo has already found and documented, not generic suggestions.

## 1. Highest-leverage: close what's already been found and parked

These aren't new ideas — they're real, named gaps this repo's own
verification passes already surfaced. Closing them is the highest-confidence
way to add value, precisely because the investigation cost is already paid.

- **Wire the SIEM stack that already exists but has never fired.** Wazuh,
  Falco, and fluent-bit each have a real `docker-compose.*.yml` sitting
  unreferenced by the main stack (`docs/NEXTGEN_SOC_ROADMAP.md` §0). A
  platform calling itself a "SOC/CERT platform" with zero live SIEM signal
  flowing in is a real, visible gap to anyone evaluating it seriously —
  and the config work (custom Wazuh rule pack) is already partially done.
- **`kronos-attest case-report` doesn't live-re-read MinIO/Postgres/TSA** —
  it only replays an offline export (COMP-2). For a platform whose whole
  pitch is court-admissible chain of custody, the flagship CLI command for
  producing a *court-facing report* not actually re-verifying live state
  at report time is a real credibility gap, not just a missing feature.
- **Volatility3 module beyond pstree/psscan** — memory forensics is
  arguably the single most differentiating DFIR capability versus a
  generic log-analysis tool, and the hard infrastructure (sandboxed
  runtime, worker image, queue routing) is already built and proven for
  two plugins. Extending plugin coverage (`malfind`, `netscan`, `dlllist`,
  `cmdline`) is now mostly plugin-wiring effort, not new architecture.
- **A real Kubernetes deployment of `charts/kronos/`** has never been
  attempted (`helm lint`/`template` pass, `helm install` against a live
  cluster does not). For anyone evaluating this for real production use,
  "the Helm chart has never actually been installed" is a material
  credibility question a prospective adopter will ask immediately.
- **Real browser E2E coverage** (see `docs/PLAYWRIGHT_E2E_TEST_PLAN.md`,
  written alongside this list) — the frontend has real bugs been found by
  hand three separate times this session (SSE field-name mismatch, magic-byte
  gap, retry-button unverified) that a maintained suite would catch
  automatically going forward instead of by user bug report.

## 2. Product value: what would make an analyst *want* this over a competitor

- **AI-assisted triage narrative generation.** KronOS already has
  everything needed to generate a real, grounded incident narrative — real
  `Detection` rows with ATT&CK tags, real matched timeline events, real
  correlation data, real audit trail. A `DetectionSummaryService` that
  feeds an LLM the *real* structured data (never asking it to invent facts)
  to produce a first-draft analyst narrative — "what happened, in what
  order, on what host, matching which techniques" — would cut real analyst
  time on the single most repetitive part of triage. This is squarely in
  reach given the extensibility idiom already in place (mirrors
  `RiskScoreBreakdown`'s "explainable, sourced" precedent — an LLM
  narrative must cite which real Detection/timeline fields it used, not
  free-associate).
- **A real "case timeline" cross-evidence view** — today, timeline data is
  queried per-case via OpenSearch/Dashboards, but there's no first-party
  KronOS UI that shows *one unified, cross-evidence, cross-parser* story
  for a case (an EVTX logon at 14:02, a CloudTrail API call at 14:03, a
  Suricata connection at 14:04, one visual timeline). This is the
  "Harfanglab-style graph" the v2-features list already named and
  deferred — worth reconsidering now that the backend data model to
  support it (unified ECS schema across all parsers) is mature.
- **Detection validation as a product feature, not just an internal
  harness.** I1 built a real regression harness proving rules still fire
  on ATT&CK-technique-shaped telemetry — expose a *customer-facing*
  "detection health" dashboard (using I2's own new `MetricCalculator`
  framework) showing real coverage/fire-rate/MTTD per org over time. Most
  competing SIEM/detection products don't expose this kind of honest
  self-assessment to the customer; doing so is a real differentiator, not
  just an internal QA tool.
- **Rule-pack marketplace / sharing.** `RulePack`/`CustomRule` versioning
  and Cosign-signed third-party packs already exist (C3). A curated,
  in-product catalogue of vetted community/vendor rule packs (signed,
  versioned, one-click subscribe per org) turns an internal extensibility
  mechanism into a real network-effect feature.
- **Cost/scale transparency for the buyer.** The tenant-quota work landing
  alongside this list is the first building block; extending it into a
  real per-org usage *dashboard* (via I2's metrics framework) — "you're at
  62% of your storage quota, ingest rate trending up 8%/week" — turns a
  purely defensive cost-control feature into a value-add self-service tool.

## 3. Technical robustness & power

- **A real migration tool.** Several new Postgres columns this session
  landed with a comment like `create_all only adds missing TABLES, not
  columns... needs a real one-time manual ALTER TABLE` (risk_score,
  risk_factors, external_ticket_id, and now storage quota). This is
  accumulating real production risk. Adopting a real migration tool
  (Alembic is the standard SQLAlchemy-ecosystem choice, matching this
  repo's existing `sqlalchemy`/`asyncpg` stack) would retire this whole
  class of "did the deployed DB actually get this column" risk.
- **A cached/rate-limited layer in front of `TenantUsageService`'s
  `SUM(size_bytes)` query** once it's live and its real-world query cost
  is measured (I5's own performance-validation discipline applies here:
  measure first, optimize only if the real number demands it).
- **`OpenSearchClient.bulk_index`'s silent partial-failure mode (A4)** —
  flagged, still open. A single dropped document in a case is exactly the
  kind of quiet data-loss bug that erodes trust in a forensic tool
  specifically, more than in an ordinary web app.
- **Real Firecracker microVM isolation** for the Plaso/heavy-parse path —
  currently a subprocess-in-container, not the hardened microVM the
  design docs describe. For a tool that regularly ingests attacker-
  controlled artifacts (a malicious KAPE collection literally triggered a
  real ClamAV detection this session), the gap between "sandboxed
  container" and "hardened microVM with no network" is a real security
  posture difference worth closing before handling hostile input from
  external customers.
- **Structured-artifact presentation layer** — `StructuredArtifact.content`
  is deliberately schema-less today ("capture now, design later," per
  `Data_Source_Module_System.md`). As Volatility/YARA/other non-timeline
  modules grow, a real query/visualization surface for this data (even a
  simple typed-by-`kind` renderer registry, mirroring `ParserRegistry`'s
  own extensibility idiom) turns already-collected data into something an
  analyst can actually use without reading raw JSON.
- **A real CI-capable, security-enabled compose profile** (already named
  as a prerequisite in the Playwright plan and in I1's own findings) — this
  unblocks not just E2E tests but any future integration test needing a
  real security-enabled OpenSearch/Keycloak pair in CI, a recurring blocker
  named independently by at least two different roadmap items now.

## 4. Beauty / UX polish

- **A real design pass on the "status color language."** `StatusPill`/
  `TriageStatePill` encode meaning through color across evidence states
  and triage states — worth a deliberate, documented color system (and a
  real a11y contrast audit, per the Playwright plan's §3.8) rather than
  whatever ad hoc choices accumulated per-component over time.
- **Empty states and first-run experience.** A brand-new org's `CasesPage`/
  `DetectionsPage` with zero data is a real first impression moment for
  every new customer — worth deliberate design (a real "create your first
  case" guided empty state) rather than a bare empty table.
- **Command palette / keyboard-driven navigation** (a `cmd+k` style
  quick-switcher across cases/evidence/detections) — analysts working a
  live incident value speed; this is a well-understood, high-perceived-
  value pattern in comparable professional tools (Linear, GitHub) that
  this codebase's existing TanStack Router + Zustand stack could support
  without a major architecture change.
- **Real-time collaborative presence** — already named and deferred in
  `roadmap.md`'s v2 list (CRDT/Yjs) for good reason (real complexity), but
  worth reconsidering a *much* smaller version first: just "who else is
  looking at this case right now" (presence, no shared editing) is a
  small fraction of the complexity and most of the perceived value for a
  SOC where multiple analysts often work the same incident.
- **Dark mode** (if not already fully covered by the Tailwind v4 setup —
  worth an explicit audit; a security tool used in dim SOC rooms during
  overnight shifts has a genuine, not just cosmetic, reason to get this
  right, unlike most consumer apps).
- **Dashboards embed polish** — the iframe embed already auto-opens the
  right case/timeline (a real, hard-won fix this session), but the visual
  seam between the KronOS shell and the embedded OpenSearch Dashboards
  chrome is a place where "powerful backend, bolted-on-looking frontend"
  perception risk lives; worth a deliberate look once real browser E2E
  coverage (§3.6 of the Playwright plan) makes iterating on it safe.

## 5. Longer-horizon / bigger bets

- **Multi-org user support** (already named in `roadmap.md`'s v2 list —
  the JWT shape is already multi-org-ready, the backend just reads the
  first org today). This unlocks MSSP/consultant use cases (one analyst
  legitimately working multiple client orgs) that the current single-org-
  per-session model structurally can't serve.
- **A real "detection-to-evidence-to-report" one-click workflow** —
  chaining H3 (detection-triggered evidence collection), the metrics
  framework, and `kronos-attest`'s report generation into a single guided
  flow ("this detection escalated → here's the collected evidence → here's
  a draft court-ready report") would visibly demonstrate the SOC-and-
  forensics synthesis this platform's whole architecture was built around,
  as one coherent product moment rather than three separate features an
  analyst has to know to chain together themselves.
- **Track D (sandboxed third-party/customer-supplied parser execution)** —
  still gated behind first-party modules being solid, per
  `Extensibility_Architecture_Proposal.md` §4. This is the mechanism that
  would let KronOS become a genuine platform (partners/customers shipping
  their own vetted parsers) rather than a fixed set of six first-party
  ones — high effort, but the single biggest lever on long-term
  extensibility and ecosystem value.
