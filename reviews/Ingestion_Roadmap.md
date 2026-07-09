# Ingestion & Parsing Roadmap — Next Steps

**Status:** living roadmap (2026-07-09). Scope: the evidence
detection → parsing → mapping → ingestion pipeline and its extensibility.
Complements the two design docs it depends on:

- `reviews/KAPE_Coverage_Analysis.md` — what artifacts we cover vs. KAPE.
- `reviews/Extensibility_Architecture_Proposal.md` — the container /
  disk-image / dynamic-plugin design this roadmap sequences.

This is **workstream-level** sequencing for the ingestion pipeline; it does
not replace the repo-wide `roadmap.md` (frontend/infra/Helm/CI).

---

## Where we are (done)

Recent work already merged on `fix/evidence-upload-camelcase`:

- Pipeline **wired end-to-end** (upload → parse → OpenSearch), Plaso worker
  service building, OpenSearch ISM 409 tolerated, auth refresh self-healing,
  admin/Keycloak org endpoints fixed.
- Parser **correctness pass** against real forensic samples (Plaso test
  corpus): fixed nginx (dropped 9/15 real lines), CloudTrail (Lake/S3 NDJSON
  shape), prefetch (uncompressed SCCA). Added
  `tests/unit/parsers/test_real_world_samples.py` + `tests/fixtures/samples/real/`.
- "No parser found" now cleanly fails evidence → ERROR instead of hanging.
- Gap analysis + extensibility architecture written.

Baseline today: **EVTX, AWS CloudTrail, nginx/Apache logs** parse cleanly;
**prefetch, registry hives, SQLite, journald** go through Plaso (coverage
gated by `PlasoParser.supports()`, Plaso worker output not yet fully
verified E2E).

---

## The plan, in order

The three tracks below are **sequential by intent** (per product direction):
stabilize first, then deepen parsers, then build the image/container system.
Track A runs until the reported-bug backlog is drained; B and C are gated on
A being quiet.

---

## Track A — Stabilization (NOW: incoming bug reports)

**Goal:** the existing happy path (upload a single supported artifact → see
its timeline in OpenSearch) is rock-solid for every format we claim to
support, before adding surface area. **User will submit new bugs; this track
absorbs them.**

Working method for each reported bug (the loop we've been running):

1. Reproduce against a **real sample file** — add it to
   `tests/fixtures/samples/real/` if it's a new artifact/shape (with
   provenance in `NOTICE.md`).
2. Write a failing test that drives the **real code path**
   (`ParserRegistry.get_parser` → `parse` → normalize), not a hand-crafted
   fixture that just matches the parser.
3. Root-cause (not bypass), fix, verify: full unit suite + `ruff`/`black`/
   `mypy` clean, confirm pre-existing lint/type counts unchanged.
4. One focused commit per bug, pushed to the working branch.

Exit criteria for Track A:

- [ ] No open reported ingestion bug.
- [ ] Every currently-registered parser has at least one **real-sample**
      regression test (EVTX ✅, CloudTrail ✅, nginx ✅, prefetch-detect ✅ —
      registry/SRUM/journald still synthetic-only).
- [ ] Plaso worker **verified E2E**: confirm it emits real events (not the
      `plaso:placeholder` stub) for registry hive, SQLite, and prefetch on a
      real run — this validates a large "🟡 partial" swath of the KAPE
      matrix without new code. (Currently unverifiable in-sandbox; needs a
      real Docker run.)

---

## Track B — Parser depth & coverage (NEXT: after bugs settle)

**Goal:** close the highest-value single-file artifact gaps from the KAPE
matrix, and make the parser layer ready to be fed many files by Track C.
Order = impact/effort from `KAPE_Coverage_Analysis.md §6`.

- [ ] **B1 — Verify & harden the Plaso path.** Turn the dev subprocess stub
      into a verified parser: real `log2timeline`/`psort` invocation, map
      Plaso's schema (`datetime`, `timestamp_desc`, `source_short`,
      `message`, `parser`, …) cleanly onto `TimelineRecord`, `--parsers`
      filtering by artifact type for speed. Cements registry/SQLite/prefetch
      coverage.
- [ ] **B2 — `$MFT` parsing.** Richest Windows timeline artifact,
      universally collected. Add a `supports()` trigger (`FILE0`/`BAAD`
      signature or `$MFT` name) and route to Plaso; verify output.
- [ ] **B3 — LNK + JumpLists.** Cheap, high-signal, Plaso-supported — needs
      detection routing.
- [ ] **B4 — ESE database routing** (SRUM `SRUDB.dat`, SUM, `Windows.edb`,
      BITS). Distinct from SQLite; detect ESE magic (`\xef\xcd\xab\x89` at
      offset 4).
- [ ] **B5 — CSV parser.** Ingest pre-parsed **EZ Tools CSV** (MFTECmd /
      EvtxECmd output) and audit-log CSV exports. Also the groundwork for
      "KAPE-output modules" in Track C / Extensibility Phase 4.
- [ ] **B6 — Mapping consistency review.** Ensure every parser fills the same
      ECS core fields consistently (`event.category`/`type`, `host.name`,
      `user.name`) so cross-source timeline queries behave. One normalization
      audit across all parsers.

Each B item follows the Track-A method: real sample + real-path test +
root-caused mapping.

---

## Track C — Containers & disk images (LATER: the big one)

**Goal:** ingest the *actual* output of a KAPE collection — a `.zip` or a
disk image (E01/raw/VHDX/VMDK) full of artifacts — by exploding it into
inner files and re-dispatching each to the (now-deepened) parser layer, with
the path-in-image recorded. Follows
`Extensibility_Architecture_Proposal.md` phasing.

- [ ] **C0 — Provenance fields.** Add `source_path` + `container_sha256` to
      `KronosProvenance` (additive), surface as ECS `file.path`. Ships before
      extractors so the schema is ready. *(Trivial, do first.)*
- [ ] **C1 — `ArchiveExtractor` + ZIP/GZIP.** New ABC (separate from
      `ForensicParser`), `ExtractorRegistry`, and bounded **recursive
      re-dispatch** of inner artifacts through `ParserRegistry`. **Zip-bomb
      guards** (max depth, max total bytes, max file count, per-file cap →
      ERROR, never OOM). *This is the #1 real-world gap — a KAPE `.zip`
      upload is the most likely thing an examiner actually sends.*
- [ ] **C2 — `DiskImageExtractor` on dfVFS.** E01/Ex01, raw/dd, VHDX, VMDK,
      QCOW, read-only path-spec walk; per-event `source_path` from the image;
      **whole-image → Plaso fallback** for coarse "just parse everything".
      Higher risk (native libs, must run sandboxed).
- [ ] **C3 — Sub-evidence model decision** (see Extensibility §6.1): inner
      artifacts as child records under one custody entry (recommended) vs.
      full child `Evidence` rows. Resolve before C1 lands in prod, as it
      shapes schema + FSM.

---

## Track D — Dynamic plugins (FUTURE: security-critical, do deliberately)

**Goal:** third-party / customer-supplied parsers and KAPE-output modules,
**without ever letting a module leak client data**. Explicitly gated behind
Tracks A–C being solid; this is the last thing built, on purpose.

- [ ] **D1 — Generalize `FirecrackerLauncher` → `SandboxedExternalParser`.**
      The single mechanism for untrusted code: bytes in (stdin/vsock), JSONL
      out, **no network, no secrets, ephemeral read-only rootfs**,
      CPU/RAM/timeout caps, output schema-validated at the trust boundary.
- [ ] **D2 — Two-tier registry.** First-party in-process parsers **always
      win** over sandboxed third-party ones; plugins loaded from a
      **Cosign-verified, Trivy-scanned, manifest-declared allowlist** — never
      ambient import.
- [ ] **D3 — Real sandbox substrate.** Replace the dev subprocess stub with
      gVisor/Firecracker for Tier-2 code (non-optional for untrusted
      plugins); startup confinement self-test (no-egress / no-secrets
      assertions) before any evidence is accepted.
- [ ] **D4 — KAPE-output modules.** EZ Tools CSV mappers as sandboxed
      parsers (builds on B5 + D1).

**Non-negotiable invariant across D:** the tenant index name is always
computed by KronOS from the authenticated `TenantContext`, never from plugin
output — a plugin can never cross tenant boundaries or exfiltrate evidence.

---

## Dependency graph

```
Track A (stabilize) ──► Track B (parser depth) ──► Track C (containers/images)
     always-on              B1 gates C's value        C0 ► C1 ► C2
                                                        │
                                                        ▼
                                              Track D (plugins, sandboxed)
                                              D1 ► D2 ► D3 ► D4  (needs B5 for D4)
```

- A is a rolling prerequisite (don't build on shifting sand).
- C's payoff depends on B (extraction only helps if the parsers it feeds are
  good and verified).
- D depends on C1's re-dispatch plumbing and B5, and must not start before
  the sandbox substrate (D3) is real.

---

## Immediate next action

Awaiting the **new bug reports** (Track A). Each will be reproduced with a
real sample, fixed at root cause, covered by a real-path regression test,
and pushed as a focused commit — same loop as the last batch.
