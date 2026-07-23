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
verified E2E). **Update (2026-07): Track C (containers/images) shipped for
ZIP + E01** — see that section below and `poc/kape_ingestion_test/` for the
real end-to-end verification. This also verified a *slice* of Track A's
Plaso-E2E exit criterion for real, as a side effect: the E01 test drove
real `log2timeline`/`psort` output for prefetch, volume-metadata, and
EVTX-via-Plaso content (not the `plaso:placeholder` stub) — registry hive
and a real Plaso-routed SQLite artifact are **still unverified**, so that
exit criterion stays open below.

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
      matrix without new code. **Prefetch: done** (real run via both
      `poc/full_ingestion_test/` and `poc/kape_ingestion_test/`, genuine
      `windows:prefetch:execution` events, not the placeholder). **Registry
      hive and a real Plaso-routed SQLite artifact: still open.**

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

## Track C — Containers & disk images (DONE for ZIP + E01, 2026-07)

**Goal:** ingest the *actual* output of a KAPE collection — a `.zip` or a
disk image (E01/raw/VHDX/VMDK) full of artifacts — by exploding it into
inner files and re-dispatching each to the (now-deepened) parser layer, with
the path-in-image recorded. Shipped with one deliberate simplification vs.
`Extensibility_Architecture_Proposal.md`'s original phasing — see below.

- [x] **C0 — Provenance fields.** Done: `source_path` + `container_sha256`
      added to `KronosProvenance` (`src/domain/timeline.py`, additive),
      surfaced as ECS `file.path` (`src/application/timeline_normalization.py`)
      and mapped in the OpenSearch index template.
- [x] **C1 — ZIP recursive re-dispatch.** Done, but as a **simplification**:
      shipped as `ZipArchiveParser` (`src/external/parsers/archive.py`), a
      `ForensicParser` subclass registered first in `ParserRegistry`, instead
      of the originally-sketched separate `ArchiveExtractor` ABC +
      `ExtractorRegistry` + new orchestration branch. This meant **zero**
      changes to `ParsingOrchestrationService`'s control flow — it still
      just "resolve one parser, call parse(), get records" — which shipped
      and verified in one pass instead of a parallel dispatch path. Real
      zip-bomb guards (max depth via `ContextVar`, max total bytes actually
      read — never trusting `ZipInfo.file_size` — max member count) and a
      zip-slip path-traversal guard, all with real tests
      (`tests/unit/parsers/test_archive.py`). GZIP is **not** done.
      Verified end-to-end against a real KAPE-shaped zip
      (`poc/kape_ingestion_test/`, 4 different inner parsers dispatched from
      one container).
- [x] **C2 — Disk images: E01 only, via whole-image Plaso fallback.** Done
      for **EWF/E01** specifically (`PlasoParser.supports()` detects the
      real EWF magic; `log2timeline`'s own dfVFS auto-detection walks the
      image, no new extractor code needed since dfVFS is already a real
      Plaso dependency). raw/dd, VHDX, VMDK, QCOW are **not yet triggered**
      (same mechanism would likely work, unverified). Per-event
      `source_path` comes from Plaso's own `display_name`/`filename` field,
      gated on the dfVFS type-indicator prefix so a single-file parse's
      local temp path is never mistaken for a real in-image path (see
      `src/external/sandbox/firecracker.py::_plaso_source_path`). A real,
      reproducible Plaso/dfVFS/libewf interop bug was found and worked
      around while building the E01 test fixture — a **FAT12** filesystem
      inside the EWF silently drops all real file content (only directory
      `fs:stat` events survive); FAT16 does not have this problem — see
      `tests/fixtures/samples/real/kape/NOTICE.md`.
- [x] **C3 — Sub-evidence model decision.** Resolved as recommended:
      inner artifacts stay under the **same** `Evidence`/custody entry —
      no child `Evidence` rows. `kronos.source_path`/`container_sha256`
      alone distinguish them, avoiding FSM/schema churn.

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
