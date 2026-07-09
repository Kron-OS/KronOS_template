# Extensibility Architecture Proposal — Containers, Disk Images & Dynamic Plugins

**Status:** design proposal (2026-07-09). No code change yet — companion to
`reviews/KAPE_Coverage_Analysis.md`.

**Goal.** Let KronOS ingest the *output of a KAPE triage collection* — which
arrives as a **ZIP archive** or a **forensic disk image** (E01, raw/dd,
VHDX, VMDK, …) containing many artifact files — and become **extensible**
with:

1. dynamically loaded **parsers** (new artifact formats, incl. third-party /
   customer-supplied), and
2. dynamically loaded **KAPE-output modules** (interpret a target's
   collected files / EZ Tools CSVs).

**Hard constraint (drives the whole design).** A processing module must
**never be able to exfiltrate client data**. Forensic evidence is the most
sensitive data KronOS holds; a malicious or buggy third-party parser that
can open a socket, read Vault/MinIO credentials, or see another tenant's
bytes is an unacceptable, multi-tenant-breaking data leak. Security and
maintainability are therefore the two axes everything below is judged on.

---

## 1. Research summary

### 1.1 KAPE output shape (what we must ingest)

- A KAPE run produces a **directory tree**: raw collected artifacts
  (`Targets`) and/or parsed CSV/JSON (`Modules`, usually EZ Tools format),
  plus a timestamped execution log.
- Examiners hand this off as a **container**: a `.zip` (most common), or a
  **disk image** the collection was pulled from.
- So the unit of upload is no longer "one artifact = one parser". It is
  "one container → N inner artifacts, each with a **path inside the
  container/image**, each needing its own parser".

### 1.2 Disk-image formats (via dfVFS)

Plaso already depends on **dfVFS** (Digital Forensics Virtual File System),
which is the right abstraction to read images without mounting them.
dfVFS supports, among others
([dfVFS supported formats](https://dfvfs.readthedocs.io/en/latest/sources/Supported-formats.html)):

| Family | Formats | Backing lib |
|---|---|---|
| Expert Witness | EWF `E01`/`Ex01`/`S01` | libewf / pyewf |
| Raw | `dd`, `raw`, split raw | (native) |
| Virtual disks | VHD, **VHDX**, VMDK, QCOW1/2/3 | libvhdi, libvmdk, libqcow |
| Volume/FS | GPT/MBR partitions, NTFS, ext, APFS, HFS+, FAT | libfsntfs, libfsext, … |

dfVFS gives a uniform `path spec` API to walk partitions → file systems →
files **read-only, offset-based, no host mount** — exactly what we want for
a non-intrusive, sandboxable extractor. Plaso itself ingests a KAPE
directory *or* a disk image directly by auto-detecting artifacts, which is
the fallback "just feed the whole thing to Plaso" path.

### 1.3 Dynamic plugin loading — the security fork in the road

Two fundamentally different models
([secure plugin architectures](https://dev.to/cyberpath/designing-secure-plugin-architectures-for-desktop-applications-1meh),
[sandboxing untrusted Python](https://ubos.tech/news/sandboxing-untrusted-python-code-secure-execution-strategies-and-ubos-solutions/),
[openedx/codejail](https://github.com/openedx/codejail)):

- **In-process** (`importlib` / `entry_points` / plugin `.py` imported into
  the worker). Zero isolation: the plugin runs with the worker's full
  ambient authority — network egress, env vars, Vault token, MinIO keys,
  every tenant's data in the same process. **Fine for first-party, audited
  code; categorically unacceptable for third-party/customer code.** This is
  the leak vector to design out.
- **Out-of-process, sandboxed** (subprocess in gVisor/Firecracker microVM
  with a strict I/O contract). The plugin gets **only the bytes of the file
  it must parse** (stdin/vsock), emits **only JSONL** (stdout), has **no
  network, no secrets, an ephemeral read-only rootfs**, and is
  CPU/RAM/time-capped. Process isolation costs serialization + context-switch
  latency, but that cost is the price of not leaking evidence.

**KronOS already has the right pattern**: `FirecrackerLauncher`
(`src/external/sandbox/firecracker.py`) runs Plaso exactly this way — bytes
in, JSONL out, separate process. The proposal **generalizes that one
bespoke launcher into the standard mechanism for all untrusted code.**

---

## 2. Current architecture (baseline)

```
upload → RECEIVED
  └─ ParsingOrchestrationService.execute_parse
       ├─ _detect_parser: read 8 KB → ParserRegistry.get_parser (first-match-wins)
       ├─ storage.stream_object → parser.parse(stream) → AsyncIterator[TimelineRecord]
       └─ TimelineIngestionService: batch → ECS doc → per-tenant index → bulk
```

Key facts that shape the design:

- `ForensicParser` ABC = `supports()` + `parse()` (`application/parsing.py`).
- Registry is **hard-coded** in `get_parser_registry()`
  (`external/dependencies.py`) — 4 parsers, first-party, in-process.
- `KronosProvenance` (`domain/timeline.py`) already stamps every record with
  `evidence_id / case_id / org_id / sha256 / parser / parser_version /
  record_index`.
- **The index name is computed by KronOS from `TenantContext`, never from
  parser output** (`build_index_name`). This is the load-bearing tenant-
  isolation invariant we must preserve for any plugin model.

---

## 3. Proposed architecture

Three new concepts, each an ABC with a **stable, serializable I/O contract**
so implementations (incl. sandboxed / third-party) are fully decoupled from
KronOS internals.

### 3.1 `ArchiveExtractor` — explode a container into inner artifacts

A **new abstraction, separate from `ForensicParser`** (keeps the parser
contract clean). It yields *artifacts*, not timeline records.

```python
class ExtractedArtifact(BaseModel):
    source_path: str          # path INSIDE the container/image, e.g.
                              # "C/Windows/System32/winevt/Logs/System.evtx"
    size_bytes: int
    open_stream: Callable[[], AsyncIterator[bytes]]   # lazy; never buffers whole image

class ArchiveExtractor(ABC):
    @abstractmethod
    def supports(self, filename, content_type, header_bytes) -> bool: ...
    @abstractmethod
    async def extract(self, stream, evidence, tenant) -> AsyncIterator[ExtractedArtifact]: ...
```

Concrete extractors:

| Extractor | Detects | Impl |
|---|---|---|
| `ZipExtractor` | `PK\x03\x04` | stdlib `zipfile` streaming, **with zip-bomb guards** |
| `GzipExtractor` / `TarExtractor` | `\x1f\x8b`, ustar | stdlib |
| `DiskImageExtractor` | `EVF`/`EWF`, VHDX/VMDK/QCOW magic, or raw+partition scan | **dfVFS**, read-only path-spec walk |

**Orchestration change.** `execute_parse` first asks an `ExtractorRegistry`
whether the upload is a container. If yes:

```
container upload
  └─ extractor.extract → for each ExtractedArtifact:
        ├─ ParserRegistry.get_parser(inner_name, ..., inner_header)   ← recurse
        ├─ parser.parse(inner_stream) → records
        └─ every record annotated with source_path (+ container sha256)
```

- **Recursion is bounded**: max depth (e.g. a zip-in-zip), max total
  extracted bytes / file count, per-artifact size cap → zip-bomb / image-
  bomb defense. Exceeding a limit fails the evidence to ERROR with a clear
  reason, never OOMs the worker.
- **Fallback**: for a disk image or a whole KAPE dir where per-file routing
  is impractical, route the *entire container* to the existing Plaso path
  (Plaso auto-detects artifacts) — the "feed everything to Plaso" mode.
- **Sub-evidence model** (open decision, see §6): each inner artifact can be
  (a) a lightweight child record under the parent evidence (one custody
  entry per upload, `source_path` distinguishes them), or (b) a full child
  `Evidence` row. Recommend (a) first — simpler custody, less schema churn.

### 3.2 `source_path` in provenance (the "path in the image" requirement)

Add two optional fields to `KronosProvenance` (frozen model, additive,
backward-compatible):

```python
source_path: str | None = None       # path inside the container/image
container_sha256: str | None = None   # sha256 of the parent container (custody link)
```

- Surfaced in OpenSearch as ECS **`file.path`** (searchable) **and** kept in
  `kronos.source_path` (provenance). The examiner can then filter "all
  events from `.../winevt/Logs/Security.evtx` inside `evidence.e01`".
- **Custody stays intact through extraction**: parent container is hashed +
  RFC-3161 timestamped at intake (unchanged); each inner record links back
  via `container_sha256`, so a derived timeline event is always traceable to
  the sealed original image.

### 3.3 `SandboxedExternalParser` — the ONLY way third-party code runs

Generalize `FirecrackerLauncher` into a reusable runner. A dynamically
loaded / third-party parser is **not imported**; it is an **artifact
(container image or signed bundle) executed in a sandbox** behind the exact
same `ForensicParser` interface, so orchestration is unchanged:

```
ForensicParser.parse(stream)                     # in-process, FIRST-PARTY only
        vs.
SandboxedExternalParser.parse(stream):           # THIRD-PARTY / untrusted
    launch sandbox(image=plugin, net=NONE, secrets=NONE, rootfs=ro, tmp=ephemeral,
                   cpu=cap, mem=cap, timeout=cap)
    write file bytes → stdin/vsock
    read JSONL ← stdout
    validate each line against TimelineRecord schema     # ← trust boundary
    yield TimelineRecord (index name set by KronOS, not the plugin)
```

Same mechanism serves **KAPE-output modules** (a module that knows how to
turn `MFTECmd.csv` / a specific target's files into records) — it's just
another sandboxed `ForensicParser` whose `supports()` matches that output.

---

## 4. Two-tier trust model (core of the security design)

| | **Tier 1 — First-party** | **Tier 2 — Third-party / customer** |
|---|---|---|
| Examples | `evtx`, `nginx`, `cloudtrail`, `plaso`, core extractors | community plugins, customer-written parsers, custom KAPE modules |
| Loading | in-process, discovered via internal entry points | **sandboxed subprocess/microVM only** — never imported |
| Trust basis | code review + in repo + CI | **zero trust** — treated as hostile |
| Network | worker policy | **deny-all egress** (NetworkPolicy, already a 4-zone concept in `charts/`) |
| Secrets | injected (Vault/MinIO) | **none injected** — sandbox env is empty |
| Filesystem | worker fs | read-only rootfs + per-job ephemeral `/tmp`, destroyed after |
| Input | object stream | **only** the one file's bytes (stdin/vsock) |
| Output | `TimelineRecord` objects | **only** JSONL, schema-validated before use |
| Resources | worker limits | hard CPU / RAM / wall-clock caps (kill on breach) |
| Provenance | trusted | `parser`+`parser_version` recorded; **index name computed by KronOS from TenantContext, ignoring plugin output** |

**Why this stops data leaks, concretely:**

- No egress → a plugin *cannot* POST client bytes to an external host.
- No secrets in the sandbox → a plugin *cannot* reach Vault, MinIO, Postgres,
  OpenSearch, or Keycloak even if it wanted to.
- One job = one tenant's one file (KronOS already builds per-task, loop-
  scoped resources — `celery_runtime.py`); sandboxes are **never reused
  across tenants**, so no cross-tenant residue.
- The tenant index is derived from the authenticated `TenantContext`, **not**
  from anything the plugin emits → a plugin cannot write into another
  tenant's index (the classic "confused deputy" leak) even by lying in its
  output.
- Output is schema-validated at the trust boundary → a plugin cannot inject
  malformed docs, oversized fields, or unexpected control data downstream.

### 4.1 Plugin supply-chain integrity

A third-party plugin is distributed as a **manifest + signed image**,
aligning with the project's existing Chainguard/Trivy/Cosign stack
(`CLAUDE.md` tech stack):

```yaml
# plugin.manifest.yaml
name: acme-lnk-parser
version: 1.2.0
kind: parser            # parser | extractor | kape-module
detects:
  magic: ["0x4C000000"]      # LNK header
  extensions: [".lnk"]
resources: { cpu: "1", memory: "512Mi", timeout_seconds: 300 }
image: registry.example/plugins/acme-lnk-parser@sha256:...
```

- **Cosign-verified signature** + **Trivy scan** gates before a plugin is
  registrable (same daily-scan discipline the project already mandates).
- Manifest is **declarative** (magic/extension/resources) — KronOS reads it
  to route and resource-cap **without executing plugin code to ask what it
  supports**. Detection metadata is data, not code.
- **Allowlist, not open loading**: plugins are enabled per deployment (and
  optionally per tenant) by an admin; there is no ambient "drop a `.py` in a
  folder and it runs" path.

---

## 5. Registry evolution (maintainability)

Replace the hard-coded `get_parser_registry()` with a **layered registry**,
resolution order fixed so trust boundaries can't be subverted:

```
ExtractorRegistry     (containers/images)   ─┐
ParserRegistry:                              ├─ first-match-wins WITHIN a tier,
  1. first-party parsers  (in-process)       │   tiers checked high-trust first
  2. tenant/global plugins (sandboxed)      ─┘
```

- **First-party always wins over third-party** for the same bytes → a
  plugin can never hijack/shadow a core parser (e.g. can't replace EVTX
  handling to siphon events).
- First-party discovery via internal Python **entry points** (setuptools
  group, e.g. `kronos.parsers`) — decouples registration from the DI wiring,
  so adding a core parser is one entry-point line, not an edit to
  `dependencies.py`. Still all in-repo, reviewed code.
- Third-party plugins loaded from the **verified manifest set** for the
  deployment/tenant, each wrapped as a `SandboxedExternalParser`.
- Stable JSONL contract means plugins are **versioned and independently
  deployable** — no lockstep with KronOS releases.
- Every plugin ships its **own sample + conformance test** (the pattern just
  established in `tests/unit/parsers/test_real_world_samples.py`): a plugin
  is only registrable if it round-trips its declared sample through the
  sandbox into valid `TimelineRecord`s. Runtime confinement is itself
  smoke-tested at startup (no-egress / no-secrets assertions) before any
  real evidence is accepted.

---

## 6. Open decisions (need product input)

1. **Sub-evidence granularity** — inner artifacts as child records under one
   custody entry (recommended: simpler) vs. full child `Evidence` rows
   (heavier, but each artifact gets its own FSM/legal-hold). Affects schema
   + FSM.
2. **Per-tenant plugins?** — global allowlist only, or can a tenant enable a
   private plugin? Per-tenant raises isolation questions (a tenant's plugin
   must still be sandboxed and never see other tenants) but is a strong SaaS
   selling point.
3. **Disk-image strategy** — per-file extraction via dfVFS + re-dispatch
   (fine-grained, our parsers, `source_path` per event) vs. whole-image to
   Plaso (fast to build, coarser mapping). Likely **both**, chosen by size /
   artifact selection.
4. **Sandbox substrate for v1** — reuse the current subprocess stub
   (dev-simplification, weak isolation), or invest in gVisor/Firecracker now
   given untrusted third-party code is the explicit target. For Tier-2 code,
   real isolation is not optional.

---

## 7. Suggested phasing

| Phase | Deliverable | Unlocks | Risk |
|---|---|---|---|
| **0** | `source_path`/`container_sha256` in `KronosProvenance` + ECS `file.path` mapping | field ready before extractors exist | trivial, additive |
| **1** | `ArchiveExtractor` ABC + `ZipExtractor`/`GzipExtractor` + bounded recursive re-dispatch | **the #1 real-world gap**: KAPE `.zip` uploads work with existing parsers | medium; needs bomb guards |
| **2** | `DiskImageExtractor` on dfVFS (E01/raw/VHDX/VMDK) + whole-image→Plaso fallback | E01 ingestion; `source_path` from image | higher; native libs in sandbox |
| **3** | Generalize `FirecrackerLauncher` → `SandboxedExternalParser` + manifest + Cosign/Trivy gate + layered registry | **first safe third-party parser**, no-leak by construction | security-critical; do last, deliberately |
| **4** | KAPE-output modules (EZ Tools CSV mappers) as sandboxed parsers | native EZ Tools CSV ingestion w/o full Plaso | builds on phase 3 |

---

## 8. One-line summary

Add a **container/disk-image extraction layer** (dfVFS-backed) that explodes
an upload into inner artifacts — each re-dispatched to the existing parser
registry and tagged with its **`source_path`** — and make extensibility safe
by a **two-tier trust model** where first-party parsers stay in-process but
**all third-party/custom code runs only in a no-network, no-secrets,
per-job-ephemeral sandbox emitting schema-validated JSONL**, with the tenant
index always computed by KronOS from the authenticated context and never
from plugin output. That is what makes new parsers/modules pluggable
**without ever letting a module leak client data.**
