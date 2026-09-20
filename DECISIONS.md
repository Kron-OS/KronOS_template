# KronOS — Decisions Log

**What this file is:** an append-only record of decisions with lasting
rationale — the "why we did X instead of Y" that a future session would
otherwise have to re-derive or, worse, silently reverse. Each entry is a
historical fact: once written, it is never rewritten or deleted, only
superseded by a later dated entry that says so explicitly. This is what
keeps it from going stale the way a "current state" document does — a
decision that was true when made stays a true *record* even after the
code around it changes again.

**What does NOT belong here:** current implementation state ("X is
built", "Y is broken") — that's `STATUS.md`, which is a living document
updated in place, not appended to. A row in this file answers "why",
not "what's true right now."

**How to add an entry:** append to the bottom of the relevant section
(or add a new dated section) — never edit an existing entry except to add
a `**Superseded:**` line pointing at the entry that replaces it. Format:

```
### <short title>
**Date:** YYYY-MM-DD (or "pre-2026-09, exact date unknown" for entries
backfilled from older docs)
**Decision:** what was decided
**Why:** the reasoning / what alternative was rejected and why
**Superseded:** (only if applicable) by <later entry>
```

---

## Architecture (project inception — backfilled from `CLAUDE.md`, exact dates unknown)

### Keycloak Organizations for multi-tenancy, not Groups
**Decision:** tenant isolation is modeled on Keycloak 26+ Organizations.
**Why:** Groups don't give per-tenant admin delegation or org-scoped
invite flows without significant custom work; Organizations do natively.

### MinIO Object Lock (Compliance mode) for evidence WORM
**Decision:** evidence objects are written under MinIO Object Lock in
Compliance mode, not Governance mode or an application-level immutability
check.
**Why:** legal/forensic admissibility requires WORM enforcement that
survives even an admin credential compromise — Governance mode can be
overridden by a privileged user, Compliance mode cannot.

### evtx-rs fast path + Plaso (sandboxed subprocess) for parsing
**Decision:** two parsing tiers — a fast native-Rust EVTX parser for the
common case, Plaso (via `log2timeline`) for everything else Plaso covers,
run as a sandboxed subprocess rather than in-process.
**Why:** Plaso is comprehensive but slow and has a large, less-trusted
dependency surface; evtx-rs is fast but EVTX-only. The subprocess boundary
contains Plaso's dependency risk without waiting for a full Firecracker
microVM implementation (see the "Firecracker microVM" gap in `STATUS.md`
— the isolation is real container/subprocess sandboxing, not literally
Firecracker, despite naming in the code).

### OpenSearch with ECS + `kronos.*` provenance fields
**Decision:** timeline records are indexed using the Elastic Common Schema
plus a KronOS-specific `kronos.*` field namespace for provenance
(parser, record index, source path, etc.), not a bespoke schema.
**Why:** ECS gives forensic-standard field names other SOC tooling
already expects; the `kronos.*` namespace keeps KronOS-specific metadata
from colliding with or polluting the standard schema.

### Chain-of-custody as an append-only, hash-chained audit log
**Decision:** every state transition emits an immutable `AuditEvent`;
each row's hash includes the previous row's hash
(`row_hash = SHA256(prev_row_hash || canonical_json(event))`).
**Why:** tamper-evidence and legal admissibility — an altered or deleted
historical row breaks the chain verifiably, not just "trust the database."

### `ForensicParser` is the only module interface — no parallel "Module" hierarchy
**Date:** pre-2026-09 (`CLAUDE.md` §G.1)
**Decision:** every data-source module (Windows/KAPE, Linux, memory/
Volatility, mobile, network, cloud, ...) implements the single
`ForensicParser` ABC. `parse()` yields timeline records; the optional
`extract_artifacts()` yields non-timeline `StructuredArtifact`s. A single
class may do both and internally run several sub-analyses.
**Why:** a second parallel hierarchy ("Module" vs "Parser") was proposed
and explicitly rejected (`reviews/Data_Source_Module_System.md` §2) —
it would duplicate registration/dispatch/sandboxing logic that already
exists once for `ForensicParser`, for no real gain in expressiveness.

### `StructuredArtifact.content` is an opaque dict, no per-kind schema
**Date:** pre-2026-09 (`CLAUDE.md` §G.2)
**Decision:** non-timeline artifact output (`pstree`, a NetFlow graph, a
`.plist` snapshot) is stored as `content: dict[str, Any]` with a
namespaced `kind` string, not a per-kind typed schema.
**Why:** deliberate product-direction choice — capture and store safely
now, design presentation/analysis schemas later once enough real kinds
exist to generalize from. Building the schema speculatively, before that
data exists, was judged more likely to be wrong than useful.

### Two-tier module trust model reused unchanged from the container/plugin design
**Date:** pre-2026-09 (`CLAUDE.md` §G.3)
**Decision:** first-party pure-Python modules run in-process; first-party
modules wrapping an external tool (Volatility, mac_apt, Hayabusa, ...) run
as a sandboxed subprocess via the same `FirecrackerLauncher` pattern.
Third-party/customer code is Track D — gated, not started.
**Why:** `reviews/Extensibility_Architecture_Proposal.md` §4 already
designed this boundary for containers/plugins; re-designing it per module
type would be pure duplication for no new requirement.

---

## Operational / process decisions (backfilled from `docs/archive/status-history/HANDOFF_AND_ORCHESTRATION.md` §2.7)

### Manual Keycloak user-id entry for "Add Member", not a name/email picker (original version)
**Date:** pre-2026-09-02
**Decision:** the original case-member-add UI took a raw user ID.
**Why:** a case-lead has no org-user-listing access (`GET /api/admin/users`
is org-admin-only) and widening that RBAC boundary was treated as a
separate design question.
**Superseded:** 2026-09-02 — a case-scoped `GET /{case_id}/member-candidates`
endpoint was added (gated by the same `assert_case_lead_or_admin` check),
giving a real search-as-you-type picker without widening the org-wide RBAC
boundary.

### `remove_case_member` does not re-validate the target user, unlike `add_case_member`
**Decision:** removing a non-existent/non-member id is left as a safe
no-op rather than validated up front.
**Why:** validating would cost a real Keycloak Admin API round trip to
guard against something that's already harmless.

### `add_case_member`/`remove_case_member` are idempotent by design
**Decision:** adding an already-present member or removing a non-member
both return 200, not an error.
**Why:** deliberate UX choice, not an oversight — do not "fix" this into
erroring.

### No automatic retroactive reindex after an OpenSearch mapping fix
**Decision:** a mapping/template fix does not automatically reindex
already-existing live data; a reindex is a real, explicit, operator-run
script.
**Why:** reindexing is potentially large/slow against live data — too
impactful to trigger automatically as a side effect of a code deploy.

### `dynamic: false` + explicit `strings_as_keyword` template, not a plain revert to OpenSearch defaults
**Decision:** the index template sets `dynamic: false` paired with an
explicit dynamic_template forcing pure `keyword` mapping for strings.
**Why:** a plain revert to OpenSearch's default dynamic mapping would
reintroduce the original bug (`text`+`.keyword` multi-fields breaking
bare-name `term` queries) that `dynamic: false` was introduced to fix.
Anyone touching `index_template.json` again should re-read
`poc/opensearch_auto_index_fields/README.md` and
`poc/ecs_schema_hardening/README.md` first — it's a two-layer fix and
easy to partially undo.

### `cluster.max_shards_per_node` raised to 2000 (workaround, not a fix)
**Date:** 2026-09 (exact date not recorded in the source doc)
**Decision:** raised the dev OpenSearch cluster's shard ceiling from the
1000 default to 2000 after months of accumulated per-case-per-month E2E
indices exhausted it, rather than deleting old indices.
**Why:** the project owner's explicit choice when asked (deleting old
indices was the other option) — this is flagged as a workaround, not a
permanent fix; the underlying accumulation (ISM rollover creates a new
index per case per month, never deleted) is still real. See `STATUS.md`'s
known-gaps section.

### Standing product-scope directives (explicit, not to be re-litigated without new instruction)
**Decision:** no SIEM wiring (Wazuh/Falco/Fluent-bit each have a compose
file but are not referenced by any shipped compose profile, and no rule
has ever fired against a real event); no v2 features (advanced timeline
search, case collaboration/comments, non-Sigma detection rules, DFIR
report generation, API rate limiting beyond what already exists for
connector config mutations).
**Why:** explicit, repeated project-owner instruction ("no SIEM wiring
for now", "no v2 features for now"). Do not build UI or backend work
assuming either is coming without a fresh, explicit instruction.

### `audit.py`'s `/export`/`/verify`/`/merkle-proof` routes deliberately have no web UI
**Decision:** confirmed deliberate, not a gap.
**Why:** these routes exist specifically to feed the standalone,
third-party-runnable `kronos-attest` CLI for independent forensic
verification, per the original design spec (`roadmap.md` §4.3). Do not
build a web UI for these without re-reading that design intent first.

---

## Connector marketplace (2026-09, this initiative)

### Dedicated Vault mount + AppRole for connector secrets, separate from KES
**Date:** 2026-09
**Decision:** per-org connector credentials (Defender/Sentinel/Splunk
HEC/CEF syslog) live under their own Vault KV-v2 mount
(`kronos-connectors`) and AppRole, not the existing KES transit mount/token.
**Why:** least privilege — this is new, sensitive, customer-outbound
credential material; reusing the KES token's broader access would widen
blast radius for no benefit.

### No silent global-Settings fallback for connector config
**Decision:** once `connector_configs` exists, an org with no row for a
given connector is simply not polled/pushed — it never falls back to a
global `Settings` value.
**Why:** direct requirement from the project owner ("independent for any
client, no collision") — a silent global fallback would be exactly the
kind of cross-tenant coupling that requirement rules out. This is also
why the old global `Settings.defender_*`/`splunk_hec_*`/`cef_syslog_*`/
`sentinel_*` fields were removed entirely once every relying org was
backfilled, rather than kept as a fallback path.

### Reversible disable vs. permanent delete for connector configs
**Decision:** `POST .../config/disable` (reversible, keeps config+secrets,
system can also auto-set it via the circuit breaker) is a distinct
operation from `DELETE .../config` (permanent, wipes config + Vault
secret).
**Why:** "remove an endpoint" needs both a fast reversible kill switch
(useful mid-incident) and genuine permanent removal — collapsing them
into one operation would make either the kill switch too destructive or
the removal not actually removing anything.

### Credential-bearing connector mutations require a one-time step-up ticket, not just aal2
**Date:** 2026-09
**Decision:** `admin_connector_config.py` and `admin_integration_sources.py`
require both an aal2 session AND a single-use `X-Step-Up-Ticket` (minted
via `POST /api/step-up/ticket`), matching `DELETE /api/evidence/{id}`'s
bar. This is a **stronger** bar than `admin.py`'s quota/invite/role-change
routes, which check aal2 only, no ticket.
**Why:** credential issuance/rotation is judged at least as sensitive as
evidence deletion. This inconsistency (two different step-up bars in the
same app) is intentional, not an oversight — but it is easy to forget
when building a new admin form, which is exactly what happened: the
connector marketplace's frontend (`PushConnectorKeyPanel.tsx`,
`ConnectorConfigForm.tsx`) was originally wired assuming the *weaker*
aal2-only bar (copying the quota/invite pattern) and every mutation
silently hung in an infinite refresh-retry loop until a real Playwright
run against the real backend caught it (2026-09-19). Fixed via
`frontend/src/lib/stepUpTicket.ts`. **Anyone adding a new step-up-gated
admin mutation must check which bar the backend route actually enforces
before copying an existing frontend pattern** — do not assume aal2-only.

### `ADMIN_TOTP_SECRET` must be kept in sync in two files
**Date:** 2026-09-19
**Decision:** the dev-seeded `admin` user's real registered TOTP secret is
duplicated in `poc/auth_flow/dev_totp_secrets.py` (Python PoC scripts) and
`frontend/e2e/stepup.ts` (Playwright) because Playwright can't import a
Python module.
**Why:** a prior re-registration (deleting and re-enrolling the admin's
TOTP credential) updated only the Python copy, silently breaking every
step-up-gated Playwright spec in the suite with "Invalid authenticator
code" failures that looked like flakiness but weren't — a real,
previously-unverified bug, only caught when a new E2E spec exercised the
step-up path for real. Both files now cross-reference each other in
comments so a future re-registration updates both.

---

## Infrastructure (2026-09-19)

### Presigned evidence uploads route through the main origin, not a dedicated port
**Date:** 2026-09-19
**Decision:** `MINIO_PUBLIC_ENDPOINT`/`MINIO_PUBLIC_URL` point at
`https://kronos.local` (the main app's own origin, default port) instead
of a dedicated `:9444`. nginx proxies MinIO's real bucket-name-prefixed
paths (`location ~ ^/kronos-evidence-`) on the main `:443` server block;
the old dedicated `:9444` server block and its published port are removed
entirely, not just deprecated.
**Why:** a dedicated port is a dedicated browser *origin* even with the
same hostname/cert — a browser that had only ever trusted the main site's
self-signed cert had never been prompted to trust `:9444`'s, so every
upload silently failed at the TLS handshake with an undiagnosable
"Network error" (real, reproduced bug — confirmed via a real HAR showing
`status: 0` on both the CORS preflight and the PUT, and nginx's access
log showing nothing at all for the failed attempts). This also directly
serves the same "reduce non-standard ports in real infra" principle
raised for the CEF-syslog connector (see below) — fewer distinct
listening ports means fewer firewall/router rules that can drift out of
sync with what the app actually needs. Verified with real, non-bypassed
TLS chain validation (a real login + presign + PUT + finalize against the
real step-ca root CA, not `-k`/`verify=False`) before removing the old
port, per `CLAUDE.md` §F.

## Volatility / memory forensics (2026-09-19)

### OS-family is detected per file via `banners.Banners`, not assumed Windows
**Date:** 2026-09-19
**Decision:** `VolatilityModule()` (real production construction, no
explicit `plugins`) now runs the real, OS-agnostic `banners.Banners`
plugin first (`VolatilityLauncher.detect_os_family()`) and picks
`LINUX_DEFAULT_PLUGINS` or `DEFAULT_PLUGINS` based on the real banner
string shape (`"Linux version ..."` vs a `*.pdb|<guid>|<age>` PDB
reference) — real-verified against both families, not guessed. An
explicit `plugins` argument (tests, the on-demand picker) bypasses
detection entirely; detection only ever fills in the real default.
Unrecognized/undetectable banners fail open to the Windows default (the
behavior every image got before this existed) rather than raising.
**Why:** the alternative — always requesting the Windows plugin set — is
what this codebase actually did before this date, silently wasting a full
scan on a Linux image (every `windows.*` plugin fails with
`UnsatisfiedException` against a Linux layer) and never surfacing any
Linux-specific findings at all.

### No real Linux memory sample was found publicly available — self-generated one instead
**Date:** 2026-09-19
**Decision:** built a real Ubuntu 22.04 (`5.15.0-191-generic`) memory
sample from scratch — isolated QEMU/KVM guest VM (never the shared host's
own kernel), LiME for acquisition, `btf2json` (not `dwarf2json`, which
doesn't accept a raw BTF blob in the pinned release) for the ISF symbol
table, built from the guest's own `/sys/kernel/btf/vmlinux` + `System.map`.
**Why:** every real, publicly-downloadable Linux sample checked was a dead
end (expired CTF link, domain-squatted wiki page, a maintained "samples
index" repo with zero Linux entries — see
`reviews/Volatility_Linux_Plugin_Research.md` for the full real trail).
Self-generating turned out better anyway: a fresh, known-good modern
kernel with real, checkable planted content, rather than an opaque
found file of unknown provenance.

### `linux.malware.lsmod.Lsmod` corrected to `linux.lsmod.Lsmod`
**Date:** 2026-09-19
**Decision:** the curated Linux eager plugin list uses `linux.lsmod.Lsmod`,
not `linux.malware.lsmod.Lsmod`.
**Why:** the original research draft guessed the `.malware.` namespace by
incorrect analogy with the *other* real Windows/Linux plugins that genuinely
are duplicated across both namespaces (malfind, check_afinfo, hidden_modules,
etc.) — `lsmod` is not one of them. Caught by an actual run against a real
sample (`not found (not registered/importable)`), not by re-reading the
docs more carefully — the real, load-bearing reason this codebase's
verification-first rule (`CLAUDE.md` §F) exists at all.

## Documentation process (2026-09-19)

### One living status file + one append-only decisions log, replacing per-session dated docs
**Date:** 2026-09-19
**Decision:** `STATUS.md` and `DECISIONS.md` (both repo root) are now the
only place project state and rationale are recorded. The prior pattern —
a new `docs/GAP_AUDIT_<date>_MILESTONE_<letters>.md` per work cycle, plus
three separate, overlapping "the one honest status doc" attempts
(`PROGRESS.md`, `docs/HANDOFF_AND_ORCHESTRATION.md`,
`docs/PRODUCT_STATUS_AND_V2_PREVIEW.md`) — is retired; all of it moved to
`docs/archive/status-history/` as historical record, not current truth.
**Why:** the project owner flagged that documentation no longer matched
reality and asked for a mechanism that stays honest without becoming
another rotting artifact. A narrative "current state" doc drifts the
moment work continues; an ever-growing pile of dated snapshot docs makes
it impossible to tell which one is current without reading several and
comparing dates (confirmed live: 93 gap-audit docs plus three competing
status docs had accumulated by this date). The fix is structural, not
"write better docs": one file that is edited in place (so there is never
a second copy to disagree with), one file that is only ever appended to
(so a past decision can't silently drift), and updating both is treated
as part of finishing a task — the same discipline as running tests —
rather than a separate documentation pass that's easy to skip.

## Volatility / memory forensics (2026-09-20)

### Linux dual-emit timeline fix is investigated and blocked, not skipped
**Date:** 2026-09-20
**Decision:** did not implement the "combine `linux.boottime.Boottime`
with per-process boot-relative offset" plan for Linux `TimelineRecord`
dual-emit that `reviews/Volatility_Linux_Plugin_Research.md` had flagged
as the next step. Instead ran it for real against the existing
self-generated Linux sample/ISF first (`poc/volatility_linux_boottime/`)
and found it genuinely blocked: `linux.boottime.Boottime` raises
`AttributeError: Unable to find timekeeper` against this codebase's own
`btf2json`-built ISF — the same real ISF-metadata gap already documented
for `linux.malware.hidden_modules.Hidden_modules`. Confirmed the
underlying per-process offset (`task.start_time`) is real and readable
directly via the object layer even with the plugin broken, so the data
exists; only the wall-clock boot anchor does not resolve on this ISF.
**Why:** `CLAUDE.md` §F/§G.5 requires running an integration against the
real dependency before writing `src/` code, specifically to catch exactly
this kind of gap between "the plan reads correctly" and "the plan
actually executes." Writing the combine-logic without this check would
have produced code that raises the same `AttributeError` the first time
any Celery worker actually ran it against a real Linux image built the
same way this codebase's own reference sample was. Left named and
unimplemented with two real ways forward
(`poc/volatility_linux_boottime/README.md`) rather than merging a
plausible-looking fix that cannot work against this codebase's own real
verification sample.
