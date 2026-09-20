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
**Superseded:** by the entry immediately below (same day, later session)
— option (a) was attempted and works.

### Linux dual-emit timeline: implemented via `linux.pslist.PsList`, conditional on the ISF-generation tool
**Date:** 2026-09-20
**Decision:** implemented Linux `TimelineRecord` dual-emit using
`linux.pslist.PsList`'s "CREATION TIME" column (added to
`LINUX_DEFAULT_PLUGINS`, `src/external/sandbox/volatility_launcher.py`;
`VolatilityModule._timeline_rows()`/`_row_to_timeline_record()`,
`src/external/parsers/volatility.py`, generalized to handle Linux's
different row field names via `_ROW_FIELD_NAMES`) — not the
`linux.boottime.Boottime` + manual per-process-offset combination
originally planned. volatility3 already computes this internally
(`task.get_create_time()` = `boottime + task.start_time`); no manual
combination was needed in KronOS's own code once a working ISF was
available.
**Why:** the previous entry's blocker (`linux.boottime.Boottime` fails
against this codebase's own `btf2json`-built ISF because `tk_core`'s type
doesn't resolve) turned out to be specific to *how the target image's
symbol table was generated*, not a fundamental gap in volatility3 or this
codebase's design. Downloaded the real, matching Ubuntu `-dbgsym` package
for the identical kernel build (`5.15.0-191-generic`) already used by the
existing self-generated sample, extracted the real debug `vmlinux`, and
ran the real `dwarf2json` tool against it (real steps, real captured
output — `poc/volatility_linux_boottime/README.md`'s "Part 2", per
`CLAUDE.md` §F). Applied to the *same* memory capture (an ISF only needs
to match the kernel build, not a specific boot of it — no new VM/sample
needed), `linux.boottime.Boottime` and `linux.pslist.PsList` both resolved
`tk_core`/`timekeeper` correctly and produced real, plausible timestamps
for all 105 real sample rows. Fed the real captured rows through the
actual (non-mocked) `src/` functions to confirm the production code path,
not just the external tool, works. This makes the fix **conditional, not
unconditional**: an org whose Linux ISF was built by `btf2json` (this
codebase's own self-generated sample included) still gets zero Linux
`TimelineRecord`s — handled as an honest "not a timeline-shaped row"
outcome, not a crash or regression, exactly like a Windows row with no
`CreateTime` already was. This is judged an acceptable, real improvement
rather than "not good enough to ship until it works unconditionally":
most distro kernels have a `dwarf2json`-compatible debug/dbgsym package
available (this is precisely what made the comparison possible at all),
so the conditional path covers the common real case, and the alternative
(a from-scratch `timekeeper`-independent wall-clock anchor) is a separate
piece of work with its own accuracy caveats that this fix makes
unnecessary to build right now.
**Also found and fixed this session:** while investigating, discovered
`/tmp` on the shared host running this initiative's Docker stack is a
RAM-backed `tmpfs` capped at 3.6GB — downloading the 1GB `.ddeb` and doing
a full (not targeted) extraction there exhausted it and broke all shell
command execution on the host (affecting any concurrent session, not just
this one) until the large files were removed. Documented in
`poc/volatility_linux_boottime/README.md`'s "Host gotcha" section as a
standing caution for future large-file PoC work on this host: use a
real-disk path (`/home/reca/scratch/<name>/`), never `/tmp`.

## Connector marketplace (2026-09-20)

### Connector config/key modals get `max-h-[90vh] overflow-y-auto`
**Date:** 2026-09-20
**Decision:** `ConnectorConfigForm.tsx`'s and `PushConnectorKeyPanel.tsx`'s
inner modal container both gained `max-h-[90vh] overflow-y-auto`; previously
neither had any height cap or scroll behavior.
**Why:** closing the two connector-marketplace E2E coverage gaps named in
`STATUS.md` (Wazuh/Zeek PUSH, Splunk HEC/Sentinel/Defender POLL config
forms) surfaced a real bug, not a test artifact: Microsoft Sentinel's config
form has 8 parameters, tall enough that the fixed-position, unscrollable
modal pushed its own Save button below the visible viewport with no way to
reach it — reproduced with a screenshot before fixing, per `CLAUDE.md` §F.
`PushConnectorKeyPanel.tsx` doesn't currently have a connector with enough
provisioned keys to trigger the same overflow, but has the identical
structural risk (an unbounded list of API-key rows) so got the same fix
pre-emptively rather than waiting for its own real failure. Real Playwright
re-run of all 7 marketplace connectors (Suricata/Wazuh/Zeek PUSH,
CEF-syslog/Splunk HEC/Sentinel SINK, Defender POLL) confirmed green after
rebuilding and redeploying the nginx image with the fix.

## Frontend E2E infrastructure (2026-09-20)

### `KronosPage.pollLiveText`'s seed guard fixed to track a real transition, not just "current value != seed"
**Date:** 2026-09-20
**Decision:** `pollLiveText` (`frontend/e2e/pages/KronosPage.ts`) now tracks
an explicit `observedRealChange` boolean, set the first time any state
transition is observed, and uses that (not `last !== seedValue`) both to
decide when to break out of the poll loop and whether to return a real
terminal value or `null`.
**Why:** real, reproduced bug, found writing `evidence-dual-dependency-outage.spec.ts`
(the two-simultaneous-dependency-failure fault-injection gap named in
`STATUS.md`) — the first spec in the suite to seed a watch with a terminal
value (`"Error"`) and then legitimately expect the SAME terminal value
again after a real intervening transition (`Error -> Scanning -> Parsing ->
Error`, i.e. recovering ClamAV while OpenSearch was still down, so the
retry correctly fails a second time). The old code used `last !== seedValue`
for both the break condition and the final return, so it correctly kept
polling through the real transitions (never broke early) but then, once
`last` cycled back to equal `seedValue` again, silently returned `terminal:
null` instead of the real second `"Error"` — indistinguishable, from the
caller's point of view, from the exact stale-read case the seed guard was
originally built to catch. Confirmed every OTHER existing call site
(`evidence-retry.spec.ts`, `evidence-parse-retry.spec.ts`,
`evidence-intake-retry.spec.ts`, `evidence-intake-retry-dev-stack.spec.ts`,
and the no-seed callers) only ever seeds a DIFFERENT value than the one it
waits for, so this fix is behavior-preserving for all of them — verified
both by code inspection and by a real, live re-run of
`evidence-retry.spec.ts` (green, 2.6min) after the fix, not just reasoning
about it.

### `EvidenceDetailDrawer`'s Retry click doesn't close the drawer — page object needs an explicit close between recovery cycles
**Date:** 2026-09-20
**Decision:** added `CaseDetailPage.closeEvidenceDrawer()` (clicks the
drawer's own `×`, `aria-label="Close"`, waits for the dialog to detach) and
call it after `clickRetry()` in `evidence-dual-dependency-outage.spec.ts`
before opening the drawer again for a second recovery cycle.
**Why:** real, reproduced bug (same spec as above) — `retryMutation.mutate()`
in `EvidenceDetailDrawer.tsx` never calls `onClose`, so the drawer (and its
`fixed inset-0 z-40 bg-black/50` backdrop) stays mounted after Retry is
clicked. Every prior recovery spec only opens the drawer once per test, so
this was never exercised before; a second `openEvidenceDrawer()` call in
the same test hung for the full 15-minute test timeout with Playwright
retrying a click intercepted by the leftover backdrop. Fixed in the test
harness (an explicit close between cycles), not the component — leaving the
drawer open after Retry is a real, deliberate UX choice (lets the user keep
watching the row) that this decision does not second-guess.

## Volatility / memory forensics (2026-09-20, continued)

### Wired up real remote ISF lookup, accepting real outbound network access from the sandboxed worker
**Date:** 2026-09-20
**Decision:** `Settings.volatility_remote_isf_url` defaults to
`https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json`
-- volatility3's own project's real, CI-verified remote ISF index (see
`github.com/volatilityfoundation/volatility3` PR #1316, "Enable Remote ISF
server for Linux testcases") -- and the sandboxed Volatility worker
subprocess now makes real outbound HTTPS requests to GitHub to fetch it
and, when a match is found, the specific matched ISF file. Threaded
through `VolatilityLauncher`'s multi-plugin/OS-detection path and the
on-demand curated-plugin picker; empty string disables (fully offline).
**Why:** real, reproduced bug against a real user-uploaded 4GB Ubuntu
memory image -- every plugin failed with `UnsatisfiedException` because
this worker calls volatility3's framework API directly, never its own CLI
(the only other code that ever sets `constants.REMOTE_ISF_URL`), so remote
symbol lookup was never attempted regardless of real network access;
manually building a per-kernel ISF (the alternative explored first, see
`poc/volatility_linux_boottime/`) does not scale to arbitrary
user-uploaded images and was explicitly ruled out by the project owner as
not viable "regardless of kernel version" for this use case. No evidence
content or evidence-derived data is ever transmitted -- the fetched index
is a public document, matching happens entirely locally against the
already-downloaded image, and only the specific matched kernel build's ISF
URL (not evidence bytes) is ever requested from GitHub, visible only in
GitHub's own access logs. This is the explicitly-requested option between
the two named in the original diagnosis (`STATUS.md`'s Volatility remote
ISF entry) and is consistent with this component's existing trust tier
(`CLAUDE.md` §G.3: sandboxed-subprocess-wrapping-an-external-tool, not the
stricter no-network Track D tier) -- not a new sandboxing exception
invented for this fix.

## Evidence upload / infra (2026-09-20, continued)

### nginx's evidence-proxy location needs proxy_request_buffering off
**Date:** 2026-09-20
**Decision:** `location ~ ^/kronos-evidence-` in
`docker/nginx/nginx-lan-https.conf.template` sets
`proxy_request_buffering off;`.
**Why:** real user report of a multi-GB upload sitting at 0% with no
visible progress. Confirmed live in nginx's own error log:
`"a client request body is buffered to a temporary file"` -- nginx's
default (`on`) writes the whole request body to
`/var/cache/nginx/client_temp/` before forwarding any of it upstream,
serializing a multi-GB transfer behind a second full disk write+read on
top of the browser's own transfer. Not a total hang -- both real uploads
that triggered the report did eventually reach `COMPLETE` -- but
indistinguishable from one within any realistic UI-watching window,
especially on a disk-contended host. Verified fixed with a real 1GiB
presigned PUT through the rebuilt nginx container (23s, no buffering
warning) before asking the user to retry, not assumed from reading the
nginx docs alone.

### Companion-file (.vmss/.vmsn) support does not exist, confirmed by direct test, not just theory
**Date:** 2026-09-20
**Decision:** did not build "attach a companion file" as part of this
session's work, despite verifying (`poc/volatility_remote_isf/`) that a
missing `.vmss`/`.vmsn` plausibly explains zero-row walk-based Linux
plugins.
**Why:** the project owner supplied the real `.vmsn` for the exact file
already under investigation, uploaded as a second evidence item on the
same case. Real result: both parses completed, but with byte-identical
output to the `.vmem`-only run -- confirming (not just theorizing) that
two independent evidence uploads never become co-resident on disk the
way volatility3's own same-directory/same-basename companion-file
detection requires, and that zipping them together wouldn't help either
(`archive.py`'s container recursion dispatches members one at a time,
never simultaneously on disk). Building the real feature (associate a
second upload with an existing memory-forensics evidence item; download
and stage both under matching basenames before invoking the worker) is
real, separate, scoped work -- left as a named follow-up, not attempted
speculatively before confirming the underlying assumption with the real
files in hand.
