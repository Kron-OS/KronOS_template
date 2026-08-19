# Gap Audit — Milestone FF (continuation, 2026-08-19)

Follow-up to `docs/GAP_AUDIT_2026-08-19_MILESTONE_EE.md` (Milestone EE,
fully resolved: EE1 CLOSED). EE's own execution plan pointed at continuing
the direct-review method on the rest of the SOAR/response subsystem
(H1/H3/H4). This pass reviewed H3 (automated evidence collection on
detection).

---

## FF1 — `CollectForensicArtifactAction`'s `artifact_path` was an unrestricted local file-read (real security gap, never exploited — zero live callers)

**STATUS (2026-08-19, commit TBD): CLOSED, verified.**

H3 (roadmap Milestone M7) shipped `CollectForensicArtifactAction`, which
hands an already-staged forensic artifact into the real evidence
pipeline, custody-attributed to a Detection. H3's own status note already
honestly flagged "no automatic Detection→Playbook trigger wiring this
pass" — confirmed still true by direct grep (zero references to this
class anywhere in `src/external/`, not even registered in
`PlaybookActionRegistry`, unlike `RevokeKeycloakSessionAction` before
Milestone EE's own EE1 fix).

**The finding, applying the exact lens EE1 itself demonstrated matters:**
what happens if a future pass wires this action up the same
straightforward way EE1 just wired up H2's containment action?
`artifact_path` (`params["artifact_path"]`, entirely caller-supplied) was
read with zero restriction — `Path(artifact_path).is_file()` then
`.read_bytes()`, no containment check of any kind. If this action were
ever exposed via any caller-reachable trigger, an attacker (or a buggy
playbook step) could name an arbitrary path on the backend container's
own filesystem — `/app/.env`, a mounted Kubernetes secret, an SSH private
key — and have its real bytes ingested as "evidence," attributed to a
Detection the caller can name, and then downloaded by any user with
case-read access via the real, already-shipped
`GET /api/cases/{id}/evidence/{id}/download` route (Milestone X1) — a
genuine, complete local-file-disclosure chain, not a hypothetical one.
**Not currently exploitable** (zero live callers, confirmed), but exactly
the kind of landmine that would have gone live silently the next time
someone reused the EE1 pattern without separately re-deriving this
action's own, materially different threat model.

**Fix:** `staging_dir` is now a REQUIRED constructor argument (no
default — deliberately, so a future DI-wiring pass cannot construct this
action without consciously deciding what's allowed, the same discipline
`RevokeKeycloakSessionAction`'s own tenant-isolation checks already model
for a different resource). `artifact_path` is resolved
(`Path.resolve()`, which follows symlinks to their real target) and
checked with `Path.is_relative_to(staging_dir)` **before** any filesystem
stat or read on the caller-supplied path — rejecting an out-of-bounds
path before ever touching it, avoiding even a minor file-existence oracle
(a different error for "outside staging_dir" vs. "inside but missing"
would let a caller binary-search real paths on the host). The subsequent
read uses the already-validated, resolved path (not the original
caller-supplied string), avoiding any TOCTOU gap between validation and
the actual read.

**Verified (real attack-vector tests, not just the happy path):** this
fix is pure application-layer path logic with no external service to
integrate against, so CLAUDE.md §F's "real dependency" PoC pattern
doesn't apply the way it does for MinIO/Postgres/Keycloak-touching
fixes elsewhere in this initiative — the appropriate verification is
thorough unit coverage of the real attack surface, which this has:
- A file that exists but is outside `staging_dir` → rejected.
- A literal `..` traversal path → rejected.
- A symlink planted *inside* `staging_dir` pointing *outside* it →
  rejected (proves `resolve()`'s symlink-following actually defeats this,
  not just literal path-string tricks).
- A real, legitimate in-bounds artifact → still succeeds (regression
  guard — the containment check isn't so strict it breaks the real case).

All 4 new tests independently confirmed to genuinely fail against the
pre-fix code (the fix's own worktree/diff temporarily stashed, tests
re-run in isolation, confirmed they fail — `TypeError` for the removed
constructor argument, consistent with direct reading of the unfixed
`execute()` method's own unrestricted `artifact_path.read_bytes()` call)
before being trusted. All 9 pre-existing H3 tests updated to pass
`staging_dir=tmp_path` (matching where their own test artifacts already
live) and continue to pass unmodified in behavior. Full backend suite
before/after: 1993 → 1997 passed (+4, zero regressions), 2 skipped both
times. `ruff`/`black`/`mypy` clean.

**Priority: P1** — a real, complete local-file-disclosure vulnerability
class, currently dormant only because the action has no live caller yet;
closing it now (cheaply, while the well-tested action is still small and
isolated) is far cheaper than finding it after a future wiring pass ships
it live, which is exactly the failure mode this direct-review method
exists to catch before it happens.

---

## Execution plan

**FF1**: found and closed this pass, orchestrator-direct (pure
application-layer fix, no external dependency, well within DD1/CC1-style
direct-fix scope).

Remaining candidates, unchanged:
- H1 (playbook engine core) and H4 (case/ticket integration) still
  haven't had this same direct-review treatment.
- The six EDR/SIEM connectors from Milestones P/Q/R/S also haven't been
  freshly re-examined this way.
- `charts/kronos/files/nginx.conf.template` Helm sync — no live
  consequence yet.
- Prod OpenSearch demo-cert gap — needs a real project-owner TLS
  decision, not attempted.
