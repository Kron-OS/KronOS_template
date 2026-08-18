# Gap Audit — Milestone AA (continuation, 2026-08-18)

Follow-up to `docs/GAP_AUDIT_2026-08-18_MILESTONE_Z.md` (Milestone Z,
fully resolved: Z1 CLOSED). Re-checked `docs/GAP_AUDIT_2026-08-17.md`'s
"still genuinely blocked" list first — no change since Milestone Z. This
pass picked up the highest-value item Milestone Z's own execution plan
had already surfaced but not attempted: P2-5's "L"-sized `kronos_attest`
offline-only credibility gap.

---

## AA1 — `kronos-attest` only ever verified a static offline export, never the live Postgres source of truth

**STATUS (2026-08-18, commit `cbd4e79`): CLOSED, verified live.**

`docs/GAP_AUDIT_2026-08.md`'s P2-5 finding (open since Milestone T,
never attempted, sized "L"): every `kronos-attest` command
(`verify`/`day-report`/`case-report`/`merkle-root`/`merkle-proof`) only
ever read events from a static `--audit-log <path>` JSON export,
previously produced by `GET /api/audit/export`. For a platform whose
flagship claim is court-admissible chain of custody, a report tool that
can only verify a static export (never the live database) is a real
credibility gap — an opposing party could question whether the export
file handed over is really what the database currently holds.

**Design done by the orchestrator before dispatch** (this repo's own
established practice for substantial items — W3's export scope, W14's
PUSH/POLL honesty, W8's hash-storage design all did the same): rather
than have `kronos_attest` grow its own parallel Postgres client code,
reuse the app's own already-proven, already-verified pieces verbatim —
`PostgresAuditLogRepository.stream_by_org()` (the exact same method
`GET /api/audit/export` already uses, proven in Milestone W3) and
`_to_export_dict()` (the exact same event-to-dict field-shaping that
function's own docstring already warns must never drift, since
`kronos_attest/verifier.py`'s `_canonical_json()` reads those exact keys
to recompute row hashes). This keeps `AttestationReport`'s own
verification logic (`report.py`, correct and covered by its own
regression tests since Milestone W11's P1-W19 fix) completely unchanged —
only the event *source* gained a second path.

**Fix:** `kronos_attest/cli.py` gained `--database-url`/`DATABASE_URL`
env-var (matching `migrations/env.py`'s own established convention) and
`--org-id` options on `verify`/`day-report`/`case-report`, mutually
exclusive with `--audit-log` (validated with clear `click.UsageError`s
for every invalid combination — both given, neither given, one without
the other, an ambient `DATABASE_URL` left in a shell not silently
hijacking a plain `--audit-log` invocation). Live mode streams the org's
full, unfiltered audit chain fresh from the real Postgres source of
truth via `asyncio.run()` (Click commands are sync; `stream_by_org` is
async), disposing the engine in a `finally` block per CLAUDE.md §A.5's
resource-lifecycle discipline.

**Verified end-to-end (`poc/kronos_attest_live_mode/`), not just unit-mocked:**
ran both modes as real CLI subprocesses against the real shared dev
Postgres, for a real org with 33 real events (including a real case with
2 events and 1 evidence file) — 23/23 checks passed, with byte-identical
`merkle_root`/`chain_valid`/`break_count`/`event_count`/
`org_chain_fully_intact`/`evidence_ids` between the offline export mode
and the live mode for the same real data. Plus real CLI-level validation
of every mutually-exclusive-option error case. New unit tests
(`tests/unit/test_attest.py`, +8) cover the same validation logic with
`CliRunner` + a mocked live-fetch boundary (only the external DB call is
mocked, per CLAUDE.md §B.5 — domain objects are never mocked). Full
backend test suite before/after: 1955 → 1963 passed (+8, zero
regressions), 2 skipped both times. `ruff`/`black`/`mypy` clean.

**Explicitly out of scope, named not silently dropped:**
- **Live MinIO evidence-hash re-verification** (re-hashing each case's
  real evidence file bytes in MinIO against `Evidence.sha256` stored in
  Postgres) — a real, valuable, separately-scoped future item (needs its
  own design pass on how a standalone CLI authenticates to MinIO; not
  attempted here). **CLOSED 2026-08-18 as Milestone BB's own BB1 — see
  `docs/GAP_AUDIT_2026-08-18_MILESTONE_BB.md`.**
- **"Live TSA re-querying"** — not a real gap: RFC 3161 timestamp token
  verification (`kronos_attest/tsa.py`) is already fully real,
  cryptographic, self-contained verification of the token embedded in
  each anchor event — there is no meaningful "ask the TSA server again"
  operation for a report tool. The original P2-5 finding's phrasing
  ("live re-reading MinIO/Postgres/**TSA**") slightly overstated this;
  documented here so a future pass doesn't re-flag it.
- **`merkle-root`/`merkle-proof` live mode** — left offline-only; a
  trivial, mechanical follow-up (same pattern, lower value than the
  report commands) if ever wanted.

**Priority: P2** — real, long-standing, already-identified credibility
gap for the platform's flagship chain-of-custody claim, closed with a
clean, low-risk design (verbatim reuse of already-proven components, zero
change to the verification logic itself).

---

## Execution plan

**AA1**: dispatched and closed this pass (subagent, isolated worktree —
substantial enough to warrant it, unlike Z1's small direct fix).
Independently re-verified by the orchestrator before merge: real diff
read, real PoC output inspected, test counts re-run directly (1963
passed/2 skipped, matching the subagent's own claim exactly), ruff/black/
mypy re-run directly.

Remaining candidates from Milestone Z's own execution plan, still not
attempted (unchanged from that doc, listed here for continuity):
- `charts/kronos/files/nginx.conf.template` still lacks V8's real
  access-log fix (no live consequence yet, Helm/K8s log-shipping remains
  entirely unwired).
- `docs/access-management-review.md`'s still-open prod OpenSearch
  demo-cert gap (needs a real TLS material provisioning decision, not
  purely technical).
- The MinIO evidence-hash re-verification follow-on to AA1, named above.
