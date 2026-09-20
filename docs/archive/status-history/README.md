# Archived status/audit documents

Everything in this directory is a **dated snapshot** — accurate at the time
it was written, not maintained since, and not a source of current truth.
This directory exists so that history isn't lost, not so it gets read as
if it were current.

**Current project state lives in two places, and only two:**
`STATUS.md` and `DECISIONS.md` (both at the repo root). If something in
this archive conflicts with those files, the root files win, always.

## Why this archive exists

Between 2026-06 and 2026-09, each work session wrote its own dated
status/handoff/gap-audit document instead of updating one canonical file:

- `GAP_AUDIT_2026-*_MILESTONE_*.md` (93 files) — one per work cycle,
  A → JJJJJ.
- `PROGRESS.md`, `HANDOFF_AND_ORCHESTRATION.md`,
  `PRODUCT_STATUS_AND_V2_PREVIEW.md` — three separate, overlapping
  attempts at "the one honest current-state doc," each written by a
  different session, none aware it was the third such attempt.
- `ASSESSMENT_SYNTHESIS_2026-08.md`, `verification-pass-findings.md`,
  `SECURITY_AUDIT.md`, `access-management-review.md` — one-off point-in-
  time audits, valid the day they were written.

The result: a reader could never tell which document was authoritative
without reading several and cross-referencing dates, and — since none of
these files were ever consolidated — the set of "current status" documents
only ever grew. This is the exact problem `STATUS.md`'s own header
addresses: **there is now exactly one status document, updated in place.**
Decisions with lasting rationale were pulled out of this pile into
`DECISIONS.md` (append-only, so it can't go stale the way a "current
state" narrative can); the rest stays here as evidence of work actually
done, in case a future investigation needs the detailed history.

Do not add new files to this directory as part of normal work. If you're
about to write `docs/GAP_AUDIT_<date>_MILESTONE_<X>.md` or a new
"HANDOFF"/"STATUS"/"PROGRESS" doc, stop — update `STATUS.md` in place
instead (and `DECISIONS.md` if what you did was a decision with lasting
rationale, not just a status change).
