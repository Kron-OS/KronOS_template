# PoC: `GET /api/audit/export` -> real `kronos-attest` CLI

## What this proves

`src/external/routes/audit.py::export_org_audit_log` (roadmap Milestone
W/W3, `docs/ASSESSMENT_SYNTHESIS_2026-08.md` P1-W4) is the route that
produces the JSON export file `kronos-attest case-report`/`day-report`
consume. This PoC exercises it against a real Postgres-backed
`AuditLogRepository` (not the InMemory test double) and the real,
installed `kronos-attest` CLI (subprocess, not imported), per CLAUDE.md SS
F.

Versions: Postgres `postgres:16-alpine` (real running `docker-postgres-1`),
`sqlalchemy` 2.0.51, real `python -m kronos_attest.cli` entry point.

## Run

```
source ~/venv/bin/activate
python poc/kronos_attest_export/run_poc.py
```

Requires the real dev stack's Postgres reachable at `localhost:5432`
(`docker-postgres-1`, already running — not started/stopped by this PoC).

## Result

**All 24 checks pass, including case-report for a real multi-case org.**
The route returns 200, correct `Content-Disposition`, exactly the caller's
5 org events (not the other org's), and the real `kronos-attest
merkle-root`/`verify`/`day-report`/`case-report` commands all run
successfully against the route's real output with `chain_valid: true` for
every scope — including both `case_a` (3 events) and `case_b` (2 events)
of this PoC's own deliberately multi-case, interleaved scenario.

**Update (2026-08-16, Milestone W11): this run originally found (and this
PoC's own README originally documented as out-of-scope) a real,
pre-existing bug in `kronos_attest/report.py::case_report()`/`day_report()`
— both `chain_valid: false` for `case_a`/`case_b` on the very first run of
this PoC, despite zero tampering. That bug is now FIXED** (see
`kronos_attest/report.py`, `tests/unit/test_attest.py`'s
`TestCaseReportMultiCaseRegression`/`TestDayReportMultiDayRegression`) —
re-running this exact PoC after the fix is what proves it (this file's
`output.txt` is the fixed, passing run).

**Original root cause (confirmed by direct code read, not guessed):**
`AttestationReport.case_report()` filtered the full export down to one
case's events, then called `ChainVerifier.verify(case_events)` in
isolation — recomputing each event's row hash by chaining from a fixed
genesis hash against only the filtered subset, when the real chain those
events belong to is the org's FULL, contiguous history. A case-filtered
subset's first event's real `prev_row_hash` almost never points at
genesis (it points at whatever org-wide event actually preceded it), so
re-chaining an isolated subset from genesis was close to guaranteed to
report `chain_valid: false` for any real multi-case org, even with zero
tampering. `day_report()` shared the identical flaw for any org whose
history spans more than one day. `poc/chain_of_custody/`'s earlier,
single-case scenario never exposed it by coincidence (its filtered subset
happened to equal the org's entire chain).

**The fix:** `case_report()`/`day_report()` now run `ChainVerifier.verify()`
ONCE over the FULL, unfiltered event list (the real chain), then scope
`chain_valid`/`break_count` down to breaks whose `event_id` falls within
the case/day being reported — rather than re-verifying an isolated,
non-contiguous subset as if it were its own chain. A new
`org_chain_fully_intact` field additionally surfaces the org-wide picture
separately, so an auditor isn't blind to tampering elsewhere in the org
while looking at one case's own report. See `kronos_attest/report.py`'s
own updated docstrings for the full reasoning, including the (correct,
intentional) property that a real tamper still cascades forward to every
event chained after it, regardless of which case/day they belong to.
