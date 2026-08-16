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

**Route-level checks: all real and passing.** The route returns 200,
correct `Content-Disposition`, exactly the caller's 5 org events (not the
other org's), and the real `kronos-attest merkle-root`/`verify`/`day-report`
commands all run successfully against the route's real output with
`chain_valid: true`.

**A real, pre-existing bug in `kronos_attest/report.py::case_report()` was
found and is NOT fixed by this PoC or this route — it is a separate,
out-of-scope finding, reported here for a future milestone:**

```
`kronos-attest case-report` (case_a, 3 events) -> exit=0
{
  "case_id": "...", "event_count": 3, "chain_valid": false, "break_count": 2, ...
}
```

**Root cause (confirmed by direct code read, not guessed):**
`AttestationReport.case_report()` (`kronos_attest/report.py`) filters the
full export down to one case's events, then calls
`ChainVerifier.verify(case_events)`. `ChainVerifier.verify()`
(`kronos_attest/verifier.py`) recomputes each event's row hash by chaining
against the *previous event in the list it was given*, starting from a
fixed genesis hash — it has no way to know that the real previous event in
that org's actual chain was a *different case's* event, since this org has
two cases with interleaved audit events (the realistic, common case). The
case-filtered subset's first event's real `prev_row_hash` points at
whatever org-wide event genuinely preceded it in Postgres, which is never
the genesis hash unless that event happens to be the org's very first-ever
audit event. Re-chaining from genesis over an isolated, non-contiguous
subset is close to guaranteed to report `chain_valid: false` for any real
multi-case org, even when nothing was tampered with.

This is why `poc/chain_of_custody/`'s own earlier run reported
`case-report`'s `chain_valid: true` — that PoC's scenario had exactly ONE
case in a fresh, single-case org, so the case-filtered subset happened to
equal the org's entire chain (no interleaving to expose the bug). This
PoC's scenario deliberately seeds TWO cases with interleaved events
specifically to surface it.

**`day_report()` shares the identical design flaw** (same
filter-then-isolated-re-chain pattern) but this PoC's own scenario didn't
expose it, since all seeded events happened to fall on the same real day —
a day-filtered subset that happens to equal the whole export doesn't
trigger the bug either. It would reproduce identically for any org whose
audit history spans more than one day (i.e., every real deployment).

**Why this PoC does not fix it:** the correct fix requires real design
work on `ChainVerifier`/`AttestationReport`'s contract (e.g., verifying the
FULL unfiltered chain first for tamper-detection, then reporting the
case/day-scoped event count and a case/day-scoped Merkle root computed
over that subset's *own* leaf hashes without re-deriving a broken isolated
hash chain) — this touches `kronos_attest/verifier.py`,
`kronos_attest/report.py`, `kronos_attest/cli.py`'s output contract, and
their existing tests (`tests/unit/test_kronos_attest.py`,
`tests/unit/test_attest.py`, `poc/chain_of_custody/`). That is a
real, separate, scoped fix — flagged here as a new finding for the
Milestone W tracking doc, not attempted under this item's own budget
(mirrors this initiative's own established discipline: one real,
well-scoped thing per W-item, not opportunistic scope creep mid-task).

See `output.txt` for the full real captured run (2 real, expected
failures on this known, now-documented, out-of-scope bug; all export-route
checks pass).
