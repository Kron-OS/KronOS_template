# PoC: Postgres -> Merkle root -> real RFC3161 TSA anchor -> real kronos-attest CLI

## What this actually does

Real Postgres, real `AuditLogService.anchor_day()` (real Merkle root
computation over real audit events), a real openssl-ts-backed RFC 3161 TSA
responder (reusing `poc/rfc3161/`'s throwaway CA + `openssl ts -reply`
server — the repo's own dev-compose `tsa` stub is not a real RFC 3161
responder, see that PoC's README), and the real, installed `kronos-attest`
CLI (`python -m kronos_attest.cli`) run as a real subprocess against a real
JSON export — every subcommand: `verify`, `merkle-root`, `merkle-proof`,
`day-report`, `case-report`.

## Pre-existing bug fixed first: local-vs-UTC day mismatch (found in `poc/full_pipeline/`)

Before building this PoC, fixed the timezone bug `poc/full_pipeline/README.md`
documented: `src/external/celery_app.py`'s `anchor_audit_log` beat task
computed `yesterday = date.today() - timedelta(days=1)` using the **local**
server timezone, while every audit event is timestamped `datetime.now(UTC)`
and `GET /api/audit/merkle-proof/{id}` scopes lookups by the **UTC** calendar
date. On this host (`Europe/Paris`, UTC+2), that mismatch made
`tests/unit/test_audit_routes.py::TestMerkleProof::test_single_event_proof_after_anchoring`
and `test_tampered_root_after_anchoring_returns_409` fail for real (both
tests independently carried the exact same `date.today()` bug in their own
fixtures — not a coincidence, since the tests were written to match the
buggy app behavior at the time). Fixed both the app
(`datetime.now(UTC).date()`) and the two tests. Verified: both tests now
pass.

## Real bug found and fixed: `AttestationReport.day_report()`'s `tsa_anchored` was ALWAYS False

`AuditLogService.anchor_day()` (`src/application/audit_log.py`) logs the
`AUDIT_MERKLE_ANCHORED` bookkeeping event with
`details = {"date": ..., "root_hash": ..., "event_count": ..., "tsa_token": ...}`.
`kronos_attest/report.py`'s `_verify_tsa_anchor()` filtered candidate anchor
events with `if details.get("day") != day: continue` — the wrong key. Since
`details.get("day")` is always `None`, this condition was always true,
`continue` fired on every single anchor event, and the function always fell
through to its final `return False, None` — meaning **`day_report`'s
`tsa_anchored` field could never be `True`, for any day, ever, even when the
day genuinely was TSA-anchored with a valid signature.**

Confirmed empirically, not just by reading the code: ran a real
`anchor_day()` against a real TSA, exported the real events, and
`kronos-attest day-report --tsa-cert ca.pem` returned:
```json
{ "day": "2026-07-21", "tsa_anchored": false, "tsa_gen_time": null }
```
for a day that had, moments earlier, gotten a real, valid RFC 3161 token
(confirmed separately via `kronos-attest verify --tsa-cert`, which uses the
*correct* key path and printed `TSA anchor unknown: valid` — the "unknown"
there being the same key-mismatch bug's cosmetic twin in `cli.py`'s
`_verify_all_tsa_anchors`, which doesn't gate control flow there but prints
the wrong label).

Also revealing: an **existing unit test**
(`tests/unit/test_tsa_round_trip.py::test_day_report_tsa_anchored_true_for_genuine_token`)
asserted `tsa_anchored is True` and passed — because its own synthetic
fixture hardcoded `"details": {"day": day, ...}`, matching the *buggy* key
rather than what the real `AuditLogService.anchor_day()` actually produces.
The test never ran against a real anchor export; it validated its own
assumption, which happened to match the bug. Exactly the failure mode
CLAUDE.md Section F exists to catch.

**Fixed:**
- `kronos_attest/report.py`: `details.get("day")` → `details.get("date")`.
- `kronos_attest/cli.py`: same key fix in `_verify_all_tsa_anchors`'s label lookup.
- `tests/unit/test_tsa_round_trip.py`: both fixtures' `"day": day` → `"date": day`,
  so the test now actually reflects the real event contract.

Re-verified after the fix: `day-report --tsa-cert` now correctly returns
`"tsa_anchored": true, "tsa_gen_time": "2026-07-21T23:05:27...+00:00"`, and
`verify --tsa-cert` prints `TSA anchor 2026-07-21: valid` (the real date,
not "unknown").

## Full checklist — 15/15 passed after the fixes

- 5 real events logged to real Postgres
- Real `anchor_day()` call: real non-empty Merkle root, real anchor row
  persisted in Postgres, real 2269-byte RFC 3161 token stored
- Full chain still verifies intact after anchoring
- Real export → `kronos-attest merkle-root` runs successfully
- `kronos-attest verify --tsa-cert`: chain intact, event found, **TSA anchor
  genuinely cryptographically verified** (not just "present")
- `kronos-attest merkle-proof`: real inclusion proof emitted
- `kronos-attest day-report --tsa-cert`: `tsa_anchored: true` (the fixed bug)
- `kronos-attest case-report`: all 5 real case events found, chain valid
- Tamper test: mutating one `row_hash` in the real export makes
  `kronos-attest verify` exit nonzero and report `Chain BROKEN: 2 break(s)`
  (two, not one — tampering one row also breaks the *next* row's tracked
  `prev_hash` chain, exactly the intended cascading tamper-evidence)

## Note on two legitimately different Merkle roots

`kronos-attest merkle-root` (spans every event in the export, including the
`AUDIT_MERKLE_ANCHORED` bookkeeping event itself) and `AuditLogService.
anchor_day()`'s own root (deliberately excludes that bookkeeping event — see
its docstring: including it would make the root self-referential) are
different by design, not a bug — confirmed both compute correctly for their
respective, intentionally different leaf sets.

## Files
`export.json` / `export_tampered.json` — real captured exports from this run.
