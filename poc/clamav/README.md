# PoC: real ClamAV scanning (`clamav/clamav:stable`)

## What this actually does

Two scripts, both against a real `clamav/clamav:stable` container (real
`clamd`, real signature database — took ~1 min to finish loading on first
boot) and a real MinIO for the intake integration:

- `run_poc.py`: the real `ClamAVScanner`/`NoOpScanner` classes directly,
  plus the real `configure_clamav_from_settings()` fail-open(dev)/
  fail-closed(prod) gate.
- `run_poc_intake.py`: the real `EvidenceIntakeService._run_scan()` call
  path — `finalize_upload` → validate → scan → hash → promote — with a
  real EICAR file actually PUT to real MinIO first, exactly like a real
  upload. Evidence/audit repos are in-memory here (already verified
  against real Postgres separately) — scoped to the scanning integration
  point per CLAUDE.md B.5.

The EICAR string is the antivirus industry's standard, harmless test file
(https://www.eicar.org/) — not a real virus, designed so every AV engine
flags it identically. This is the normal, safe way to test AV integration.

## Results: 12/12 passed. No bugs found — this component pair is genuinely solid.

`run_poc.py` (7/7):
1. Real clean bytes → real ClamAV reports clean.
2. Real EICAR string → real ClamAV detects it (`Eicar-Test-Signature`).
3. EICAR streamed across multiple small async chunks (the real streaming
   `INSTREAM` path, not a single write) — still detected.
4. `configure_clamav_from_settings()`, all three real paths:
   - dev + reachable real clamd → wires the real `ClamAVScanner` (confirmed
     by type, not just "no exception").
   - dev + unreachable clamd → falls back to `NoOpScanner` with a warning,
     as designed (this exact fallback has been visible in every prior
     PoC's logs as `clamav_unreachable_dev_fallback` — now explicitly
     confirmed as intentional, correct behavior, not a leftover bug).
   - **production** + unreachable clamd → **raises `StorageError`**,
     refusing to start rather than silently scanning nothing (EVID-6) —
     the actual fail-closed security gate, exercised for real.

`run_poc_intake.py` (5/5):
5. A real clean file goes through the full real intake call path
   (presigned MinIO PUT → `finalize_upload` → validate → scan → hash →
   promote) and reaches `RECEIVED`.
6. A real EICAR file, same real call path, is rejected: `ValidationError`
   raised, evidence lands in `ERROR` with `error_reason =
   "infected:Eicar-Test-Signature"` (the real detected threat name, not a
   generic message), and a real `EVIDENCE_SCAN_FAILED` audit event is
   logged with the full real audit trail
   (`upload_requested` → `scan_started` → `scan_failed`).

No fixes needed in `src/` for this pair.
