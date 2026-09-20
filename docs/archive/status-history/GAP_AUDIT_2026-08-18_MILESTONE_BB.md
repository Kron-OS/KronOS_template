# Gap Audit — Milestone BB (continuation, 2026-08-18)

Follow-up to `docs/GAP_AUDIT_2026-08-18_MILESTONE_AA.md` (Milestone AA,
fully resolved: AA1 CLOSED). This pass picked up AA1's own explicitly
named follow-on rather than re-scanning from scratch, since it was
already a well-understood, high-value, ready-to-scope item.

---

## BB1 — `kronos-attest case-report` couldn't verify evidence FILE bytes, only the audit trail describing them

**STATUS (2026-08-18, commit `68fab25`): CLOSED, verified live.**

AA1 (Milestone AA) added a real `--database-url`/`--org-id` live-Postgres
mode to `kronos-attest`, closing the "is the audit trail itself real"
half of the platform's chain-of-custody credibility gap. It explicitly
named one thing left out of scope: even with live mode, `case-report`
could confirm a case's audit *events* (including references to evidence
IDs) form a valid, untampered hash chain — but never actually checked
whether the evidence *file bytes themselves*, sitting in MinIO, still
match the SHA-256 hash recorded for them in Postgres at intake time. A
tampered/corrupted evidence file wouldn't have shown up as a chain break
at all, since the audit chain only records metadata, not a live re-hash
of the referenced file.

**Design done by the orchestrator before dispatch** (continuing the same
practice used for AA1 itself): keep `kronos_attest/report.py`'s
`CaseReport` dataclass and `AttestationReport.case_report()` pure and
dependency-free — this feature is purely additive at the CLI layer.
`--verify-evidence-hashes` (new flag on `case-report` only, not
`day-report`, since evidence is case-scoped) requires live-Postgres mode
already being active (evidence hashes aren't part of the audit-event
export shape at all, offline or live) plus new
`--minio-endpoint`/`--minio-access-key`/`--minio-secret-key`/
`--minio-use-tls` options (each with a `MINIO_*` env-var fallback,
mirroring `--database-url`'s own `DATABASE_URL` convention). For each
evidence ID the case actually references: looks up the real `Evidence`
row (`PostgresEvidenceRepository.get_by_id`), and if it's been
hashed/promoted, streams the real object bytes from MinIO
(`S3EvidenceStorage.stream_object`, never buffered whole into memory)
and recomputes a real running SHA-256, comparing against the stored
value. Results land as a new `evidence_integrity` key in the CLI's JSON
*output* only — never a new field on the pure `CaseReport` dataclass.

**Verified end-to-end (`poc/kronos_attest_evidence_hash_check/`), including the case that actually matters — a real detected tamper, not just the happy path:**
- Real pre-existing case/evidence in the shared dev stack: two promoted
  evidence items correctly reported `"verified"` (real re-hash matched
  Postgres's stored `sha256`), one un-promoted item correctly reported
  the honest `"not_yet_hashed"` status rather than a false pass/fail.
- A fresh, clearly-scoped throwaway org/case/evidence
  (`kronos-poc-bb1-...`) was driven through a real upload→promote flow,
  confirmed `"verified"`, then its real MinIO object bytes were
  deliberately corrupted via a direct `PutObject` — the real CLI then
  correctly reported `"MISMATCH"` with both the expected (Postgres) and
  computed (re-hashed MinIO) SHA-256 values shown. Original bytes were
  restored afterward and re-verified `"verified"` again. Throwaway
  Postgres rows were deleted and independently confirmed absent by the
  orchestrator (`SELECT count(*) FROM cases/evidence WHERE
  case_id/evidence_id = ...` → `0` for both) — audit-log rows were
  deliberately left intact (append-only by design). Old, corrupted MinIO
  object *versions* can't be purged before their WORM retention date —
  expected Object Lock behavior, not a cleanup failure, matching a prior
  finding from `poc/evidence_download/`.
- New unit tests (`tests/unit/test_attest.py`, +7) cover every new option
  combination and the offline-mode regression guard (confirms
  `evidence_integrity` never appears unless the flag is explicitly set).
  Full backend test suite before/after: 1963 → 1970 passed (+7, zero
  regressions), 2 skipped both times. `ruff`/`black`/`mypy` clean.
  Independently re-verified by the orchestrator before merge (not just
  the subagent's self-report): real diff read, real PoC output inspected,
  test counts (1970/2) and lint re-run directly, throwaway-row deletion
  independently confirmed via a direct Postgres query.

**Priority: P2** — a real, materially important strengthening of the
platform's flagship chain-of-custody claim: it is now possible to prove
not just that the audit trail is internally consistent, but that the
actual evidence files it describes are still byte-identical to what was
recorded at intake.

---

## Execution plan

**BB1**: dispatched and closed this pass (subagent, isolated worktree).

Remaining candidates, unchanged from Milestone AA's own execution plan,
still not attempted:
- `charts/kronos/files/nginx.conf.template` still lacks V8's real
  access-log fix (no live consequence yet, Helm/K8s log-shipping remains
  entirely unwired).
- `docs/access-management-review.md`'s still-open prod OpenSearch
  demo-cert gap (needs a real TLS material provisioning decision, not
  purely technical — likely needs the project owner's input rather than
  a unilateral call).
