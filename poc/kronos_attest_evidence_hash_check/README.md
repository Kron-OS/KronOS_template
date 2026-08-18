# PoC: `kronos-attest case-report --verify-evidence-hashes`

Gap Audit BB1, follow-on to AA1/P2-5
(`docs/GAP_AUDIT_2026-08-18_MILESTONE_AA.md`): AA1 gave `kronos-attest`
live-Postgres audit-chain verification but explicitly left MinIO evidence
byte-level re-verification out of scope. This PoC verifies the new
`case-report --verify-evidence-hashes` option: for each evidence file a case
references, it re-streams the real bytes from MinIO, recomputes a real
SHA-256, and compares it against `Evidence.sha256` in Postgres — real
tamper detection, not just chain-hash verification.

## Versions pinned

- `boto3==1.43.46` (`boto3>=1.34` in `pyproject.toml`)
- `sqlalchemy==2.0.51`, `asyncpg==0.31.0`, `click==8.4.2` — same as
  `poc/kronos_attest_live_mode/README.md`'s own pinned versions (unchanged)
- Postgres: `postgres:16-alpine` — the real, running `docker-postgres-1`
  (`docker inspect docker-postgres-1 --format '{{.Config.Image}}'`)
- MinIO: `minio/minio:latest` — the real, running `docker-minio-1`
  (`docker inspect docker-minio-1 --format '{{.Config.Image}}'`), creds
  `kronos_minio` / `kronos_minio_dev_password` confirmed via
  `docker inspect docker-minio-1` env output, matching
  `docker/docker-compose.dev.yml`'s `MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD`
  defaults.

## What this PoC does

**Part 1 (read-only, real pre-existing data).** A direct, read-only SQL
query against the real shared `docker-postgres-1` (before writing this
script — see the orchestrating agent's own transcript for the raw
`SELECT`s) found a real, pre-existing org (`org_alias=kronos-dev`,
`org_id=482072f5-8086-4815-be03-879cc2eaecb5`) with a case
(`case_id=c6284b59-fe95-4b72-8a75-3a3abcc062d2`) whose real audit events
reference 3 real evidence rows:

- `e2d863a9-...` and `d29734a3-...` — both real `COMPLETE`-state evidence
  with `sha256`/`minio_evidence_key` already populated (a real, prior
  CloudTrail-JSON upload from earlier dev/PoC work).
- `b384dc58-...` — a real `ERROR`-state evidence whose ClamAV scan flagged
  `infected:Eicar-Test-Signature` before hashing/promotion ever ran, so
  `sha256`/`minio_evidence_key` are genuinely still `NULL` in Postgres — a
  real, naturally-occurring `"not_yet_hashed"` case, not fabricated.

Running the real, installed `kronos-attest` CLI as a real subprocess
(`python -m kronos_attest.cli case-report --database-url ... --org-id
482072f5-... --case-id c6284b59-... --verify-evidence-hashes --minio-endpoint
http://localhost:9000 --minio-access-key kronos_minio --minio-secret-key
kronos_minio_dev_password --minio-use-tls false`) against this real,
untouched data demonstrates both the real `"verified"` outcome (both
promoted evidence's real MinIO bytes hash to the value Postgres already
recorded) and the real `"not_yet_hashed"` outcome, all read-only — no data
was created, modified, or deleted for this part.

**Part 2 (fresh throwaway data only, real corruption).** `"MISMATCH"` can't
be demonstrated safely against someone else's real evidence, so this part
drives a full real upload→promote flow via `EvidenceIntakeService` (the same
real Postgres, the same real MinIO — no separate throwaway Postgres needed
this run; the `quota_held` schema-drift issue `poc/evidence_download/`'s
README documents was checked directly against `information_schema.columns`
before writing this script and confirmed **absent** from the current shared
`evidence` table) into a brand-new, uniquely-named throwaway org
(`kronos-poc-bb1-<random hex>`) and case:

1. Upload real JSON content, PUT to a real presigned MinIO URL, call
   `start_intake()` → real `validate → scan → hash → promote`, landing a
   real object in a real, freshly-created per-org WORM bucket
   (`kronos-evidence-kronos-poc-bb1-<hex>`) with `Evidence.sha256` set in
   Postgres.
2. Real CLI run → `"verified"` (bytes match, unmodified).
3. **Deliberately corrupt** the real object: a second `PutObject` to the
   exact same bucket/key with different bytes, via `boto3` directly (the
   same `S3EvidenceStorage._client` the app itself uses, no separate tool
   invented). Because the evidence bucket has Object Lock enabled
   (`S3EvidenceStorage._ensure_bucket`), MinIO requires bucket versioning
   for Object Lock, so this **lands as a new object version**, not a true
   in-place overwrite — but a plain `GetObject` (no `VersionId`, exactly
   what `S3EvidenceStorage.stream_object()` issues) always serves the
   newest version, so the real CLI's re-hash genuinely reads the corrupted
   bytes.
4. Real CLI run → `"MISMATCH"`, with `expected_sha256` (from Postgres) and
   `computed_sha256` (freshly re-hashed from the real corrupted MinIO
   bytes) both printed and provably different — confirmed to equal a local
   `hashlib.sha256()` of the exact corrupted content this script wrote.
5. **Restore**: a third `PutObject` with the original, correct bytes to the
   same key (another new version, now current again).
6. Real CLI run → `"verified"` again, confirming the restore worked and
   that detection isn't sticky/cached.
7. **Cleanup**: `PostgresEvidenceRepository.delete_by_id()` and
   `PostgresCaseRepository.delete()` hard-delete the throwaway evidence and
   case rows from the real shared Postgres. The throwaway org's `audit_log`
   rows are deliberately **left intact** — the audit log is append-only by
   design (CLAUDE.md §A.2); a handful of harmless, clearly-labeled PoC
   events for a throwaway org is consistent with that design, and deleting
   them would mean modifying the very artifact this feature exists to
   protect. The corrupted/original MinIO object **versions** similarly
   cannot be purged before their WORM retention date (`retention_days`
   default, `S3EvidenceStorage.__init__`) — that is Object Lock Compliance
   mode working exactly as intended (the whole point of WORM evidence
   storage), not a PoC bug, and matches the same conclusion
   `poc/evidence_download/`'s own README already reached for its own
   throwaway bucket. The bucket's **current** object version is the
   restored, correct content, so nothing is left visibly "corrupted."

## How to run

```
/home/reca/venv/bin/python poc/kronos_attest_evidence_hash_check/run_poc.py
```

Requires `docker-postgres-1` and `docker-minio-1` already running and
reachable on `localhost:5432`/`localhost:9000` (they were, throughout this
run).

## Result (see `output.txt` for the full real captured run)

**17 passed, 0 failed.** Key lines:

```
[PASS] real pre-existing promoted evidence e2d863a9... verified -- {'status': 'verified', 'expected_sha256': 'fa14d982...', 'computed_sha256': 'fa14d982...'}
[PASS] real pre-existing promoted evidence d29734a3... verified -- {'status': 'verified', 'expected_sha256': 'fa14d982...', 'computed_sha256': 'fa14d982...'}
[PASS] real pre-existing un-promoted evidence b384dc58... -> not_yet_hashed -- {'status': 'not_yet_hashed'}
[PASS] real evidence promoted (sha256 + minio_evidence_key set) via real validate->scan->hash->promote -- state=RECEIVED sha256=02fe1386...
[PASS] fresh evidence verified BEFORE corruption -- {'status': 'verified', ...}
[PASS] MISMATCH detected on the real corrupted object -- {'status': 'MISMATCH', 'expected_sha256': '02fe1386...34e', 'computed_sha256': '99eb62d8...c57'}
[PASS] expected_sha256 (Postgres) != computed_sha256 (real re-hashed MinIO bytes) -- expected=02fe1386...34e computed=99eb62d8...c57
[PASS] computed_sha256 matches a real local hash of the corrupted content
[PASS] verified again after restoring the original bytes -- {'status': 'verified', ...}
[PASS] throwaway evidence row deleted from Postgres
[PASS] throwaway case row deleted from Postgres
```

## Scope note

Only `case-report` gained `--verify-evidence-hashes` — `day-report` is not
case-scoped, so there is no natural evidence-file set to check there (see
the parent task's own explicit scope note). No `src/` production code was
touched; `S3EvidenceStorage`/`PostgresEvidenceRepository` are used exactly
as they already exist, read-only from `kronos_attest`'s point of view
(aside from this PoC's own throwaway write/corrupt/restore/delete sequence,
entirely confined to data this PoC itself created).
