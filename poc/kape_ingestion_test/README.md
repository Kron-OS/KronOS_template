# kape_ingestion_test — real KAPE zip + E01 ingestion, end to end

Verifies the new container-ingestion feature (`ZipArchiveParser` +
`PlasoParser`'s EWF/E01 routing, see `src/external/parsers/archive.py` and
`docs/verification-pass-findings.md`) against the real, live dev stack:
real login → real case creation → real upload/finalize of both KAPE-shaped
fixtures (`tests/fixtures/samples/real/kape/`, see that directory's
`NOTICE.md` for provenance) → the real autonomous pipeline → a real
OpenSearch fetch verifying every record's `source_path`/ECS `file.path` and
`container_sha256` provenance, not just a doc-count aggregation (same
"don't just count, verify content" approach as `poc/full_ingestion_test/`).

## How to run

```
docker compose -f docker/docker-compose.dev.yml -p kronos-dev up -d
# restart backend/celery workers if src/ changed after they last started --
# get_parser_registry() caches the registry per-process
docker compose -f docker/docker-compose.dev.yml -p kronos-dev restart \
    kronos-backend celery-worker celery-worker-plaso

/home/reca/venv/bin/python3 poc/kape_ingestion_test/run_kape_ingest.py   # login, case, upload+finalize both files
/home/reca/venv/bin/python3 poc/kape_ingestion_test/poll_and_verify.py  # poll to COMPLETE, fetch+verify real docs
```

## What's exercised

| Fixture | Backend path | Real coverage |
|---|---|---|
| `kape_triage.zip` | `ZipArchiveParser` (registered first in `ParserRegistry`, HEAVY queue) recursively re-dispatches each member to its own real parser | evtx-rs, chrome-history, nginx, plaso (prefetch) — 4 different inner parsers in one container |
| `kape_triage.E01` | `PlasoParser`'s EWF magic detection routes the *whole image* to `log2timeline`/`psort`, which auto-detects "storage media image" via dfVFS and walks the FAT filesystem itself | Real multi-file image parse: EVTX + Prefetch content, both with real in-image `source_path` |

## Real bug found and fixed (this feature)

`MagicByteValidator` had no EWF/E01 signature — a real KAPE-produced E01
would 422 at `finalize_upload` before ever reaching `PlasoParser`. Fixed by
adding the real, verified `EVF\x09\x0d\x0a\xff\x00` signature to
`_MAGIC_TABLE` (`src/application/validation.py`).

## Real bug found while *building the E01 test fixture* (not a KronOS bug)

See `tests/fixtures/samples/real/kape/NOTICE.md` for the full writeup: an
EWF image with a **FAT12** filesystem (the default `mkfs.vfat` picks for
small images) makes Plaso's signature scanner silently fail to read any
real file content (`pysigscan`/`libsigscan` "unable to read buffer"),
while the run still exits 0 and reports success — it just quietly emits
only directory `fs:stat` events, hiding the failure behind a
`record_count > 0`. Reproduced and root-caused via `pinfo --verbose` on the
Plaso storage file; fixed by forcing FAT16 (`mkfs.vfat -F 16`) for the
committed fixture. Not something KronOS itself can fix (it's a
Plaso/dfVFS/libewf interop limitation, and real Windows KAPE collections
are virtually always NTFS, not FAT), but worth flagging for anyone building
similar small test images.

## Captured output (real run, 2026-07-23)

See `output.txt` for the full captured run (upload/finalize responses, poll
sequence, final `kape_verification.json`, and a real EVTX event spot-check
straight from OpenSearch). Summary:

```json
{
  "total_documents": 631,
  "by_parser": {"chrome-history": 3, "evtx-rs": 194, "nginx": 15, "plaso": 419},
  "zip_source_paths_expected_present": true,
  "e01_source_paths_expected_present": true,
  "flagged_parsing_errors": [],
  "container_sha256_mismatches": [],
  "verdict": "PASS"
}
```

`plaso: 419` = 5 real events from the zip's Prefetch member +
414 real events from the E01's whole-image parse (388
`windows:evtx:record`, 24 `fs:stat`, 1 `windows:prefetch:execution`, 1
`windows:volume:creation`) — confirming the E01 path recovers full real
content, not just the FAT12-fixture's directory-listing-only failure mode
documented above.

Every one of the 631 real documents carries the correct `kronos.source_path`
/ ECS `file.path` (the exact real in-container/in-image path) and
`kronos.container_sha256` (matching the respective outer evidence's own
sha256) — zero mismatches, zero parsing-error/placeholder markers flagged.
