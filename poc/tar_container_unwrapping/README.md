# tar_container_unwrapping — roadmap E1 real PoC

**Gap Audit Milestone ZZZ note:** the `forensic2.E01` fixture this PoC
builds/uses now lives at
`tests/fixtures/samples/real/tar_container/forensic2.E01` (this repo's
established convention for real fixture bytes), not directly in this
directory — `build_fixture.py`/`run_ingest.py` updated accordingly. Also
now reused by `frontend/e2e/evidence-upload-heavy-parser-archive.spec.ts`
for real browser E2E coverage of `TarArchiveParser`, closing the gap
Milestone YYY's own recommendation named (this PoC's own real verification
predates that initiative and had never been cited/wired into CI).

Real, reproduced incident this closes (`docs/NEXTGEN_SOC_ROADMAP.md` E1): a
`forensic2.E01`-named evidence file was actually a **tar archive** containing
`image.dd` (a raw disk image) and `memory.dmp`. Nothing in KronOS recognised
the tar wrapping, so the raw tar bytes were fed straight at Plaso's dfVFS
whole-image path, dfVFS found no partition table (the file starts with a tar
header, not a disk image), and **zero timeline events were extracted** — a
silent, total data-loss failure for exactly this composite-package shape.

Per CLAUDE.md Section F, this directory captures the *actual* verification
runs — against real host tools and the real, already-running dev stack — that
informed `src/external/parsers/tar_archive.py`, the raw-disk-image additions
to `src/external/parsers/plaso.py`, and the new `_MAGIC_TABLE` entries in
`src/application/validation.py`. Nothing here was assumed from memory.

## Versions pinned (per CLAUDE.md F.2 step 1)

- `plaso==20260512` — `docker/Dockerfile.plaso-worker` (confirmed: `docker exec
  docker-celery-worker-plaso-1 /opt/venv/bin/log2timeline --version` →
  `plaso - log2timeline version 20260512`).
- `dfvfs` — whatever plaso 20260512 pulls in transitively (not pinned
  separately in this repo); confirmed importable (`import dfvfs` succeeds)
  inside `docker-celery-worker-plaso-1`.
- Python 3.14 stdlib `tarfile` — the interpreter this repo's own venv/Docker
  image uses (`from __future__ import annotations` + match statements
  elsewhere in `src/` already assume 3.11+; verified `tarfile.GNU_MAGIC` /
  `tarfile.POSIX_MAGIC` directly against the installed stdlib, see below).
- GNU tar 1.35 — this dev host's own `tar` CLI (`tar --version`), used only to
  cross-check the magic byte claim below, not shipped as a runtime dependency.
- `e2fsprogs` 1.47.2 (`mke2fs -V`), `ntfs-3g`/`ntfsprogs` (`mkntfs`, apt
  `1:2022.10.3-5ubuntu1.1`), `dosfstools` (`mkfs.vfat`) — real host tools used
  only to build synthetic raw disk images for this PoC, not runtime
  dependencies of KronOS itself.

## Sub-investigation 1: real tar magic bytes (not guessed)

POSIX ustar mandates an 8-byte `magic`+`version` field at header offset 257.
Built real tars on this host and inspected the raw bytes with `xxd`:

```
$ tar -cf test_gnu.tar -C dir a.txt          # GNU tar 1.35 default format
$ xxd -s 257 -l 8 test_gnu.tar
00000101: 7573 7461 7220 2000                      ustar  .
$ python3 -c "import tarfile; ... tarfile.open(..., format=tarfile.PAX_FORMAT)"  # Python's own default
$ xxd -s 257 -l 8 test_py.tar
00000101: 7573 7461 7200 3030                      ustar.00
$ python3 -c "import tarfile; print(tarfile.GNU_MAGIC, tarfile.POSIX_MAGIC)"
GNU_MAGIC b'ustar  \x00'   POSIX_MAGIC b'ustar\x0000'
```

Both share the 5-byte `b"ustar"` prefix — that is exactly what
`TarArchiveParser.supports()` and `validation.py`'s new `_MAGIC_TABLE` entry
check (`(257, b"ustar", "tar")`). Pre-POSIX (V7) tar has no magic at a fixed
offset — out of scope, documented in `tar_archive.py`'s module docstring:
every tar producer a real DFIR workflow encounters on a reasonably current
Linux/macOS (GNU tar, BSD tar, Python's own `tarfile`, UAC) defaults to
ustar-compatible headers.

## Sub-investigation 2: is the raw-disk-image sub-gap real? (yes)

Before touching any KronOS code, checked whether `PlasoParser`/dfVFS can
handle a **bare** raw disk image (`image.dd`, no EWF/E01 wrapper) at all —
`_EWF_MAGIC` only matches real EWF, and `.dd`/`.img`/`.raw` weren't in
`_SUPPORTED_EXTENSIONS`. If this sub-gap were real and left unfixed,
unwrapping the tar alone would not have fixed the actual incident: the tar
would explode fine, but `image.dd` would then hit "no parser found" and
vanish, reproducing the same zero-events failure one layer deeper.

Built three real raw disk images directly on this host (no root needed for
ext4 via `mke2fs -d`; root+loop+`mount` needed for NTFS via `mkntfs`; `mtools`
for FAT16, matching `tests/fixtures/samples/real/kape/NOTICE.md`'s existing
precedent) and fed each straight at the real, already-running
`docker-celery-worker-plaso-1` container's `log2timeline`/`psort`:

```
$ dd if=/dev/zero of=image.dd bs=1M count=16
$ mke2fs -F -t ext4 -d srcdir/ image.dd     # real files, real distinct mtimes
$ xxd -s 1080 -l 16 image.dd
00000438: 53ef 0100 0100 0000 69d0 6d6a 0000 0000  S.......i.mj....   # real 0xEF53

$ docker cp image.dd docker-celery-worker-plaso-1:/tmp/image.dd
$ docker exec docker-celery-worker-plaso-1 /opt/venv/bin/log2timeline \
    --quiet --status_view none --storage-file /tmp/rawdd.plaso /tmp/image.dd
Source path             : /tmp/image.dd
Source type             : storage media image        # <-- dfVFS auto-detected it, zero flags
Processing completed.

$ docker exec ... /opt/venv/bin/psort --quiet -o json_line -w /tmp/rawdd.jsonl /tmp/rawdd.plaso
# 20 real events; alpha.txt/bravo.txt/sub/charlie.txt each present with their
# real, distinct timestamps and display_name "EXT:/alpha.txt" etc.
```

Repeated identically for a real NTFS image (`mkntfs` + loop-mount +
`touch -d`, magic `"NTFS    "` at offset 3 — `display_name` came back
`"NTFS:\alpha.txt"`) and a real FAT16 image (`mkfs.vfat -F 16` + `mtools`
`mcopy`/`mmd`, magic `"FAT16   "` at offset 54 — `display_name` came back
`"FAT:\alpha.txt"`). All three: real events, real timestamps, zero extra
flags/config, same `log2timeline`/`psort` subprocess invocation
`src/external/sandbox/firecracker.py` already uses for EWF.

**Finding: dfVFS's source-analyzer already auto-detects ext2/3/4, NTFS, and
FAT filesystem superblocks directly — no separate `DiskImageExtractor` or
dfVFS "RAW" type-indicator flag was needed.** The real gap was entirely at
the KronOS layer: `MagicByteValidator` had no raw-filesystem entries (so a
directly-uploaded `.dd` would 422 before ever reaching a parser), and
`PlasoParser.supports()` had no raw-filesystem magic check (so even a member
dispatched from inside a container, bypassing upload-time validation, would
still resolve to "no parser found" via `ParserRegistry.get_parser()`).
`_DFVFS_TYPE_PREFIXES` in `firecracker.py` already listed `"EXT:"`,
`"NTFS:"`, and `"FAT:"` (added defensively ahead of need, it turns out) —
`_plaso_source_path()` needed zero changes.

Fixed by adding the three real, verified magic signatures (ext offset 1080,
NTFS offset 3, FAT16/32 offsets 54/82) to both `PlasoParser.supports()` and
`validation.py`'s `_MAGIC_TABLE` — see those files' own code comments for the
full byte-level detail.

## The actual end-to-end reproduction

`build_fixture.py` builds the real synthetic incident reproduction:

1. A real directory with 3 files (`alpha.txt`, `bravo.txt`, `sub/charlie.txt`)
   at 3 real, distinct `touch -d` timestamps.
2. `mke2fs -F -t ext4 -d srcdir/ image.dd` — a real 16 MiB ext4 filesystem
   populated directly from that directory (no mount/root needed).
3. A placeholder `memory.dmp` (44000 bytes of a fixed repeating marker — NOT
   a real memory dump; Volatility/memory parsing is roadmap E5, out of scope
   here. The point of including it is to prove the "recognised container
   member, no parser yet" path doesn't crash or silently vanish).
4. Both packed into a real tar via Python's `tarfile`, named **`forensic2.E01`**
   — the exact misleading extension from the real incident, to prove
   detection is magic-byte-driven, not extension-driven.

`run_ingest.py` then drives the **real** evidence-intake pipeline against the
real, already-running dev stack (`docker/docker-compose.dev.yml`, project
`docker`): real PKCE login (`case-lead`/dev Keycloak), real case creation,
real presigned MinIO upload, real `finalize_upload` call — after which
KronOS's own autonomous pipeline (CLAUDE.md §E) takes over with zero further
client involvement.

`poll_and_verify.py` polls `GET /api/cases/{id}/evidence` to a terminal state,
then fetches every real OpenSearch document for the case and checks:

- Each of the 3 real files inside `image.dd` produced real timeline events
  carrying the **exact real timestamp** set on that file (not just "some
  events came out") — the literal reproduction of "zero events extracted"
  being fixed, shown as non-zero with real, spot-checkable content.
- `memory.dmp` produced **zero** records (E5/Volatility not built yet) but
  did **not** trigger any `plaso:placeholder`/error marker and did not sink
  the evidence to `ERROR` — the `tar_member_no_parser` log line (mirroring
  `ZipArchiveParser`'s pre-existing `zip_member_no_parser` precedent) is the
  trace of record for "recognised container member, no parser yet".
- Every record's `kronos.container_sha256` matches the outer tar's own
  sha256 — no cross-contamination.

## How to run

```
docker compose -f docker/docker-compose.dev.yml -p docker up -d
# code changes are picked up via the read-only src/ bind mount -- just restart:
docker compose -f docker/docker-compose.dev.yml -p docker restart \
    kronos-backend celery-worker celery-worker-plaso

# NOTE: this dev stack's LAN-HTTPS leaf cert (docker/init/tls-init-entrypoint.sh)
# is short-lived. If real_browser_login() fails with
# "certificate has expired", reissue it (root CA is unaffected, only the
# leaf) and restart nginx:
docker compose -f docker/docker-compose.dev.yml -p docker run --rm tls-init
docker compose -f docker/docker-compose.dev.yml -p docker restart nginx

/home/reca/venv/bin/python3 poc/tar_container_unwrapping/build_fixture.py
/home/reca/venv/bin/python3 poc/tar_container_unwrapping/run_ingest.py
/home/reca/venv/bin/python3 poc/tar_container_unwrapping/poll_and_verify.py
```

## Captured output (real run)

See `output.txt` for the full transcript of the three scripts above (most
recent real run). Summary (`verification.json`):

```json
{
  "total_documents": 20,
  "by_parser": {"plaso": 20},
  "real_file_hits": {
    "alpha.txt":          {"event_count": 4, "correct_timestamp_present": true},
    "bravo.txt":          {"event_count": 4, "correct_timestamp_present": true},
    "sub/charlie.txt":    {"event_count": 4, "correct_timestamp_present": true}
  },
  "all_image_dd_files_recovered_with_correct_timestamps": true,
  "memory_dmp_produced_zero_records": true,
  "flagged_parsing_errors": [],
  "container_sha256_mismatches": [],
  "final_evidence_state": "COMPLETE",
  "verdict": "PASS"
}
```

`by_parser: {"plaso": 20}` because a raw disk image's whole-image parse is
still `PlasoParser`'s own dfVFS routing (same as EWF) — `TarArchiveParser`
itself contributes no records directly, only recursion; its own real,
verified behaviour (recursive re-dispatch, tar-slip rejection, shared
depth/byte budget with `ZipArchiveParser`, "no parser yet" handling) is
covered by the fast synthetic unit tests in
`tests/unit/parsers/test_tar_archive.py` instead of re-derived here, per
this repo's existing convention (`poc/kape_ingestion_test/` does the same
split: real end-to-end pipeline PoC here, adversarial/guard-behaviour unit
tests alongside the parser).

## Not covered here (honest scope boundary)

- **`.tar.gz`** (UAC's real output format): out of scope for this item —
  see `tar_archive.py`'s module docstring for why (gzip bytes at offset 0
  hide the ustar header, so this parser's magic check correctly does not
  claim it). A future module would need to peel the gzip layer first
  (itself just another `ForensicParser` in the same recursive chain, per
  `reviews/DFIR_Artifact_Landscape.md`'s own note that UAC's shape is
  "structurally identical to the KAPE .zip case KronOS already solved").
- **Real memory-dump parsing**: `memory.dmp` here is a placeholder by
  design — Volatility integration is roadmap E5, which explicitly depends
  on this item (E1) being done first.
- **GPT/MBR-partitioned raw images**: this PoC's raw images are
  single-filesystem-directly-on-the-file (`mke2fs`/`mkntfs`/`mkfs.vfat`
  writing straight to the image, no partition table) — matching the
  incident's own `image.dd` shape. A partitioned raw image would resolve
  via dfVFS's `TSK:`/partition-table path instead (`_DFVFS_TYPE_PREFIXES`
  already lists `"TSK:"`), which is a distinct dfVFS code path this PoC did
  not separately re-verify (the EWF fixture in
  `tests/fixtures/samples/real/kape/` already exercises a FAT filesystem
  *without* a partition table too, for what it's worth — the same shape).
