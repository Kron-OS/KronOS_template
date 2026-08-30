# Provenance

`forensic2.E01` is **not actually an EWF/E01 image** — it is a real POSIX
ustar tar archive, deliberately misnamed with a `.E01` extension, that
reproduces a real incident documented in `poc/tar_container_unwrapping/README.md`:
a `forensic2.E01`-named evidence file that was actually a tar archive
containing a raw disk image, which nothing in KronOS recognized before
`TarArchiveParser` (`src/external/parsers/tar_archive.py`) was built —
the raw tar bytes were fed straight at Plaso's dfVFS whole-image path,
found no partition table, and silently produced zero timeline events.

Built by `poc/tar_container_unwrapping/build_fixture.py` — a real,
synthetic-but-genuine reproduction, not sourced from a third party:

- A real 16 MiB ext4 filesystem (`mke2fs -F -t ext4 -d srcdir/`),
  populated with 3 real files (`alpha.txt`, `bravo.txt`, `sub/charlie.txt`)
  at 3 real, distinct `touch -d` timestamps.
- A placeholder `memory.dmp` (44000 bytes of a fixed repeating marker —
  NOT a real memory dump; proves the "recognised container member, no
  parser yet" path doesn't crash or silently vanish, not a memory-forensics
  fixture).
- Both packed into a real tar via Python's `tarfile`, named `forensic2.E01`
  to prove `TarArchiveParser`'s detection is magic-byte-driven (POSIX
  ustar's real 5-byte `"ustar"` prefix at header offset 257), not
  extension-driven — exactly mirroring the real incident's own misleading
  filename.

Originally committed directly under `poc/tar_container_unwrapping/`;
relocated here (Gap Audit Milestone ZZZ) to match this repo's established
convention (`tests/fixtures/samples/real/kape/`, etc.) of keeping real
fixture bytes under `tests/fixtures/`, with `poc/` scripts and
`frontend/e2e/*.spec.ts` files referencing them from here rather than
duplicating the ~4 MB file. `poc/tar_container_unwrapping/build_fixture.py`/
`run_ingest.py` updated to reference this path (`git mv`, history
preserved).

Full real-run verification transcript (20 real timeline events, correct
per-file timestamps, `container_sha256` provenance match, `memory.dmp`
correctly producing zero records without erroring): see
`poc/tar_container_unwrapping/README.md` and its own `output.txt`/
`verification.json`.

Used by `poc/tar_container_unwrapping/run_ingest.py` and
`frontend/e2e/evidence-upload-heavy-parser-archive.spec.ts`.
