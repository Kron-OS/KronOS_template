# Provenance

**No Windows OS or Windows container was used to produce these files.**
Confirmed on this host: `docker pull --platform windows/amd64
mcr.microsoft.com/windows/nanoserver` succeeds (Docker will happily download
Windows image layers), but `docker run` on that image fails immediately
(`unable to find user ContainerUser: no matching entries in passwd file`) --
Linux's `containerd`/`runc` has no Windows kernel to host the container.
There is no Windows ISO or QEMU on this host either. Per explicit user
direction, these fixtures instead package **real forensic artifact bytes**
(the same files in `tests/fixtures/samples/real/`, themselves sourced from
the [Plaso](https://github.com/log2timeline/plaso) project's `test_data/`,
see the parent `NOTICE.md`) under the **real KAPE target destination folder
convention** -- confirmed via public documentation/write-ups (KAPE mirrors
the source drive letter as a top-level folder, e.g.
`<tdest>\C\Windows\System32\config\SAM`) -- so the container/extraction
*code path* is exercised identically to a real KAPE `.zip`/`.E01`, even
though no live Windows system was collected from.

| File | Contents | Built with |
|---|---|---|
| `kape_triage.zip` | `C/Windows/System32/winevt/Logs/System.evtx`, `C/Windows/Prefetch/CMD.EXE-087B4001.pf`, `C/Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History`, `C/inetpub/logs/LogFiles/W3SVC1/u_ex260723.log` | Python stdlib `zipfile` (`ZIP_DEFLATED`), real artifact bytes copied in unmodified |
| `kape_triage.E01` | A **FAT16** filesystem image containing `C/Windows/System32/winevt/Logs/System.evtx` + `C/Windows/Prefetch/CMD.EXE-087B4001.pf` | `mkfs.vfat -F 16` (forced -- see the real bug below) + `mtools` (`mmd`/`mcopy`) to build the raw filesystem image, then **`ewfacquirestream` 20140816** (real libewf CLI, apt `ewf-tools`) to convert it to a real EWF/E01 image (`deflate:best` compression) |

Real-run verification (not assumed):
- `pyewf` (20240506, matching `docker/Dockerfile.plaso-worker`'s pinned
  environment) reads the E01 back; first 8 bytes are the real EWF magic
  `EVF\x09\x0d\x0a\xff\x00`.
- `dfvfs` (20260717, the same version installed as a real Plaso dependency
  in `docker/Dockerfile.plaso-worker`) walks the E01's FAT filesystem and
  finds both real files at their exact real paths/sizes.
- A real `log2timeline`/`psort` run (Plaso 20260512, the exact version
  pinned in this repo) against the E01 auto-detects it as a "storage media
  image" and emits 414 real events (388 `windows:evtx:record`, 24 `fs:stat`,
  1 `windows:prefetch:execution`, 1 `windows:volume:creation`), each
  carrying dfVFS's own real in-image path via `display_name`/`filename`
  (e.g. `FAT:\C\Windows\Prefetch\CMD.EXE-087B4001.pf`) -- this is exactly
  what `src/external/sandbox/firecracker.py::_plaso_source_path()` maps
  into `kronos.source_path`/ECS `file.path`.

**Real bug found while building this fixture (not a KronOS bug -- a
Plaso/dfVFS/libewf interop limitation, documented here so nobody rebuilds a
broken fixture the same way):** an EWF image whose FAT filesystem is
**FAT12** (the default `mkfs.vfat` picks for images under ~16 MiB, which the
first version of this fixture was) makes `log2timeline`'s signature scanner
fail silently per file with `pysigscan_scanner_scan_file_object: unable to
scan file` / `libsigscan_scanner_scan_file_io_handle: unable to read
buffer.` for every real file inside the image -- confirmed via `pinfo
--verbose` on the generated `.plaso` storage file (2 extraction warnings,
one per real file). The run still exits 0 and reports "Processing
completed", and Plaso still emits real `fs:stat` *directory*-listing events
(so `record_count > 0` in KronOS's own logs), but **zero events come from
the actual file content** -- confirmed reproducible independent of
compression (tested both `deflate:best` and `none`) and independent of
image size alone (an 8 MiB uncompressed FAT12 image reproduces it; a 16 MiB
**FAT16** image of the same real files, same compression, does not --
414/414 real events). This fixture is built with `-F 16` forced specifically
to avoid it. A production KAPE collection off a real Windows system is
virtually always NTFS, not FAT, so this specific bug is unlikely to bite in
practice -- flagged here as a real, verified finding for anyone building
small FAT test images against this exact Plaso/dfVFS/libewf version
combination, not as something KronOS itself needs to fix.

Used by `tests/unit/parsers/test_archive.py` and
`poc/kape_ingestion_test/`.
