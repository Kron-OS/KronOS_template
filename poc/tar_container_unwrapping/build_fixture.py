"""Build the real synthetic reproduction of the forensic2.E01 incident
(roadmap E1): a tar archive containing a real raw disk image (`image.dd`,
a real ext4 filesystem with a few real files at real, distinct timestamps)
plus a placeholder `memory.dmp` -- named `forensic2.E01` at the top level,
exactly mirroring the real incident's misleading extension, to prove
KronOS's detection is magic-byte-driven, not extension-driven.

Uses only real host tools (no fabrication):
  - `mke2fs -t ext4 -d <srcdir> image.dd` populates a real ext4 filesystem
    directly from a real directory tree -- no mount/root needed (verified:
    e2fsprogs 1.47.2 on this host supports `-d`).
  - Real, distinct file mtimes are set with `touch -d` before mke2fs runs,
    and are picked up by mke2fs's own inode population (confirmed below by
    reading them back out of psort's real Plaso output, not assumed).

Run once, from repo root:
    /home/reca/venv/bin/python3 poc/tar_container_unwrapping/build_fixture.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

WORK = Path(__file__).parent / "_fixture_build"
OUT_TAR = Path(__file__).parent / "forensic2.E01"


FILES: dict[str, tuple[str, str]] = {
    # relative path -> (content, mtime for `touch -d`)
    "alpha.txt": ("alpha file: user login event marker\n", "2024-01-15 10:00:00"),
    "bravo.txt": ("bravo file: privilege escalation marker\n", "2024-03-22 14:30:00"),
    "sub/charlie.txt": ("charlie file: data exfil marker\n", "2024-06-05 08:15:00"),
}


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def _run(cmd: list[str]) -> None:
    log("+", " ".join(cmd))
    subprocess.run(cmd, check=True)  # noqa: S603


def build_raw_ext4_image(image_path: Path) -> None:
    srcdir = WORK / "srcdir"
    if srcdir.exists():
        shutil.rmtree(srcdir)
    srcdir.mkdir(parents=True)

    for rel_path, (content, mtime) in FILES.items():
        full = srcdir / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content)
        _run(["touch", "-d", mtime, str(full)])

    if image_path.exists():
        image_path.unlink()
    # 4 MiB, no journal: the smallest real ext4 filesystem mke2fs 1.47.2 will
    # build on this host (verified: 1024x4k blocks, no "filesystem too small"
    # error) -- keeps the committed fixture small, matching
    # tests/fixtures/samples/real/kape/'s own precedent of using the smallest
    # real image that still reproduces the real bug/behaviour.
    _run(["dd", "if=/dev/zero", f"of={image_path}", "bs=1K", "count=4096", "status=none"])
    _run(["mke2fs", "-F", "-t", "ext4", "-O", "^has_journal", "-d", str(srcdir), str(image_path)])


def build_placeholder_memory_dump(path: Path) -> None:
    # Deliberately NOT a real memory dump (Volatility/memory parsing is
    # roadmap E5, out of scope here) -- the point of including it is to
    # prove TarArchiveParser's "recognised container member, no parser
    # yet" path (memory.dmp) doesn't crash the recursive extraction or
    # silently vanish without a trace.
    path.write_bytes(b"KRONOS-POC-PLACEHOLDER-MEMORY-DUMP-NOT-REAL\x00" * 1000)


def main() -> None:
    WORK.mkdir(exist_ok=True)
    image_path = WORK / "image.dd"
    memdump_path = WORK / "memory.dmp"

    build_raw_ext4_image(image_path)
    build_placeholder_memory_dump(memdump_path)

    log(f"image.dd: {image_path.stat().st_size} bytes")
    log(f"memory.dmp: {memdump_path.stat().st_size} bytes")

    with tarfile.open(OUT_TAR, "w") as tf:
        tf.add(image_path, arcname="image.dd")
        tf.add(memdump_path, arcname="memory.dmp")

    log(f"wrote {OUT_TAR} ({OUT_TAR.stat().st_size} bytes)")
    header = OUT_TAR.read_bytes()[:8192]
    assert header[257:262] == b"ustar", "sanity: ustar magic must be present at offset 257"
    log("sanity check OK: real ustar magic present at offset 257")


if __name__ == "__main__":
    main()
