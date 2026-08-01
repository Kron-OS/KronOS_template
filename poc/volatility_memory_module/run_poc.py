#!/usr/bin/env python3
"""Real, end-to-end PoC for roadmap E5 (Volatility3 memory-dump module).

Run from the repo root with the project's own venv, and with the real
`vol` CLI (volatility3==2.28.0) on PATH:

    PATH="/path/to/a/venv/with/volatility3/bin:$PATH" \
        KRONOS_CRIDEX_VMEM_PATH=/path/to/cridex.vmem \
        ~/venv/bin/python3 poc/volatility_memory_module/run_poc.py

Never commits the real sample -- see README.md for the download/verification
instructions and the real sha256 this run computed.

Steps (CLAUDE.md §F.2):
  1. Pin + re-confirm the real tool version (already done, see README.md).
  2. Real magic-byte investigation against the real downloaded file.
  3. Ground truth: run the real `vol` CLI directly (bare subprocess, no
     KronOS code at all) for windows.info / windows.pstree / windows.psscan.
  4. Run the real, sandboxed VolatilityLauncher (src/external/sandbox/
     volatility_launcher.py) against the same real file -- proves the
     subprocess/JSON-io wrapping works for real.
  5. Run the real VolatilityModule.extract_artifacts() (src/external/
     parsers/volatility.py) against the same real file, using this
     repo's own StructuredArtifact/EvidenceProvenance types -- proves the
     whole module, not just the launcher, produces real, well-formed
     artifacts end to end.

Scope note (see this PoC's own README "Gaps" section): step 5 stops at
StructuredArtifact construction. Driving these through the full HTTP
upload -> validate -> parse -> Postgres pipeline was not attempted in this
pass -- an honestly-scoped fallback per CLAUDE.md §F/the roadmap brief,
not a claim of full pipeline integration.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

SAMPLE_PATH = os.environ.get(
    "KRONOS_CRIDEX_VMEM_PATH", "/home/reca/scratch/kronos-poc-volatility/cridex.vmem"
)


def _section(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def step1_confirm_sample() -> None:
    _section("STEP 1/5: Real sample present + sha256")
    path = Path(SAMPLE_PATH)
    if not path.exists():
        print(f"MISSING: {path} -- see README.md for the download instructions. Aborting.")
        sys.exit(1)
    size = path.stat().st_size
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha256.update(chunk)
    print(f"path:   {path}")
    print(f"size:   {size} bytes")
    print(f"sha256: {sha256.hexdigest()}")


def step2_magic_byte_investigation() -> None:
    _section("STEP 2/5: Real magic-byte investigation")
    with open(SAMPLE_PATH, "rb") as fh:
        header = fh.read(4096)
    print(f"first 16 bytes:              {header[:16]!r}")
    print(f"PAGEDUMP (MS crash dump) in first 4096 bytes: {b'PAGEDUMP' in header}")
    print(f"PAGEDU64 (MS crash dump) in first 4096 bytes: {b'PAGEDU64' in header}")
    print(f"LiME magic bytes 'LiME' in first 4096 bytes:  {b'LiME' in header}")
    print(
        "Conclusion: no verified magic bytes for this raw .vmem sample -- "
        "extension-only detection (.vmem/.mem/.raw/.dmp/.lime) is the honest "
        "answer, wired into MagicByteValidator._MEMORY_DUMP_EXTENSIONS and "
        "VolatilityModule.supports()."
    )
    # Also verify no accidental collision with PlasoParser's own fixed-offset
    # magic checks (ext4/NTFS/FAT/REGF/SQLite/prefetch/EWF) -- real bytes,
    # not assumed.
    checks = {
        "offset3-11 (NTFS)": header[3:11],
        "offset54-62 (FAT16/12)": header[54:62],
        "offset82-90 (FAT32)": header[82:90],
        "offset1080-1082 (ext superblock)": header[1080:1082],
        "offset0-4 (REGF)": header[0:4],
        "offset0-15 (SQLite)": header[0:15],
        "offset0-9 (EWF)": header[0:9],
    }
    print("\nCollision check against PlasoParser's real fixed-offset magics:")
    for label, value in checks.items():
        print(f"  {label}: {value!r}")


def step3_ground_truth_cli() -> None:
    _section("STEP 3/5: Ground truth -- bare `vol` CLI (no KronOS code)")
    vol_bin = _require_vol_bin()
    for plugin in ("windows.info", "windows.pstree", "windows.psscan"):
        print(f"\n--- vol -q -r json -f {SAMPLE_PATH} {plugin} ---")
        completed = subprocess.run(  # noqa: S603
            [vol_bin, "-q", "-r", "json", "-f", SAMPLE_PATH, plugin],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        print(f"returncode: {completed.returncode}")
        stdout = completed.stdout.strip()
        print(f"stdout ({len(stdout)} bytes): {stdout[:600]}")
        if completed.stderr.strip():
            print(f"stderr (first 300 chars): {completed.stderr.strip()[:300]}")


def _require_vol_bin() -> str:
    import shutil

    vol_bin = shutil.which("vol")
    if vol_bin is None:
        print("FATAL: 'vol' CLI not found on PATH -- install volatility3==2.28.0 first.")
        sys.exit(1)
    return vol_bin


async def step4_real_launcher() -> None:
    _section("STEP 4/5: Real sandboxed VolatilityLauncher")
    from src.external.sandbox.volatility_launcher import VolatilityLauncher

    launcher = VolatilityLauncher(timeout_seconds=180)
    result = await launcher.run(SAMPLE_PATH)
    print(f"primary plugin:    {result.plugin}")
    print(f"primary rows:      {len(result.rows)}")
    print(f"used_fallback:     {result.used_fallback}")
    print(f"fallback plugin:   {result.fallback_plugin}")
    print(f"fallback rows:     {len(result.fallback_rows) if result.fallback_rows else 0}")
    if result.fallback_rows:
        print("\nReal process rows recovered via windows.psscan fallback:")
        for row in result.fallback_rows:
            print(f"  PID={row['PID']:<6} PPID={row['PPID']:<6} {row['ImageFileName']}")


async def step5_real_module() -> None:
    _section("STEP 5/5: Real VolatilityModule.extract_artifacts()")
    from src.external.parsers.volatility import VolatilityModule
    from tests.fixtures.factories import make_evidence, make_tenant_context

    async def _file_stream(path: str) -> AsyncIterator[bytes]:
        with open(path, "rb") as fh:
            while chunk := fh.read(4 * 1024 * 1024):
                yield chunk

    evidence = make_evidence()
    tenant = make_tenant_context()
    parser = VolatilityModule(timeout_seconds=180)

    artifacts = [
        a
        async for a in parser.extract_artifacts(_file_stream(SAMPLE_PATH), evidence, tenant)
    ]

    print(f"StructuredArtifacts produced: {len(artifacts)}")
    for artifact in artifacts:
        rows = artifact.content["rows"]
        print(
            f"\n  kind={artifact.kind!r} plugin={artifact.content['plugin']!r} "
            f"row_count={len(rows)} record_index={artifact.kronos.record_index}"
        )
        print(f"  kronos.evidence_id={artifact.kronos.evidence_id}")
        print(f"  kronos.parser={artifact.kronos.parser} parser_version={artifact.kronos.parser_version}")
        if rows:
            print(f"  first row: {rows[0]}")


def main() -> None:
    step1_confirm_sample()
    step2_magic_byte_investigation()
    step3_ground_truth_cli()
    asyncio.run(step4_real_launcher())
    asyncio.run(step5_real_module())
    _section("PoC complete")


if __name__ == "__main__":
    main()
