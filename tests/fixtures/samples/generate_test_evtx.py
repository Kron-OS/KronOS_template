"""Script to generate a minimal test.evtx file for the EVTX parser test suite.

Run this script once to create the fixture file:
    python tests/fixtures/samples/generate_test_evtx.py

Requires the 'evtx' package (pyevtx-rs):
    pip install evtx

The generated file is a valid EVTX file that contains a small number of events
sourced from the evtx library's own test corpus.  If the evtx library does not
provide a sample corpus, this script writes a minimal hand-crafted EVTX header
so that FastEvtxParser.supports() returns True even if parsing yields no records.
"""

from __future__ import annotations

import pathlib
import sys

SAMPLES_DIR = pathlib.Path(__file__).parent
OUTPUT = SAMPLES_DIR / "test.evtx"


def main() -> None:
    try:
        import evtx  # type: ignore[import-untyped]
    except ImportError:
        print("evtx package not installed. Run: pip install evtx", file=sys.stderr)
        sys.exit(1)

    # Try to locate a bundled sample inside the evtx package.
    evtx_pkg_dir = pathlib.Path(evtx.__file__).parent
    candidates = list(evtx_pkg_dir.rglob("*.evtx"))

    if candidates:
        src = candidates[0]
        OUTPUT.write_bytes(src.read_bytes())
        print(f"Copied {src} → {OUTPUT} ({OUTPUT.stat().st_size} bytes)")
        return

    # Fallback: write the EVTX magic + minimal header so supports() works.
    # The evtx library may reject this on parse — that is acceptable since
    # test_parse_yields_records already skips when the file has no parseable events.
    magic = b"ElfFile\x00" + b"\x00" * 4088
    OUTPUT.write_bytes(magic)
    print(
        f"Warning: no sample EVTX found in evtx package; wrote stub header → {OUTPUT}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
