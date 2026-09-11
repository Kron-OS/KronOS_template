"""Real PoC: open the real `forensic2` EWF evidence, extract the raw
media payload via pyewf, and confirm the extracted bytes are genuinely
volatility3-analyzable.

Real, pinned versions used (introspected live inside `celery-worker-plaso`,
the exact container this will eventually run in):
  - pyewf (libewf-python) 20240506 -- a transitive dependency of dfvfs
    (20260731), which Plaso (20260512, docker/Dockerfile.plaso-worker)
    already depends on. NOT a new dependency: already installed.
  - volatility3 2.28.0 (already pinned, src/external/parsers/volatility.py).

Real docs used: no reachable official pyewf usage doc was fetched (this
container has no outbound internet); the exact installed module's own
introspected API (`dir(pyewf)`, `dir(pyewf.handle())`) was used as the
ground truth for this exact pinned version instead -- CLAUDE.md SS F.2 step 2
prefers official docs, but the installed binary's own real API surface for
the exact pinned build is at least as authoritative and was verified
against the real forensic2 file, not guessed.

Real evidence used: case 43097ab0-aae3-4968-915b-8f0229ac3865, evidence
ab9a6e5d-4982-4d81-997d-1085170e2e39 ("forensic2"), downloaded from the
real dev MinIO (kronos-evidence-kronos-dev bucket) -- the same file
diagnosed earlier in this session as a real EWF/E01 container currently
routed to PlasoParser and never reaching Volatility at all.

Run inside celery-worker-plaso (has pyewf + volatility3 both installed):
    docker cp run_poc.py docker-celery-worker-plaso-1:/tmp/run_poc.py
    docker exec docker-celery-worker-plaso-1 python3 /tmp/run_poc.py \
        /tmp/forensic2 /tmp/forensic2_extracted.raw
"""

from __future__ import annotations

import json
import logging
import sys


def extract_raw_media(ewf_path: str, output_path: str) -> int:
    """Open *ewf_path* via pyewf and write its raw media payload to
    *output_path*. Returns the real media size in bytes."""
    import pyewf

    # Real finding: pyewf.glob() requires a filename WITH a real EWF
    # extension (.E01 etc) to determine the segment-naming pattern -- it
    # raises OSError against the real forensic2 evidence bytes, because
    # KronOS's own MinIO storage convention keys objects by UUID with no
    # extension at all (confirmed live: "missing extension" from
    # libewf_glob_determine_format). Opening the single real filename
    # directly (no glob) works for a single-segment EWF, which this file
    # is -- multi-segment (.E01/.E02/...) support would need the real
    # filename preserved through storage, a real, separate follow-up if a
    # future sample turns out to need it.
    handle = pyewf.handle()
    handle.open([ewf_path])
    try:
        media_size = handle.get_media_size()
        chunk_size = 4 * 1024 * 1024
        with open(output_path, "wb") as out:
            remaining = media_size
            while remaining > 0:
                chunk = handle.read(min(chunk_size, remaining))
                if not chunk:
                    break
                out.write(chunk)
                remaining -= len(chunk)
        return media_size
    finally:
        handle.close()


def run_volatility_automagic_diagnosis(raw_path: str) -> dict:
    """Reuses poc/volatility_multiplugin/run_poc.py's own real, proven
    `run_multi_plugin` construction pattern (shared Context + automagic +
    plugins.construct_plugin) -- the exact mechanism VolatilityModule
    itself uses in production -- run for a single plugin
    (windows.pstree.PsTree) against the just-extracted raw bytes. DEBUG
    logging is enabled so the real automagic.windows logger output (the
    same "WindowsIntelStacker hits"/"No suitable kernels found during
    pdbscan" lines this session's earlier live diagnosis of ch2.dmp
    decisively relied on) is captured verbatim, not re-derived.
    """
    logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")

    import time

    import volatility3.plugins
    from volatility3 import framework
    from volatility3.framework import automagic, contexts, plugins
    from volatility3.framework.automagic import stacker

    framework.require_interface_version(2, 0, 0)
    ctx = contexts.Context()
    framework.import_files(volatility3.plugins, True)
    ctx.config["automagic.LayerStacker.single_location"] = f"file://{raw_path}"

    available_automagics = list(automagic.available(ctx))
    plugin_list = framework.list_plugins()
    plugin_name = "windows.pstree.PsTree"
    plugin_cls = plugin_list[plugin_name]

    t0 = time.time()
    try:
        chosen_automagics = automagic.choose_automagic(available_automagics, plugin_cls)
        if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
            ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin_cls)
        constructed = plugins.construct_plugin(
            ctx, chosen_automagics, plugin_cls, "poc", None, None
        )
        grid = constructed.run()
        rows: list = []

        def visitor(node, accumulator):
            accumulator.append(node.path)
            return accumulator

        grid.populate(visitor, rows)
        return {
            "plugin": plugin_name,
            "construct_seconds": round(time.time() - t0, 3),
            "rows": len(rows),
            "layer_names": list(ctx.layers),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 -- PoC: report the real error, don't crash
        return {
            "plugin": plugin_name,
            "construct_seconds": round(time.time() - t0, 3),
            "layer_names": list(ctx.layers),
            "error": f"{type(exc).__name__}: {exc}",
        }


def main() -> None:
    ewf_path = sys.argv[1]
    output_path = sys.argv[2]

    print(f"=== Opening real EWF file: {ewf_path} ===")
    media_size = extract_raw_media(ewf_path, output_path)
    print(f"media_size (real, from pyewf.get_media_size()): {media_size}")

    import os

    real_output_size = os.path.getsize(output_path)
    print(f"real bytes written to {output_path}: {real_output_size}")
    assert real_output_size == media_size, "extracted byte count must match declared media size"

    print("=== Running real volatility3 automagic diagnosis on extracted bytes ===")
    result = run_volatility_automagic_diagnosis(output_path)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
