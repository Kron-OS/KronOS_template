#!/usr/bin/env python3
"""KronOS Volatility3 worker: run several real volatility3 plugins against a
memory image, sharing ONE resolved automagic context, and emit one JSON
result document to stdout -- the same "small standalone script, JSON in/out,
everything else on stderr" shape as docker/plaso/kronos-plaso-worker.py and
docker/yara/kronos-yarax-worker.py. Runs inside this subprocess, never inside
the caller's (API/Celery worker) process -- CLAUDE.md SSG.3.

**Milestone CCCCC rewrite.** The prior version shelled out to the `vol` CLI
once *per plugin*, redoing the expensive part (DTB/page-table detection +
kernel symbol table resolution) from scratch every time. Real-verified this
session (poc/volatility_multiplugin/, volatility3==2.28.0, pinned): building
ONE ``volatility3.framework.contexts.Context``, resolving automagic once,
then looping ``plugins.construct_plugin()`` for multiple plugin classes
against that SAME context lets every plugin after the first construct in
~0.1-0.5s instead of paying the full automagic cost again (measured up to
13s for one real sample). This worker now uses volatility3's own framework
API directly (the exact sequence ``volatility3.cli.CommandLine.run()`` uses
internally) instead of the `vol` CLI, and reuses
``volatility3.cli.text_renderer.JsonRenderer``'s own TreeGrid-walking visitor
for row extraction rather than hand-rolling a second one (also verified live
in the same PoC).

**Plugin names are the real, canonical ``module.ClassName`` form**
(``windows.pstree.PsTree``, not ``windows.pstree``) -- confirmed live this
session: ``framework.list_plugins()`` only recognises the full form; the
short form only worked via the `vol` CLI's own argparse prefix-matching,
which this worker no longer goes through.

**pstree/psscan no longer need a conditional fallback for the
StructuredArtifact side** -- both are now just two of the several plugins in
the eager set below and run unconditionally (running psscan is no longer an
extra ~7s `vol` subprocess, it's ~0.15s of shared-context reuse), so an
analyst always gets both listings, not just whichever the old fallback logic
picked. Both real findings that motivated the old fallback logic are still
true and still handled, just generalized:

1. **``cridex.vmem`` wrinkle** (Windows XP + volatility3==2.28.0,
   verified in ``poc/volatility_memory_module/README.md`` and reconfirmed
   this session in ``poc/volatility_multiplugin/output.txt``):
   ``windows.pstree`` legitimately returns zero rows (a real, exit-0,
   no-exception empty linked-list walk) while ``windows.psscan`` recovers
   the real process census via pool-tag scanning from the same file. Both
   still run and both are still reported -- this worker no longer needs to
   *decide* whether to run the second one, it always does.
2. **``ch2.dmp`` automagic-construction failure** (a real user-reported
   sample, Gap Audit Milestone AAAAA/BBBBB follow-up): some images make
   volatility3's own automagic layer stacker unable to find a valid
   Windows DTB/kernel at all -- every plugin sharing that context fails
   identically (all raise inside ``construct_plugin()``), reported
   per-plugin, never silently dropped, never aborting the whole worker run.

**Per-plugin error isolation, generalized from the old primary/fallback
pair to a real loop over N plugins**: one plugin's ``construct_plugin()``
or render failure (e.g. a genuinely unsupported plugin for this OS/build)
must not prevent the other plugins already sharing the constructed context
from completing -- each plugin's own result carries its own
``status``/``error``, independent of every other plugin's outcome.

**Wall-clock budget**: a single ``--timeout-seconds`` bounds the WHOLE run
(sum of every plugin), checked between plugin iterations (not mid-plugin,
via a soft elapsed-time guard rather than a signal-based interrupt) --
malfind/filescan alone measured 24s/11s on a modest 1.6GB image and will be
worse on larger real-world ones, so this must budget across the set, not
per-plugin. A plugin skipped for running out of budget is reported honestly
(``status: "skipped_timeout_budget"``), never silently absent.

Usage:
    python kronos-volatility-worker.py \
        --evidence-path /mnt/evidence/sample.vmem \
        --plugins windows.pstree.PsTree,windows.psscan.PsScan,windows.dlllist.DllList \
        --timeout-seconds 300

**Milestone EEEEE: two on-demand, single-target modes.** Real-verified in
``poc/volatility_dumpfiles/`` and ``poc/volatility_registry_printkey/`` --
these do NOT share the eager multi-plugin context above (they are
independently-triggered, one-shot analyst actions, not part of every parse):

    --evidence-path X --dumpfiles-physaddr OFFSET --dumpfiles-output-dir DIR
        Real, decisive PoC finding: windows.filescan's own "Offset" column
        is a PHYSICAL address; targeting windows.dumpfiles via
        plugins.DumpFiles.physaddr = [offset] (not --virtaddr) is the
        mechanism that actually extracts bytes for a specific filescan row.
        Writes each extracted file to DIR via a real FileHandlerInterface
        subclass (mirrors volatility3's own CLIFileHandler), emits
        {"status", "error", "dumped_files": [{"filename", "path", "sha256",
        "size_bytes"}]}.

    --evidence-path X --registry-hive-offset OFFSET [--registry-key KEY]
        Real-verified: a scoped, non-recursive windows.registry.printkey
        call (hive offset + optional key path, recurse=False) is fast
        (~0.35s) and bounded, vs. >200s for an unscoped recursive dump.
        Always uses a FRESH Context (never the eager multi-plugin one) --
        real-verified that reusing one shared Context across repeated
        printkey calls against the same hive raises
        LayerException("Layer already exists: ...") since HiveList.list_hives
        re-adds the hive layer on every call and volatility3 never
        deregisters it between calls. Emits {"status", "error", "plugin",
        "rows": [...]}.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
from typing import Any

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("kronos-volatility-worker")

# The real eager plugin set (Milestone CCCCC's plan): every plugin here runs
# unconditionally, sharing one context, on every memory-dump parse.
# `windows.malware.malfind.Malfind` (not the deprecated `windows.malfind.Malfind`
# -- confirmed live this session) is the "suspicious executables" signal.
_DEFAULT_PLUGINS = (
    "windows.pstree.PsTree",
    "windows.psscan.PsScan",
    "windows.dlllist.DllList",
    "windows.cmdline.CmdLine",
    "windows.malware.malfind.Malfind",
    "windows.filescan.FileScan",
    "windows.registry.hivelist.HiveList",
)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="KronOS volatility3 sandboxed multi-plugin runner")
    p.add_argument("--evidence-path", required=True)
    p.add_argument(
        "--plugins",
        default=",".join(_DEFAULT_PLUGINS),
        help="Comma-separated real volatility3 plugin names (module.ClassName form).",
    )
    p.add_argument("--timeout-seconds", type=int, default=300)
    p.add_argument(
        "--dumpfiles-physaddr",
        type=int,
        default=None,
        help="On-demand mode: physical address (from a windows.filescan row's "
        "own Offset column) to target with windows.dumpfiles.",
    )
    p.add_argument(
        "--dumpfiles-output-dir",
        default=None,
        help="Directory to write extracted file bytes into (on-demand dumpfiles mode).",
    )
    p.add_argument(
        "--registry-hive-offset",
        type=int,
        default=None,
        help="On-demand mode: hive offset (from a windows.registry.hivelist row) "
        "to run a scoped windows.registry.printkey call against.",
    )
    p.add_argument(
        "--registry-key",
        default=None,
        help="Optional subkey path (on-demand registry mode); omitted = hive root.",
    )
    return p.parse_args()


def _emit(result: dict) -> None:
    """Write the single JSON result document to stdout."""
    print(json.dumps(result, default=str), flush=True)


def _run_all_plugins(
    evidence_path: str, plugin_names: list[str], timeout_seconds: int
) -> dict[str, dict[str, Any]]:
    """Run every plugin in *plugin_names* against ONE shared Context.

    Returns ``{plugin_name: {"status": "ok"|"scan_error"|"skipped_timeout_budget",
    "rows": [...], "error": str|None}}``. Never raises for a single plugin's
    own failure -- see this module's own docstring for why (each plugin's
    ``construct_plugin()``/render call is independently wrapped).
    """
    import volatility3
    import volatility3.plugins
    from volatility3 import framework
    from volatility3.cli.text_renderer import JsonRenderer
    from volatility3.framework import automagic, contexts, interfaces, plugins
    from volatility3.framework.automagic import stacker

    framework.require_interface_version(2, 0, 0)

    ctx = contexts.Context()
    import_failures = framework.import_files(volatility3.plugins, True)
    if import_failures:
        logger.warning("volatility3 plugin import failures: %s", ", ".join(sorted(import_failures)))

    ctx.config["automagic.LayerStacker.single_location"] = f"file://{evidence_path}"
    available_automagics = list(automagic.available(ctx))
    plugin_list = framework.list_plugins()

    results: dict[str, dict[str, Any]] = {}
    start = time.time()

    for plugin_name in plugin_names:
        elapsed = time.time() - start
        if elapsed >= timeout_seconds:
            logger.warning(
                "volatility3 worker timeout budget (%ss) exhausted before %s; skipping",
                timeout_seconds,
                plugin_name,
            )
            results[plugin_name] = {
                "status": "skipped_timeout_budget",
                "rows": [],
                "error": f"skipped: {elapsed:.1f}s of {timeout_seconds}s budget already used",
            }
            continue

        if plugin_name not in plugin_list:
            logger.error("volatility3 plugin %s not found (not registered/importable)", plugin_name)
            results[plugin_name] = {
                "status": "scan_error",
                "rows": [],
                "error": f"{plugin_name} not found in the real plugin registry",
            }
            continue

        plugin_cls = plugin_list[plugin_name]
        try:
            chosen_automagics = automagic.choose_automagic(available_automagics, plugin_cls)
            if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
                ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(
                    plugin_cls
                )
            constructed = plugins.construct_plugin(
                ctx, chosen_automagics, plugin_cls, "plugins", None, None
            )
            grid = constructed.run()
        except Exception as exc:  # noqa: BLE001 -- one plugin's failure must not sink the others
            logger.warning(
                "volatility3 plugin %s failed: %s: %s", plugin_name, type(exc).__name__, exc
            )
            results[plugin_name] = {
                "status": "scan_error",
                "rows": [],
                "error": f"{type(exc).__name__}: {exc}",
            }
            continue

        try:
            renderer = JsonRenderer()
            ignore_columns = renderer.ignored_columns(grid)
            tree: list = []

            def visitor(node, accumulator, _grid=grid, _ignore=ignore_columns, _renderer=renderer):
                acc_map, final_tree = accumulator
                node_dict: dict[str, Any] = {"__children": []}
                for column_index, column in enumerate(_grid.columns):
                    if column in _ignore:
                        continue
                    type_renderer = _renderer._type_renderers.get(
                        column.type, _renderer._type_renderers["default"]
                    )
                    data = type_renderer(list(node.values)[column_index])
                    if isinstance(data, interfaces.renderers.BaseAbsentValue):
                        data = None
                    node_dict[column.name] = data
                if node.parent and node.parent.path in acc_map:
                    acc_map[node.parent.path]["__children"].append(node_dict)
                else:
                    final_tree.append(node_dict)
                acc_map[node.path] = node_dict
                return (acc_map, final_tree)

            grid.populate(visitor, ({}, tree))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "volatility3 plugin %s ran but row extraction failed: %s: %s",
                plugin_name,
                type(exc).__name__,
                exc,
            )
            results[plugin_name] = {
                "status": "scan_error",
                "rows": [],
                "error": f"row extraction failed: {type(exc).__name__}: {exc}",
            }
            continue

        logger.info("volatility3 plugin %s: %d rows", plugin_name, len(tree))
        results[plugin_name] = {"status": "ok", "rows": tree, "error": None}

    return results


def _run_dumpfiles(evidence_path: str, physaddr: int, output_dir: str) -> dict[str, Any]:
    """On-demand, single-target windows.dumpfiles run (real, decisive
    mechanism confirmed in poc/volatility_dumpfiles/): targets
    plugins.DumpFiles.physaddr = [physaddr] against a fresh Context (this is
    always a one-shot call, never repeated against the same Context, so the
    registry printkey layer-reuse issue this worker's other on-demand mode
    works around does not apply here -- still uses a fresh Context per
    invocation for consistency with that same "one worker subprocess per
    on-demand click" production shape).

    Returns {"status", "error", "dumped_files": [...]}. Never raises for a
    real extraction failure -- reported as scan_error, same discipline as
    the eager multi-plugin path.
    """
    import io

    import volatility3
    import volatility3.plugins
    from volatility3 import framework
    from volatility3.framework import automagic, contexts, interfaces, plugins
    from volatility3.framework.automagic import stacker

    framework.require_interface_version(2, 0, 0)

    class _KronosFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
        """Real FileHandlerInterface impl -- close() writes accumulated
        bytes to output_dir and records real sha256/size. Mirrors
        volatility3's own CLIFileHandler (see this module's docstring)."""

        captured: list[dict[str, Any]] = []

        def __init__(self, filename: str) -> None:
            io.BytesIO.__init__(self)
            interfaces.plugins.FileHandlerInterface.__init__(self, filename)

        def close(self) -> None:
            if self.closed:
                return
            self.seek(0)
            data = self.read()
            safe_name = os.path.basename(self.preferred_filename)
            out_path = os.path.join(output_dir, safe_name)
            with open(out_path, "wb") as f:
                f.write(data)
            _KronosFileHandler.captured.append(
                {
                    "filename": safe_name,
                    "path": out_path,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size_bytes": len(data),
                }
            )
            io.BytesIO.close(self)

    _KronosFileHandler.captured = []

    ctx = contexts.Context()
    framework.import_files(volatility3.plugins, True)
    ctx.config["automagic.LayerStacker.single_location"] = f"file://{evidence_path}"
    available_automagics = list(automagic.available(ctx))
    plugin_list = framework.list_plugins()

    plugin_name = "windows.dumpfiles.DumpFiles"
    if plugin_name not in plugin_list:
        return {"status": "scan_error", "error": f"{plugin_name} not found", "dumped_files": []}

    plugin_cls = plugin_list[plugin_name]
    ctx.config["plugins.DumpFiles.physaddr"] = [physaddr]

    try:
        chosen = automagic.choose_automagic(available_automagics, plugin_cls)
        if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
            ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin_cls)
        constructed = plugins.construct_plugin(
            ctx, chosen, plugin_cls, "plugins", None, _KronosFileHandler
        )
        grid = constructed.run()
        row_count = 0

        def visitor(node: Any, acc: Any) -> Any:
            nonlocal row_count
            row_count += 1
            return acc

        grid.populate(visitor, None)
    except Exception as exc:  # noqa: BLE001
        logger.warning("volatility3 dumpfiles failed: %s: %s", type(exc).__name__, exc)
        return {
            "status": "scan_error",
            "error": f"{type(exc).__name__}: {exc}",
            "dumped_files": [],
        }

    logger.info(
        "volatility3 dumpfiles physaddr=%s: %d rows, %d files captured",
        physaddr,
        row_count,
        len(_KronosFileHandler.captured),
    )
    if not _KronosFileHandler.captured:
        return {
            "status": "scan_error",
            "error": f"No file recoverable at physaddr={physaddr} "
            f"(plugin produced {row_count} row(s) but wrote no bytes)",
            "dumped_files": [],
        }
    return {"status": "ok", "error": None, "dumped_files": _KronosFileHandler.captured}


def _run_registry_printkey(evidence_path: str, hive_offset: int, key: str | None) -> dict[str, Any]:
    """On-demand, scoped windows.registry.printkey run against a FRESH
    Context (real-verified in poc/volatility_registry_printkey/: a shared
    Context reused across repeated printkey calls against the same hive
    raises LayerException("Layer already exists: ...") since HiveList never
    deregisters the hive layer between calls)."""
    import volatility3
    import volatility3.plugins
    from volatility3 import framework
    from volatility3.cli.text_renderer import JsonRenderer
    from volatility3.framework import automagic, contexts, interfaces, plugins
    from volatility3.framework.automagic import stacker

    framework.require_interface_version(2, 0, 0)
    plugin_name = "windows.registry.printkey.PrintKey"

    ctx = contexts.Context()
    framework.import_files(volatility3.plugins, True)
    ctx.config["automagic.LayerStacker.single_location"] = f"file://{evidence_path}"
    available_automagics = list(automagic.available(ctx))
    plugin_list = framework.list_plugins()

    if plugin_name not in plugin_list:
        return {
            "status": "scan_error",
            "error": f"{plugin_name} not found",
            "plugin": plugin_name,
            "rows": [],
        }

    plugin_cls = plugin_list[plugin_name]
    ctx.config["plugins.PrintKey.offset"] = hive_offset
    ctx.config["plugins.PrintKey.recurse"] = False
    if key:
        ctx.config["plugins.PrintKey.key"] = key

    try:
        chosen = automagic.choose_automagic(available_automagics, plugin_cls)
        if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
            ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin_cls)
        constructed = plugins.construct_plugin(ctx, chosen, plugin_cls, "plugins", None, None)
        grid = constructed.run()
        renderer = JsonRenderer()
        ignore = renderer.ignored_columns(grid)
        rows: list[dict[str, Any]] = []

        def visitor(node: Any, acc: list[dict[str, Any]]) -> list[dict[str, Any]]:
            d: dict[str, Any] = {}
            for i, col in enumerate(grid.columns):
                if col in ignore:
                    continue
                r = renderer._type_renderers.get(col.type, renderer._type_renderers["default"])
                val = r(list(node.values)[i])
                d[col.name] = None if isinstance(val, interfaces.renderers.BaseAbsentValue) else val
            acc.append(d)
            return acc

        grid.populate(visitor, rows)
    except Exception as exc:  # noqa: BLE001
        logger.warning("volatility3 registry printkey failed: %s: %s", type(exc).__name__, exc)
        return {
            "status": "scan_error",
            "error": f"{type(exc).__name__}: {exc}",
            "plugin": plugin_name,
            "rows": [],
        }

    logger.info(
        "volatility3 registry printkey offset=%s key=%s: %d rows", hive_offset, key, len(rows)
    )
    return {"status": "ok", "error": None, "plugin": plugin_name, "rows": rows}


def main() -> None:
    args = _parse_args()

    try:
        import volatility3  # noqa: F401
    except ImportError:
        # This worker's own runtime is missing the real dependency -- an
        # infrastructure problem (mirrors kronos-yarax-worker.py's identical
        # "yara_x not installed" scan_error path), never a plugin-specific
        # failure.
        logger.error("volatility3 not installed in this worker's runtime")
        _emit(
            {
                "status": "scan_error",
                "error": "volatility3 not installed in worker runtime",
                "plugins": {},
            }
        )
        sys.exit(0)

    if args.dumpfiles_physaddr is not None:
        logger.info(
            "Starting volatility3 on-demand dumpfiles run: evidence=%s physaddr=%s",
            args.evidence_path,
            args.dumpfiles_physaddr,
        )
        if not args.dumpfiles_output_dir:
            _emit(
                {
                    "status": "scan_error",
                    "error": "--dumpfiles-output-dir is required",
                    "dumped_files": [],
                }
            )
            sys.exit(0)
        result = _run_dumpfiles(
            args.evidence_path, args.dumpfiles_physaddr, args.dumpfiles_output_dir
        )
        _emit(result)
        sys.exit(0)

    if args.registry_hive_offset is not None:
        logger.info(
            "Starting volatility3 on-demand registry printkey run: evidence=%s offset=%s key=%s",
            args.evidence_path,
            args.registry_hive_offset,
            args.registry_key,
        )
        result = _run_registry_printkey(
            args.evidence_path, args.registry_hive_offset, args.registry_key
        )
        _emit(result)
        sys.exit(0)

    plugin_names = [p.strip() for p in args.plugins.split(",") if p.strip()]
    logger.info(
        "Starting volatility3 multi-plugin run: evidence=%s plugins=%s",
        args.evidence_path,
        plugin_names,
    )

    try:
        plugin_results = _run_all_plugins(args.evidence_path, plugin_names, args.timeout_seconds)
    except Exception as exc:  # noqa: BLE001 -- a truly unexpected failure (e.g. can't build a Context)
        logger.error("volatility3 worker run failed outright: %s: %s", type(exc).__name__, exc)
        _emit(
            {
                "status": "scan_error",
                "error": f"{type(exc).__name__}: {exc}",
                "plugins": {
                    name: {
                        "status": "scan_error",
                        "rows": [],
                        "error": "worker run failed outright",
                    }
                    for name in plugin_names
                },
            }
        )
        sys.exit(0)

    any_ok = any(r["status"] == "ok" for r in plugin_results.values())
    _emit(
        {
            "status": "ok" if any_ok else "scan_error",
            "error": None if any_ok else "no plugin produced a usable result",
            "plugins": plugin_results,
        }
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
