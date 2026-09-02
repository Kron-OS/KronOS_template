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
"""

from __future__ import annotations

import argparse
import json
import logging
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


def main() -> None:
    args = _parse_args()
    plugin_names = [p.strip() for p in args.plugins.split(",") if p.strip()]
    logger.info(
        "Starting volatility3 multi-plugin run: evidence=%s plugins=%s",
        args.evidence_path,
        plugin_names,
    )

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
