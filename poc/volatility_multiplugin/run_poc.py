"""PoC: verify volatility3's own framework API supports constructing ONE
shared Context, resolving automagic (DTB detection + kernel symbol table
load) exactly once, then looping plugins.construct_plugin() for MULTIPLE
plugin classes against that same context -- avoiding the "redo the
expensive automagic scan for every plugin" cost that a naive "shell out to
`vol` once per plugin" design pays.

Version pinned: volatility3==2.28.0 (docker/Dockerfile.plaso-worker).
Runs inside the real celery-worker-plaso container (the actual pinned
install, not a host-side venv) via `docker exec`.

Real samples used:
  - cridex.vmem (Windows XP SP3, Cridex/Feodo banking trojan) -- the small,
    public, redistributable sample already referenced by
    poc/volatility_memory_module/README.md. Downloaded to
    /home/reca/scratch/kronos-poc-volatility/cridex.vmem on this host,
    copied into the container at /tmp/cridex.vmem for this run. NOT
    committed to git (same convention as every other PoC that uses it).
  - Challenge.raw -- a REAL 1.6 GB Windows 7 memory image uploaded by the
    project owner to a real live case on this dev stack (case
    43097ab0-aae3-4968-915b-8f0229ac3865, evidence
    e9f3287f-3858-4018-bcee-42a4bcbb0bc3). Verified live against this
    sample too (see output.txt) but NOT redistributed -- it is real
    user-owned investigative data, not a public research sample. Anyone
    reproducing this PoC without access to that org's MinIO can still
    fully verify the architecture via cridex.vmem alone.

Run: docker exec docker-celery-worker-plaso-1 python3 /path/to/this/file.py
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import volatility3
import volatility3.plugins
from volatility3 import framework
from volatility3.cli.text_renderer import JsonRenderer
from volatility3.framework import automagic, contexts, interfaces, plugins
from volatility3.framework.automagic import stacker

framework.require_interface_version(2, 0, 0)

# The eager plugin set this PoC verifies (per Milestone CCCCC's plan) --
# malfind uses the non-deprecated import path (windows.malfind.Malfind is
# deprecated in this pinned version, confirmed live in the planning pass).
EAGER_PLUGINS = [
    "windows.pstree.PsTree",
    "windows.psscan.PsScan",
    "windows.dlllist.DllList",
    "windows.cmdline.CmdLine",
    "windows.malware.malfind.Malfind",
    "windows.filescan.FileScan",
    "windows.registry.hivelist.HiveList",
]


def run_multi_plugin(file_path: str, plugin_names: list[str]) -> dict:
    """Run every plugin in *plugin_names* against ONE shared Context,
    returning {plugin_name: {"rows": int, "construct_seconds": float,
    "render_seconds": float, "error": str|None}}.
    """
    ctx = contexts.Context()
    failures = framework.import_files(volatility3.plugins, True)
    ctx.config["automagic.LayerStacker.single_location"] = f"file://{file_path}"
    available_automagics = list(automagic.available(ctx))
    plugin_list = framework.list_plugins()

    results: dict = {"plugin_import_failures": failures, "plugins": {}}

    for plugin_name in plugin_names:
        entry: dict = {"rows": 0, "construct_seconds": None, "render_seconds": None, "error": None}
        if plugin_name not in plugin_list:
            entry["error"] = f"not found in plugin_list ({len(plugin_list)} plugins loaded)"
            results["plugins"][plugin_name] = entry
            continue

        plugin_cls = plugin_list[plugin_name]
        t0 = time.time()
        try:
            chosen_automagics = automagic.choose_automagic(available_automagics, plugin_cls)
            if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
                ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin_cls)
            constructed = plugins.construct_plugin(
                ctx, chosen_automagics, plugin_cls, "plugins", None, None
            )
            entry["construct_seconds"] = round(time.time() - t0, 3)
        except Exception as exc:  # noqa: BLE001 -- PoC: capture and report, don't crash the loop
            entry["construct_seconds"] = round(time.time() - t0, 3)
            entry["error"] = f"{type(exc).__name__}: {exc}"
            results["plugins"][plugin_name] = entry
            continue

        t1 = time.time()
        try:
            grid = constructed.run()
            renderer = JsonRenderer()
            ignore_columns = renderer.ignored_columns(grid)
            tree: list = []

            def visitor(node, accumulator, _grid=grid, _ignore=ignore_columns, _renderer=renderer):
                acc_map, final_tree = accumulator
                node_dict: dict = {"__children": []}
                for column_index, column in enumerate(_grid.columns):
                    if column in _ignore:
                        continue
                    r = _renderer._type_renderers.get(column.type, _renderer._type_renderers["default"])
                    data = r(list(node.values)[column_index])
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
            entry["render_seconds"] = round(time.time() - t1, 3)
            entry["rows"] = len(tree)
            entry["sample_row"] = json.dumps(tree[0], default=str)[:300] if tree else None
        except Exception as exc:  # noqa: BLE001
            entry["render_seconds"] = round(time.time() - t1, 3)
            entry["error"] = f"render failed: {type(exc).__name__}: {exc}"

        results["plugins"][plugin_name] = entry

    return results


def main() -> None:
    for label, path in [
        ("cridex.vmem", "/tmp/cridex.vmem"),
        ("challenge.raw (real user upload, not redistributed)", "/tmp/challenge.raw"),
    ]:
        if not Path(path).exists():
            print(f"=== {label} ({path}) SKIPPED: file not present ===")
            continue
        print(f"=== {label} ({path}) ===")
        result = run_multi_plugin(path, EAGER_PLUGINS)
        print(json.dumps(result, indent=2, default=str))
        print()


if __name__ == "__main__":
    main()
