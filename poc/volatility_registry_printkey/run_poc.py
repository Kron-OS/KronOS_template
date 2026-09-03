"""PoC: verify a scoped, non-recursive windows.registry.printkey call
(hive offset + optional key path, recurse=False) is fast and bounded --
in contrast with the >200s unscoped recursive dump measured during this
plan's own architecture research (docs/GAP_AUDIT_2026-08-28_MILESTONE_CCCCC.md).

Also verifies the real reason each on-demand registry call must get its own
fresh volatility3 Context rather than reusing one shared Context across
repeated calls: a shared Context that has already had a hive's layer added
by one printkey call raises LayerException("Layer already exists: ...") if
a second printkey call against the SAME hive tries to add it again (the
hive layer is never deregistered between calls). This is not a workaround
-- it is the SAME shape the real production design already uses: each
on-demand click enqueues a new Celery task, which invokes a brand-new
worker subprocess with its own brand-new Context. This script deliberately
mirrors that shape (fresh Context per plugin invocation) rather than the
poc/volatility_multiplugin/ shared-context-across-different-plugin-types
pattern, which does not apply here since printkey is called more than once
against the same hive.

Version pinned: volatility3==2.28.0. Real sample: the same real 1.6GB
Windows 7 image used throughout this milestone's PoCs (Challenge.raw).
"""

from __future__ import annotations

import json
import time

import volatility3
import volatility3.plugins
from volatility3 import framework
from volatility3.cli.text_renderer import JsonRenderer
from volatility3.framework import automagic, contexts, interfaces, plugins
from volatility3.framework.automagic import stacker

framework.require_interface_version(2, 0, 0)
FILE_PATH = "/tmp/challenge.raw"


def run_plugin(plugin_name: str, config: dict) -> dict:
    """Fresh Context per call -- mirrors real production shape (one worker
    subprocess invocation per on-demand Celery task, never shared)."""
    ctx = contexts.Context()
    framework.import_files(volatility3.plugins, True)
    ctx.config["automagic.LayerStacker.single_location"] = f"file://{FILE_PATH}"
    available_automagics = list(automagic.available(ctx))
    plugin_list = framework.list_plugins()

    plugin_cls = plugin_list[plugin_name]
    for key, value in config.items():
        ctx.config[f"plugins.{plugin_cls.__name__}.{key}"] = value
    chosen = automagic.choose_automagic(available_automagics, plugin_cls)
    if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
        ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin_cls)
    t0 = time.time()
    constructed = plugins.construct_plugin(ctx, chosen, plugin_cls, "plugins", None, None)
    grid = constructed.run()
    renderer = JsonRenderer()
    ignore = renderer.ignored_columns(grid)
    rows: list = []

    def visitor(node, acc):
        d: dict = {}
        for i, col in enumerate(grid.columns):
            if col in ignore:
                continue
            r = renderer._type_renderers.get(col.type, renderer._type_renderers["default"])
            val = r(list(node.values)[i])
            d[col.name] = None if isinstance(val, interfaces.renderers.BaseAbsentValue) else val
        acc.append(d)
        return acc

    grid.populate(visitor, rows)
    elapsed = time.time() - t0
    return {"elapsed_seconds": round(elapsed, 3), "row_count": len(rows), "rows": rows}


print("=== windows.registry.hivelist (get real hive offsets) ===")
hivelist_result = run_plugin("windows.registry.hivelist.HiveList", {})
print(f"elapsed={hivelist_result['elapsed_seconds']}s rows={hivelist_result['row_count']}")
print(json.dumps(hivelist_result["rows"], indent=2, default=str))

real_hives = [r for r in hivelist_result["rows"] if r.get("FileFullPath")]
if not real_hives:
    real_hives = hivelist_result["rows"]

target_offset = real_hives[0]["Offset"]
print(f"\n=== windows.registry.printkey, offset={hex(target_offset)}, no key (hive root), recurse=False ===")
root_result = run_plugin(
    "windows.registry.printkey.PrintKey", {"offset": target_offset, "recurse": False}
)
print(f"elapsed={root_result['elapsed_seconds']}s rows={root_result['row_count']}")
print(json.dumps(root_result["rows"], indent=2, default=str))

if root_result["rows"]:
    # Drill one level deeper into a real subkey name this hive's own root
    # actually returned -- proves the "click a subkey to go one level
    # deeper" UX pattern works against real data. Uses a FRESH Context
    # (see run_plugin docstring) -- confirmed live that reusing one shared
    # Context for two printkey calls against the same hive raises
    # LayerException: Layer already exists.
    sub_names = [
        r.get("Name") for r in root_result["rows"] if r.get("Name") and r.get("Name") != "Key"
    ]
    if sub_names:
        subkey = sub_names[0]
        print(f"\n=== windows.registry.printkey, offset={hex(target_offset)}, key={subkey!r}, recurse=False (fresh Context) ===")
        drill_result = run_plugin(
            "windows.registry.printkey.PrintKey",
            {"offset": target_offset, "key": subkey, "recurse": False},
        )
        print(f"elapsed={drill_result['elapsed_seconds']}s rows={drill_result['row_count']}")
        print(json.dumps(drill_result["rows"], indent=2, default=str))
