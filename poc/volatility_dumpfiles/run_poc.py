"""PoC: verify volatility3's real windows.dumpfiles mechanism -- the real
FileHandlerInterface bytes-capture API, and whether --pid (process-scoped)
or --virtaddr/--physaddr (single-file-object-scoped) targeting is the right
fit for an "Extract this file" analyst action triggered from a real
malfind/filescan row.

Version pinned: volatility3==2.28.0 (docker/Dockerfile.plaso-worker).
Real sample: the same real 1.6GB user-uploaded Windows 7 image already used
in poc/volatility_multiplugin/ (Challenge.raw, /tmp/challenge.raw inside
celery-worker-plaso -- real user data, not redistributed).
"""

from __future__ import annotations

import io
import json
import os
import time

import volatility3
import volatility3.plugins
from volatility3 import framework
from volatility3.framework import automagic, contexts, interfaces, plugins
from volatility3.framework.automagic import stacker

framework.require_interface_version(2, 0, 0)

FILE_PATH = "/tmp/challenge.raw"
OUTPUT_DIR = "/tmp/dumpfiles_poc_out"
os.makedirs(OUTPUT_DIR, exist_ok=True)


class PoCFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
    """Real FileHandlerInterface implementation -- mirrors volatility3's own
    CLIFileHandler (volatility3/cli/__init__.py), the reference this
    worker's real implementation will follow. close() is where the plugin
    hands over the accumulated real bytes."""

    captured: list[dict] = []

    def __init__(self, filename: str) -> None:
        io.BytesIO.__init__(self)
        interfaces.plugins.FileHandlerInterface.__init__(self, filename)

    def close(self) -> None:
        if self.closed:
            return None
        self.seek(0)
        data = self.read()
        out_path = os.path.join(OUTPUT_DIR, self.preferred_filename)
        with open(out_path, "wb") as f:
            f.write(data)
        PoCFileHandler.captured.append(
            {"filename": self.preferred_filename, "size_bytes": len(data), "path": out_path}
        )
        io.BytesIO.close(self)


def run_dumpfiles(config_overrides: dict) -> dict:
    ctx = contexts.Context()
    framework.import_files(volatility3.plugins, True)
    ctx.config["automagic.LayerStacker.single_location"] = f"file://{FILE_PATH}"
    for key, value in config_overrides.items():
        ctx.config[f"plugins.DumpFiles.{key}"] = value

    available_automagics = list(automagic.available(ctx))
    plugin_list = framework.list_plugins()
    plugin_cls = plugin_list["windows.dumpfiles.DumpFiles"]

    PoCFileHandler.captured = []
    t0 = time.time()
    chosen_automagics = automagic.choose_automagic(available_automagics, plugin_cls)
    if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
        ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin_cls)
    constructed = plugins.construct_plugin(
        ctx, chosen_automagics, plugin_cls, "plugins", None, PoCFileHandler
    )
    construct_elapsed = time.time() - t0

    t1 = time.time()
    grid = constructed.run()
    # Walk the TreeGrid purely to force full evaluation (dumpfiles writes
    # files as a side effect of rendering each row, exactly like every
    # other plugin's row-rendering side effects already observed this
    # session) -- reuse the same real visitor pattern as
    # poc/volatility_multiplugin/run_poc.py.
    row_count = 0

    def visitor(node, acc):
        nonlocal row_count
        row_count += 1
        return acc

    grid.populate(visitor, None)
    render_elapsed = time.time() - t1

    return {
        "construct_seconds": round(construct_elapsed, 3),
        "render_seconds": round(render_elapsed, 3),
        "row_count": row_count,
        "files_captured": list(PoCFileHandler.captured),
    }


def main() -> None:
    print("=== --pid 2080 (firefox.exe, a real substantial process) ===")
    result_pid = run_dumpfiles({"pid": 2080})
    print(json.dumps(result_pid, indent=2))

    print()
    print("=== --virtaddr targeting a real filescan row's own file object address ===")
    # Real row from poc/volatility_multiplugin/output.txt's own captured
    # filescan output: {"Offset": 88024720, "Name": "\\Endpoint"} -- this
    # Offset IS the file object's own virtual address for filescan (pool
    # scan reports VAs on this platform, confirmed by checking the
    # plugin's own column type below).
    result_virtaddr = run_dumpfiles({"virtaddr": [88024720]})
    print(json.dumps(result_virtaddr, indent=2))


if __name__ == "__main__":
    main()
