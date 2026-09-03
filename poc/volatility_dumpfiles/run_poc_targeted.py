import io
import json
import os
import sys

import volatility3
import volatility3.plugins
from volatility3 import framework
from volatility3.cli.text_renderer import JsonRenderer
from volatility3.framework import automagic, contexts, interfaces, plugins
from volatility3.framework.automagic import stacker

framework.require_interface_version(2, 0, 0)
FILE_PATH = "/tmp/challenge.raw"
OUTPUT_DIR = "/tmp/dumpfiles_poc_out2"
os.makedirs(OUTPUT_DIR, exist_ok=True)


class PoCFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
    captured = []

    def __init__(self, filename):
        io.BytesIO.__init__(self)
        interfaces.plugins.FileHandlerInterface.__init__(self, filename)

    def close(self):
        if self.closed:
            return None
        self.seek(0)
        data = self.read()
        out_path = os.path.join(OUTPUT_DIR, self.preferred_filename)
        with open(out_path, "wb") as f:
            f.write(data)
        PoCFileHandler.captured.append({"filename": self.preferred_filename, "size_bytes": len(data)})
        io.BytesIO.close(self)


ctx = contexts.Context()
framework.import_files(volatility3.plugins, True)
ctx.config["automagic.LayerStacker.single_location"] = f"file://{FILE_PATH}"
available_automagics = list(automagic.available(ctx))
plugin_list = framework.list_plugins()

# Step 1: real filescan run, get real fresh rows.
filescan_cls = plugin_list["windows.filescan.FileScan"]
chosen = automagic.choose_automagic(available_automagics, filescan_cls)
if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
    ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(filescan_cls)
constructed = plugins.construct_plugin(ctx, chosen, filescan_cls, "plugins", None, None)
grid = constructed.run()
renderer = JsonRenderer()
ignore = renderer.ignored_columns(grid)
rows = []


def visitor(node, acc):
    d = {}
    for i, col in enumerate(grid.columns):
        if col in ignore:
            continue
        r = renderer._type_renderers.get(col.type, renderer._type_renderers["default"])
        val = r(list(node.values)[i])
        d[col.name] = None if isinstance(val, interfaces.renderers.BaseAbsentValue) else val
    acc.append(d)
    return acc


grid.populate(visitor, rows)
# Pick a row whose Name looks like a real file with an extension (more
# likely to be a real, dumpable cached file than a device/pipe object).
candidates = [r for r in rows if r.get("Name") and "." in str(r.get("Name", ""))][:5]
print("real candidate filescan rows:", json.dumps(candidates, indent=2))

# Step 2: try dumpfiles with --virtaddr AND --physaddr against the SAME
# fresh Offset, same context, same run.
for target_row in candidates[:2]:
    offset = target_row["Offset"]
    for mode in ("virtaddr", "physaddr"):
        PoCFileHandler.captured = []
        ctx.config[f"plugins.DumpFiles.{mode}"] = [offset]
        for other in ("virtaddr", "physaddr"):
            if other != mode:
                
                try:
                    del ctx.config[f"plugins.DumpFiles.{other}"]
                except KeyError:
                    pass
        df_cls = plugin_list["windows.dumpfiles.DumpFiles"]
        chosen2 = automagic.choose_automagic(available_automagics, df_cls)
        constructed2 = plugins.construct_plugin(ctx, chosen2, df_cls, "plugins", None, PoCFileHandler)
        grid2 = constructed2.run()
        count = 0

        def v2(node, acc):
            global count
            count += 1
            return acc

        grid2.populate(v2, None)
        print(
            f"offset={hex(offset)} name={target_row.get('Name')!r} mode={mode} "
            f"rows={count} captured={PoCFileHandler.captured}"
        )
