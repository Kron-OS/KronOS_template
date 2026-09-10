"""Follow-up isolated checks: windows.vadinfo (confirmed dump=False default,
safe) and windows.sessions (needs timeliner -- does it actually run without
extra config?), each in its own fresh Context (see run_poc_isolated.py's
own docstring for why isolation matters)."""

from __future__ import annotations

import json
import sys
import importlib.util
import os

_RUN_POC_PATH = os.environ.get("KRONOS_POC_RUN_POC_PATH", "/tmp/poc_multiplugin_run_poc.py")
spec = importlib.util.spec_from_file_location("run_poc", _RUN_POC_PATH)
mod = importlib.util.module_from_spec(spec)
sys.modules["run_poc"] = mod
spec.loader.exec_module(mod)


def main() -> None:
    path = "/tmp/challenge.raw"
    for plugin in ["windows.vadinfo.VadInfo", "windows.sessions.Sessions"]:
        result = mod.run_multi_plugin(path, [plugin])
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
