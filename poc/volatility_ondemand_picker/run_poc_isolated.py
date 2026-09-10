"""Re-checks windows.consoles/svcscan each in their OWN fresh Context --
the shared-context batch run in run_poc.py hit a real LayerException
(registry hive layer collision between multiple hive-touching plugins
sharing one Context), which is a harness artifact of testing many plugins
together, not a real problem for the actual on-demand mechanism: each
on-demand call (VolatilityLauncher.run(path, plugins=[one_plugin])) always
gets a brand-new subprocess/Context, exactly like run_registry_key already
does today (see that method's own docstring for the identical real
LayerException reason). This isolates each plugin the same way production
on-demand calls actually will.
"""

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
    for plugin in ["windows.consoles.Consoles", "windows.svcscan.SvcScan"]:
        result = mod.run_multi_plugin(path, [plugin])
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
