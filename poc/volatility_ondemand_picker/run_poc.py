"""PoC: real timing/safety check for the curated on-demand Volatility
plugin picker's Phase-1 candidates (reviews/Volatility_Missing_Modules_MemLabs6.md).

Reuses poc/volatility_multiplugin/run_poc.py's exact shared-context
harness unmodified (already proved correct for the 7 eager plugins,
Milestone CCCCC) -- this just points it at the new candidate plugin names.

Version pinned: volatility3==2.28.0 (docker/Dockerfile.plaso-worker).
Run inside the real celery-worker-plaso container.

Real sample: Challenge.raw, a REAL 1.6 GB Windows 7 memory image uploaded
by the project owner to a real live case on this dev stack (case
43097ab0-aae3-4968-915b-8f0229ac3865, evidence
e9f3287f-3858-4018-bcee-42a4bcbb0bc3) -- the project owner explicitly
pointed to this case for this exact purpose. Downloaded fresh via a direct
MinIO boto3 pull (kronos-evidence-kronos-dev bucket) to /tmp/challenge.raw
inside the container for this run; NOT redistributed/committed (same
convention as every other PoC using this file).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "volatility_multiplugin"))
from run_poc import run_multi_plugin  # noqa: E402

# Phase-1 candidates for the curated on-demand allowlist (plan:
# /home/reca/.claude/plans/abstract-imagining-umbrella.md).
CANDIDATE_PLUGINS = [
    "windows.envars.Envars",
    "windows.windows.Windows",
    "windows.handles.Handles",
    "windows.getsids.GetSIDs",
    "windows.privileges.Privs",
]

# Deliberately excluded candidates, checked anyway for real comparison data
# against the already-measured eager set (malfind/filescan were ~11-24s
# render on this same image) -- confirms or corrects the "bytes_scanner ==
# slow" reasoning from the research doc rather than leaving it a guess.
COMPARISON_PLUGINS = [
    "windows.consoles.Consoles",
    "windows.svcscan.SvcScan",
]


def main() -> None:
    path = "/tmp/challenge.raw"
    if not Path(path).exists():
        print(f"SKIPPED: {path} not present")
        return
    print(f"=== Challenge.raw (real user upload, not redistributed) ===")
    result = run_multi_plugin(path, CANDIDATE_PLUGINS + COMPARISON_PLUGINS)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
