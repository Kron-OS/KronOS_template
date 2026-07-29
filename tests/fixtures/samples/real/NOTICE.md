# Provenance

The files in this directory are real-world sample artifacts taken from the
[Plaso](https://github.com/log2timeline/plaso) project's `test_data/`
directory (commit `d028e5b`, `main` branch), used here to test KronOS's own
parsers against real forensic artifacts instead of hand-crafted fixtures
that were written to match the parser under test.

Plaso is licensed under the Apache License, Version 2.0
(https://github.com/log2timeline/plaso/blob/main/LICENSE). These files are
redistributed unmodified under that license.

| File | Source path in Plaso's repo | Format |
|---|---|---|
| `system.evtx` | `test_data/evtx/System2.evtx` | Windows EVTX (System event log) |
| `aws_cloudtrail.jsonl` | `test_data/aws_cloudtrail.jsonl` | AWS CloudTrail Lake/S3-export NDJSON |
| `apache_access.log` | `test_data/apache_access.log` | Apache/nginx combined + Common Log Format access log |
| `CMD.EXE-087B4001.pf` | `test_data/winprefetch/CMD.EXE-087B4001.pf` | Windows Prefetch (uncompressed SCCA format) |

Used by `tests/unit/parsers/test_real_world_samples.py`.
