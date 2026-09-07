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

## Cross-source log alignment samples (Milestone HHHHH)

Added for `tests/unit/parsers/test_cross_source_log_alignment.py` — real
samples used to check whether KronOS normalizes semantically-equivalent
events (e.g. a "signin") consistently across different real source types.
Full investigation, real captured output, and provenance detail:
`poc/cross_source_log_alignment/`.

| File | Source | Format |
|---|---|---|
| `windows_security.evtx` | `omerbenamram/evtx` (the real upstream project for the pinned `evtx`/pyevtx-rs Python package), `samples/Security_short_selected.evtx`, Apache-2.0, redistributed unmodified | Windows Security channel EVTX, genuine EventID 4625 (failed logon) record |
| `linux_auth.log` | This host's own real `/var/log/auth.log.1` — a genuine local PAM `session opened`/`session closed` login sequence, no third-party attribution needed (this repo's own operational data, timestamps/hostname unmodified) | Linux syslog-style auth log |
| `custom_container.log` | Real `docker logs` output from a briefly-run `redis:7-alpine` container (BSD-3-Clause), representative of "a custom container's own bespoke log format" that KronOS has no dedicated parser for | Redis's own real startup-log format |
