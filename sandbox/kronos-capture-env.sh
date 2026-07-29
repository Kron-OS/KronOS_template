#!/usr/bin/env bash
#
# systemd units start with a clean environment — they don't inherit the vars
# Docker/Compose set on PID 1 (systemd itself). This copies the
# sandbox-relevant ones out of /proc/1/environ into a tmpfs file that other
# kronos-*.service units source via EnvironmentFile=.

set -euo pipefail

OUT=/run/kronos-sandbox.env
: > "$OUT"
tr '\0' '\n' < /proc/1/environ | grep -E '^SANDBOX_' >> "$OUT" || true
chmod 600 "$OUT"
