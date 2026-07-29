#!/usr/bin/env bash
# Quick status check: is the watchdog installed, and what happened recently.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MARKER="# kronos-dev-autoresume"

echo "=== crontab entry ==="
crontab -l 2>/dev/null | grep -F "$MARKER" || echo "(not installed)"

echo
echo "=== last 20 log lines ==="
tail -n 20 "$SCRIPT_DIR/.state/watchdog.log" 2>/dev/null || echo "(no log yet)"
