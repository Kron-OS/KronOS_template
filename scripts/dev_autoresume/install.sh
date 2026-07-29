#!/usr/bin/env bash
# Installs the autonomous-resume crontab entry.
#
# Uses real crontab (OS-level, systemd cron daemon), not a bash sleep-loop:
# it survives this shell dying, this terminal closing, or the sandbox being
# restarted, as long as the underlying host/container persists and cron
# itself is running.
#
# Fires every 15 minutes. Each firing is a single, cheap, idempotent attempt
# (attempt_resume.sh) that's a no-op (besides a log line) whenever the
# account is still usage/spend-limited -- it costs nothing but a failed API
# call attempt each time it's still limited.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MARKER="# kronos-dev-autoresume"
CRON_LINE="*/15 * * * * ${SCRIPT_DIR}/attempt_resume.sh ${MARKER}"

chmod +x "$SCRIPT_DIR/attempt_resume.sh"

EXISTING="$(crontab -l 2>/dev/null || true)"
if printf '%s\n' "$EXISTING" | grep -qF "$MARKER"; then
    echo "Already installed. Current crontab entry:"
    printf '%s\n' "$EXISTING" | grep -F "$MARKER"
    exit 0
fi

{ printf '%s\n' "$EXISTING"; echo "$CRON_LINE"; } | crontab -

echo "Installed. Crontab now:"
crontab -l | grep -F "$MARKER"
echo
echo "Logs: $SCRIPT_DIR/.state/watchdog.log"
echo "Stop with: $SCRIPT_DIR/stop.sh"
