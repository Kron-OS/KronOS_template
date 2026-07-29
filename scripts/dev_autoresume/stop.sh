#!/usr/bin/env bash
# Removes the autonomous-resume crontab entry. Does not kill an in-flight
# attempt (attempt_resume.sh's flock just lets the current one finish
# naturally); it only stops future firings.

set -euo pipefail

MARKER="# kronos-dev-autoresume"
EXISTING="$(crontab -l 2>/dev/null || true)"

if ! printf '%s\n' "$EXISTING" | grep -qF "$MARKER"; then
    echo "Not installed -- nothing to stop."
    exit 0
fi

printf '%s\n' "$EXISTING" | grep -vF "$MARKER" | crontab -
echo "Removed. Current crontab:"
crontab -l 2>/dev/null || echo "(empty)"
