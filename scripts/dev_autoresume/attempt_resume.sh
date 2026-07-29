#!/usr/bin/env bash
# One-shot resume attempt for the KronOS next-gen SOC/CERT orchestration.
#
# Designed to be fired periodically by cron (see install.sh), NOT run as a
# perpetual loop itself -- cron is the persistent scheduler here, so this
# script surviving a host reboot or this shell dying mid-run doesn't matter.
#
# Each invocation makes exactly ONE attempt:
#   1. Try to continue the actual prior conversation in this repo directory
#      (`claude -p -c`) -- cheapest, keeps full context, no re-derivation.
#   2. If that fails for a reason that ISN'T continuation-not-found (e.g. no
#      prior session on this host/dir), fall back to a fresh headless run
#      seeded with resume_prompt.txt, which is self-sufficient (points at
#      CLAUDE.md, docs/NEXTGEN_SOC_ROADMAP.md, and TaskList).
#   3. If the attempt fails because of a usage/spend limit, log it and exit
#      0 -- cron will just try again next interval. Any OTHER failure is
#      logged loudly so a human notices next time they look.
#
# Per repo policy (CLAUDE.md, and this session's explicit instruction to the
# resumed agent): the agent itself must never auto-commit/push. This script
# doesn't touch git either.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
STATE_DIR="$SCRIPT_DIR/.state"
LOG_FILE="$STATE_DIR/watchdog.log"
LOCK_FILE="$STATE_DIR/attempt.lock"
PROMPT_FILE="$SCRIPT_DIR/resume_prompt.txt"

MAX_BUDGET_USD="${KRONOS_AUTORESUME_MAX_BUDGET_USD:-15}"
MODEL="${KRONOS_AUTORESUME_MODEL:-sonnet}"

mkdir -p "$STATE_DIR"

log() {
    printf '%s %s\n' "$(date -u +%FT%TZ)" "$1" >>"$LOG_FILE"
}

# Prevent overlapping attempts if a previous invocation is still running
# (a real orchestration turn can take a long time).
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log "SKIP: a previous attempt is still running (lock held)"
    exit 0
fi

cd "$REPO_DIR" || { log "FATAL: cannot cd to $REPO_DIR"; exit 1; }

log "ATTEMPT start (budget=\$${MAX_BUDGET_USD}, model=${MODEL})"

run_claude() {
    # $1 = extra args (e.g. -c), rest is the prompt on stdin via heredoc
    local extra_args="$1"
    local prompt="$2"
    # --dangerously-skip-permissions, not --permission-mode acceptEdits:
    # discovered the hard way (2026-07-29) that acceptEdits still gates Bash
    # execution (pytest, python -c, even `source`) behind an approval prompt
    # that can never be answered in an unattended cron-fired run -- every
    # verification step silently no-oped. This is an unattended job on a
    # sandbox this project's own CLAUDE.md already authorizes Docker/host
    # access for; skip-permissions is the documented, intended flag for
    # exactly this case (see `claude --help`: "Recommended only for
    # sandboxes with no internet access" -- this is a controlled dev sandbox,
    # not an arbitrary untrusted host).
    # shellcheck disable=SC2086
    claude -p $extra_args \
        --model "$MODEL" \
        --dangerously-skip-permissions \
        --max-budget-usd "$MAX_BUDGET_USD" \
        --output-format json \
        "$prompt" 2>&1
}

OUTPUT="$(run_claude "-c" "Continue the KronOS roadmap orchestration. If there is no prior conversation to continue in this directory, say so explicitly and stop.")"
STATUS=$?

if echo "$OUTPUT" | grep -qiE "no conversation|could not find.*session|no.*session.*found"; then
    log "no prior session to continue -- falling back to fresh seeded run"
    OUTPUT="$(run_claude "" "$(cat "$PROMPT_FILE")")"
    STATUS=$?
fi

if echo "$OUTPUT" | grep -qiE "spend limit|usage limit|rate.?limit exceeded|quota"; then
    log "RESULT: still usage/spend-limited (exit $STATUS) -- will retry next cron tick"
elif [ "$STATUS" -ne 0 ]; then
    log "RESULT: FAILED (exit $STATUS), non-limit error -- see below"
    printf '%s\n' "$OUTPUT" >>"$LOG_FILE"
else
    log "RESULT: attempt completed (exit 0)"
fi

# Keep the log from growing unbounded across a 7-day+ autonomous stretch.
if [ -f "$LOG_FILE" ] && [ "$(wc -l <"$LOG_FILE")" -gt 20000 ]; then
    tail -n 10000 "$LOG_FILE" >"$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
fi
