#!/usr/bin/env bash
#
# claude-auto — supervise the Claude Code CLI so it rides through Plan usage
# limits automatically. When `claude` stops because the plan's usage window is
# exhausted, this waits until the window resets (parsed from Claude's own
# message when possible, otherwise a periodic retry) and then RESUMES the same
# conversation with `--continue`, so no context is lost. Any non-limit exit is
# passed straight through (it does not paper over real crashes).
#
# Usage:
#   claude-auto                       # interactive, auto-resumes across limits
#   claude-auto -p "run the tests"    # headless one-shot, auto-resumes
#   claude-auto <any claude args...>  # args are forwarded to the first run
#
# Tunables (env):
#   CLAUDE_AUTO_FALLBACK_SLEEP  seconds to wait when no reset time is parseable
#                               (default 1200 = 20 min; the loop retries until
#                                the window frees, so being early is harmless).
#   CLAUDE_AUTO_MAX_RETRIES     max limit-waits before giving up (0 = unlimited).
#   CLAUDE_AUTO_BUFFER          extra seconds added after a parsed reset time.
#   CLAUDE_BYPASS               1 (default) adds --dangerously-skip-permissions.
#   CLAUDE_BIN                  claude binary to use (default: claude).

set -uo pipefail

: "${CLAUDE_AUTO_FALLBACK_SLEEP:=1200}"
: "${CLAUDE_AUTO_MAX_RETRIES:=0}"
: "${CLAUDE_AUTO_BUFFER:=60}"
: "${CLAUDE_BYPASS:=1}"
: "${CLAUDE_BIN:=claude}"

log() { echo "[claude-auto] $*" >&2; }

# Regex identifying a Plan usage-limit stop (broad on purpose).
_LIMIT_RE='usage limit|usage limit reached|reached your .*limit|plan limit|limit will reset|rate limit'

# Echoes seconds to sleep until the usage window resets, parsed from Claude's
# message; empty if nothing parseable. Uses GNU date, which understands both
# "3:00 PM" and "15:00". A wrong guess is self-correcting: if we wake too early
# we simply hit the limit again and wait once more.
parse_reset_seconds() {
    local logfile="$1" tok epoch now
    # "resets at 3:00 PM" / "reset at 3 PM" / "reset at 15:00"
    tok="$(grep -oiE 'reset[s]?( at)? [0-9]{1,2}(:[0-9]{2})? ?(am|pm)?' "$logfile" \
            | grep -oiE '[0-9]{1,2}(:[0-9]{2})? ?(am|pm)?' | head -1)"
    [ -z "$tok" ] && return 0
    epoch="$(date -d "$tok" +%s 2>/dev/null)" || return 0
    now="$(date +%s)"
    # If the parsed clock time already passed today, it means "tomorrow".
    if [ "$epoch" -le "$now" ]; then
        epoch="$(date -d "$tok tomorrow" +%s 2>/dev/null)" || epoch=$((now + CLAUDE_AUTO_FALLBACK_SLEEP))
    fi
    echo $(( epoch - now + CLAUDE_AUTO_BUFFER ))
}

flags=()
[ "$CLAUDE_BYPASS" = "1" ] && flags+=(--dangerously-skip-permissions)

first_args=("$@")
waits=0
resume=0

while : ; do
    logfile="$(mktemp)"
    if [ "$resume" = "1" ]; then
        log "resuming previous conversation (--continue)"
        "$CLAUDE_BIN" "${flags[@]}" --continue 2>&1 | tee "$logfile"
    else
        "$CLAUDE_BIN" "${flags[@]}" "${first_args[@]}" 2>&1 | tee "$logfile"
    fi
    rc=${PIPESTATUS[0]}

    if grep -qiE "$_LIMIT_RE" "$logfile"; then
        wait_s="$(parse_reset_seconds "$logfile")"
        [ -z "$wait_s" ] && wait_s="$CLAUDE_AUTO_FALLBACK_SLEEP"
        [ "$wait_s" -lt 30 ] 2>/dev/null && wait_s=30
        rm -f "$logfile"

        waits=$((waits + 1))
        if [ "$CLAUDE_AUTO_MAX_RETRIES" -ne 0 ] && [ "$waits" -gt "$CLAUDE_AUTO_MAX_RETRIES" ]; then
            log "usage limit hit and CLAUDE_AUTO_MAX_RETRIES=$CLAUDE_AUTO_MAX_RETRIES exhausted; stopping"
            exit 75  # EX_TEMPFAIL
        fi
        log "Plan usage limit reached — waiting ${wait_s}s (attempt ${waits}) then resuming…"
        sleep "$wait_s"
        resume=1
        continue
    fi

    rm -f "$logfile"
    # Not a usage-limit stop: forward the real outcome and exit.
    log "claude exited (code ${rc}); not a usage-limit stop — done."
    exit "$rc"
done
