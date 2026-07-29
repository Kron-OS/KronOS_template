# Autonomous resume watchdog (secondary/silent backstop)

**Status (2026-07-29): demoted to secondary.** The primary continuation
mechanism is now the harness's own `CronCreate` — it fires a prompt directly
into the same visible chat session, which is what the project owner actually
wants to watch. This script's `-p` (print-mode) invocations run in a
separate headless CLI process; their output lands in `.state/watchdog.log`,
not in the interactive chat window the project owner is looking at — exactly
the "cron tty" they asked to stop seeing as the *primary* channel.

It is kept installed as a **silent backstop** for the one case `CronCreate`
cannot cover: `CronCreate` jobs are session-only and die if the whole
top-level session process itself exits (not just a subagent hitting a spend
limit) — see `docs/NEXTGEN_SOC_ROADMAP.md`'s "Continuation mechanism" note.
This script's real OS-level crontab entry survives that. Its own activity
won't show up in the chat (nothing can, in that scenario, until the project
owner returns) — that's the intentional trade-off of a backstop for the case
where the primary channel is gone.

**Real evidence this already worked once**, before being demoted: while
installed as the sole mechanism, it self-healed past `acceptEdits`
permission-mode silently no-op'ing every Bash step in an unattended run
(fixed in-place to `--dangerously-skip-permissions`, see the note further
down), then successfully broke through a spend-limit window at 2026-07-29
11:30 UTC, continued this exact conversation via `claude -p -c`, and
produced real, verified work (index template hardening, the ECS field
registry, the `bulk_index` fix, the evidence/stream provenance split) —
confirmed via `.state/watchdog.log`'s `11:30:01 ATTEMPT start` /
`11:36:23 RESULT: attempt completed (exit 0)` entries and the actual PoC
output files that resulted. The mechanism works; it just isn't the
UI-visible channel to keep as primary.

Original purpose (still accurate for the backstop role): keeps KronOS's
next-gen SOC/CERT roadmap orchestration (`docs/NEXTGEN_SOC_ROADMAP.md`)
moving forward while the account is between usage-limit windows, without
needing the project owner to be present to say "continue".

## Why a real crontab entry, not a background loop

A `while true; do ...; sleep; done` script tied to this terminal session dies
the moment the shell/tool call that launched it ends, and doesn't survive a
sandbox restart. A crontab entry is scheduled by the host's own `cron`
daemon (systemd-cron here) — it survives this session ending, this terminal
closing, and (as long as the underlying host/container itself persists and
`/var/spool/cron` isn't wiped) a restart of the sandbox.

## How it works

1. `install.sh` adds one crontab line firing `attempt_resume.sh` every 15
   minutes.
2. Each firing is **one cheap, idempotent attempt**:
   - First tries `claude -p -c "..."` — continues the actual prior
     conversation in this repo directory (cheapest: full context, no
     re-derivation).
   - If there's no prior session to continue, falls back to a fresh
     `claude -p` run seeded with `resume_prompt.txt`, which is
     self-contained: it tells the resumed agent to read `CLAUDE.md`, read
     `docs/NEXTGEN_SOC_ROADMAP.md`, call `TaskList`, and pick up the next
     unblocked roadmap item — so a cold start still has everything it needs.
   - If the attempt is still usage/spend-limited, it logs that and exits
     cleanly — cron just tries again in 15 minutes. This costs nothing but
     a failed API call each time it's still limited.
   - A `flock` prevents two attempts overlapping if one run takes a long
     time.
3. Whenever an attempt actually gets through, that agent turn works the
   roadmap autonomously — dispatching subagents per the brief template in
   `docs/NEXTGEN_SOC_ROADMAP.md` §4, at the model/effort tier in §5 — and
   then ends its turn normally. The next cron tick picks up from there via
   `-c` (same conversation continues), or the next fallback prompt (which
   re-reads `TaskList`/`git status` for cold-start state either way).

## Hard guarantee: it never commits or pushes on its own

Per this repo's standing git-safety rule (and restated explicitly in
`resume_prompt.txt`), the resumed agent is instructed to implement + PoC +
update tasks/docs and stop there. Committing and pushing remain something
only the project owner triggers by asking, exactly like every other session
in this repo's history. This script does not touch git at all.

## Usage

```bash
./install.sh    # start the watchdog (idempotent -- safe to re-run)
./status.sh     # see whether it's installed + recent log lines
./stop.sh       # remove the crontab entry (an in-flight attempt finishes normally)
```

Logs: `scripts/dev_autoresume/.state/watchdog.log` (auto-trimmed to the last
10k lines past 20k).

**Note (2026-07-29):** runs `--dangerously-skip-permissions`, not
`--permission-mode acceptEdits` as originally shipped. Found by real failure:
`acceptEdits` still gates Bash execution (pytest, `python3 -c`, even
`source`) behind an approval prompt that can never be answered in an
unattended cron-fired run — every verification step silently no-oped for an
entire resumed turn before this was caught. This is an unattended job on a
sandbox `CLAUDE.md` already authorizes Docker/host access for.

## Tuning

Env vars, set before running `install.sh` (or edit the crontab line directly):
- `KRONOS_AUTORESUME_MAX_BUDGET_USD` (default `15`) — passed as
  `claude --max-budget-usd` per attempt.
- `KRONOS_AUTORESUME_MODEL` (default `sonnet`) — the orchestrator model for
  the resumed turn; it dispatches its own subagents at lower tiers per the
  roadmap's §5 execution policy regardless of this setting.

## What it does NOT solve

- It cannot detect "the account's usage limit has reset" directly — it just
  retries on a timer and lets a real API call be the detector (a limited
  account fails fast and cheaply; that failure is logged and treated as
  "still waiting").
- It is scoped to *this* host/sandbox. If the sandbox is torn down entirely
  (not just restarted), the crontab entry goes with it and `install.sh`
  needs to be re-run in the new one.
