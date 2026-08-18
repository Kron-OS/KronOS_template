# PoC: warn when `kronos-attest` secrets are passed as literal CLI arguments (Gap Audit Milestone CC)

## Background

This is a self-found finding: Milestone AA (`AA1`) and Milestone BB
(`BB1`) — both from earlier this same initiative — added
`--database-url`/`--minio-access-key`/`--minio-secret-key` to
`kronos_attest/cli.py` as real `click.option()` string values, each with
an `envvar=...` fallback already documented in its own `--help` text as
the preferred path. Nothing, however, actually warned a user who followed
the `--help` text's literal flag names instead of the env var that doing
so leaks the credential (a DB password embedded in the DSN, or a MinIO
secret/access key) into `ps`/`/proc/<pid>/cmdline` — visible to any other
user on a shared host — and typically into shell history files. This is a
real, live secret-hygiene gap in this initiative's own recently-added
code, not a hypothetical.

## Fix

`kronos_attest/cli.py` gained `_warn_if_secrets_from_cli(ctx)`, called at
the top of `verify`/`day-report`/`case-report`. Uses Click's own
`ctx.get_parameter_source(name)` to distinguish "value came from an
explicit CLI argument" (`ParameterSource.COMMANDLINE`) from "value came
from its environment variable" (`ParameterSource.ENVIRONMENT`) — prints a
clear `WARNING:` line to stderr for each of `--database-url`/
`--minio-secret-key`/`--minio-access-key` supplied this way. Deliberately
only warns, never blocks: CLI-supplied secrets remain fully supported
(real scripting use cases exist where an env var isn't practical), but
the risk is no longer silent.

## Verified (real, not assumed)

Ran the real CLI, with a real `DATABASE_URL` connection to the shared dev
Postgres, in both modes — see `output.txt`:

1. `DATABASE_URL` env var set, no CLI secret flags → clean JSON output,
   no warning.
2. `--database-url` given as a literal CLI flag (same real connection) →
   the exact same correct JSON output, PLUS the new `WARNING:` line on
   stderr.

Also: `tests/unit/test_attest.py`'s new `TestCLISecretOptionWarnings`
class (5 tests) — the mocked-fetch layer confirms the warning fires (or
doesn't) for every combination of CLI-flag vs. env-var vs. offline mode,
without needing a real DB connection for that layer of testing (the real
DB connection above is the separate, required end-to-end proof per
CLAUDE.md §F).

**Real regression caught and fixed while adding this:** Click 8.4.2 (the
version actually pinned in this repo's venv, confirmed via
`click.testing.CliRunner.__init__`'s real signature) removed the
`mix_stderr` constructor argument some AA1/BB1-era test-writing guidance
assumed would still exist — the new tests initially used it and failed
outright with a `TypeError`. Fixed by using `CliRunner()` (no argument)
and `result.stderr`, which is still available as a separately-populated
attribute independent of `result.output` (confirmed directly:
`result.output` mixes stdout+stderr together by default in this version,
`result.stdout`/`result.stderr` remain separately accessible). This also
surfaced a **second, real regression**: five pre-existing tests (from
AA1/BB1) parsed `json.loads(result.output)`, which broke the moment any
stderr warning appeared in the same invocation (mixed into `.output`) —
fixed by switching all five to `json.loads(result.stdout)`, which is
strictly more correct regardless of whether stderr output is present.

Full backend test suite before/after: 1970 → 1975 passed (+5, zero
regressions), 2 skipped both times. `ruff`/`black`/`mypy` clean.

## How to run

Real commands are in `output.txt`, reproduced from an interactive session
against the real dev stack (`DATABASE_URL=postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos`).
