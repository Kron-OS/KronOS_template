# Gap Audit — Milestone CC (continuation, 2026-08-18)

Follow-up to `docs/GAP_AUDIT_2026-08-18_MILESTONE_BB.md` (Milestone BB,
fully resolved: BB1 CLOSED). Re-checked `docs/GAP_AUDIT_2026-08-17.md`'s
"still genuinely blocked" list — unchanged. Also spot-checked several
older "flagged, not fixed" markers surfaced by a broader
`docs/*.md`/`poc/*/README.md` grep — **all of these turned out to be
stale, already-resolved findings the older docs were simply never updated
to reflect** (the OpenSearch http/https scheme mismatch — resolved by V1;
the fluent-bit `Syslog_Severity_Key` numeric-severity bug and missing
nginx access-log producer — both resolved by V8; the Defender poll
beat-task gap — resolved by V2). Confirmed each directly against current
code before discounting it (`docker-compose.prod.yml`'s real
`OPENSEARCH_URL`, `docker/fluent-bit/fluent-bit.conf`'s real
`severity_num` filter chain, `celery_app.py`'s real `poll_defender_alerts`
beat task) rather than assuming the "not fixed" label was still accurate.

With the two remaining named candidates (Helm `nginx.conf.template` sync —
genuinely no live consequence yet; prod OpenSearch demo-cert — needs a
real project-owner TLS decision, not attempted, this is a fully
autonomous cron-triggered session with no one to ask in real time) both
either low-value or genuinely blocked, this pass instead found a real,
concrete, **self-found** gap by re-examining this initiative's own most
recently landed code (AA1/BB1) rather than older docs.

---

## CC1 — `kronos-attest`'s own new `--database-url`/`--minio-secret-key` CLI flags leak credentials into `ps`/shell history

**STATUS (2026-08-18, commit TBD): CLOSED, verified live.**

Milestones AA (`AA1`) and BB (`BB1`) — both from earlier in this same
initiative — added `--database-url`, `--minio-access-key`, and
`--minio-secret-key` to `kronos_attest/cli.py` as plain `click.option()`
string values, each with a documented `envvar=...` fallback already
described in its own `--help` text as the preferred way to supply it.
Nothing, however, actually warned a user who took the `--help` text's
flag name literally that doing so leaks the credential (a DB password
embedded in the DSN, or a MinIO secret/access key) into
`ps`/`/proc/<pid>/cmdline` — visible to any other user on a shared host —
and typically into shell history files. This is a real, live
secret-hygiene gap in this initiative's own recently-added code, found by
directly re-examining that code rather than an external audit doc.

**Fix:** `_warn_if_secrets_from_cli(ctx)`, called at the top of
`verify`/`day-report`/`case-report`. Uses Click's own
`ctx.get_parameter_source(name)` to tell "value came from an explicit CLI
argument" apart from "value came from its environment variable" — prints
a clear `WARNING:` line to stderr for each secret-bearing option supplied
the risky way. Deliberately only warns, never blocks (CLI-supplied
secrets remain fully supported for real scripting use cases).

**Verified end-to-end (`poc/kronos_attest_secret_cli_warning/`):** real
CLI invocations against the real shared dev Postgres, both with
`DATABASE_URL` set as an env var (clean output, no warning) and with
`--database-url` given as a literal flag (same correct output, plus the
new warning on stderr). New unit tests
(`tests/unit/test_attest.py::TestCLISecretOptionWarnings`, 5 tests) cover
every CLI-flag/env-var/offline-mode combination.

**Two real regressions caught and fixed while building this, both
self-caught before being called done:**
1. Click 8.4.2 (the version actually pinned in this repo) removed
   `CliRunner`'s old `mix_stderr` constructor argument — the new tests
   initially used it and failed with a `TypeError`. Fixed by using
   `CliRunner()` (no argument) and `result.stderr`, confirmed still
   separately available independent of `result.output` (which mixes
   stdout+stderr by default in this version).
2. That same stdout/stderr mixing broke five **pre-existing** AA1/BB1
   tests that parsed `json.loads(result.output)` — the moment any stderr
   warning appeared in the same invocation, `.output` was no longer valid
   JSON. Fixed by switching all five to `json.loads(result.stdout)`,
   strictly more correct regardless of whether stderr output is present.

Full backend test suite before/after: 1970 → 1975 passed (+5, zero
regressions), 2 skipped both times. `ruff`/`black`/`mypy` clean.

**Priority: P3** — real, but the underlying secret-supply mechanism (env
vars) was already correct and already the documented default; this closes
a "silent footgun" gap, not a currently-exploited one.

---

## Execution plan

**CC1**: found and closed this pass, orchestrator-direct (small,
self-contained, discovered by re-examining this initiative's own recent
work rather than dispatched from an external audit doc).

Remaining candidates, unchanged, both either low-value or blocked:
- `charts/kronos/files/nginx.conf.template` Helm sync — no live
  consequence yet (Helm/K8s log-shipping entirely unwired); fine to pick
  up as a quick win if a future pass has nothing better, but not chased
  as a priority.
- Prod OpenSearch demo-cert gap (`docs/access-management-review.md`) —
  needs a real TLS material provisioning decision from the project owner;
  not attempted (this is a fully autonomous, cron-triggered session with
  no one to ask in real time — flagging honestly rather than guessing or
  silently dropping it).

**Honest note for the next pass:** the well of unilaterally-actionable,
previously-undiscovered gaps found via `docs/*.md` grep scanning is
genuinely running dry — most remaining hits are either stale (already
fixed, doc never updated — confirmed several this pass) or need a
decision only the project owner can make. The next pass should consider:
re-reading this initiative's own most recently landed code (as this pass
did for CC1) rather than re-scanning the same docs; or treating "the docs
are stale and should be reconciled" itself as the next real, scoped task,
since several out-of-date "not fixed" markers were found this pass alone
and there are likely more.
