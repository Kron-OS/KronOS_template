# PoC: V8 -- fluent-bit severity-mapping fix + nginx access-log producer

Two small, real, independent fixes for `docs/GAP_AUDIT_2026-08.md`'s P1-5
and P1-6 (Milestone V8). Each has its own subdirectory since they touch
different files and were verified independently:

- **`severity/`** -- P1-5: the real `Syslog_Severity_Key level` bug (fed a
  keyword string, never a number) in `docker/fluent-bit/fluent-bit.conf`'s
  syslog `[OUTPUT]`. Fixed with five `modify` `[FILTER]`s translating
  KronOS's real structured-logger level strings to real RFC 5424 numeric
  severities into a new `severity_num` field. Real before/after captured
  against a real `fluent/fluent-bit:3.1.10` container and a real local UDP
  syslog receiver.
- **`nginx_access_log/`** -- P1-6: the `nginx_logs` Docker volume with no
  real producer. Fixed with a real `access_log`/`error_log` pair in
  `docker/nginx/nginx.conf.template` (JSON format, matching fluent-bit's
  own pre-existing but previously-unfed `kronos.nginx` `[INPUT]`) writing
  to a non-default filename inside that volume, plus the matching volume
  mount/declaration wiring in `docker-compose.dev.yml`/
  `docker-compose.fluent-bit.yml`. Real before/after captured against the
  real dev-stack nginx image and a real fluent-bit container.

Both subdirectories found and fixed a real, previously-unverified nuance
beyond what the gap audit itself documented -- see each subdirectory's own
README for the full account:

- `severity/`: the old bug didn't uniformly fall back to one default
  severity; it silently landed `error`/`critical` as `info` (6) while
  `debug`/`info`/`warning` happened to land correctly despite still
  logging a warning.
- `nginx_access_log/`: (1) the official `nginx:alpine` base image's
  `access.log`/`error.log` symlinks get copied into a fresh named volume
  on first use, so the fix had to use a non-colliding filename; (2)
  fluent-bit's own bundled `json` PARSER hardcodes a `Time_Key time` that
  collides with a naively-named JSON field, caught live and fixed by
  renaming to `timestamp`.

## Real files changed (all `docker/`, zero `src/` Python)

- `docker/fluent-bit/fluent-bit.conf`
- `docker/nginx/nginx.conf.template`
- `docker/docker-compose.dev.yml`
- `docker/fluent-bit/docker-compose.fluent-bit.yml`

## Real containers/volumes/networks

All `kronos-poc-*`-prefixed, all torn down at the end of each subdirectory's
own verification run. No container from the shared, already-running dev
stack (`docker-*`) or `portainer_agent` was ever started, stopped, or
modified by this PoC -- both fixes were verified against fully separate
throwaway stacks per this task's own stated preference.
