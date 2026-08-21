#!/bin/sh
# Real fix, Gap Audit Milestone LL (closes poc/redis_prod_secret_cli_exposure/'s
# finding): redis:7-alpine has no native "_FILE" env-var convention for
# --requirepass the way the official postgres image supports
# POSTGRES_PASSWORD_FILE, so a small entrypoint script is the real
# mechanism -- reads the real Docker secret file at container start and
# passes it to redis-server as a resolved shell variable, never baked into
# the image's own Config.Cmd/Entrypoint (`docker inspect` only ever shows
# this script's own invocation, never the resolved password -- verified
# against the real pinned redis:7-alpine image before this file was
# written, see poc/redis_prod_secret_cli_exposure/README.md's own
# "Fix verification" section for the captured run).
set -e

REDIS_PASSWORD="$(cat "$REDIS_PASSWORD_FILE")"

exec redis-server --requirepass "$REDIS_PASSWORD" --appendonly yes
