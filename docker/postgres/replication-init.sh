#!/bin/sh
# One-shot job, real precedent already in this compose file (`keycloak-init`
# uses the identical restart:"no" one-shot pattern for a different
# bootstrap-ordering problem). Flips the primary into synchronous
# replication mode ONLY after postgres-replica is confirmed healthy and
# streaming.
#
# Why this can't just be `command:` flags on postgres-primary at cold boot
# (real, empirically reproduced finding -- see
# poc/postgres_replication/README.md "real finding #2" and
# poc/postgres_replication/output.txt PART 1 for the actual captured
# deadlock): the postgres:16-alpine entrypoint creates the POSTGRES_DB
# database via a completely ordinary client transaction during its own
# /docker-entrypoint-initdb.d bootstrap, before any replica can possibly
# exist. synchronous_commit defaults to "on" in vanilla Postgres 16, so
# with synchronous_standby_names already naming a standby that has never
# connected, that CREATE DATABASE blocks forever -- the primary never
# finishes bootstrap and never starts accepting real connections.
#
# synchronous_standby_names has context=sighup (empirically confirmed
# against this exact pinned image via `SELECT name,context FROM
# pg_settings`), so this ALTER SYSTEM + pg_reload_conf() is reload-safe --
# no primary restart, no dropped connections, no replication re-sync.
set -e

PGPASSWORD="$(cat /run/secrets/db_password)"
export PGPASSWORD

psql -h postgres -U kronos -d kronos -c \
	"ALTER SYSTEM SET synchronous_standby_names = 'kronos_prod_replica';"
psql -h postgres -U kronos -d kronos -c "SELECT pg_reload_conf();"

echo "[postgres-replication-init] primary is now in synchronous replication mode (sync_standby=kronos_prod_replica)"
