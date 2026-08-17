#!/bin/sh
# Runs once via /docker-entrypoint-initdb.d on first boot of the primary
# (only when $PGDATA is empty). Creates the dedicated replication role the
# postgres-replica service's pg_basebackup / streaming connection
# authenticates as. Password is read from the mounted Docker secret file,
# never hardcoded or logged -- mirrors this file's existing
# POSTGRES_PASSWORD_FILE convention.
#
# Real-verified pattern: identical in shape to
# poc/postgres_replication/primary-init/01-create-replicator.sql, adapted
# from a static .sql file to a shell script only because the password must
# come from a runtime secret file rather than being hardcoded.
set -e

REPL_PASSWORD="$(cat /run/secrets/replication_password)"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<-EOSQL
	CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD '$REPL_PASSWORD';
EOSQL
