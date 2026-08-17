#!/bin/sh
# Real replica bootstrap for postgres:16-alpine (matches the primary
# service's image tag in this same compose file exactly). Postgres core
# ships no "start as a replica" toggle -- the real, documented mechanism
# (postgresql.org/docs/16/app-pgbasebackup.html) is `pg_basebackup -R`
# against the primary, which writes standby.signal + primary_conninfo into
# postgresql.auto.conf. Verified end-to-end against this exact pinned image
# in poc/postgres_replication/ before this file was written (see that
# PoC's README + output.txt for the real captured run).
set -e

REPL_PASSWORD="$(cat /run/secrets/replication_password)"

if [ -z "$(ls -A "$PGDATA" 2>/dev/null)" ]; then
	echo "[replica-entrypoint] \$PGDATA is empty -- bootstrapping via pg_basebackup from $PRIMARY_HOST"

	until pg_isready -h "$PRIMARY_HOST" -p 5432 -U "$REPL_USER" >/dev/null 2>&1; do
		echo "[replica-entrypoint] waiting for primary $PRIMARY_HOST:5432..."
		sleep 1
	done

	PGPASSWORD="$REPL_PASSWORD" pg_basebackup \
		-D "$PGDATA" \
		-Fp -Xs -P -R \
		-d "host=$PRIMARY_HOST port=5432 user=$REPL_USER application_name=$REPLICA_APPLICATION_NAME"

	chmod 700 "$PGDATA"
	echo "[replica-entrypoint] pg_basebackup complete -- standby.signal + primary_conninfo written to postgresql.auto.conf"
fi

exec docker-entrypoint.sh postgres -c hot_standby=on
