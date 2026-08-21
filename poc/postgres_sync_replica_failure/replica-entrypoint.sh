#!/bin/sh
# Real replica bootstrap for postgres:16-alpine, pinned to match
# docker-compose.dev.yml / docker-compose.prod.yml's existing `postgres:`
# service image tag exactly.
#
# Postgres core ships no "start as a replica" mode toggle -- the real,
# documented mechanism (postgresql.org/docs/16/app-pgbasebackup.html,
# fetched live for this PoC) is: run `pg_basebackup -R` against the
# primary. Per the official docs: "-R / --write-recovery-conf: Creates a
# standby.signal file and appends connection settings to the
# postgresql.auto.conf file in the target directory... The
# postgresql.auto.conf file will record the connection settings and, if
# specified, the replication slot that pg_basebackup is using, so that
# streaming replication will use the same settings later on." That is the
# real Postgres-16-native mechanism this script exercises -- no
# hand-rolled recovery.conf (removed in PG12+), no Patroni/repmgr.
set -e

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
