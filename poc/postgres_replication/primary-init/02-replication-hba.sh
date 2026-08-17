#!/bin/sh
# Runs once via /docker-entrypoint-initdb.d on first boot of the primary.
#
# Real, confirmed finding (postgresql.org/docs/16/auth-pg-hba-conf.html,
# fetched live for this PoC): the pg_hba.conf `database` field value `all`
# does NOT match physical replication connections -- "the value replication
# specifies that the record matches if a physical replication connection is
# requested" as a *distinct* value from `all`. The official postgres:16
# image's own docker-entrypoint.sh only ever appends
# `host all all all $POSTGRES_HOST_AUTH_METHOD` (confirmed by extracting
# /usr/local/bin/docker-entrypoint.sh from the real pulled image), which
# does not cover replication connections at all. Without this explicit
# entry the replica's pg_basebackup/streaming connection is rejected with
# "no pg_hba.conf entry for replication connection" -- a real, commonly
# hit gotcha (see docker-library/postgres#1132 and the pgsql-general
# thread "no pg_hba.conf entry for replication connection from host").
set -e
echo "host replication replicator all scram-sha-256" >> "$PGDATA/pg_hba.conf"
