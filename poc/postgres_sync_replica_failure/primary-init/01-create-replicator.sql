-- Runs once via /docker-entrypoint-initdb.d on first boot of the primary
-- (only when $PGDATA is empty). Creates the dedicated replication role the
-- replica's pg_basebackup / streaming connection authenticates as.
CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'kronos_poc_repl_pw';
