#!/bin/sh
# Gap Audit Milestone MM -- real, disposable end-to-end verification that:
#   1. db-migrate's real `alembic upgrade head` command (via the new
#      migrations/db_url.py DATABASE_URL_FILE fallback) actually connects to
#      and migrates a real, disposable Postgres.
#   2. kronos-backend/celery-worker's bare `Settings()` call (via the new
#      src/config.py secrets_dir support) actually connects to that same
#      real Postgres, plus a real, disposable Redis, using DSNs resolved
#      from mounted secret files -- never a plaintext env var.
#   3. `docker inspect --format '{{json .Config.Env}}'` on BOTH real running
#      containers shows no plaintext password anywhere.
#
# Everything here uses distinctly-named kronos-poc-secretfix-* containers/
# network, torn down at the end. Nothing in the shared dev stack
# (docker-kronos-backend-1, etc.) is touched.
#
# Run from the repo root: sh poc/backend_prod_secret_config_env_exposure/run_poc.sh
set -e

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

NET=kronos-poc-secretfix-net
PG=kronos-poc-secretfix-postgres
REDIS=kronos-poc-secretfix-redis
IMG=kronos-backend-secret-fix-test
SECRETS_DIR=/tmp/kronos-poc-secretfix-secrets
PG_PW='R3alSecretPW!987'
REDIS_PW='R3disSecretPW!123'

cleanup() {
	echo "--- cleanup ---"
	docker rm -f "$PG" "$REDIS" kronos-poc-secretfix-migrate-inspect kronos-poc-secretfix-app-inspect 2>/dev/null || true
	docker network rm "$NET" 2>/dev/null || true
	rm -rf "$SECRETS_DIR" /tmp/kronos-poc-secretfix-verify.py
}
trap cleanup EXIT

echo "=== 1. Build the real backend image from docker/Dockerfile ==="
docker build -f docker/Dockerfile -t "$IMG" .

echo "=== 2. Disposable network + real Postgres + real Redis ==="
docker network create "$NET"
docker run -d --name "$PG" --network "$NET" \
	-e POSTGRES_DB=kronos -e POSTGRES_USER=kronos -e POSTGRES_PASSWORD="$PG_PW" \
	postgres:16-alpine
sleep 4
docker exec "$PG" pg_isready -U kronos

docker run -d --name "$REDIS" --network "$NET" \
	redis:7-alpine redis-server --requirepass "$REDIS_PW"
sleep 2
docker exec "$REDIS" redis-cli -a "$REDIS_PW" --no-auth-warning ping

echo "=== 3. Real Docker-secret-style files (full DSN per file, field-named) ==="
mkdir -p "$SECRETS_DIR"
printf 'postgresql+asyncpg://kronos:%s@%s:5432/kronos' "$PG_PW" "$PG" >"$SECRETS_DIR/database_url"
printf 'redis://:%s@%s:6379/0' "$REDIS_PW" "$REDIS" >"$SECRETS_DIR/redis_url"
printf 'redis://:%s@%s:6379/1' "$REDIS_PW" "$REDIS" >"$SECRETS_DIR/celery_broker_url"
printf 'redis://:%s@%s:6379/2' "$REDIS_PW" "$REDIS" >"$SECRETS_DIR/celery_result_backend"

echo "=== 4. Real db-migrate: alembic upgrade head via DATABASE_URL_FILE ==="
docker run -d --name kronos-poc-secretfix-migrate-inspect \
	--network "$NET" \
	-v "$SECRETS_DIR":/run/secrets:ro \
	-e DATABASE_URL_FILE=/run/secrets/database_url \
	"$IMG" alembic upgrade head
sleep 4
docker logs kronos-poc-secretfix-migrate-inspect
echo "--- db-migrate Config.Env (must show no plaintext password) ---"
docker inspect kronos-poc-secretfix-migrate-inspect --format '{{json .Config.Env}}'
echo
echo "--- real tables created ---"
docker exec "$PG" psql -U kronos -d kronos -c '\dt'

cat >/tmp/kronos-poc-secretfix-verify.py <<'PYEOF'
import asyncio
from src.config import Settings

settings = Settings()  # bare call, exactly like startup.py / celery_app.py
print("secrets_dir:", Settings.model_config.get("secrets_dir"))
print("database_url (masked repr):", repr(settings.database_url))
print("redis_url (masked repr):", repr(settings.redis_url))


async def main() -> None:
    import redis.asyncio as aioredis
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(settings.database_url.get_secret_value())
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT 1"))
        assert result.scalar() == 1
    await engine.dispose()
    print("POSTGRES CONNECT: OK (real SELECT 1 via settings.database_url)")

    for field in ("redis_url", "celery_broker_url", "celery_result_backend"):
        r = aioredis.from_url(getattr(settings, field).get_secret_value())
        assert await r.ping() is True
        await r.aclose()
        print(f"REDIS ({field}) CONNECT: OK")


asyncio.run(main())
print("ALL REAL CONNECTIONS SUCCEEDED")
PYEOF

echo "=== 5. Real kronos-backend/celery-worker path: bare Settings() via secrets_dir ==="
docker run -d --name kronos-poc-secretfix-app-inspect \
	--network "$NET" \
	-v "$SECRETS_DIR":/run/secrets:ro \
	-v /tmp/kronos-poc-secretfix-verify.py:/verify.py:ro \
	-e KRONOS_SECRETS_DIR=/run/secrets \
	-e MINIO_ENDPOINT=minio:9000 -e MINIO_ACCESS_KEY=dummy -e MINIO_SECRET_KEY=dummy \
	-e OPENSEARCH_URL=https://opensearch:9200 -e OPENSEARCH_USERNAME=dummy -e OPENSEARCH_PASSWORD=dummy \
	-e KEYCLOAK_URL=https://keycloak:8443 -e KEYCLOAK_CLIENT_SECRET=dummy \
	-e VAULT_URL=https://vault:8200 -e VAULT_TOKEN=dummy \
	"$IMG" python /verify.py
sleep 3
docker logs kronos-poc-secretfix-app-inspect
echo "--- kronos-backend-shaped container Config.Env (must show no plaintext password) ---"
docker inspect kronos-poc-secretfix-app-inspect --format '{{json .Config.Env}}'
echo
echo "--- grep for real plaintext secret material anywhere in full docker inspect ---"
if docker inspect kronos-poc-secretfix-app-inspect kronos-poc-secretfix-migrate-inspect | grep -q "$PG_PW\|$REDIS_PW"; then
	echo "FAIL: plaintext secret found in docker inspect output"
	exit 1
else
	echo "PASS: 0 matches for real plaintext passwords in docker inspect output"
fi

echo "=== DONE -- see output.txt for the captured run this README documents ==="
