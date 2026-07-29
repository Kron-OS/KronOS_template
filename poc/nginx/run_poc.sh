#!/usr/bin/env bash
# PoC: real nginx (docker/nginx/nginx.conf.template, unmodified) in front of
# the real FastAPI app (src/external/fastapi_app.py's real CORSMiddleware),
# using nginx's real envsubst-templating mechanism -- never previously run.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# Must be 8000: nginx.conf.template hardcodes "server kronos-backend:8000;"
# in its upstream block (matches the real docker-compose backend service
# port) -- --add-host only remaps the HOSTNAME, not the port.
BACKEND_PORT=8000
# nginx runs with --network host (see below) -- real finding along the way:
# `--add-host kronos-backend:host-gateway` on a normal bridge network timed
# out at the raw TCP level in this sandboxed Docker host (confirmed with a
# bare alpine+curl container -- not an nginx.conf.template or backend bug,
# a sandbox networking restriction on the bridge-to-host path). --network
# host + a plain 127.0.0.1 host-mapping sidesteps it entirely and matches
# real docker-compose's own topology just as faithfully (real container,
# real proxy_pass, real upstream keepalive).
NGINX_PORT=80

docker rm -f kronos-poc-nginx kronos-poc-nginx-crash >/dev/null 2>&1
pkill -f "uvicorn src.external.fastapi_app:app" >/dev/null 2>&1
sleep 1

# --- Real backend, real production module (src.external.fastapi_app:app),
# no DATABASE_URL so it skips DB wiring (only /openapi.json is exercised,
# a route needing no DB/auth). ---
source ~/venv/bin/activate 2>/dev/null || true
CORS_ALLOWED_ORIGINS="http://localhost,http://localhost:5173,http://localhost:4173" \
  nohup python3 -m uvicorn src.external.fastapi_app:app --host 0.0.0.0 --port ${BACKEND_PORT} \
  > /tmp/kronos_poc_nginx_backend.log 2>&1 &
BACKEND_PID=$!
echo "real backend (uvicorn) started, pid=$BACKEND_PID, port=${BACKEND_PORT}"
for i in $(seq 1 30); do
  curl -s -o /dev/null "http://localhost:${BACKEND_PORT}/openapi.json" && break
  sleep 1
done
echo "backend ready"

# --- Real finding #1 (reproduced deliberately): nginx CRASHES AT STARTUP if
# ANY of the four CSP-origin vars is fully unset (not just empty) -- not the
# "harmless empty string" the template's own comment claims. Real
# docker-compose*.yml always sets all four (even to "", via ${VAR:-}
# defaults), which avoids this -- but ANY other invocation that doesn't
# (a bare docker run, or -- confirmed separately -- the current Helm chart,
# whose nginx Deployment sets NONE of these four env vars at all) hits this. ---
echo ""
echo "### Reproducing the unset-var nginx startup crash (OPENSEARCH_DASHBOARDS_URL left unset) ###"
docker run -d --name kronos-poc-nginx-crash \
  --network host \
  --add-host kronos-backend:127.0.0.1 \
  -e KEYCLOAK_PUBLIC_URL="https://keycloak.kronos-poc.example" \
  -e BACKEND_PUBLIC_URL="" \
  -e MINIO_PUBLIC_URL="" \
  -v "$REPO_ROOT/docker/nginx/nginx.conf.template:/etc/nginx/templates/default.conf.template:ro" \
  nginx:alpine >/dev/null
sleep 2
docker logs kronos-poc-nginx-crash 2>&1 | tail -5
docker inspect kronos-poc-nginx-crash --format 'Running={{.State.Running}} ExitCode={{.State.ExitCode}}'

# --- The REAL, working configuration: all four vars present (matching
# docker-compose*.yml's actual ${VAR:-} pattern -- always present, default
# empty), used for the rest of this PoC's functional checks. ---
echo ""
echo "### Starting the real, correctly-configured nginx (all 4 vars present, matching docker-compose*.yml) ###"
docker run -d --name kronos-poc-nginx \
  --network host \
  --add-host kronos-backend:127.0.0.1 \
  -e KEYCLOAK_PUBLIC_URL="https://keycloak.kronos-poc.example" \
  -e BACKEND_PUBLIC_URL="" \
  -e MINIO_PUBLIC_URL="" \
  -e OPENSEARCH_DASHBOARDS_URL="" \
  -v "$REPO_ROOT/docker/nginx/nginx.conf.template:/etc/nginx/templates/default.conf.template:ro" \
  nginx:alpine >/dev/null
for i in $(seq 1 30); do
  curl -s -o /dev/null "http://localhost:${NGINX_PORT}/" && break
  sleep 1
done
echo "nginx ready"

echo "Running run_poc.py..."
CRASHED=$(docker inspect kronos-poc-nginx-crash --format '{{.State.Running}}')
BACKEND_PORT=${BACKEND_PORT} NGINX_PORT=${NGINX_PORT} NGINX_CRASHED="${CRASHED}" \
  python3 "$SCRIPT_DIR/run_poc.py"
STATUS=$?

kill "$BACKEND_PID" >/dev/null 2>&1
exit $STATUS
