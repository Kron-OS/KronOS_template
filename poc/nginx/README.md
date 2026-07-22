# PoC: real nginx CSP/CORS headers, backend↔nginx (step 9)

## Component pair
`docker/nginx/nginx.conf.template` (unmodified, real envsubst templating)
in front of `src/external/fastapi_app.py`'s real `CORSMiddleware`.

## Versions (pinned, read from this repo)
- `nginx:alpine` (`docker/docker-compose.prod.yml`) — resolved to the real
  running version: `nginx/1.31.3`.
- The real backend module, run via `uvicorn src.external.fastapi_app:app`
  (no `DATABASE_URL`, so DB wiring is skipped — only `/openapi.json` and
  `/api/cases` are exercised, neither needs a database).

## What this actually does
`run_poc.sh` starts the real backend (real production module, real
`CORSMiddleware` config) and a real `nginx:alpine` container with the real,
unmodified `nginx.conf.template` mounted via nginx's own envsubst-templating
mechanism (`/etc/nginx/templates/default.conf.template`) — the exact
mechanism `docker-compose.prod.yml` uses. `run_poc.py` then drives real
requests through both layers.

**Environment note:** nginx and the backend run as sibling processes on the
same network namespace (`--network host` + a `127.0.0.1` host mapping for
`kronos-backend`), not the bridge-network `--add-host ... host-gateway`
pattern used elsewhere in this repo's PoCs — that pattern's raw TCP
connections timed out in this sandbox (confirmed with a bare `alpine+curl`
container hitting the same host-gateway IP:port with no nginx involved at
all), a sandbox networking restriction, not an nginx/backend bug.

## Real finding #1 (severe): nginx crashes at startup if a CSP-origin var is left unset
The template's own comment claims: *"An unset var substitutes to empty
string, which is safe here."* **This is false for a truly unset variable.**
Read the real `/docker-entrypoint.d/20-envsubst-on-templates.sh` inside the
image: it builds its substitution filter from `for name in ENVIRON` —
i.e., only environment variable *names actually present* in the container
get substituted. A var never passed at all is not just left as literal
`${VARNAME}` text (already bad) — nginx's own config parser then tries to
interpret that leftover `${...}` as **its own** variable syntax, and dies:
```
nginx: [emerg] unknown "opensearch_dashboards_url" variable
```
Confirmed for real: a container started with `OPENSEARCH_DASHBOARDS_URL`
completely unset never reaches "ready" — `docker inspect` shows
`Running=false ExitCode=1` (`output.txt`).

**Why this hasn't bitten the repo's own compose files:** both
`docker-compose.dev.yml`/`docker-compose.prod.yml` set all four origin
vars unconditionally, via `${VAR:-}` (always present, default empty) —
confirmed this actually works by starting the *correctly*-configured
container the same way (all four vars present, three empty) and getting a
real, working CSP header with the empty ones correctly collapsing to
nothing, not crashing. **What does hit it:** any other invocation that
doesn't guarantee all four — a bare `docker run`, or, confirmed separately
below, the current Helm chart, which sets none of them at all.

**Fixed:** corrected the misleading comment in `docker/nginx/nginx.conf.template`
to describe the real failure mode instead of the false "harmless empty
string" claim.

## Real finding #2 (severe, separate from CSP): the Helm chart's nginx Deployment references a ConfigMap that is never created
While researching how the Helm chart wires these same CSP vars (it doesn't
use envsubst at all — `charts/kronos/templates/nginx/deployment.yaml`
mounts a ConfigMap directly at `/etc/nginx/conf.d`, bypassing nginx's
template mechanism entirely), found that `nginx-config` — the ConfigMap
volume the Deployment mounts — **was never defined anywhere in the chart**.
Confirmed with a real `helm template` render (had to `helm dependency
update` first — the chart declares real Bitnami `postgresql`/`redis`
subchart dependencies): grepping the full rendered output for `kind:
ConfigMap` found exactly one, `{fullname}-config` (the general app-config
one, unrelated), and zero for `{fullname}-nginx-config`. Every real
Kubernetes deployment of this chart would leave the nginx pods (the
`app.kubernetes.io/zone: dmz` layer — the *only* ingress point) stuck in
`ContainerCreating`/`FailedMount` forever. No ingress traffic could ever
reach the cluster.

**Fixed:**
- `charts/kronos/files/nginx.conf.template` — a chart-local copy of the
  real `docker/nginx/nginx.conf.template` (same "kept in sync manually"
  pattern this chart already uses for
  `scripts/provision_keycloak_org.sh`/`charts/kronos/files/provision_keycloak_org.sh`),
  with the CSP header's `${VAR}` shell placeholders replaced by real Helm
  `{{ .Values.x }}` expressions — this file is rendered by Helm's `tpl`
  function, not nginx's envsubst, so `{{ }}` is the right substitution
  syntax here, and `| default ""` sidesteps finding #1 entirely (a
  render-time empty string, never a dangling `${VAR}` for nginx to choke on).
- `charts/kronos/templates/nginx/configmap.yaml` — the missing ConfigMap,
  using the same `.Files.Get`/`tpl` pattern the chart's own
  `provision-org-configmap.yaml` already established.
- `charts/kronos/values.yaml` — added `nginx.backendPublicUrl`/
  `nginx.minioPublicUrl` (default empty, matching `docker-compose.prod.yml`'s
  own default — this chart's ingress topology never publishes those
  origins directly to browsers either).

**Verified for real** (no live cluster available, but the two strongest
checks that don't need one):
1. `helm template` (after `helm dependency update`, real Bitnami charts
   fetched) — the ConfigMap now renders, with the real values
   (`https://auth.kronos.example.com`, `https://dashboards.kronos.example.com`)
   correctly substituted into the CSP header and the two empty ones
   correctly collapsing to nothing, not left as `${VAR}`.
2. Extracted the exact rendered `default.conf` content and ran it through
   **real nginx's own config validator**: `docker run ... nginx:alpine
   nginx -t` → `configuration file /etc/nginx/nginx.conf syntax is ok` /
   `test is successful`. This is the strongest verification available
   without a live cluster: the actual bytes Kubernetes would mount into the
   pod are confirmed to be a genuinely valid nginx config, not just
   valid-looking YAML.

## Real finding #3 (design confirmation, not a bug): nginx's `add_header` inheritance rule silently drops other security headers on `/silent-check-sso.html`
nginx's real, documented behavior: a location block with its **own**
`add_header` does not inherit *any* `add_header` from the server level —
not a partial merge, all-or-nothing. `/silent-check-sso.html` sets its own
CSP (`frame-ancestors 'self'`) and, as a direct consequence, **genuinely
lacks** `X-Frame-Options`, `X-Content-Type-Options`, and
`Strict-Transport-Security` — confirmed for real (`output.txt`, section 3),
compared directly against the root `/` response (no location-level
`add_header`), which correctly carries all of them. Not fixed here — this
endpoint is a same-origin, no-user-content static HTML file whose own CSP
already constrains framing, so the practical exposure is low, but it's
flagged because the *absence* of the other headers on this one location
was clearly never verified before (their presence elsewhere might create
false confidence that they're global).

## Result: 15/15 real checks passed (`output.txt`)
- Real CORS preflight: allowed origin gets echoed back with
  `allow-credentials: true`; disallowed origin gets no CORS header at all;
  a request with no `Origin` header gets none either (all real
  `CORSMiddleware` behavior, not assumed).
- Real CSP header via real nginx: the set var substitutes correctly, the
  empty (but present) vars correctly collapse to nothing.
- Real `add_header` inheritance gotcha confirmed on `/silent-check-sso.html`
  vs. the root response.
- Real `/api/` proxy: a request through nginx reaches the real backend, the
  backend's real CORS header survives `proxy_pass` unmodified, and nginx's
  own CSP header is present on the *same* proxied response — both layers
  genuinely stack.

## Files
- `run_poc.sh` — full reproducible bootstrap (real backend + real nginx,
  including the deliberate crash reproduction) + `run_poc.py`
- `run_poc.py` — the actual verification
- `output.txt` — captured transcript of the last real run (15/15 passed)

## Cleanup
```bash
docker rm -f kronos-poc-nginx kronos-poc-nginx-crash
pkill -f "uvicorn src.external.fastapi_app:app"
```
