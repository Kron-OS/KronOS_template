# LAN HTTPS access — step-ca, nginx TLS termination, and three reverse proxies

**Component pairs verified, alone then together, per CLAUDE.md §F and the
user's explicit instruction to PoC each piece before finishing the
integration:**

| # | Component(s) | Alone or combined | Result |
|---|---|---|---|
| 1 | step-ca (real, already-running dev instance) | alone | Root CA fetch + verified re-fetch + leaf cert issuance via the live `admin` JWK provisioner — all real, no mocks |
| 2 | nginx `:443` TLS termination (SPA + backend API/auth/SSE) | alone | Real TLS 1.3 handshake, cert chains to the step-ca root, `/healthz` 200 through the proxy |
| 3 | nginx `:8443` → Keycloak | combined (nginx+Keycloak) | Discovery doc reachable over HTTPS, `issuer`/`authorization_endpoint` correctly pinned to the LAN HTTPS address |
| 4 | nginx `:9444` → MinIO | combined (nginx+MinIO) | **1 real bug found + fixed** (below) — a real SigV4-signed presigned PUT through the proxy, verified by reading the object back |
| 5 | nginx `:5602` → OpenSearch Dashboards | combined (nginx+Dashboards) | Real 302 redirect to Keycloak login (Dashboards' own `authRequired: false` route, same pattern the existing dev healthcheck already relies on) |
| 6 | All of the above | combined, full stack | All 18 services healthy, all four HTTPS origins live simultaneously |

## What was actually run

Real dev-stack containers (`docker-compose.dev.yml`), not mocks. Root CA
extracted from the real `tls-init` container's output volume
(`docker cp` from `docker_tls_certs`) and used as `--cacert` for every
`curl` call below — i.e. these are genuine chain-of-trust validations, not
`-k`/insecure-skip-verify checks.

See `output.txt` for the full captured run (tls-init logs, all four `curl`
checks, and `docker compose ps`). Highlights:

```
$ curl -v --cacert root_ca.crt https://192.168.5.13/healthz
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768 / id-ecPublicKey
*   subject: CN=192.168.5.13
*   issuer: O=KronOS Internal CA; CN=KronOS Internal CA Intermediate CA
< HTTP/1.1 200 OK
{"status":"ok"}

$ curl --cacert root_ca.crt https://192.168.5.13:8443/realms/kronos/.well-known/openid-configuration
issuer: https://192.168.5.13:8443/realms/kronos
authorization_endpoint: https://192.168.5.13:8443/realms/kronos/protocol/openid-connect/auth

$ curl -o /dev/null -w "HTTP %{http_code}" --cacert root_ca.crt https://192.168.5.13:5602/auth/openid/login
HTTP 302
```

## Bug found + fixed: MinIO presigned-PUT signature broke through the reverse proxy

**Symptom (real, reproduced):** a presigned PUT URL generated with
`MINIO_PUBLIC_ENDPOINT=https://192.168.5.13:9444` (exactly what
`src/adapter/storage/s3.py`'s `_presign_client` does — mirrored directly in
`presign_test.py`, this PoC's script) came back **403 Forbidden** when PUT
through nginx's `:9444` reverse proxy to MinIO.

**Root cause:** `nginx-lan-https.conf.template`'s MinIO server block used
`proxy_set_header Host $host;`. nginx's `$host` variable is normalized
hostname-only — it silently **drops the port**. So nginx forwarded
`Host: 192.168.5.13` to MinIO, but the presigned URL's SigV4 signature was
computed against `Host: 192.168.5.13:9444` (the exact host:port the client
actually sent, which is what `MINIO_PUBLIC_ENDPOINT` specifies and what
SigV4 always signs). MinIO recomputes the signature from the Host header it
actually receives — the port mismatch made every presigned request fail
signature validation, unconditionally, for every evidence upload that would
ever go through this proxy.

**Fix:** `proxy_set_header Host $http_host;` — `$http_host` is nginx's
"the exact incoming Host header, verbatim" variable, port included. Applied
to all four server blocks in `nginx-lan-https.conf.template` (and
`X-Forwarded-Host` for the Keycloak block) for consistency, even where it
wasn't cryptographically load-bearing like it is here.

**Verified fixed** with a real, non-mocked round trip:
1. `presign_test.py` (boto3, same client construction as
   `S3EvidenceStorage`'s `_presign_client`) signs a PUT URL against
   `https://192.168.5.13:9444`.
2. `curl --upload-file` PUTs real bytes to that URL through the (fixed)
   nginx proxy → **200 OK**.
3. A separate boto3 client, connected directly to MinIO's internal-network
   equivalent port, `GetObject`s the same key back → content matches
   byte-for-byte what was PUT.

This is exactly the kind of bug a plain `curl -k https://.../health` check
would never surface — the proxy "worked" (200s, valid TLS, correct
routing) for every non-cryptographic check; only a real signed request
exposed it. Confirms CLAUDE.md §F's own reasoning for requiring a real
round trip, not a plausible-looking config.

## Second, more serious bug found + fixed: Keycloak's login form breaks across a domain jump

**Found during exhaustive re-verification** (after a full `--no-cache`
rebuild, requested explicitly to prioritize correctness over speed): the
original design kept `localhost` clients talking to Keycloak's existing
plain-HTTP `:8080` directly, only sending *other* origins through the new
`:8443` HTTPS proxy — reasoning being `localhost` is a secure context
regardless of scheme, so no TLS is needed there.

**That reasoning was correct for non-interactive checks (JWT `iss`
validation, discovery-doc fetches) but wrong for the actual interactive
login.** Confirmed directly: a scripted PKCE login starting on
`http://localhost:8080` got as far as the login form, then a real
**400 "Restart login cookie not found."** Root cause: Keycloak's
`KC_HOSTNAME` is a single pinned value for the whole realm — every URL
Keycloak renders, including the login form's own `action=` attribute,
uses that one value (`https://192.168.5.13:8443`) **regardless of which
origin the flow started on**. Keycloak sets its session-restart cookie on
whatever origin the initial GET landed on (`localhost`); the form then
POSTs to a *different* origin (`192.168.5.13`); cookies never cross
domains; Keycloak can't find the session and rejects the POST outright.
This is real, unavoidable HTTP cookie behavior — not something a cleverer
client-side redirect can route around.

**This means a real browser hitting the actual frontend at
`http://localhost` would have hit the identical failure** the moment a
user clicked "Log in" — not just this PoC's scripted client. Caught here
specifically because this pass insisted on running the *real* existing
`poc/full_ingestion_test/login.py` end-to-end against the modified stack,
not just curling health endpoints.

**Fix:** every client — `localhost` or LAN — must start the login flow at
the exact same canonical origin Keycloak is pinned to. Removed the
per-hostname branch from `frontend/src/keycloak.ts`'s `resolveKeycloakUrl()`
entirely; `VITE_KEYCLOAK_URL` is now a real build arg
(`docker-compose.dev.yml` → `docker/Dockerfile.frontend`) always set to
`https://192.168.5.13:8443`, sourced from the same `KRONOS_LAN_HOST` value
`tls-init`'s cert SAN and Keycloak's own `KC_HOSTNAME` already use — one
source of truth, no derivation. Same fix applied to the 4 poc scripts that
independently log in against the real dev stack
(`poc/full_ingestion_test/login.py`, `run_ingest.py`;
`poc/kape_ingestion_test/run_kape_ingest.py`, `poll_and_verify.py`) —
`auth_helpers.KC` now points at the canonical origin instead of
`localhost:8080`, and `auth_helpers.trust_dev_stack_step_ca()` (new helper)
makes the scripts' `httpx` clients trust the real step-ca root instead of
failing `CERTIFICATE_VERIFY_FAILED`.

**Verified fixed** with the strongest available check: ran the actual,
pre-existing `poc/full_ingestion_test/run_ingest.py` unmodified in intent
(only its Keycloak origin/CA trust patched) against the rebuilt stack —
real PKCE login succeeds, a real case is created, all 5 real sample files
(one per registered parser) upload through the LAN-HTTPS MinIO proxy with
valid SigV4 signatures, and the autonomous pipeline (`CLAUDE.md` §E) takes
all 5 from `RECEIVED` through `PARSING` to **`COMPLETE`** with zero client
intervention — polled directly against the real backend:

```
{'aws_cloudtrail.jsonl': 'COMPLETE', 'apache_access.log': 'COMPLETE',
 'History': 'COMPLETE', 'system.evtx': 'COMPLETE', 'CMD.EXE-087B4001.pf': 'COMPLETE'}
```

This is the same real-world flow a browser goes through — login, upload,
autonomous processing — now proven correct end-to-end on the LAN-HTTPS
path, not just individually-passing component checks.

## Third bug found + fixed: Keycloak client rejected the LAN redirect URI

**Found from a real client's browser console**, after the fixes above were
already live: `keycloak-js` correctly built a login request with
`redirect_uri=https://192.168.5.13/cases` (matching the LAN origin the SPA
was actually loaded from), and Keycloak rejected it outright —
**"We are sorry... Invalid parameter: redirect_uri"** (400 on the
`/protocol/openid-connect/auth` request itself, before the login form ever
rendered).

**Root cause:** `docker/keycloak/kronos-realm.json`'s `kronos-frontend`
client only ever declared `localhost`/`127.0.0.1` origins in its
`redirectUris`/`webOrigins`/`post.logout.redirect.uris` — there was no
LAN entry, so Keycloak's own redirect-URI allowlist check (a real,
mandatory OAuth2 security control, not a formality) blocked the request
before it could reach the login form at all.

**Fix:** added `https://192.168.5.13/*` to `redirectUris`,
`https://192.168.5.13` to `webOrigins`, and the matching entry to
`post.logout.redirect.uris`, mirroring the existing `localhost` pattern
exactly. Since `KC_DB: dev-mem` (Keycloak's dev database is in-memory),
this realm-file change only takes effect after Keycloak itself is
restarted (`docker compose up -d --force-recreate keycloak`) — which
also resets the org/Dashboards-tenant state that lives in the same
in-memory DB, so `keycloak-init`/`dashboards-tenant-init` need
`--force-recreate` too, to re-provision them against the fresh realm.

**Verified fixed** two ways: a scripted login using the exact
`redirect_uri` the real browser sent (`https://192.168.5.13/cases`)
succeeded; then the full `poc/full_ingestion_test/run_ingest.py` flow was
re-run against the freshly-reprovisioned org, all 5 uploads and finalizes
still succeeding.

## Fourth bug found + fixed: `index.html` had no `Cache-Control`, so a fresh browser could still see a stale CSP

The CSP `frame-src` violation reported above recurred even after a "fresh
browser" test — while the same real client's network trace, in the exact
same session, showed nginx correctly returning the up-to-date CSP on a
`POST /auth/refresh`. That contradiction was the real clue: two different
requests, two different CSP values, same server, same moment.

**Root cause, confirmed empirically, not guessed:** `docker/nginx/nginx.conf.template`'s
`location /` (serving `index.html`, the SPA's entry point) had no
`Cache-Control` header at all — only `ETag`/`Last-Modified`. Checked
directly: nginx *does* correctly re-send the current CSP even on a `304
Not Modified` conditional-GET response (verified with a real
`If-None-Match` request), so the bug isn't in revalidation — it's that
nothing *forces* the browser to revalidate at all. Without an explicit
`Cache-Control`, a browser is free to reuse a heuristically-cached copy of
`index.html` — CSP header included — for an unbounded time without ever
contacting the server again. A config-only change (new CSP values from an
env var) doesn't touch the built file's own mtime/ETag, so it can never
invalidate a browser's already-cached copy on its own — the exact
mismatch reported.

**Fix:** `location /` now sends `Cache-Control: no-cache` (mandatory
revalidation on every load — still lets the browser reuse a fast `304`,
it just can no longer skip asking the server entirely), applied to both
`nginx.conf.template`'s `:80`/`:443` block and
`nginx-lan-https.conf.template`'s `:443` block. Fingerprinted JS/CSS
assets are untouched (`expires 1y; Cache-Control: public, immutable` on
the nested regex location) — those are safe to cache forever since a real
content change gives them a new URL. Because `add_header` in nginx drops
*all* inherited headers the moment a location defines *any* of its own,
every other header the page needs (CSP, HSTS, X-Frame-Options, etc.) had
to be redeclared inside `location /`, not just the new one — losing them
here would have been a silent security regression, not a cosmetic one.

**Verified fixed**: `curl -I` on `/` now shows `Cache-Control: no-cache`
alongside the full, current header set; a real login (with the browser's
exact `redirect_uri`) still succeeds end-to-end after the change.

## Running it again

```bash
# from a running docker-compose.dev.yml stack:
docker cp docker-tls-init-1:/certs/root_ca.crt ./root_ca.crt
curl --cacert root_ca.crt https://192.168.5.13/healthz
curl --cacert root_ca.crt https://192.168.5.13:8443/realms/kronos/.well-known/openid-configuration
curl -o /dev/null -w '%{http_code}\n' --cacert root_ca.crt https://192.168.5.13:5602/auth/openid/login
docker run --rm --network host -v "$PWD":/work -w /work python:3.12-slim \
  sh -c "pip install -q boto3 && python3 presign_test.py"
# then curl --upload-file <file> --cacert root_ca.crt "<PRESIGNED_URL from output>"
```
