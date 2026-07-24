# Accessing the dev stack from a LAN client over HTTPS

**Status:** dev-only. Verified end-to-end (real login, real evidence
upload, real autonomous ingestion to `COMPLETE`) — see
[`poc/tls_lan_https/`](../poc/tls_lan_https/README.md) for the full
captured-output record, including two real bugs found and fixed while
building this.

## Why this exists

`docker-compose.dev.yml`'s `nginx`/`keycloak`/`minio`/`opensearch-dashboards`
services only ever worked from `http://localhost`. Browsers restrict the
Web Crypto API (needed for `keycloak-js`'s PKCE login) and the Storage
Access API (Keycloak's silent-SSO iframe) to **secure contexts** —
HTTPS, or `http://localhost` specifically. A LAN IP over plain HTTP is
neither, so login broke outright from any other machine on the network.

## What was built

- `tls-init` — a one-shot container that issues a real leaf certificate
  (SAN = the LAN IP, `localhost`, `127.0.0.1`) from this stack's own
  `step-ca`, and its root CA, into a shared volume.
- `nginx` now terminates TLS for **every** browser-facing origin, reverse
  proxying to the existing internal plain-HTTP services (see
  `docker/nginx/nginx-lan-https.conf.template`):

  | Origin | HTTPS port | Plain-HTTP port (unchanged, still used internally) |
  |---|---|---|
  | SPA + `/api` + `/auth` + `/sse` | 443 | 80 |
  | Keycloak (browser-facing) | 8443 | 8080 |
  | MinIO (presigned evidence upload/download) | 9444 | 9000 |
  | OpenSearch Dashboards (Timeline tab iframe) | 5602 | 5601 |

- The frontend build now bakes in `VITE_KEYCLOAK_URL=https://<LAN host>:8443`
  (a real build arg, `docker-compose.dev.yml` → `Dockerfile.frontend`) —
  **every** client, `localhost` included, logs in via this one canonical
  origin. See `frontend/src/keycloak.ts`'s `resolveKeycloakUrl()` for why
  this can't be derived per-client: Keycloak's `KC_HOSTNAME` is a single
  pinned value for the whole realm, and the login form's own POST target
  always uses it regardless of which origin the flow started on. Starting
  the flow on a different origin than `KC_HOSTNAME` breaks the
  session-restart cookie across that domain jump — a real bug this pass
  found and fixed, not a hypothetical.

## Changing the LAN address

The default is `192.168.5.13`. To point this at a different host/IP, set
`KRONOS_LAN_HOST` before bringing the stack up:

```bash
KRONOS_LAN_HOST=10.0.0.5 docker compose -f docker/docker-compose.dev.yml up -d --build
```

(`tls-init`'s cert SAN, `keycloak`'s `KC_HOSTNAME`, and the frontend's
`VITE_KEYCLOAK_URL` build arg all read from this one variable — but note
several other places in `docker-compose.dev.yml` — `MINIO_PUBLIC_ENDPOINT`,
`OPENSEARCH_DASHBOARDS_URL`, the nginx CSP vars, ufw rules below — still
have the literal `192.168.5.13` hardcoded rather than reading
`KRONOS_LAN_HOST` too. Update those to match if you change the host; this
wasn't fully centralized in this pass.)

## Firewall

If `ufw` is active, LAN clients need these ports open (adjust the subnet):

```bash
for p in 80 443 8443 9444 5602; do
  sudo ufw allow from 192.168.5.0/24 to any port $p proto tcp comment 'kronos-dev'
done
```

## Trusting the certificate

The certs are issued by this stack's own `step-ca` — a private CA, not a
publicly trusted one. Without trusting its root, browsers will show a
security warning on `https://<LAN host>`, and — more importantly — the
OpenSearch Dashboards iframe embed (Timeline tab) and any subresource
fetch (MinIO uploads) will **fail silently** rather than show a
click-through prompt, since there's no user gesture to click through for
an iframe or a `fetch()`.

1. Extract the root CA from a running stack:

   ```bash
   docker cp docker-tls-init-1:/certs/root_ca.crt ./kronos-dev-root-ca.crt
   ```

2. Install it into the LAN client's trust store:

   - **Linux:**
     ```bash
     sudo cp kronos-dev-root-ca.crt /usr/local/share/ca-certificates/kronos-dev.crt
     sudo update-ca-certificates
     ```
     (Firefox uses its own store, not the OS one — import via
     `about:preferences#privacy` → Certificates → View Certificates →
     Authorities → Import.)
   - **macOS:** open the `.crt` file in Keychain Access, add it to the
     `login` or `System` keychain, then double-click it → Trust → "Always
     Trust" for SSL.
   - **Windows:** double-click the `.crt` file → Install Certificate →
     Local Machine → "Place all certificates in the following store" →
     Trusted Root Certification Authorities.

3. Reload the page. `https://<LAN host>` should show a valid padlock with
   no warning.

## Verifying it yourself

```bash
docker cp docker-tls-init-1:/certs/root_ca.crt ./root_ca.crt
curl --cacert root_ca.crt https://192.168.5.13/healthz
curl --cacert root_ca.crt https://192.168.5.13:8443/realms/kronos/.well-known/openid-configuration
curl -o /dev/null -w '%{http_code}\n' --cacert root_ca.crt https://192.168.5.13:5602/auth/openid/login
```

All three should succeed with a clean cert chain (no `-k`/insecure flag
needed). See `poc/tls_lan_https/README.md` for a real presigned-upload
verification against MinIO's proxy as well.
