# Accessing the dev stack from a LAN client over HTTPS

**Status:** dev-only. Verified end-to-end (real login, real evidence
upload, real autonomous ingestion to `COMPLETE`) — see
[`poc/tls_lan_https/`](../poc/tls_lan_https/README.md) for the full
captured-output record, including every real bug found and fixed while
building this.

**`kronos.local` is the sole authorized domain for this app.** Every
origin restriction anywhere in the stack — CORS allowlists, CSP source
lists, Keycloak's client `redirectUris`/`webOrigins`, the TLS certificate's
SAN — grants `https://kronos.local` and nothing else. There are
deliberately no `localhost`/`127.0.0.1`/bare-IP entries left anywhere in
that list. This isn't just tidiness: every one of those used to be a
second, independently-hardcoded value (in `frontend/index.html`'s `<meta>`
CSP tag, in the Keycloak realm's client allowlists, in nginx's own CSP env
vars) that silently drifted out of sync with the others — real bugs found
and fixed in this repo's own history, see `poc/tls_lan_https/README.md`.

## Why this exists

`docker-compose.dev.yml`'s `nginx`/`keycloak`/`minio`/`opensearch-dashboards`
services only ever worked from `http://localhost`. Browsers restrict the
Web Crypto API (needed for `keycloak-js`'s PKCE login) and the Storage
Access API (Keycloak's silent-SSO iframe) to **secure contexts** —
HTTPS, or `http://localhost` specifically. A LAN IP over plain HTTP is
neither, so login broke outright from any other machine on the network.

## Making `kronos.local` resolve

This is a real hostname, not a magic value — some DNS mechanism has to
point it at the server. Two options:

- **mDNS (`.local` names, zero-config)** was the first thing tried here
  and is the "right" way to do this — but on this host, `avahi-daemon`
  refused to publish `kronos.local` with a `Local name collision` even
  restricted to a single physical interface with IPv6 disabled (something
  else already answering for that name on the same network segment,
  couldn't fully diagnose without `avahi-browse`, not installed). Don't
  assume this will fail on your network too — it's worth trying first
  (`echo "<server-ip> kronos.local" | sudo tee -a /etc/avahi/hosts &&
  sudo systemctl restart avahi-daemon`, then check
  `journalctl -u avahi-daemon` for the same error) — but have the fallback
  ready.
- **`/etc/hosts` (guaranteed to work, one line per client):** on the
  server and every LAN client that needs access:
  ```bash
  echo "<server-lan-ip> kronos.local" | sudo tee -a /etc/hosts   # Linux/macOS
  ```
  Windows: add the same line to
  `C:\Windows\System32\drivers\etc\hosts` (as Administrator).

## What was built

- `tls-init` — a one-shot container that issues a real leaf certificate
  (SAN = `kronos.local` only) from this stack's own `step-ca`, and its
  root CA, into a shared volume.
- `nginx` terminates TLS for **every** browser-facing origin, reverse
  proxying to the existing internal plain-HTTP services (see
  `docker/nginx/nginx-lan-https.conf.template`):

  | Origin | HTTPS (kronos.local) | Plain-HTTP port (unchanged, still used internally) |
  |---|---|---|
  | SPA + `/api` + `/auth` + `/sse` | `https://kronos.local` (443) | 80 |
  | Keycloak (browser-facing) | `https://kronos.local:8443` | 8080 |
  | MinIO (presigned evidence upload/download) | `https://kronos.local:9444` | 9000 |
  | OpenSearch Dashboards (Timeline tab iframe) | `https://kronos.local:5602` | 5601 |

- The frontend build bakes in `VITE_KEYCLOAK_URL=https://kronos.local:8443`
  (a real build arg, `docker-compose.dev.yml` → `Dockerfile.frontend`) —
  **every** client logs in via this one canonical origin, unconditionally.
  See `frontend/src/keycloak.ts`'s `resolveKeycloakUrl()` for why this
  can't be derived per-client, e.g. a `localhost` special case: Keycloak's
  `KC_HOSTNAME` is a single pinned value for the whole realm, and the
  login form's own POST target always uses it regardless of which origin
  the flow started on. A client starting the flow on a *different* origin
  than `KC_HOSTNAME` loses its session-restart cookie crossing that domain
  boundary — a real bug this pass found and fixed (`poc/tls_lan_https/`),
  not a hypothetical, and the reason a single canonical domain is
  necessary rather than just tidier.

## Changing the domain or its target IP

`KRONOS_LAN_HOST` (default `kronos.local`) drives `tls-init`'s cert SAN,
`keycloak`'s `KC_HOSTNAME`, and the frontend's `VITE_KEYCLOAK_URL` build
arg:

```bash
KRONOS_LAN_HOST=kronos-dev.example docker compose -f docker/docker-compose.dev.yml up -d --build
```

Several other places still hardcode the literal string `kronos.local`
rather than reading `KRONOS_LAN_HOST` — `MINIO_PUBLIC_ENDPOINT`,
`CORS_ALLOWED_ORIGINS`, `OPENSEARCH_DASHBOARDS_URL`, the nginx CSP env
vars, `docker/keycloak/kronos-realm.json`'s client allowlists,
`docker/opensearch-dashboards/opensearch_security_openid.yml`'s
`base_redirect_url`, and `frontend/.env.example`. Update all of these to
match if you change the domain name; this wasn't fully centralized in
this pass. **`docker/keycloak/kronos-realm.json` needs the new value added
by hand** — Keycloak rejects any `redirect_uri` not on its client's
allowlist outright ("Invalid parameter: redirect_uri"), a real bug found
and fixed while testing this against an actual LAN client. After changing
the realm file, Keycloak needs a real restart to pick it up (`KC_DB:
dev-mem` — its dev database is in-memory, imported fresh on every boot),
which also resets the org/Dashboards-tenant state living in that same
in-memory DB:

```bash
docker compose -f docker/docker-compose.dev.yml up -d --force-recreate keycloak
# wait for it to report healthy, then:
docker compose -f docker/docker-compose.dev.yml up -d --force-recreate keycloak-init dashboards-tenant-init
```

To point the domain at a *different IP* without changing the name itself
(e.g. the server's LAN IP changed), just update the DNS/hosts-file mapping
— nothing in the stack's own config needs to change, since it only ever
refers to the hostname, never the IP directly.

## Firewall

If `ufw` is active, LAN clients need these ports open (adjust the subnet
— this is IP/subnet-based, unrelated to the `kronos.local` domain name):

```bash
for p in 80 443 8443 9444 5602; do
  sudo ufw allow from 192.168.5.0/24 to any port $p proto tcp comment 'kronos-dev'
done
```

## Trusting the certificate

The certs are issued by this stack's own `step-ca` — a private CA, not a
publicly trusted one. Without trusting its root, browsers will show a
security warning on `https://kronos.local`, and — more importantly — the
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

3. Reload the page. `https://kronos.local` should show a valid padlock
   with no warning.

## Verifying it yourself

```bash
echo "<server-lan-ip> kronos.local" | sudo tee -a /etc/hosts
docker cp docker-tls-init-1:/certs/root_ca.crt ./root_ca.crt
curl --cacert root_ca.crt https://kronos.local/healthz
curl --cacert root_ca.crt https://kronos.local:8443/realms/kronos/.well-known/openid-configuration
curl -o /dev/null -w '%{http_code}\n' --cacert root_ca.crt https://kronos.local:5602/auth/openid/login
```

All three should succeed with a clean cert chain (no `-k`/insecure flag
needed). See `poc/tls_lan_https/README.md` for a real presigned-upload
verification against MinIO's proxy, and a full real login + evidence
upload + autonomous-ingestion run against `kronos.local`, as well.
