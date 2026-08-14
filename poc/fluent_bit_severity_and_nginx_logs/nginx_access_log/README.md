# PoC: nginx access-log real producer for `nginx_logs` (Gap Audit P1-6)

**Objective.** Prove, against this repo's own already-built dev-stack nginx
image (`docker-nginx:latest`, built from `docker/Dockerfile.frontend` +
`docker/nginx/nginx.conf.template`) and a real `fluent/fluent-bit:3.1`
container, that the real fix (an `access_log` directive writing real JSON
lines to a non-default filename inside the `nginx_logs` volume, plus a
matching fluent-bit `[INPUT]` path change) makes a real HTTP request's
access-log line actually land in fluent-bit's tail input and flow through to
its OUTPUT -- closing the "volume declared, no real producer" gap.

## Versions pinned (real, this pass)

- `docker-nginx:latest` -- this repo's own already-built image for the
  `nginx` service in `docker-compose.dev.yml` (`build: {context: .., 
  dockerfile: docker/Dockerfile.frontend}`), base `FROM nginx:alpine` (the
  exact, currently-pinned tag in that Dockerfile -- not assumed/"latest"
  beyond what the repo itself pins). Reused as-is rather than rebuilt, since
  this fix is `nginx.conf.template`-only (bind-mounted over the image's own
  baked-in template for this test) and no Dockerfile change was needed.
- `fluent/fluent-bit:3.1` -- same pinned tag as the severity PoC (real
  `v3.1.10`, commit `e28f447995`).

## Real, previously-unverified gap found while building this fix

Inspected the real, already-built dev-stack nginx image directly:

```
$ docker run --rm docker-nginx:latest sh -c "ls -la /var/log/nginx/ && id"
lrwxrwxrwx    1 nginx    nginx           11 Jul 15 23:31 access.log -> /dev/stdout
lrwxrwxrwx    1 nginx    nginx           11 Jul 15 23:31 error.log -> /dev/stderr
uid=101(nginx) gid=101(nginx) groups=101(nginx),101(nginx)
```

The official `nginx:alpine` base image ships `access.log`/`error.log` as
symlinks to `/dev/stdout`/`/dev/stderr`. A real, freshly-created, empty
`nginx_logs` named volume mounted at `/var/log/nginx` gets its *initial*
contents copied from the image directory on first use (real, confirmed
Docker behavior, re-verified live below) -- **including those two
symlinks**. Pointing `access_log` at the default `access.log` filename
would therefore silently follow the symlink straight back to stdout, never
producing a real file fluent-bit's `tail` `[INPUT]` could read. Fixed by
writing to a **different** filename, `kronos-access.log`, which sidesteps
the symlink entirely.

**A second real bug was found and fixed while verifying the first fix
end-to-end** (not anticipated from source-reading alone): fluent-bit's own
bundled `/fluent-bit/etc/parsers.conf` `json` PARSER hardcodes `Time_Key
time` + `Time_Format %d/%b/%Y:%H:%M:%S %z` (an Apache/nginx-combined-log
timestamp format). The first draft of `nginx.conf.template`'s JSON
`log_format` used a field named `"time"` (matching `$time_iso8601`), which
collided with that hardcoded `Time_Key` and produced a real, captured
`[warn] [parser:json] invalid time format ... for '2026-...'` on every
record. Fixed by renaming the field to `"timestamp"` -- which also happens
to match the field name this repo's own `kronos.backend`/`kronos.celery`
structlog-based sources already use (`structlog.processors.TimeStamper`'s
own default key), keeping the JSON shape coherent across all `kronos.*`
sources.

## Real bundled fluent-bit parsers confirmed (not guessed)

`docker create` + `docker cp` (no shell/`cat` in the distroless-like
fluent-bit image) of the real `/fluent-bit/etc/parsers.conf`: confirmed a
real bundled regex `nginx` parser exists (matching the *default* nginx
"combined" log format) alongside the `json` parser. **Not used** here:
`docker/fluent-bit/fluent-bit.conf`'s own pre-existing `kronos.nginx`
`[INPUT]` block already declared `Parser json` (anticipated, never fed,
since Milestone S) -- matching that with a real JSON `access_log` format
keeps the whole pipeline coherent instead of also having to change
fluent-bit's own parser choice.

## Real end-to-end run

1. Real named Docker volume `kronos-poc-nginx-logs` created fresh.
2. Real `docker-nginx:latest` container run with the fixed
   `docker/nginx/nginx.conf.template` bind-mounted over the image's own
   baked-in template, the fresh volume mounted at `/var/log/nginx`, and a
   throwaway self-signed cert (`openssl req -x509 ...`) mounted at
   `/etc/kronos/tls` (needed only because this image also bakes in
   `nginx-lan-https.conf.template`, an unrelated LAN-HTTPS template that
   requires cert files to exist for nginx to start at all -- not part of
   this fix, worked around for this PoC only).
3. Real `curl` request against the container's published port.
4. Real content of `/var/log/nginx/kronos-access.log` inspected directly
   inside the running container.
5. A real `fluent/fluent-bit:3.1` container (this repo's own,
   unmodified, real `docker/fluent-bit/fluent-bit.conf`) started against
   the **same** named volume (read-only), tailing
   `/var/log/nginx/kronos-access.log`.
6. A second real `curl` request generated while fluent-bit was already
   running and watching (genuine live-tail, not pre-seeded backfill).
7. fluent-bit's own `stdout` `[OUTPUT]` inspected for the real forwarded
   record.

### Step 2: real volume-copy-of-symlinks behavior confirmed live

```
$ docker exec kronos-poc-nginx-fixed ls -la /var/log/nginx/
-rw-r--r--    1 nginx    nginx         281 Aug 14 14:05 kronos-access.log
-rw-r--r--    1 nginx    nginx           0 Aug 14 14:05 kronos-error.log
lrwxrwxrwx    1 nginx    nginx          11 Jul 15 23:31 access.log -> /dev/stdout
lrwxrwxrwx    1 nginx    nginx          11 Jul 15 23:31 error.log -> /dev/stderr
```

Confirms both halves of the finding: the symlinks really were copied into
the fresh volume (`access.log`/`error.log` still point at `/dev/stdout`/
`/dev/stderr`), AND the new filename really did create a genuine regular
file, owned by uid 101 (`nginx`, this image's own non-root `USER`),
writable -- no permission workaround needed.

### Step 3-4: real HTTP request -> real JSON access-log line

```
$ curl -s -o /dev/null -w "HTTP status: %{http_code}\n" \
    "http://localhost:18080/some-poc-test-path?x=1"
HTTP status: 200

$ docker exec kronos-poc-nginx-fixed cat /var/log/nginx/kronos-access.log
{"time":"2026-08-14T14:05:21+00:00","remote_addr":"172.25.2.1","request_method":"GET","request_uri":"/some-poc-test-path?x=1","server_protocol":"HTTP/1.1","status":200,"body_bytes_sent":3056,"request_time":0.000,"http_referer":"","http_user_agent":"curl/8.18.0","service":"nginx"}
```

(this capture is from the FIRST draft, before the `"time"` -> `"timestamp"`
rename -- kept here as the honest record of the field-name bug being found;
see below for the field-renamed, fully-fixed capture)

Also confirmed (separately, not shown) that a real request to `/nginx-health`
(this file's own dedicated Kubernetes-probe location, `access_log off;`)
correctly produced **no** line in `kronos-access.log` -- the explicit
per-location override still works as designed.

### Steps 5-7: real fluent-bit tail -> parse -> stdout, field-name bug found and fixed live

**First attempt (the `"time"` field collision, real bug found):**

```
$ curl ... "http://localhost:18080/poc/fluent-bit-e2e-check?evidence=v8"
HTTP status: 200

$ docker logs kronos-poc-fb-nginx
[2026/08/14 14:06:14] [ info] [input:tail:tail.3] inotify_fs_add(): inode=1179959 watch_fd=1 name=/var/log/nginx/kronos-access.log
[2026/08/14 14:06:24] [error] [parser] cannot parse '2026-08-14T14:06:24+00:00'
[2026/08/14 14:06:24] [ warn] [parser:json] invalid time format %d/%b/%Y:%H:%M:%S %z for '2026-08-14T14:06:24+00:00'
```

**After the real fix (`nginx.conf.template`'s JSON field renamed `"time"` ->
`"timestamp"`, fresh volume, fresh nginx + fluent-bit containers):**

```
$ curl -s -o /dev/null -w "HTTP status: %{http_code}\n" \
    "http://localhost:18080/poc/v8-fixed-check?evidence=v8-after"
HTTP status: 200

$ docker logs kronos-poc-fb-nginx
[2026/08/14 14:07:13] [ info] [output:syslog:syslog.2] setup done for wazuh-manager:514 (TLS=off)
[2026/08/14 14:07:13] [ info] [output:stdout:stdout.3] worker #0 started
[2026/08/14 14:07:13] [ info] [http_server] listen iface=0.0.0.0 tcp_port=2020
[2026/08/14 14:07:13] [ info] [sp] stream processor started
[2026/08/14 14:07:13] [ info] [input:tail:tail.3] inotify_fs_add(): inode=1179697 watch_fd=1 name=/var/log/nginx/kronos-access.log
{"date":1786716440.386071,"timestamp":"2026-08-14T14:07:20+00:00","remote_addr":"172.25.2.1","request_method":"GET","request_uri":"/poc/v8-fixed-check?evidence=v8-after","server_protocol":"HTTP/1.1","status":200,"body_bytes_sent":3056,"request_time":0.0,"http_referer":"","http_user_agent":"curl/8.18.0","service":"nginx","cluster":"poc","env":"poc"}
```

**Zero `[warn]`/`[error]` lines.** The real access-log record for the real
`curl` request landed in fluent-bit's real `stdout` OUTPUT, correctly
JSON-parsed, with the `record_modifier` FILTER's `cluster`/`env` fields
correctly appended (proving the record really did flow through the same
`kronos.*`-matched FILTER chain every other KronOS log source uses, not a
bypassed path) -- full pipeline confirmed: real HTTP request -> real nginx
JSON access log -> real shared volume -> real fluent-bit `tail` [INPUT] ->
real `json` PARSER -> real `record_modifier` FILTER -> real `stdout`
OUTPUT.

## Real containers/volumes/networks created (all `kronos-poc-*`, torn down after)

- `kronos-poc-nginx-net` -- dedicated bridge network.
- `kronos-poc-nginx-backend-stub` -- a plain `nginx:alpine` container given
  network aliases (`kronos-backend`, `keycloak`, `minio`,
  `opensearch-dashboards`, `wazuh-manager`, `opensearch`) purely so the real
  `nginx.conf.template`'s `upstream {}` block and the real, unrelated,
  also-baked-in `nginx-lan-https.conf.template` can resolve their proxy
  targets at config-load time without failing to start -- no traffic is
  ever actually proxied to it in this PoC (only `/`, `/nginx-health`, and
  the SPA-fallback paths under `/poc/...` are exercised, none of which
  `proxy_pass` anywhere).
- `kronos-poc-nginx-fixed` -- the real nginx container under test.
- `kronos-poc-fb-nginx` -- the real, unmodified
  `docker/fluent-bit/fluent-bit.conf`, run against the same volume.
- `kronos-poc-nginx-logs` (named volume, recreated fresh between the two
  fluent-bit attempts to prove the fix from a clean state).

Confirmed via `docker ps -a` / `docker volume ls` / `docker network ls`
after teardown that none remain (the only stray `kronos-poc-*` volume found,
`kronos-poc-clamav-sizetest-data`, predates this session and was not
created or touched by this PoC).

## How to reproduce

```bash
docker volume create kronos-poc-nginx-logs
docker network create kronos-poc-nginx-net
docker run -d --name kronos-poc-nginx-backend-stub --network kronos-poc-nginx-net \
  --network-alias kronos-backend --network-alias keycloak --network-alias minio \
  --network-alias opensearch-dashboards --network-alias wazuh-manager --network-alias opensearch \
  nginx:alpine

mkdir -p /tmp/kronos-poc-nginx-tls
openssl req -x509 -newkey rsa:2048 -keyout /tmp/kronos-poc-nginx-tls/server.key \
  -out /tmp/kronos-poc-nginx-tls/server.crt -days 1 -nodes -subj "/CN=kronos-poc"
chmod 644 /tmp/kronos-poc-nginx-tls/server.key /tmp/kronos-poc-nginx-tls/server.crt

docker run -d --name kronos-poc-nginx-fixed --network kronos-poc-nginx-net \
  -v <repo>/docker/nginx/nginx.conf.template:/etc/nginx/templates/default.conf.template:ro \
  -v kronos-poc-nginx-logs:/var/log/nginx \
  -v /tmp/kronos-poc-nginx-tls:/etc/kronos/tls:ro \
  -p 18080:80 docker-nginx:latest

curl http://localhost:18080/some-real-path

docker run -d --name kronos-poc-fb-nginx --network kronos-poc-nginx-net \
  -v <repo>/docker/fluent-bit/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro \
  -v kronos-poc-nginx-logs:/var/log/nginx:ro \
  -e KRONOS_CLUSTER=poc -e KRONOS_ENV=poc \
  -e OPENSEARCH_HOST=opensearch -e OPENSEARCH_PORT=9200 \
  -e OPENSEARCH_USERNAME=admin -e OPENSEARCH_PASSWORD=admin -e WAZUH_HOST=wazuh-manager \
  fluent/fluent-bit:3.1

curl http://localhost:18080/another-real-path
docker logs kronos-poc-fb-nginx   # observe the real forwarded record

docker rm -f kronos-poc-nginx-fixed kronos-poc-fb-nginx kronos-poc-nginx-backend-stub
docker volume rm kronos-poc-nginx-logs
docker network rm kronos-poc-nginx-net
```

## What was NOT verified here

- **Real `docker-compose.dev.yml` full-stack `up`.** This PoC uses the
  already-built `docker-nginx:latest` image with the fixed template
  bind-mounted, plus a real fluent-bit container, in an isolated throwaway
  network -- not a real `docker compose -f docker-compose.dev.yml -f
  docker/fluent-bit/docker-compose.fluent-bit.yml up` of the shared dev
  stack (per this task's own instruction to prefer a fully separate
  throwaway stack over restarting shared services when it proves the fix
  equally well). `docker compose config` validation of both the standalone
  and multi-file-merged real compose files IS covered (see the top-level
  PoC directory's parent task report) -- confirms the wiring is
  syntactically and volume-naming correct, but a live `docker compose up`
  of the real named services was not additionally run beyond this
  equivalent throwaway proof.
- **OpenSearch/Wazuh delivery for `kronos.nginx` records.** Neither OUTPUT
  currently matches the `kronos.nginx` tag (only `kronos.backend`/
  `kronos.falco` for OpenSearch; the syslog OUTPUT matches `kronos.*` and
  was real-verified for delivery mechanics by the sibling `severity/` PoC,
  not re-verified here for nginx-shaped records specifically) -- this
  matches the existing, unchanged wiring; adding a dedicated OpenSearch
  index for nginx access logs was not part of this item's scope.
