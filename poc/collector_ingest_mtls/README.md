# D2 · Collector ingest API + mTLS identity

L2 PoC: two real components genuinely linked — a real step-ca-issued client
certificate authenticates a collector, the verified identity (never the
request payload) determines `org_id`/`source_id`, and the event lands on
D1's real Redis Streams transport, with real backpressure and dedup.

## Versions pinned (re-verified against the real running stack)

- step-ca: `smallstep/step-ca:0.26.0` image (`docker/pki/docker-compose.pki.yml`);
  the real running container's CLI reports `Smallstep CLI/0.30.2`.
- **Real finding**: only an **`admin` JWK provisioner** actually exists on
  the live container. `docker/pki/bootstrap.sh`'s `kronos-sa`/ACME
  provisioner-add commands are not present on the running instance (their
  `|| true` swallows any failure silently). This matches the already-real,
  working pattern `docker/init/tls-init-entrypoint.sh` established for
  issuing the LAN HTTPS leaf cert — this PoC reuses that exact same,
  already-proven `admin` provisioner rather than trusting the unwired
  bootstrap script's assumption.
- Redis 7.4.9 via D1's already-verified `RedisStreamIngestAdapter`.
- httpx 0.28.1 / httpcore 1.0.9 (see the real, load-bearing finding below).

## Run

```
source ~/venv/bin/activate
python poc/collector_ingest_mtls/run_poc.py
```

Requires: the real dev stack up (Redis reachable on `localhost:6379`), the
real `docker-step-ca-1` container running, `openssl` on PATH (for the
untrusted-cert negative test), and Docker CLI access (`docker exec`/`docker cp`
against the step-ca container only — no other container is touched).

## Result: 17/17 checks passed (see `output.txt` for the full real run)

## Real finding #1 (significant): httpx 0.28.1's `cert=`/`verify=` combo silently fails this exact real mTLS handshake

Every `httpx` request using the convenience `cert=(crt_path, key_path)` +
`verify=<ca_path_string>` parameters failed on the very first attempt with
`[SSL: UNEXPECTED_EOF_WHILE_READING]` — **100% reproducible**, not a
flake. Before assuming this repo's own mTLS code was broken, it was
isolated with real, independent tools against the exact same running
listener and exact same cert files:

- `curl --cert collector-a.crt --key collector-a.key --cacert root_ca.crt` — **succeeds**, real `202 Accepted`.
- `openssl s_client -cert ... -key ... -CAfile ...` — **succeeds**, full TLS 1.3 handshake, `Verification: OK`.
- A plain Python script constructing an explicit `ssl.SSLContext` via
  `ssl.create_default_context(cafile=...)` + `ctx.load_cert_chain(cert, key)`,
  passed to httpx as `verify=<ctx>` — **succeeds**, real `202 Accepted`.
- The identical `cert=`/`verify=<path>` tuple form — **fails**, every time.

This conclusively isolates the issue to httpx's own certificate-loading
path for this parameter combination (TLS 1.3, EC P-256 client cert), not
to anything in `src/external/mtls_protocol.py`, `collector_mtls.py`, or
the real uvicorn/step-ca setup — all independently proven correct via
curl/openssl first. **Fix**: this PoC (and any future real client of this
API) must construct an explicit `ssl.SSLContext` and pass it as `verify=`,
never the `cert=`/`verify=<path>` tuple shortcut, for this exact library
version.

## Real finding #2: uvicorn 0.51.0 has no ASGI TLS extension

Documented in full in `src/external/mtls_protocol.py`'s own docstring
(grepped uvicorn's real installed source tree for `client_cert`/`ssl_object`/
`tls` — none of the HTTP protocol implementations reference them).
`ssl_cert_reqs=CERT_REQUIRED` + `ssl_ca_certs=...` on `uvicorn.Config` does
real, correct TLS-handshake-level enforcement (confirmed: no cert, or an
untrusted cert, resets the connection before a single HTTP byte is
processed — Part 5/6 below), but the verified peer certificate itself is
discarded afterward. `MTLSIdentityH11Protocol` recovers it via the
asyncio SSL transport's own `get_extra_info("ssl_object")` — real,
standard-library functionality, not an uvicorn feature.

## What each part of the real run proves

- **Part 0**: two real, distinct client certs issued from the live
  step-ca for two different real org UUIDs, via the real `admin`
  provisioner and a real URI SAN
  (`urn:kronos:collector:org:<uuid>:source:<name>`).
- **Part 1**: the real mTLS listener (`src/external/run_dual_listener.py`)
  starts as a real subprocess and accepts real TLS connections.
- **Part 2/3**: a real request from each collector's real cert is
  accepted (202), each deriving its own real, distinct `org_id` — never
  passed in the request body (the DTO, `IngestEventsIn`, has no
  `org_id`/`source_id` field at all).
- **Part 4**: an event payload that embeds a fake `org_id` (org B's) is
  still accepted (the schema doesn't reject arbitrary payload content —
  events are free-form `dict[str, Any]`), but real inspection of Redis
  confirms it landed under collector A's REAL cert-derived key, and org
  B's real stream was completely untouched — structural isolation, not
  app-layer filtering that could be bypassed by a different payload shape.
- **Part 5/6**: a request with no client certificate, and a request with
  a real-but-untrusted (self-signed, not step-ca-issued) certificate, are
  both rejected at the TLS handshake layer itself — confirmed via the
  real, distinct low-level errors each produces (`UNEXPECTED_EOF_WHILE_READING`
  for no cert, `Connection reset by peer` for an untrusted cert).
- **Part 7**: an identical event submitted twice (simulating a collector
  retry after a network blip) is only produced once — confirmed by
  reading the real Redis stream directly, not just trusting the second
  response's `duplicate: true` flag.
- **Part 8**: a real, enforced `COLLECTOR_MAX_STREAM_LENGTH=3` (set
  deliberately tiny for this test) is hit after 3 real events land, and
  the next real request gets a genuine `503` — not a description of what
  the code *should* do.

## Scope note: standalone listener, not yet wired into docker-compose

`src/external/run_dual_listener.py` is real, working, and started as a
real subprocess here — but it is not yet added as a service in
`docker/docker-compose.dev.yml`. Per this item's L2 scope (prove the
mechanism, two real components genuinely linked), production deployment
wiring (a new compose service/port, or folding into the existing
`kronos-backend` container as a second listener) is real follow-up work,
not attempted here to avoid unplanned scope creep on top of this item —
consistent with this session's established pattern for flagging
deployment-wiring gaps rather than silently deferring them (e.g. B3's
`kronos-stream-aggressive` tier, C2's kronos-dev legacy-index gap).

## What was NOT verified

- Real collector cert *provisioning tooling* (automated per-org/source
  cert issuance as part of onboarding a new collector) — this PoC issues
  certs by hand via `docker exec step ca certificate`, which is fine for
  proving the mechanism but not a real operational workflow; flagged as
  real follow-up, matching `collector_mtls.py`'s own docstring.
- Cert revocation/rotation — the 24h step-ca leaf cert TTL and its
  operational friction are already documented elsewhere in this repo;
  this item doesn't add new revocation handling beyond what step-ca
  itself provides.
