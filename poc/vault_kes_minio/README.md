# PoC: Vault Transit -> KES -> MinIO SSE-KMS

Per CLAUDE.md Section F ("Verification-First Integration Work"): this PoC
actually runs the chain described by `docker/vault/docker-compose.vault.yml`,
`docker/kes/docker-compose.kes.yml`, `docker/kes/kes-config.yml`, and
roadmap.md's "Prompt 5.2" against the real pinned images, rather than
inspecting the config files and assuming they're correct.

## Pinned versions (read from the repo)

- `hashicorp/vault:1.17` — `docker/vault/docker-compose.vault.yml`
- `minio/kes:2024-06-17T15-47-05Z` — `docker/kes/docker-compose.kes.yml`
- `minio/minio:latest` — `docker/docker-compose.dev.yml` (resolved to
  `RELEASE.2025-09-07T16-13-09Z` at run time)
- `minio/mc:latest` — not pinned anywhere in the repo; used only as a PoC
  test client, not part of the production stack.

## Bottom line

**The chain works end-to-end** — Vault Transit holds the master key, KES
bridges it to MinIO, MinIO applies real SSE-KMS, objects are genuinely
unreadable on disk and transparently decrypted on GET — **but only after
fixing five concrete bugs** in the repo's existing config that would have
made a naive `docker compose up` of the documented stack fail immediately.
None of these were visible from reading the files; all five were found by
actually running the containers and reading real error messages /
upstream source for the pinned versions.

## Gaps found (all fixed in this PoC's own copies — production files under
`docker/` were left untouched, per the task brief, since some of these need
a human decision about how to wire the fix in permanently)

1. **`docker/kes/kes-config.yml` uses the wrong schema for the pinned KES
   tag.** It has `keystore.vault.transit.engine_path` / `key_name` /
   `approle.retry`. The real schema for `2024-06-17T15-47-05Z`
   (confirmed against `server-config.yaml` in the `minio/kes` repo at that
   tag) is `transit.engine` / `transit.key`, and — more importantly — KES's
   Vault keystore in this version is fundamentally a **K/V-backed**
   keystore (`engine`, `version`, `prefix` fields select the K/V mount),
   with Transit used only as an *optional* wrap-at-rest layer for entries
   stored in that K/V engine. The repo's config (and its own comments, and
   roadmap.md's Prompt 5.2 framing) describe Transit as if it were the
   primary/only KMS backend KES talks to — that is not how this KES
   version's Vault integration is actually built. Fixed in
   `kes-config.yml` here by adding `engine: kv`, `version: v1`,
   `prefix: kes-keys` alongside a corrected `transit: {engine, key}` block.
   With the original repo config, KES fails to even start:
   `Error: kesconf: invalid vault keystore: invalid transit config: no key name specified`.

2. **Vault policy in `docker/vault/docker-compose.vault.yml`'s
   `vault-init` only grants `transit/*` paths.** KES's real keystore
   backend (see #1) also needs CRUD on the K/V path it stores wrapped
   entries under (`kv/kes-keys/*` here). Without this, KES's `/v1/status`
   answers fine (that only needs the identity/policy to exist) but any
   real key operation against the keystore backend fails authorization.
   Confirmed by extending the policy at runtime and watching key
   create/generate start working immediately after.

3. **Nothing in the repo hands the AppRole `role_id`/`secret_id` from
   `vault-init` to KES.** `vault-init` runs `vault write auth/approle/role/kronos-kes ...`
   which creates the *role*, but role-id and a freshly generated secret-id
   still have to be fetched (`GET .../role-id`, `POST .../secret-id`) and
   injected as `VAULT_APPROLE_ID`/`VAULT_APPROLE_SECRET` before KES can
   authenticate — `docker/kes/docker-compose.kes.yml` declares those env
   vars but defaults them to empty strings and nothing else in the repo
   populates them. This PoC's `run_poc.sh` does that fetch-and-export step
   by hand; the repo has no automated equivalent (e.g. a small
   `vault-init`-adjacent script that writes an `.env` file or a Docker
   secret) today.

4. **`docker/kes/kes-config.yml`'s own comment about the identity
   fingerprint is wrong for this KES version.** It says: `# MinIO's mTLS
   certificate identity (SHA-256 of cert)`. The real computation
   (`auth.go`, function `identifyRequest`, tag `2024-06-17T15-47-05Z`) is
   `sha256(cert.RawSubjectPublicKeyInfo)` — SHA-256 of the certificate's
   **public key info**, not the whole DER certificate. Using
   `openssl x509 -outform DER | sha256sum` (what the comment implies)
   gives a different, wrong value and the identity never matches, so KES
   returns `403 not authorized: insufficient permissions` even with a
   perfectly valid mTLS handshake. The only reliable way to get the right
   value is the KES image's own `kes identity of <cert>` command, which
   this PoC uses.

5. **`MINIO_KMS_KES_CA_PATH` (the name roadmap.md's Prompt 5.2 deliverable
   list literally specifies) is not a real MinIO env var.** Extracting
   strings from the actual `minio/minio:latest` binary shows the real name
   is `MINIO_KMS_KES_CAPATH` (no underscore before `CAPATH`). Using the
   name from the roadmap causes MinIO to silently ignore the CA and fail
   TLS verification against KES's self-issued server cert:
   `x509: certificate signed by unknown authority`.

## Separately confirmed, not a bug

- **`docker/docker-compose.dev.yml`'s `minio` service has zero
  `MINIO_KMS_KES_*` wiring today.** Confirmed by reading the file in
  full: it sets only `MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD`/
  `MINIO_API_CORS_ALLOW_ORIGIN`. `docker/docker-compose.prod.yml` sets
  `MINIO_KMS_SECRET_KEY`, which is MinIO's older single-static-key KMS
  mechanism, not KES-backed SSE-KMS — it is not equivalent to what
  roadmap.md's Prompt 5.2 asks for. As of this run, **nothing in the repo
  actually turns SSE-KMS on for the dev or prod MinIO service** — this PoC
  is the only place that wiring exists, and it exists only as a reference
  example (`docker-compose.poc.yml`), not a change to the real compose
  files.
- `mc admin kms key list` is denied for MinIO's own KES identity
  (`not authorized: insufficient permissions`) — this is **correct**,
  least-privilege behavior: the policy in `kes-config.yml` only grants
  MinIO what it actually needs (`create`/`generate`/`decrypt`/
  `bulk/decrypt`/`status`), not `list`. Not a gap.
- No usable in-container healthcheck exists for the `kes` image (no
  curl/wget, and `kes status` demands a pre-provisioned
  `MINIO_KES_API_KEY` the CLI auth path doesn't easily support without
  more setup) — minor, worked around with `depends_on: condition:
  service_started` instead of `service_healthy` in this PoC compose.

## What was actually run (see `output.txt` for full captured transcript)

1. `hashicorp/vault:1.17` dev-mode container, real `vault-init` script
   (copied verbatim from `docker/vault/docker-compose.vault.yml`) — enables
   Transit, creates `kronos-evidence` AES256-GCM96 key, writes the
   `kronos-kes` policy, enables AppRole, creates the `kronos-kes` role.
2. Manually fetched AppRole role-id/secret-id (gap #3) and extended the
   Vault policy with `kv/kes-keys/*` (gap #2).
3. Generated a real 2-tier TLS PKI (`certs/ca.crt` signs both
   `kes-server.crt` and `minio-client.crt`) — a self-signed leaf used
   directly as its own CA was tried first and produced a confusing "tls:
   client certificate is required" error from KES's app layer despite a
   TLS handshake that curl reported as successful; a genuine CA-signs-leaf
   chain is what actually works reliably.
4. `minio/kes:2024-06-17T15-47-05Z` with a corrected `kes-config.yml`
   (gap #1) and the correct client identity (gap #4, computed via
   `kes identity of`). Verified directly with mTLS `curl`:
   `/v1/status` → 200, `/v1/key/create/kronos-evidence` → 200,
   `/v1/key/generate/kronos-evidence` → 200 with real
   plaintext/ciphertext DEK pair. Confirmed via Vault's own API that the
   K/V entry KES wrote is itself a `vault:v1:...` Transit ciphertext — the
   master key genuinely never left Vault in plaintext.
5. `minio/minio:latest` with `MINIO_KMS_KES_ENDPOINT`,
   `MINIO_KMS_KES_KEY_NAME`, `MINIO_KMS_KES_CERT_FILE`,
   `MINIO_KMS_KES_KEY_FILE`, `MINIO_KMS_KES_CAPATH` (gap #5) pointed at
   KES. Clean boot, `mc admin kms key status` → Encryption ✔ Decryption ✔.
6. `mc mb` + `mc encrypt set sse-kms kronos-evidence` on a real bucket.
7. Uploaded a real object containing a unique plaintext canary string.
   Confirmed:
   - `mc stat` reports `Encryption: SSE-KMS (arn:aws:kms:kronos-evidence)`.
   - Real raw HTTP response headers (`mc --debug`) show
     `X-Amz-Server-Side-Encryption: aws:kms` and
     `X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id: arn:aws:kms:kronos-evidence`.
   - `mc cat` (S3 GET) returns the correct plaintext — transparent
     decryption confirmed.
   - `grep` for the canary string across the entire MinIO data volume on
     disk (`data/`) finds **no match** — the object's `xl.meta` (it was
     stored inline, being small) contains an IV, a KMS-sealed data key,
     and the `kronos-evidence` key ID instead of plaintext.

## How to run

```
cd poc/vault_kes_minio
bash run_poc.sh
```

This brings the whole chain up from scratch, fetches AppRole credentials,
runs the KMS/bucket/object test, dumps the on-disk proof, and leaves the
containers running for inspection. Tear down with:

```
docker compose -p kronos-poc-vaultkes -f docker-compose.poc.yml down -v
docker rm -f kronos-poc-vaultkes-mc kronos-poc-vaultkes-tmp 2>/dev/null
```

## Files

- `docker-compose.poc.yml` — vault/vault-init/kes/minio, isolated
  container names/ports (`18200`, `17373`, `29100`/`29101`) and its own
  Docker network, so it doesn't collide with the real dev stack or other
  agents' PoCs.
- `kes-config.yml` — **corrected** copy of `docker/kes/kes-config.yml`
  (see gaps #1 and #4 above for the diffs from the original).
- `certs/` — throwaway CA + KES server cert + MinIO client cert generated
  for this run (3-day validity; regenerate via `run_poc.sh` — do not treat
  as reusable secrets).
- `run_poc.sh` — end-to-end driver: brings up Vault, runs vault-init,
  fetches AppRole creds, brings up KES and MinIO, creates the bucket,
  uploads/verifies the test object, checks the raw disk bytes.
- `output.txt` — full captured transcript from the actual run described
  above.
