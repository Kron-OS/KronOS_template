# KronOS — Security & Deployment Audit

**Date:** 2026-06-26
**Branch:** `claude/security-audit-deployment-w3b39o`
**Scope:** Configuration files, application code (intake, parsing, auth, audit,
storage), and third-party tool configuration (NGINX, Keycloak, MinIO/KES/Vault,
OpenSearch, Docker, step-ca). Backend tooling: `~/venv` (Python 3.11), 367
existing unit tests pass at 82 % coverage.

This document records findings only. No production behaviour was changed by the
audit; the accompanying tests are executable bug-reports (`xfail`) so the suite
stays green while each defect is tracked. Severity uses
**Critical / High / Medium / Low**.

---

## Summary table

| ID  | Severity | Area | Finding |
|-----|----------|------|---------|
| C-1 | Critical | Storage | `S3EvidenceStorage` always reads from the quarantine bucket; promoted evidence is unreadable → parsing breaks in prod |
| C-2 | Critical | Storage/Infra | App bucket names ≠ `provision_buckets.sh` bucket names; no prefix value reconciles them |
| H-1 | High | NGINX | `upstream backend` points at host `backend`, but the compose service is `kronos-backend` → 502 on all `/api` and `/auth` |
| H-2 | High | Docker | Deps installed to `/root/.local`, then `USER kronos` runs with no access (root home is `0700`) → container can't start |
| H-3 | High | Keycloak/Auth | `organization` is an *optional* client scope and the SPA never requests it, but the backend hard-requires the claim → every request 401s |
| M-1 | Medium | Audit | `delete_evidence` hard-codes `step_up_verified: True` in the immutable audit log regardless of actual verification |
| M-2 | Medium | Intake | File-size limit is only checked against client-claimed size; real uploaded size is never enforced → size/DoS bypass |
| M-3 | Medium | Keycloak/Auth | No `acr`→LoA mapping; tokens can't carry `acr=aal2`, so step-up-gated deletion is unsatisfiable |
| M-4 | Medium | Auth/Scale | Step-up tickets + JWKS cache are per-process; with `--workers 2` / multiple pods they don't share → intermittent 401 |
| M-5 | Medium | Docker | Production image installs `.[dev]` (pytest, mypy, ruff…) → bloat + attack surface |
| L-1 | Low | NGINX | CSP allows `script-src 'unsafe-inline'` → weakens XSS defence |
| L-2 | Low | NGINX | Only the plain-HTTP `:80` server is active; the TLS 1.3 block is commented out (HSTS on HTTP is ignored) |
| L-3 | Low | Keycloak | Dev user passwords violate the realm `passwordPolicy length(12)` |
| L-4 | Low | Secrets | Committed client secret + `changeme_in_production` placeholders; must be rotated/overridden in prod |
| L-5 | Low | Crypto | Merkle tree lacks leaf/branch domain separation and duplicates the last odd node (CVE-2012-2459 class) |
| L-6 | Low | Infra | Dev NGINX mounts only `nginx.conf`, not the built SPA → `/` 404 in dev |

---

## Critical

### C-1 — Promoted evidence can never be read (`src/adapter/storage/s3.py`)

`stream_object()` and `object_exists()` derive the bucket via `_bucket_for_key()`,
which **always** returns the quarantine bucket:

```python
def _bucket_for_key(self, key: str) -> str:
    org_alias = key.split("/")[0]
    return self._quarantine_bucket(org_alias)   # never the evidence bucket
```

Quarantine and evidence object keys are produced identically by `_object_key()`,
so the key alone is ambiguous and the function cannot distinguish them. After
`finalize_upload` promotes the object to the WORM evidence bucket and **deletes
it from quarantine**, parsing calls `stream_object(evidence_key)` — which looks
in the now-empty quarantine bucket and raises `StorageError: Object not found`.

The whole parse pipeline (`ParsingOrchestrationService.start_parsing` /
`execute_parse` / `_detect_parser`) is therefore broken on the real S3 backend.
It is masked in CI because `LocalEvidenceStorage.stream_object` searches *both*
buckets.

**Impact:** No evidence can be parsed/indexed in any real deployment.
**Fix:** Make the storage API bucket-aware, e.g. add an explicit
`bucket: Literal["quarantine","evidence"]` argument (or separate
`stream_quarantine`/`stream_evidence` methods), and have callers pass the bucket
they mean. Encode the bucket in the key prefix if a single method must remain.
**Test:** `tests/unit/adapter/test_s3_storage_bugs.py::test_evidence_key_must_resolve_to_evidence_bucket`

### C-2 — Bucket names don't match the provisioning script

`scripts/provision_buckets.sh` creates:

```
kronos-<org>-quarantine
kronos-<org>-evidence
```

`S3EvidenceStorage` computes:

```python
def _quarantine_bucket(self, org): return f"{q_prefix}-{org}-quarantine"
def _evidence_bucket(self, org):   return f"{e_prefix}-{org}"   # no -evidence suffix
```

With the documented default config (`minio_quarantine_bucket_prefix ==
minio_evidence_bucket_prefix == "kronos-evidence"`) the app looks for
`kronos-evidence-<org>-quarantine` and `kronos-evidence-<org>` — **neither
exists**. And no single prefix can fix both: the evidence helper omits the
`-evidence` suffix entirely, so it can never produce `kronos-<org>-evidence`.

**Impact:** A freshly provisioned deployment can't find its buckets; uploads and
promotion fail.
**Fix:** Make the naming convention authoritative in one place and have both the
script and `S3EvidenceStorage` derive from it. Add the `-evidence` suffix to
`_evidence_bucket` and set the default prefix to `kronos`.
**Tests:** `test_default_config_prefix_matches_provisioned_buckets`,
`test_no_prefix_value_can_align_both_bucket_names`

---

## High

### H-1 — NGINX upstream name mismatch (`docker/nginx/nginx.conf`)

```nginx
upstream backend { server backend:8000; }
```

The dev compose service is named `kronos-backend` with **no** `networks.aliases`
entry, so Docker DNS cannot resolve `backend`. Every `/api/*`, `/auth/*`,
`/api/sse/*`, and `/healthz` request returns **502 Bad Gateway**.
**Fix:** point the upstream at `kronos-backend:8000`, or add a network alias
`backend` to the service.

### H-2 — Runtime image can't reach its dependencies (`docker/Dockerfile`)

```dockerfile
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
RUN useradd -r -s /bin/false kronos
USER kronos
CMD ["uvicorn", ...]
```

`pip install --user` as root writes to `/root/.local`; `/root` is mode `0700`,
so the unprivileged `kronos` user cannot traverse it. `uvicorn` (and all Python
packages) are unreachable → the container fails at start. Also `useradd -s
/bin/false` blocks `make shell-backend`.
**Fix:** install into a venv under a world-readable path (e.g. `/opt/venv`) owned
by `kronos`, or `pip install` as the `kronos` user; `chown` the dependency tree.

### H-3 — `organization` claim required but never issued (Keycloak + SPA)

`_extract_tenant()` raises `AuthenticationError("JWT is missing the
'organization' claim")` when the claim is absent. But in `kronos-realm.json` the
`organization` client scope is in **`defaultOptionalClientScopes`**, and
`frontend/src/keycloak.ts` calls `keycloak.init(...)` / `login()` without
requesting `scope=organization`. Result: SPA access tokens omit the claim and
**every authenticated API call 401s**.
**Fix:** move `organization` into `defaultDefaultClientScopes`, or have the SPA
request the scope explicitly (`login({ scope: 'organization' })` and the silent
refresh). Add an integration test that asserts the minted token carries
`organization`.

---

## Medium

### M-1 — Fabricated step-up assertion in the audit log (`evidence_intake.py`)

`delete_evidence()` writes `details={"step_up_verified": True}` unconditionally.
The service performs no verification and takes no parameter describing it; step-up
is enforced only at the route. Any non-HTTP caller (future endpoint, Celery task,
script) still emits an audit record asserting verification that never happened —
a chain-of-custody integrity defect for a legally-admissible log.
**Fix:** pass the actual verification outcome (e.g. the consumed ticket id /
boolean) into the service and record *that*; don't hard-code `True`.
**Tests:** `tests/unit/application/test_delete_evidence_audit_integrity.py`

### M-2 — Upload size limit is advisory only (`validation.py` + `evidence_intake.py`)

`FileSizeValidator` checks `evidence.metadata.size_bytes`, i.e. the value the
**client claimed** in `POST /upload/request`. The presigned PUT carries no
`content-length-range` condition, and `finalize_upload` streams the object for
scan/hash without enforcing a byte cap. A client can declare `size_bytes: 1` and
upload an arbitrarily large file, defeating `max_upload_bytes`.
**Fix:** add a MinIO presigned POST policy with `content-length-range`, and/or
enforce a hard byte ceiling while streaming during hash, aborting on overflow.

### M-3 — Step-up (`aal2`) is unreachable (Keycloak realm)

The realm defines no `acr`→LoA mapping (`acr.loa.map`) and no MFA-bearing
authentication flow, so Keycloak won't emit `acr=aal2`. `StepUpAuth.assert_acr`
requires `aal2`, so `DELETE /api/evidence/{id}` can never be satisfied.
**Fix:** configure an authentication flow with an OTP/WebAuthn step and the
`acr-to-loa` mapping so a stepped-up login yields `acr=aal2`.

### M-4 — Step-up tickets & JWKS cache are per-process

`StepUpAuth` stores tickets in an instance dict; the JWKS cache is a module
global. The Dockerfile runs `uvicorn --workers 2` and the Helm chart scales
horizontally, so a ticket issued by one worker is unknown to the next → flaky
401s on delete, and redundant JWKS fetches.
**Fix:** back step-up tickets with Redis (shared, TTL-native); optionally share
JWKS via Redis too.

### M-5 — Dev dependencies in the production image (`docker/Dockerfile`)

`pip install -e ".[dev]"` pulls pytest, mypy, ruff, black, testcontainers,
factory-boy into the runtime image — needless size and attack surface.
**Fix:** install the runtime extras only (`pip install .`), keep `[dev]` for CI.

---

## Low / Hardening

- **L-1** NGINX CSP uses `script-src 'self' 'unsafe-inline'` — prefer nonces or
  hashes; `unsafe-inline` neutralises much of the CSP's XSS value.
- **L-2** Only the plain-HTTP `:80` server is active; the TLS 1.3 block is
  commented out. The `Strict-Transport-Security` header is emitted over HTTP,
  where browsers ignore it. Enable the 443 block (or terminate TLS at the
  ingress) before production.
- **L-3** Dev users (`admin`, `analyst123`, `caselead123`) violate the realm
  `passwordPolicy length(12)`. Dev-only, but inconsistent and may fail import on
  stricter Keycloak versions.
- **L-4** `KEYCLOAK_CLIENT_SECRET=kronos-backend-secret` is committed in the
  realm and dev compose; `.env.example` ships `changeme_in_production`
  placeholders. Ensure all are overridden and the backend secret rotated for
  prod. `kronos-attest` is a public client with `directAccessGrantsEnabled`
  (ROPC) — discouraged.
- **L-5** `build_merkle_root` hashes leaves and branches the same way (no
  `0x00`/`0x01` domain separation) and duplicates the last node on odd layers,
  enabling CVE-2012-2459-style ambiguity in the anchored root. Low practical
  risk; harden with prefixes and explicit odd-node handling.
- **L-6** Dev NGINX mounts only `nginx.conf`; the built SPA is not mounted into
  `/usr/share/nginx/html`, so `/` 404s in `make dev`. Mount `frontend/dist` or
  bake it into an image.
- **Dead code:** `_MAX_HEADER_BYTES = 16` in `validation.py` is unused (intake
  reads 8 KB).

---

## What's done well (no action needed)

- JWT validation pins an algorithm allow-list (`RS256`/`PS256`) and passes it to
  `jwt.decode`, blocking `alg=none`/HS256 confusion; issuer/audience/exp/nbf all
  verified with bounded clock skew.
- Hash-chain verification re-derives from a running `prev_hash` rather than the
  stored field, so an attacker who can rewrite rows still can't forge a
  consistent chain.
- Hard tenant isolation: `QueryIsolationGuard` plus an always-on
  `kronos.org_id` term filter in `OpenSearchQueryBuilder.build`.
- Direct-to-MinIO presigned uploads keep large files off the app tier; WORM via
  Object Lock `COMPLIANCE` with default retention; SSE-KMS via KES/Vault.
- Structured logging with correlation IDs; step-up tickets are single-use and
  bound to `(user, operation, resource)`.

---

## Test artifacts added by this audit

| File | Demonstrates |
|------|--------------|
| `tests/unit/adapter/test_s3_storage_bugs.py` | C-1, C-2 |
| `tests/unit/application/test_delete_evidence_audit_integrity.py` | M-1 |

All are green (`xfail` for open defects, `pass` for locked-in current behaviour),
so CI remains green; an `xpass` signals a fix has landed and the marker should be
removed.
