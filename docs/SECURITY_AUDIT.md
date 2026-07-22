# KronOS — Security & Deployment Audit

**Date:** 2026-06-26
**Branch:** `claude/security-audit-deployment-w3b39o`
**Scope:** Configuration files, application code (intake, parsing, auth, audit,
storage), and third-party tool configuration (NGINX, Keycloak, MinIO/KES/Vault,
OpenSearch, Docker, step-ca). Backend tooling: `~/venv` (Python 3.11), 367
existing unit tests pass at 82 % coverage.

**Update 2026-06-26 (follow-up):** Most findings have been fixed on this branch;
the `Status` column tracks each. The accompanying tests now assert the corrected
behaviour (and guard against regression).

## Summary table

| ID  | Severity | Area | Finding | Status |
|-----|----------|------|---------|--------|
| C-1 | Critical | Storage | `S3EvidenceStorage` always reads from the quarantine bucket; promoted evidence is unreadable → parsing breaks in prod | ✅ Fixed |
| C-2 | Critical | Storage/Infra | App bucket names ≠ `provision_buckets.sh` bucket names; no prefix value reconciles them | ✅ Fixed |
| H-1 | High | NGINX | `upstream backend` points at host `backend`, but the compose service is `kronos-backend` → 502 on all `/api` and `/auth` | ✅ Fixed |
| H-2 | High | Docker | Deps installed to `/root/.local`, then `USER kronos` runs with no access (root home is `0700`) → container can't start | ✅ Fixed |
| H-3 | High | Keycloak/Auth | `organization` is an *optional* client scope and the SPA never requests it, but the backend hard-requires the claim → every request 401s | ✅ Fixed |
| M-1 | Medium | Audit | `delete_evidence` hard-codes `step_up_verified: True` in the immutable audit log regardless of actual verification | ✅ Fixed |
| M-2 | Medium | Intake | File-size limit is only checked against client-claimed size; real uploaded size is never enforced → size/DoS bypass | ✅ Fixed |
| M-3 | Medium | Keycloak/Auth | No `acr`→LoA mapping; tokens can't carry `acr=aal2`, so step-up-gated deletion is unsatisfiable | ⚠️ Partial — `acr.loa.map` added; MFA browser flow still to bind |
| M-4 | Medium | Auth/Scale | Step-up tickets + JWKS cache are per-process; with multiple workers/pods they don't share → intermittent 401 | ✅ Fixed — Redis-backed ticket store (atomic single-use) shared across replicas; enable with `STEP_UP_TICKET_STORE=redis` |
| M-5 | Medium | Docker | Production image installs `.[dev]` (pytest, mypy, ruff…) → bloat + attack surface | ✅ Fixed |
| L-1 | Low | NGINX | CSP allows `script-src 'unsafe-inline'` → weakens XSS defence | ✅ Fixed |
| L-2 | Low | NGINX | Only the plain-HTTP `:80` server is active; the TLS 1.3 block is commented out (HSTS on HTTP is ignored) | 📋 Documented (enable at prod) |
| L-3 | Low | Keycloak | Dev user passwords violate the realm `passwordPolicy length(12)` | ✅ Fixed |
| L-4 | Low | Secrets | Committed client secret + `changeme_in_production` placeholders; must be rotated/overridden in prod | 📋 Documented |
| L-5 | Low | Crypto | Merkle tree lacks leaf/branch domain separation and duplicates the last odd node (CVE-2012-2459 class) | 📋 Deferred (changing the anchor format breaks existing anchors) |
| L-6 | Low | Infra | Dev NGINX mounts only `nginx.conf`, not the built SPA → `/` 404 in dev | 📋 Documented |

### Fixes applied on this branch

- **C-1** — `EvidenceStorage` reads are now bucket-aware (`stream_object`/
  `object_exists` take `bucket="quarantine"|"evidence"`); parsing reads from the
  evidence bucket.
- **C-2** — the canonical names per `Project_Specifications.md` §2 /
  `reviews/Part_2_Review.md` are `kronos-evidence-<org>-quarantine` and
  `kronos-evidence-<org>`; the code and config already matched them. The actual
  deviation was in `scripts/provision_buckets.sh` (it created
  `kronos-<org>-quarantine` / `kronos-<org>-evidence`), which has been corrected
  to the canonical names.
- **H-1** — NGINX upstream now targets `kronos-backend:8000`.
- **H-2/M-5** — Dockerfile builds a venv at `/opt/venv`, installs runtime deps
  only (`pip install .`), copies it `--chown=kronos`, and runs as `kronos`.
- **H-3** — `organization` moved to `defaultDefaultClientScopes`; the SPA also
  requests `scope=organization` explicitly.
- **M-1** — `delete_evidence(..., step_up_verified: bool=False)`; the route passes
  `True` only after consuming a valid aal2 ticket, so the log is truthful.
- **M-2** — `finalize_upload` enforces the real byte count while streaming
  (`_cap_stream`), rejecting under-declared oversized uploads.
- **M-3** — realm `acr.loa.map` added (`{"aal1":1,"aal2":2}`). Emitting `aal2`
  still requires binding an MFA browser flow with LoA conditions (manual,
  environment-specific).
- **M-4** — step-up tickets are now stored behind a pluggable `TicketStore`
  (`src/external/middleware/step_up_store.py`). `RedisTicketStore` uses an atomic
  `GETDEL` so a ticket is spent exactly once even when multiple replicas race,
  and any replica can consume a ticket issued by another. `StepUpAuth` keeps its
  sync API (no route/test churn); the default is still the in-memory store.
  **To activate in production:** set `STEP_UP_TICKET_STORE=redis` and have the
  app bootstrap pass `dependencies.build_step_up_ticket_store(settings)` into
  `create_app(step_up_ticket_store=...)` (or call
  `dependencies.configure_step_up_auth(store)`). Tests
  (`tests/unit/middleware/test_step_up_store.py`) prove cross-instance sharing
  and single-use. The backend also runs a single uvicorn worker per container.
  *Note:* the JWKS cache remains per-process — that is a performance concern
  only (each process re-fetches), not a correctness one.
- **L-1** — CSP `script-src` no longer allows `'unsafe-inline'`.
- **L-3** — dev user passwords now satisfy `length(12)`.

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
**Fix applied:** the storage API is now bucket-aware — `stream_object()` /
`object_exists()` take `bucket: BucketKind = "quarantine"`; parsing passes
`bucket="evidence"`. `LocalEvidenceStorage` is now strict (one bucket per call)
so this can't be masked again.
**Test:** `tests/unit/adapter/test_s3_storage_bugs.py::test_evidence_read_resolves_to_evidence_bucket`

### C-2 — Provisioning script used non-canonical bucket names

The canonical names are defined by the design authority — `Project_Specifications.md`
§2 (lines 96–97) and `reviews/Part_2_Review.md` (lines 139, 146):

```
kronos-evidence-<org>-quarantine    (quarantine, no Object Lock)
kronos-evidence-<org>               (evidence, WORM Object Lock Compliance)
```

`S3EvidenceStorage` and `config.py` already produced exactly these names
(`_quarantine_bucket = "<prefix>-<org>-quarantine"`, `_evidence_bucket =
"<prefix>-<org>"`, prefix `kronos-evidence`). The deviation was in
`scripts/provision_buckets.sh`, which created `kronos-<org>-quarantine` /
`kronos-<org>-evidence` — so the application looked for buckets the script never
created.

**Impact:** A freshly provisioned deployment can't find its buckets; uploads and
promotion fail.
**Fix applied:** `provision_buckets.sh` now creates the canonical
`kronos-evidence-<org>-quarantine` and `kronos-evidence-<org>` buckets (prefix
overridable via `BUCKET_PREFIX`). Code/config were left as-is (already correct).
**Test:** `tests/unit/adapter/test_s3_storage_bugs.py::test_default_prefix_matches_provisioned_buckets`

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
- Hard tenant isolation: every Postgres repository scopes its query by
  `org_id` in the `WHERE` clause itself (e.g. `PostgresCaseRepository.get_by_id`),
  and OpenSearch isolation is enforced server-side via DLS on the flat JWT
  `org_id` claim (`poc/opensearch_jwt/`, `poc/keycloak_opensearch_dls/`) —
  not by an application-layer filter. `QueryIsolationGuard` and
  `OpenSearchQueryBuilder` exist as scaffolding for a future direct backend
  search API that doesn't exist yet; they have zero real call sites today
  (correctly flagged, not "done well", in
  `reviews/Static_Compliance_Pentest_Review.md` AUDIT-15).
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

---

## Ingestion Pipeline Security Review — 2026-07-03

**Branch:** `fix/evidence-upload-camelcase`  
**Scope:** Review of the ingestion pipeline after commit `dd876ae` introduced a
client-triggered parsing bypass.  All findings below are relative to the code in
this branch after the corrective commits.

### Summary table

| ID   | Severity | Area | Finding | Status |
|------|----------|------|---------|--------|
| P-1  | Critical | Pipeline | Frontend calling `parse/start` after finalize — client-controlled FSM transition | ✅ Fixed |
| P-2  | High | Routes | `POST /parse/start/{id}` unrestricted — any org member could trigger parsing | ✅ Fixed |
| P-3  | High | Queue | Wrong Celery queue names in `CeleryTaskQueue` (`parse.fast` / `parse.heavy` vs `q.parse.fast` / `q.parse.plaso`) | ✅ Fixed |
| P-4  | High | Queue | Legacy task aliases called via `apply()` (blocking, synchronous) instead of correct async tasks | ✅ Fixed |
| P-5  | High | Orphan cleanup | `stream_all_by_state` missing — orphan tasks silently skipped with `hasattr()` fallback | ✅ Fixed |
| P-6  | Medium | Queue | No recovery for evidence stuck in RECEIVED if broker is unavailable at finalize time | ✅ Fixed (auto_dispatch_received beat task) |
| P-7  | Medium | Sandbox | Plaso subprocess uses `subprocess.Popen(cmd_list)` — not shell-expanded | ✅ Safe (confirmed) |
| P-8  | Medium | AV | `configure_clamav_from_settings()` silently falls back to `NoOpScanner` on misconfiguration | ⚠️ Pre-existing — should fail loudly in production |
| P-9  | Low | SSE | SSE ticket store is process-local — multi-worker SSE tickets unreliable | ⚠️ Pre-existing (M-4 fix covers step-up; SSE needs same treatment) |
| P-10 | Low | Audit | `anchor_audit_log` logs with no `org_id` and sentinel user `00000000-0000-0000-0000-000000000001` | ⚠️ Pre-existing — correct for cross-org system task |

---

### P-1 — Critical: Frontend bypassed the autonomous ingestion pipeline

**Commit:** `dd876ae`  
**File:** `frontend/src/components/UploadDrawer.tsx`

The previous commit added a direct call to `POST /api/evidence/parse/start/{id}`
from `uploadFile()` immediately after `finalizeUploadWithHash()`.

**Problems this introduced:**

1. **Client controls a server-side FSM transition.** The RECEIVED → PARSING
   transition is a chain-of-custody event. Allowing any authenticated client to
   trigger it means the audit trail reflects user intent, not server enforcement.
   An attacker who intercepts the upload flow and does not call `parse/start` would
   leave evidence in RECEIVED state indefinitely — or could call `parse/start`
   multiple times on other users' evidence within the org.

2. **TOCTOU window.** `finalize_upload` and `parse/start` are two separate HTTP
   requests. Between them the evidence is in RECEIVED state, visible to other org
   members. A concurrent admin DELETE during this window would then receive a
   `parse/start` call on a deleted record.

3. **No retry guarantee.** If the second call fails (network error, 500 from the
   server), the evidence stays in RECEIVED permanently with no recovery path.

**Fix applied:**

- `EvidenceIntakeService._promote()` calls `task_queue.enqueue_dispatch()` as the
  final step — the Celery `dispatch_parse` task handles RECEIVED → PARSING.
- Frontend `UploadDrawer.tsx` no longer calls `startParsing()`.
- `auto_dispatch_received` beat task (hourly :15) provides broker-failure recovery.
- `POST /parse/start/{id}` restricted to `ORG_ADMIN` for manual recovery only.

---

### P-2 — High: `parse/start` was accessible to any org member

**File:** `src/external/routes/evidence.py`

The `POST /api/evidence/parse/start/{evidence_id}` endpoint had no role
restriction (`Depends(get_tenant_context)` only, no `requires_role()`).

Any authenticated member of the org could:
- Trigger parsing on any evidence in their org (not just their own uploads).
- Re-trigger parsing on evidence already in PARSING state (FSM guard prevents
  double-transition, but the request would still consume resources).

**Fix applied:** `Depends(requires_role(Role.ORG_ADMIN))` added to the endpoint.

---

### P-3 — High: Celery queue names were wrong in `CeleryTaskQueue`

**File:** `src/adapter/queue/celery_queue.py`

`enqueue_parse_fast` sent tasks to queue `"parse.fast"` and `enqueue_parse_heavy`
to `"parse.heavy"`.  The configured worker queues (per `celery_app.conf.task_routes`)
are `"q.parse.fast"` and `"q.parse.plaso"`.

Since the explicitly-passed `queue=` parameter overrides `task_routes` in Celery,
all parse tasks were sent to non-existent queues.  Workers consuming `q.parse.fast`
never received them.  Evidence would sit in PARSING state until orphan-parse
cleanup timed it out as an error.

**Fix applied:** Corrected to `q.parse.fast`, `q.parse.plaso`, `q.index`.

---

### P-4 — High: Legacy task aliases called `apply()` synchronously (blocking worker)

**File:** `src/adapter/queue/celery_queue.py`

`enqueue_parse_fast` dispatched `parse_evidence_fast` (legacy alias), which calls
`parse_artefact_fast.apply(...)`.  `apply()` executes the task **in the current
process**, blocking the calling thread until complete.  In a Celery worker this
blocks the worker slot for the full parse duration.

**Fix applied:** `CeleryTaskQueue` now dispatches `parse_artefact_fast`,
`parse_artefact_heavy`, and `dispatch_parse` directly via `apply_async()`.

---

### P-5 — High: Orphan cleanup tasks never ran (missing `stream_all_by_state`)

**Files:** `src/external/celery_app.py`, `src/adapter/repository/evidence.py`

`abort_orphan_uploads` and `abort_orphan_parses` both guarded execution with:

```python
if not hasattr(repo, "stream_all_by_state"):
    logger.warning("... skipping")
    return 0
```

`PostgresEvidenceRepository` did not implement `stream_all_by_state`, so both
tasks always returned 0 and logged a warning.  Evidence stuck in UPLOADING or
PARSING states was never cleaned up.

**Impact:** Evidence that fails mid-finalize can persist in SCANNING or HASHING
state indefinitely; evidence whose worker crashes stays in PARSING until manual
DB intervention.

**Fix applied:**
- `stream_all_by_state(state)` added to `EvidenceRepository` ABC.
- `PostgresEvidenceRepository.stream_all_by_state()` implemented (cross-org query).
- `InMemoryEvidenceRepository` (tests) also implements it.
- The `hasattr` guard removed; orphan tasks now actually run.

---

### P-7 — Medium: Subprocess security in `FirecrackerLauncher` (confirmed safe)

**File:** `src/external/sandbox/firecracker.py`

`subprocess.Popen(cmd)` where `cmd` is a Python list with `shell=False` (default).
Arguments are never shell-expanded.  The values passed — `evidence_path` (a
MinIO object key), UUIDs, and SHA-256 hashes — are all derived from our own
verified database records, not from raw user input.

**Verdict:** No injection risk.  The `# noqa: S603` comment on the `Popen` call
is appropriate (bandit false positive for shell=False subprocess).

---

### P-8 — Medium: ClamAV fallback to NoOpScanner on misconfiguration (pre-existing)

**File:** `src/external/dependencies.py` (`configure_clamav_from_settings`)

```python
except Exception:
    pass  # keep NoOpScanner in test/dev environments without ClamAV
```

If `clamd_host`/`clamd_port` are misconfigured, the service silently accepts
all files without AV scanning.  This is intentional for development, but
dangerous if it occurs in production.

**Recommended fix (not in this branch):** Differentiate dev/prod via a
`KRONOS_ENV=production` setting; raise `RuntimeError` in production mode if
ClamAV is unreachable at startup rather than falling back silently.

---

### P-9 — Low: SSE ticket store is process-local (pre-existing)

**File:** `src/external/routes/sse.py`

The `_tickets` dict is module-level and process-local.  In a multi-worker
(multi-uvicorn-process) deployment, a ticket issued by worker A cannot be
consumed by worker B.

**Recommended fix:** Apply the same `RedisTicketStore` pattern used for
step-up auth tickets (M-4 fix).  The SSE ticket is a simpler one-shot
token that would fit the same atomic `GETDEL` Redis pattern.
removed.
