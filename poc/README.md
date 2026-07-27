# Verification-first PoCs

See `CLAUDE.md` Section F for the workflow these follow. Each PoC pair
below runs the **real** dependency at the version pinned in this repo,
using KronOS's own `src/` classes wherever possible instead of
reimplementations, and keeps its actual captured output alongside the code.

**Full consolidated findings + remaining task list:** [`docs/verification-pass-findings.md`](../docs/verification-pass-findings.md).

| Directory | Component pair | Status |
|---|---|---|
| `plaso/` | Plaso 20260512 alone, against a real forensic sample | 2 bugs found + fixed (binary names, psort pre-existing-file) |
| `opensearch/` | `src/adapter/opensearch/client.py` alone, against real OpenSearch 2.11.1 | 1 bug found + fixed (`opensearch-py[async]` extra); 1 gap documented (`ensure_tenant_role` untestable with security plugin disabled) |
| `plaso_opensearch/` | The two linked: real Plaso output through the real ingestion pipeline into real OpenSearch | 1 bug found + fixed (timestamp handling silently used ingest-time instead of forensic event-time) |
| `minio/` | `S3EvidenceStorage` against real MinIO Object Lock | No bugs — genuinely correct |
| `vault_kes_minio/` | Vault → KES → MinIO SSE-KMS chain | 1 chain found broken + fixed (KES config schema, Vault policy grants, KES templating syntax) |
| `keycloak/` | `keycloak_auth.py`/`tenant_context.py` against real Keycloak 26.2 | 1 bug found + fixed (JWT `aud`-bypass with no `aud` claim) |
| `celery_redis/` | Real Celery task dispatch through Redis | No bugs — genuinely correct |
| `rfc3161/` | `RFC3161TimestampService` against a real local TSA responder | 1 bug found + fixed (`verify()` never parsed a real response) |
| `multi_tenancy/` | Cross-org isolation: Postgres + OpenSearch + JWT, real FastAPI app | 1 severe bug found + fixed (`PostgresCaseRepository` never wired); dead-code gap flagged (`QueryIsolationGuard`/`OpenSearchQueryBuilder`) |
| `postgres/` | Audit hash-chain concurrency + tamper-detection | No bugs — genuinely correct |
| `full_pipeline/` | Full backend-only evidence lifecycle, real Celery worker + real `system.evtx` | 1 bug found + fixed (dead `ensure_index_template()`); UTC-date timezone bug found and deferred to `chain_of_custody/` |
| `chain_of_custody/` | Postgres → Merkle → real RFC3161 TSA → real `kronos-attest` CLI | 2 bugs found + fixed (the timezone bug, and `tsa_anchored` always-False) |
| `clamav/` | Real ClamAV EICAR scan through the intake pipeline | No bugs — genuinely correct |
| `auth_flow/` | Scripted PKCE + step-up (TOTP) against real Keycloak | 2 bugs found + fixed: missing `/api/step-up/ticket` route; step-up MFA not conditional on `acr_values` (see `auth_flow/step_up_conditional_fix/`) |
| `auth_flow/step_up_conditional_fix/` | Root-cause + fix for the step-up conditional-flow bug above | Fixed and verified: 6/6 real PKCE logins against the actual shipped `docker/keycloak/kronos-realm.json` |
| `opensearch_jwt/` (+ `option_a_flat_claim/`) | OpenSearch security plugin + JWT authc + DLS — new construction | Found the `ensure_tenant_role()` role-mapping gap; verified the fix design (flat `org_id` claim + one generic role) |
| `keycloak_opensearch_dls/` (+ `step4_new_member/`) | Real Keycloak 26.2 flat `org_id` claim → real OpenSearch DLS, end to end | Verified the production fix design against real Keycloak; several Keycloak Admin REST gotchas found along the way (not KronOS bugs) |
| `opensearch_dashboards_tenancy/` | OpenSearch Dashboards saved-object multi-tenancy — new construction | Design confirmed sound (mechanism only, internal users) |
| `opensearch_dashboards_sso/` | Real Keycloak OIDC SSO into Dashboards + automated per-org tenant provisioning | Fixed and verified: 11/11 real checks, 8 real bugs found+fixed along the way |
| `celery_beat/` | The four beat-scheduled tasks against real seeded-stale Postgres rows | No product bugs — confirms the UTC-date fix stays fixed |
| `nginx/` | `nginx.conf.template` + real FastAPI `CORSMiddleware` | 1 bug found + fixed (misleading comment; nginx actually crashes on an unset CSP var); 1 severe Helm bug found + fixed (missing nginx ConfigMap) |
| `dashboards_embed/` | `cases.py`'s Dashboards embed-URL route vs. real Dashboards 2.11.1 source | No bug (a suspected one was ruled out via source); one question flagged for a future browser pass |
| `dashboards_embed/autoload_verification/` | Resolves the flagged question above with a real browser: does the embed URL make Discover auto-open the case's data? | Real finding: state must live in the URL fragment (`#?_a=...&_g=...&_q=...`), not the top-level query string, which the original route used and which data-explorer silently ignores — confirmed by observing the app fall back to a stale, wrong case's data with no error. Also found `security_tenant` as a real top-level query param (`security-dashboards-plugin` source) that skips the tenant-selector dialog entirely. 11/11 backend checks + real RISON decode of all 3 blobs; shipped, rebuilt, and re-verified end-to-end through the real iframe — zero clicks, no dialog, correct data |
| `full_ingestion_test/` | Full real ingestion pass on the actual `docker-compose.dev.yml` stack: real login (case-lead PKCE) → real case creation → real upload/finalize for one real sample per registered parser → autonomous pipeline to `COMPLETE` → real OpenSearch query + full-document fetch (`fetch_documents.py`) verifying all 5 parsers' actual content (not just doc counts) into `documents.json`/`ingestion_verification.json` | 1 real bug found + fixed: `MagicByteValidator` rejected a genuine uncompressed Windows Prefetch sample the actual parser (`PlasoParser`) already supported (see `docs/verification-pass-findings.md` row 24) |
| `kape_ingestion_test/` | Real login → upload/finalize of a KAPE-shaped ZIP + a real EWF (E01) image → autonomous pipeline → real OpenSearch fetch verifying every record's `source_path`/`file.path`/`container_sha256` (new container-ingestion feature, see `src/external/parsers/archive.py`) | 1 real bug found + fixed: `MagicByteValidator` had no EWF/E01 signature (422 at intake); 1 real Plaso/dfVFS/libewf interop bug found while building the E01 fixture (FAT12 silently drops all file content -- see `tests/fixtures/samples/real/kape/NOTICE.md`) |
| `suricata/` | New `SuricataEveParser` module (`reviews/Data_Source_Module_System.md`'s "pure-timeline JSON win" category) against a real `eve.json` sample (real OISF `suricata-verify` golden fixture + real userguide-cited pcap-correlated events) — standalone parser verification, then live-stack verified separately (real login/upload/finalize, 6/6 real events in OpenSearch, correctly split across 2 real monthly indices by real event timestamp) | No bugs found — first module built entirely under the new Section G process, zero registry/detection collisions with `CloudTrailParser`/`NginxParser` |
| `make_dev_bind_mount_fix/` | A real user's `make dev` run on Docker Desktop/WSL2: `keycloak-init`/`dashboards-tenant-init` (non-root `curlimages/curl`) failed to open their bind-mounted provisioning scripts, aborting the whole compose-up; `opensearch-init` (runs as root) succeeded in the same run — reproduced the fix (build the scripts into the image instead of bind-mounting) on a real Linux Docker host with the full 18-service dev stack, OS security genuinely enforced (401 unauthenticated / 200 with real creds) | 1 real bug found + fixed: non-root init containers can't rely on host bind-mount permission bits on Docker Desktop/WSL2 (`docker/init/Dockerfile.keycloak-init`, `docker/init/Dockerfile.dashboards-tenant-init`) |
| `opensearch_dashboards_dls/` | New construction: fixes OpenSearch Dashboards SSO users getting 403s on all `kronos-*` document reads. Real Keycloak 26.2 + real OpenSearch 2.11.1, two real orgs with two different realm roles, real seeded per-org documents | Root cause found: two independently-shipped authc domains needed mutually incompatible `roles_key` values from a single-valued claim, so the DLS-granting role could never be assigned to a real Dashboards SSO session. Fix (a combined multivalued `dashboard_roles` claim, verified against real Keycloak 26.2 source) gets 18/18 real checks passing, incl. real cross-org DLS isolation and least-privilege claim scoping. 3 PoC-authoring bugs found+fixed along the way (not the design: an over-255-char client-scope description crashing Keycloak import — same bug class as a prior real fix; unbounded wait loops that let a dead container hang the script 33+ min unnoticed; a missing explicit `keyword` mapping that zeroed out all search results including for admin). Not yet shipped to `scripts/`/`docker/keycloak/kronos-realm.json` — pending a real-browser pass |
| `dashboards_index_pattern_provisioning/` | New construction: auto-provisions each case's OpenSearch Dashboards index pattern at case-creation time, closing the "you need to create an index pattern first" gap the DLS fix above surfaced. Real OpenSearch Dashboards 2.11.1 saved-objects API against the live dev stack | 8/8 checks: idempotent create, discoverable via the real `_find` API, valid pattern syntax, unreachable-Dashboards failure swallowed (best-effort). Shipped (`src/adapter/opensearch/dashboards_client.py`, wired into `cases.py`'s `create_case()`), rebuilt, and re-verified with a real Playwright pass — a real API-created case's pattern appears in the real Dashboards UI with zero manual steps. Two bugs found: `PUT` vs `POST` for the saved-objects create call (`PUT` is update-only, 404s on a missing object), and the mandatory `osd-xsrf` header. Doesn't yet make Discover open the pattern directly — see its own README's "not zero-click end-to-end" note |
| `tls_lan_https/` | LAN HTTPS access, now migrated to `kronos.local` as the sole authorized domain everywhere (CORS/CSP/Keycloak redirect-URI allowlists/TLS SAN — no localhost/127.0.0.1/bare-IP entries left anywhere): real step-ca cert issuance (`tls-init`), nginx TLS termination + reverse proxies for Keycloak/MinIO/Dashboards, each checked alone then all together, re-verified after a full `--no-cache` rebuild by running the actual `poc/full_ingestion_test/` scripts (real login, real upload, real autonomous ingestion to `COMPLETE`) entirely over `kronos.local` | 6 real bugs found + fixed across the whole effort: dead `step-ca` port mapping + always-green healthcheck; nginx's `$host` dropping the port and breaking MinIO's SigV4 validation; Keycloak's login form always POSTing to the single pinned `KC_HOSTNAME` origin (a `localhost`-special-case would have broken every `localhost` browser login, root cause for going single-domain instead); `index.html`'s hardcoded `<meta>` CSP tag silently overriding nginx's own (correct) header via CSP's AND-all-policies rule; a `vite build`-with-no-`.env` regression that fix introduced; `avahi-daemon` mDNS publish collision (documented, not resolved — `/etc/hosts` used instead, see `docs/lan-dev-access.md`) |

## Fixes this pass made to `src/`/`docker/` (not just `poc/`)

1. `docker/plaso/kronos-plaso-worker.py` — look up `log2timeline`/`psort`
   (unsuffixed) before falling back to the legacy `.py`-suffixed names.
2. `docker/plaso/kronos-plaso-worker.py` — stop pre-creating psort's output
   file (psort refuses to write to an existing file); still reserve a
   unique unpredictable name via `mkstemp`, just unlink it first.
3. `src/external/sandbox/firecracker.py` — `_stream_records()` now handles
   psort's int microsecond-epoch timestamps, not just ISO strings.
4. `pyproject.toml` — `opensearch-py[async]>=2.6` (was missing the extra
   that `AsyncOpenSearch` actually requires).

Before these fixes, Plaso parsing had never actually run in this repo — it
silently produced only placeholder events — despite parser code, worker
code, and tests referencing it as if it worked.

## Why existing tests didn't catch this

`tests/unit/parsers/test_real_world_samples.py` already runs three other
parsers (Nginx, CloudTrail, EVTX) against real-world sample bytes end-to-end
and found three real bugs that way (see that file's own docstring). For
Plaso it explicitly stops at `PlasoParser.supports()` (format detection)
and never calls `.parse()`, with a comment noting the subprocess path is
"excluded from unit coverage" — matching `pyproject.toml`'s
`coverage.run.omit` list (`src/external/parsers/plaso.py`,
`src/external/sandbox/firecracker.py`). That omission is *why* three
release-blocking bugs (wrong binary names, psort's pre-existing-file
rejection, and silently-wrong timestamps) went unnoticed: the one place
that tests real parsers against real bytes deliberately didn't do that for
the one parser that shells out to a real external tool. This PoC's
`run_poc.sh`/`run_poc.py` are not a replacement for an automated test, but
they're the shape a real integration test for `PlasoParser.parse()` should
take (real container, real sample, real assertions on output) — a
worthwhile follow-up outside this PoC pass's scope.
