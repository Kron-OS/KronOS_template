# PoC: CI-realistic security-enabled compose profile (Gap Audit P1-14 / Milestone V, item V3)

Real, end-to-end verification that `docker/docker-compose.test.yml` can be
made genuinely security-enabled (OpenSearch security plugin + real Keycloak
org provisioning, not `DISABLE_SECURITY_PLUGIN=true`) and still fit a
standard GitHub Actions runner. Closes P1-14 from `docs/GAP_AUDIT_2026-08.md`
(named independently by I1's own roadmap finding and
`IMPROVEMENT_IDEAS.md` §3 as the single highest-leverage infra fix in the
repo).

## Versions pinned (read from this repo, per CLAUDE.md §F.2 step 1)

- `opensearchproject/opensearch:2.13.0` -- `docker/docker-compose.test.yml`'s
  own existing pin (kept as-is, not backported to `docker-compose.dev.yml`'s
  2.11.1 -- see "Real bugs found" below for why keeping 2.13.0 mattered).
- `quay.io/keycloak/keycloak:26.2` -- matches dev/prod.
- Real, unmodified production scripts: `scripts/provision_opensearch_security.py`,
  `scripts/provision_keycloak_org.sh`, `docker/init/Dockerfile.keycloak-init`.
- Real, unmodified production realm: `docker/keycloak/kronos-realm.json`.
- Real, unmodified production class: `src/external/middleware/keycloak_auth.py`'s
  `KeycloakTokenValidator` (never before exercised against a live Keycloak
  anywhere in this repo's test suite -- it's in `pyproject.toml`'s coverage
  `omit` list for exactly that reason, "needs live Keycloak JWKS endpoint").
- Real, unmodified production class: `src/adapter/opensearch/client.py`'s
  `OpenSearchClient` (`bulk_index`, `ensure_generic_tenant_role`, `ensure_index_template`).

## The real design question, answered with evidence (not assumed)

**Question:** can a security-enabled OpenSearch + Keycloak (+ Postgres/Redis/
MinIO) stack realistically boot and become healthy within a standard GitHub
Actions runner's resource envelope (2 CPU / 7GB RAM) and a reasonable CI
timeout?

### Step 1: measured the real, already-running dev stack (not torn down, only observed)

`docker stats --no-stream` against `docker/docker-compose.dev.yml`'s
already-running containers on this host (4 CPU / 7.1GB RAM -- close to but
slightly more CPU than a standard GHA runner's 2 CPU / 7GB):

| Service | CPU % | Mem (idle, 12-day-old container) |
|---|---|---|
| opensearch (2.11.1, security ON) | 5.70% | 729 MiB |
| keycloak (26.2, realm imported) | 0.17% | 369 MiB |
| step-ca | 0.49% | 22 MiB |
| clamav | 0.01% | **949 MiB** |
| postgres | 0.01% | 21 MiB |
| redis | 1.15% | 4.9 MiB |
| minio | 0.11% | 189 MiB |
| kronos-backend / celery-worker / celery-worker-plaso / celery-beat / nginx / tsa | negligible each | negligible each |

Real, useful signal from this alone: OpenSearch **with the security plugin
genuinely enabled** costs ~730MB, not meaningfully more than the disabled
config's own `-Xms512m -Xmx512m` heap setting would suggest -- the security
plugin itself is not the memory driver here, the JVM heap setting is.
ClamAV, by contrast, is the single heaviest service in the whole dev stack
(949MB, virus-definition DB) and is **not needed** for what this item has to
prove (see scoping decision below).

### Step 2: what does I1 (the finding that named this gap) actually need?

Read `docs/NEXTGEN_SOC_ROADMAP.md`'s I1 section in full before scoping
anything. I1's own "CI-wiring investigated, not achieved this pass" note
names exactly two concrete blockers, verbatim:
`DISABLE_SECURITY_PLUGIN=true` ("no TLS/auth, defeating the whole A3
isolation model") and "no `step-ca`/`kronos.local`/`keycloak-init`
scaffolding for the real browser-OIDC login every one of those PoCs uses."

Read further to check whether "TLS/auth" here means full mTLS/step-ca or
just OpenSearch's own bundled self-signed HTTPS: I1's own real PoC
(`poc/detection_validation_harness/`) and the design it depends on
(`poc/keycloak_opensearch_dls/`) both authenticate via **direct
password-grant token acquisition** against Keycloak's plain internal
`http://keycloak:8080` -- never through `kronos.local`/nginx/step-ca's
browser-facing TLS termination. `step-ca`/`tls-init`/nginx in
`docker-compose.dev.yml` exist **only** for the interactive browser SSO
flow (Dashboards SSO, the SPA login redirect) -- a different concern from
"does a real Keycloak-issued JWT drive real OpenSearch DLS," which is what
I1's harness and this item's own minimum bar both actually need.

**Decision: scope down, evidence-based, matching the Kafka non-adoption
decision's own documented-decision precedent:**

| Component | In this PoC's scope? | Why |
|---|---|---|
| OpenSearch security plugin | **Yes** | The actual thing P1-14 is about |
| Keycloak + real org provisioning | **Yes** | Needed for a real, non-hand-signed JWT |
| `step-ca` / `tls-init` / nginx (browser TLS) | **No** | Only needed for interactive browser SSO; I1's own harness doesn't use it |
| ClamAV | **No** | Not exercised by any OpenSearch/Keycloak-security-dependent test; heaviest service in the stack (949MB) for zero benefit here |
| `tusd` | **No** | Not in `docker-compose.test.yml` today either; unrelated to this item |

This mirrors `docker-compose.test.yml`'s own pre-existing shape (it already
omits step-ca/tusd/nginx/opensearch-dashboards -- this item only had to add
the missing *security* pieces, not invent a parallel dev-stack clone).

### Step 3: real measured numbers for the actual scoped stack

Booted for real via `run_poc.sh` (below), `docker stats --no-stream`
against the freshly-booted `kronos-poc-cisec-*` containers:

| Service | CPU % | Mem (fresh boot) |
|---|---|---|
| opensearch (2.13.0, security genuinely ON) | 1.53% | 933 MiB |
| keycloak (26.2, realm + org + client just provisioned) | 0.20% | 548 MiB |
| postgres | 0.04% | 35 MiB |
| redis | 1.20% | 3.7 MiB |
| minio | 0.06% | 105 MiB |
| **Total** | | **~1.63 GB** |

Well within a GHA runner's 7GB. Boot timing (real, captured in
`output.txt`): base services (postgres/redis/minio/opensearch/keycloak)
healthy in **41s**, `opensearch-init`+`keycloak-init` provisioning complete
3s later (**44s total**), full run including the second-org provisioning
and the real verification script: **46s** wall time, on a host with every
image already pulled.

**What this does and does NOT confirm about real GHA runners:** this 46s
figure is a *warm-image-cache* number -- this host had already pulled
`opensearchproject/opensearch:2.13.0` (~890MB), `keycloak:26.2` (~500MB),
`postgres:16-alpine`, `redis:7-alpine`, `minio/minio:latest`, and
`curlimages/curl:latest` from earlier runs. A real GHA runner pulls all of
these fresh on every job (no persistent Docker layer cache without extra
`actions/cache` wiring, which adds its own complexity/staleness risk).
Realistic estimate: image pulls likely add 1-4 minutes on top of the
measured 46s boot+test time, for a realistic total of roughly 2-6 minutes
on a real runner -- still comfortably inside a 10-20 minute CI timeout, but
this specific number is **asserted from image-size arithmetic, not
confirmed by an actual GHA run** (this sandbox cannot trigger one).

## Design decision: nightly/scheduled, not per-PR

Even though the measured footprint and boot time both easily fit a GHA
runner, `.github/workflows/security-integration-tests.yml` is wired as a
**nightly cron (`workflow_dispatch` also available for manual runs)**, not
a per-PR gate that runs on every push. This *agrees* with I1's own original
recommendation ("a scheduled/nightly job, not a per-PR gate, given
OpenSearch+Keycloak startup time") but for a more complete, evidence-based
set of reasons than the startup-time framing alone -- the real measurement
above shows startup time is not actually the binding constraint:

1. **Tax proportionality.** Only OpenSearch-security/Keycloak-org code paths
   need this. The other ~99% of PRs (frontend changes, unrelated `src/`
   modules, docs) would pay a multi-minute tax for a stack they never touch.
2. **GHA cold-pull risk this local measurement cannot rule out.** ~1.4GB of
   images pulled fresh every run is a real, not-yet-measured source of both
   added time and Docker-Hub-rate-limit flakiness that a lightweight,
   nightly cadence tolerates far better than a per-PR gate that blocks merges.
3. **Matches this initiative's own established precedent.** Every other
   H/I-series roadmap item that needed a heavier stack (I1 itself included)
   followed the same pattern: real local verification now, CI wiring as an
   explicit, scoped follow-up, nightly rather than per-PR for this exact
   class of stack.

`.github/workflows/integration-tests.yml` (the existing per-PR gate) is left
unmodified -- it correctly stays lightweight (Postgres+Redis only) for the
fast, on-every-PR feedback loop; the new nightly workflow is additive, not
a replacement.

## Real bugs found while building this (not anticipated from source-reading alone)

### Bug 1: OpenSearch 2.12.0+ requires `OPENSEARCH_INITIAL_ADMIN_PASSWORD`

`docker/docker-compose.test.yml` pins `opensearchproject/opensearch:2.13.0`
(newer than dev's 2.11.1). Confirmed via `docker logs` on the first real
boot attempt: the security plugin's bundled demo installer refuses to start
at all past 2.12.0 without this var ("No custom admin password found...
please provide a password via OPENSEARCH_INITIAL_ADMIN_PASSWORD") --
container exits 1 on every boot. This is a genuine version-specific
behavior change dev's own 2.11.1-pinned opensearch service never surfaces,
and confirms the CLAUDE.md §F.2 step 1 instruction to verify against *this
file's own* pinned version literally mattered here, not just as a
formality -- copying dev's opensearch config verbatim would have shipped a
container that can never boot. **Fixed:** added
`OPENSEARCH_INITIAL_ADMIN_PASSWORD=KronOSCiTest#2026` (also satisfies the
plugin's own password-strength validator -- tried `admin` first, rejected
for being too simple) and updated every `OS_ADMIN_PASSWORD`/
`OPENSEARCH_PASSWORD`/healthcheck reference in the file to match.

### Bug 2: compose override files concatenate `ports:`, not replace

A first version of `docker-compose.override.yml` (this directory, local-run
only, not shipped) tried to remap host ports with a plain
`ports: ["19200:9200"]` override to avoid colliding with this host's
already-running `docker-compose.dev.yml` stack. Confirmed via
`docker compose config`: Compose merges list-typed keys by
**concatenation**, so the container still also tried to bind the *base*
file's `9200:9200` and immediately lost ("port is already allocated")
against the real running dev stack. **Fixed:** the compose-spec `!override`
merge tag (Docker Compose v2.24+; this host runs v5.3.1), which replaces
the list instead of appending to it -- needs a literal space before the
flow-sequence value (`!override ["19200:9200"]`) or the YAML tag scanner
errors on the embedded `:` in the port mapping.

### Bug 3: OpenSearch's `roles_key=dashboard_roles` needs an extra client scope

The real, current `scripts/provision_opensearch_security.py` configures
OpenSearch's openid authc domain with `roles_key: "dashboard_roles"` (not
the simpler `"roles"` an earlier design iteration used -- see that script's
own inline comment for the full history). `dashboard_roles` is only emitted
by the `kronos-dashboard-roles` client scope, which only the real
`opensearch-dashboards` client is explicitly wired with in
`docker/keycloak/kronos-realm.json` -- it is **not** one of the realm's
`defaultDefaultClientScopes`, so a client created fresh via the Admin API
(this PoC's own `kronos-ci-verifier`, created to get a password-grant-
capable client since every real shipped client has
`directAccessGrantsEnabled: false`) does not get it automatically. First
real run reproduced this exactly: real login succeeded, real JWT had a real
`roles` claim, but zero `dashboard_roles` claim -- so
`kronos-generic-tenant`'s real rolesmapping (`backend_roles`) never
matched, and every DLS-scoped search 403'd. **Fixed:**
`provision_ci_org_b.py` explicitly attaches the real `kronos-dashboard-roles`
client scope to the new client (mirroring `opensearch-dashboards`'s own
wiring), confirmed fixed by the same request then returning real,
correctly-isolated search results.

This third finding is also a real, useful signal for anyone building a
*fourth* JWT-issuing client in the future (a CLI tool, a service integration,
etc.): **`directAccessGrantsEnabled` clients that need to drive
OpenSearch DLS directly must be given `kronos-dashboard-roles` explicitly** --
not documented anywhere before this PoC found it the hard way.

## What was actually run (MINIMUM BAR, all three real, all captured in `output.txt`)

Real, one real run, real captured output (`run_poc.sh` -> `output.txt`; also see `verify_security_stack.py`):

- **(a) OpenSearch security genuinely enabled + real DLS/tenant-role
  provisioning:** `opensearch-init` (the real, unmodified
  `provision_opensearch_security.py`) ran against the real 2.13.0 container
  with `DISABLE_SECURITY_PLUGIN` removed -- `openid authc domain
  configured` / `kronos-generic-tenant role + rolesmapping ensured`, both
  real HTTP calls against a real HTTPS-only OpenSearch.
- **(b) Real Keycloak + real `kronos-realm.json` import + a real provisioned
  org + a real JWT the real backend validates:** `keycloak-init` (the real,
  unmodified `provision_keycloak_org.sh`) created the real `kronos-test`
  org and linked the three real realm-imported users; a real password-grant
  login then produced a real JWT that
  `src/external/middleware/keycloak_auth.py`'s unmodified
  `KeycloakTokenValidator.validate_and_extract()` genuinely validated
  (real JWKS fetch, real signature check -- confirmed rejecting a tampered
  token with a real `AuthenticationError`) and turned into a real
  `TenantContext`.
- **(c) An I1-equivalent tenant-isolation proof:** two real users in two
  real, different Keycloak Organizations (`kronos-test` from the shipped
  `keycloak-init`, `kronos-ci-org-b` from this directory's
  `provision_ci_org_b.py`) each see **only** their own org's document
  through OpenSearch's real DLS enforcement, driven by their own real
  Keycloak-issued tokens -- something that could not even be expressed
  against the old `DISABLE_SECURITY_PLUGIN=true` stack (no security plugin
  loaded at all, so no DLS, no roles, no isolation of any kind).

**Result: 11/11 real checks passed** (`output.txt`; also independently
re-run as `tests/integration/test_security_enabled_stack.py`, **3/3 passed**
against the same live stack -- see that file for the slimmed pytest-shaped
version of the same real checks, wired into
`.github/workflows/security-integration-tests.yml`).

## Files

- `docker-compose.override.yml` -- **local-verification-only** host-port
  remap (this host already runs `docker-compose.dev.yml` on every one of
  `docker-compose.test.yml`'s standard ports); NOT used in real CI, which
  has no conflicting stack and uses the shipped file's standard ports directly.
- `provision_ci_org_b.py` -- PoC-local (not shipped): creates a second real
  org + user + a `directAccessGrantsEnabled` client, purely to prove
  cross-org isolation. Real production `scripts/provision_keycloak_org.sh`
  is invoked unmodified as a subprocess, not reimplemented.
- `verify_security_stack.py` -- the real verification (password-grant
  logins, `KeycloakTokenValidator`, `OpenSearchClient` bulk-index + DLS
  search), mirroring `poc/keycloak_opensearch_dls/run_poc.py`'s own
  already-established pattern.
- `run_poc.sh` -- full reproducible orchestration: brings up the real
  `docker-compose.test.yml` (project name `kronos-poc-cisec`, fully
  isolated from the shared dev stack), waits for real health, runs the real
  `opensearch-init`/`keycloak-init`, provisions org B, runs the real
  verification, tears down (`KEEP_STACK=1` to leave it up for inspection).
- `output.txt` -- captured transcript of the last real run (11/11 passed,
  real boot timing).

## How to reproduce

```bash
cd poc/ci_security_enabled_stack
bash run_poc.sh                 # tears its own stack down when done
KEEP_STACK=1 bash run_poc.sh    # leaves kronos-poc-cisec-* up for inspection
```

## Cleanup

```bash
docker compose -p kronos-poc-cisec \
  -f docker/docker-compose.test.yml -f poc/ci_security_enabled_stack/docker-compose.override.yml \
  down -v --remove-orphans
```
