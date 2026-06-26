# KronOS

**Forensically sound, multi-tenant evidence management and forensic timeline
analysis platform.**

KronOS ingests forensic artefacts (EVTX, CloudTrail, Nginx, Plaso-supported
formats), enforces chain-of-custody with a tamper-evident hash chain + RFC 3161
timestamping, scans and WORM-locks evidence, parses it into an ECS timeline in
OpenSearch, and isolates every tenant via Keycloak Organizations + RBAC.

- **Design authority:** [`Project_Specifications.md`](./Project_Specifications.md) + [`reviews/Part_*.md`](./reviews)
- **Backend implementation guide:** [`CLAUDE.md`](./CLAUDE.md)
- **Roadmap & progress:** [`roadmap.md`](./roadmap.md), [`PROGRESS.md`](./PROGRESS.md)
- **Security & deployment audit:** [`docs/SECURITY_AUDIT.md`](./docs/SECURITY_AUDIT.md) ⚠️ read before deploying

> ⚠️ **Pre-deployment notice.** A 2026-06 audit found a small number of
> deployment-blocking defects (NGINX upstream name, Docker runtime user, the
> Keycloak `organization` scope, and S3 bucket routing/naming). They are
> documented with severities and fixes in
> [`docs/SECURITY_AUDIT.md`](./docs/SECURITY_AUDIT.md). Resolve the **Critical**
> and **High** items before running in any shared or production environment.

---

## Architecture at a glance

```
                         ┌────────────┐
  Browser ──TLS──▶ NGINX │ rate-limit │──▶ FastAPI (uvicorn)  ──▶ Postgres (audit + metadata)
                  (SPA + │ CSP/HSTS   │        │                ──▶ MinIO  (quarantine → WORM evidence)
                  proxy) └────────────┘        │                ──▶ OpenSearch (ECS timeline, DLS)
                                               │                ──▶ Keycloak  (JWT, Organizations, step-up)
                                               ▼
                                    Redis ◀─ Celery workers ─▶ parsers (evtx-rs fast / Plaso in Firecracker)
                                               │
                              ClamAV (scan) · Vault+KES (SSE-KMS) · TSA (RFC 3161) · step-ca (mTLS)
```

Layering is strict (domain → application → adapter → external); the domain layer
imports no framework. See [`CLAUDE.md`](./CLAUDE.md) for the full design rules.

---

## Repository layout

```
src/                     FastAPI backend (domain / application / adapter / external)
kronos_attest/           Standalone offline audit-verification CLI (`kronos-attest`)
frontend/                React 19 + Vite + TanStack Router SPA
docker/                  Dockerfile, compose files, and per-service configs
  ├── docker-compose.dev.yml     14-service local stack
  ├── docker-compose.prod.yml    hardened stack (Vault, KES, secrets)
  ├── nginx/ keycloak/ kes/ vault/ pki/ wazuh/ falco/ fluent-bit/ plaso/ tusd/
charts/kronos/           Helm chart for Kubernetes (backend, celery, nginx, netpols, HPA, PDB)
scripts/                 provision_buckets.sh, provision_wazuh.sh
tests/                   unit/ (fast, no Docker) + integration/ (testcontainers)
docs/                    architecture, subsystem docs, runbooks, SECURITY_AUDIT.md
Makefile                 dev / test / lint / helm / build targets
```

---

## Prerequisites

| Tool | Version | For |
|------|---------|-----|
| Docker + Compose v2 | recent | local stack, integration tests |
| Python | 3.11+ | backend, tests, attest CLI |
| Node.js | 20+ | frontend |
| Helm + kubectl | 3.x / 1.27+ | Kubernetes deployment |
| `mc` (MinIO client) | latest | bucket provisioning |

---

## Quick start — local development

The dev stack runs everything in containers with insecure dev defaults
(security plugins disabled, dev secrets). **Never expose it publicly.**

```bash
# 1. Create your env file and adjust as needed
cp docker/.env.example docker/.env      # edit secrets before any non-laptop use

# 2. Bring up the full stack (postgres, redis, minio, opensearch[-dashboards],
#    keycloak, clamav, tusd, tsa, step-ca, backend, celery worker+beat, nginx)
make dev                 # foreground;  `make dev-detach` for background
make logs                # tail everything;  `make logs-backend` for one service

# 3. Provision per-org object-storage buckets (quarantine + WORM evidence + SSE-KMS)
ORG_ALIAS=dev MINIO_ROOT_USER=kronos_minio \
  MINIO_ROOT_PASSWORD=kronos_minio_dev_password \
  ./scripts/provision_buckets.sh

# 4. (optional) SIEM index template + DLS role
./scripts/provision_wazuh.sh
```

**Service endpoints (dev):**

| Service | URL | Notes |
|---------|-----|-------|
| API (direct) | http://localhost:8000 | FastAPI, `--reload` |
| API + SPA (via NGINX) | http://localhost | see audit H-1 before relying on this |
| Keycloak | http://localhost:8080 | admin / `admin` (dev) |
| MinIO console | http://localhost:9001 | `kronos_minio` / dev password |
| OpenSearch | http://localhost:9200 | security plugin disabled (dev only) |
| OpenSearch Dashboards | http://localhost:5601 | timeline iframe source |

**Dev Keycloak users** (realm `kronos`): `admin` (org-admin), `case-lead`,
`analyst`. Passwords are in `docker/keycloak/kronos-realm.json` (dev only).

Useful targets:

```bash
make shell-backend     # exec into the backend container
make shell-postgres    # psql into the dev DB
make reset-db          # DROP/CREATE public schema
make dev-down          # stop and remove the stack
```

### Frontend dev (hot reload, against the dev backend)

```bash
cp frontend/.env.example frontend/.env   # points at localhost:8080 / :8000
cd frontend && npm install
npm run dev                              # http://localhost:5173
```

---

## Running tests, linting, type-checks

Backend tests use the `~/venv` virtualenv (create it with
`python -m venv ~/venv && ~/venv/bin/pip install -e ".[dev]"`).

```bash
make test            # unit tests + coverage gate (≥80%)
make test-fast       # unit tests, quiet, no coverage gate
make test-integration   # spins up docker-compose.test.yml (Postgres + MinIO)
make lint            # ruff
make typecheck       # mypy --strict
make format-check    # black --check
make check           # lint + typecheck + format-check + test

cd frontend && npm test && npm run lint   # frontend
```

The audit added executable bug-reports under
`tests/unit/adapter/` and `tests/unit/application/`; they are `xfail` for open
defects so the suite stays green. An `xpass` means a defect was fixed and the
marker can be removed.

### Offline audit attestation (`kronos-attest`)

```bash
~/venv/bin/pip install -e .          # installs the `kronos-attest` entry point

# The audit-log export (a JSON list of event objects) is passed via --audit-log:
kronos-attest verify       --audit-log export.json --event-id <uuid>   # verify chain + locate event
kronos-attest merkle-root  --audit-log export.json                     # recompute the anchored root
kronos-attest merkle-proof --audit-log export.json --event-id <uuid>   # emit inclusion proof
kronos-attest day-report   --audit-log export.json --day 2026-06-26    # per-day attestation report
kronos-attest case-report  --audit-log export.json --case-id <uuid>    # per-case attestation report
```

---

## Production deployment

Two supported paths: **Docker Compose** (single host) and **Helm/Kubernetes**
(recommended). In both cases, first work through the **Critical/High** items in
[`docs/SECURITY_AUDIT.md`](./docs/SECURITY_AUDIT.md).

### Configuration (environment variables)

All backend config comes from env vars (`src/config.py`, pydantic-settings).
Secrets have **no defaults** — a missing required var fails fast at startup.

| Variable | Required | Purpose |
|----------|----------|---------|
| `DATABASE_URL` | ✅ | `postgresql+asyncpg://user:pass@host:5432/kronos` |
| `REDIS_URL` | ✅ | Redis DSN (Celery broker/result backend may be separate) |
| `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | ✅ | Celery transport |
| `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY` | ✅ | object storage |
| `MINIO_USE_TLS` | – | default `true`; set `false` only in dev |
| `OPENSEARCH_URL`, `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD` | ✅ | timeline index |
| `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET` | ✅ | auth |
| `VAULT_URL`, `VAULT_TOKEN` | ✅ | KMS / secrets |
| `TSA_URL` | – | RFC 3161 timestamping endpoint |
| `CLAMD_HOST`, `CLAMD_PORT` | – | ClamAV (default `localhost:3310`) |
| `MAX_UPLOAD_BYTES`, `PRESIGNED_URL_EXPIRY_SECONDS` | – | intake limits |
| `TLS_CERT_PATH`, `TLS_KEY_PATH`, `TLS_CA_PATH` | – | internal mTLS |
| `OPENSEARCH_DASHBOARDS_URL` | – | timeline iframe embed |

Never commit `.env`. In production, source secrets from Vault / Kubernetes
Secrets / Docker secrets — not from files in the image.

### Path A — Docker Compose (single host)

`docker/docker-compose.prod.yml` adds Vault + KES (SSE-KMS) and consumes
pre-built images `ghcr.io/<org>/backend:<tag>` plus Docker secrets.

```bash
cd docker
cp .env.example .env            # fill in REAL secrets (rotate the Keycloak secret)

# Provide production secrets (example for the bundled db_password secret)
printf '%s' "$(openssl rand -base64 32)" > secrets/db_password.txt

# Pull/point at a published image and start
export GITHUB_REPOSITORY=kron-os/kronos
export IMAGE_TAG=<git-sha-or-release>
docker compose -f docker-compose.prod.yml up -d

# One-time provisioning
ORG_ALIAS=<org> ./../scripts/provision_buckets.sh
./../scripts/provision_wazuh.sh
```

Production hardening checklist (cross-referenced to the audit):

- Enable TLS: uncomment the `:443` TLS 1.3 server block in
  `docker/nginx/nginx.conf` and mount certs from step-ca (audit **L-2**).
- Fix the NGINX upstream to `kronos-backend:8000` (audit **H-1**).
- Build a runtime-only image and run as a user that can read its deps
  (audit **H-2**, **M-5**).
- Move the Keycloak `organization` scope to default and confirm minted tokens
  carry it (audit **H-3**); configure the `acr`→`aal2` LoA mapping for step-up
  deletes (audit **M-3**).
- Reconcile bucket naming between the app and `provision_buckets.sh`
  (audit **C-1**, **C-2**) — without this, uploads and parsing fail.
- Turn the OpenSearch security plugin back on (the dev compose disables it).

Optional add-on stacks live in their own compose files and can be layered in:
`docker/vault/`, `docker/kes/`, `docker/pki/`, `docker/wazuh/`, `docker/falco/`,
`docker/fluent-bit/`.

### Path B — Kubernetes (Helm) — recommended

The chart in `charts/kronos/` deploys the backend, the Celery workers
(fast / Plaso / index / beat), NGINX, 4-zone NetworkPolicies, an HPA, a PDB, a
ServiceAccount, and a ConfigMap. It expects gVisor (fast parsers) and Firecracker
(Plaso) RuntimeClasses, and external managed Postgres/Redis/MinIO/OpenSearch/
Keycloak/Vault (configured via `values.yaml`).

```bash
make helm-lint                 # lint the chart
make helm-template             # render manifests for review

# Create the secrets the chart references (names per values.yaml), e.g.:
kubectl create namespace kronos
kubectl -n kronos create secret generic kronos-secrets \
  --from-literal=database-url='postgresql+asyncpg://...' \
  --from-literal=keycloak-client-secret='...' \
  --from-literal=vault-token='...'        # etc.

# Install
make helm-install-dev          # values-dev.yaml
make helm-install-prod         # values.yaml
make helm-uninstall
```

Review and override before installing prod: `image.*`, `replicaCount`,
`autoscaling`, `resources`, `ingress` (host + TLS), `keycloak.*`, `opensearch.*`,
`minio.*`, `vault.*`, `celery.*`, `networkPolicies.*`, and the
`gvisorRuntimeClass` / `firecrackerRuntimeClass` names.

### Building & publishing images

```bash
make build                     # docker build -t kronos-backend:dev
make push                      # push ghcr.io/kron-os/kronos-backend:<sha>
```

CI (`.github/workflows/`): `test.yml` (unit+integration), `build.yml` (Trivy
scan + Syft SBOM + image build), `deploy.yml` (registry push, post-merge).

---

## Day-2 operations

- **Audit chain & attestation.** `anchor_audit_log` (Celery beat, 02:00 UTC)
  computes the daily Merkle root and anchors it via the TSA. Verify exports
  offline with `kronos-attest` (above). The hash chain is verified using a
  running previous-hash, so DB rewrites are detectable.
- **Scheduled maintenance (Celery beat).** `abort_orphan_uploads` (hourly, 2h
  timeout) and `abort_orphan_parses` (hourly :30, 3h timeout) reap stuck work.
- **Evidence lifecycle.** `UPLOADING → SCANNING → HASHING → RECEIVED → PARSING →
  COMPLETE` (or `ERROR`). Promotion copies into the WORM bucket; deletion removes
  only platform metadata — the WORM object is retained until its Object Lock
  expires, and requires org-admin + an `aal2` step-up ticket.
- **SIEM & runtime detection.** Wazuh rules (`docker/wazuh/etc/`), Falco rules
  (`docker/falco/`), and the Fluent-bit pipeline ship app/celery/falco/nginx logs
  to OpenSearch + Wazuh. Triage guidance: `docs/runbooks/siem-alert-response.md`.
- **Backups.** Persist and back up the Postgres volume (audit + metadata), the
  MinIO evidence buckets (WORM), and Vault's storage (KMS keys). Losing Vault
  means losing access to SSE-KMS-encrypted evidence.

---

## License

See [`LICENSE`](./LICENSE).
