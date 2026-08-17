# KronOS Deployment Guide

## Prerequisites

- Docker 24+ and Docker Compose v2
- kubectl 1.28+
- Helm 3.14+
- `step` CLI (smallstep) for PKI operations
- `vault` CLI for secret management

## Local Development

### 1. Start the full dev stack

```bash
# Copy env template
cp docker/.env.example docker/.env
# Edit docker/.env with dev credentials (dev defaults work out of the box)

# Start all services
make dev
```

Services available after startup:
| Service | URL | Credentials |
|---|---|---|
| Backend API | http://localhost:8000/docs | — |
| Keycloak Admin | http://localhost:8080/admin | admin / admin |
| MinIO Console | http://localhost:9001 | kronos_minio / kronos_minio_dev_password |
| OpenSearch | http://localhost:9200 | — (security disabled in dev) |
| OS Dashboards | http://localhost:5601 | — |
| Frontend (Vite) | http://localhost:5173 | — |

### 2. Start the frontend separately

```bash
cd frontend && npm run dev
# or
make frontend-dev
```

### 3. Run tests

```bash
make test           # unit tests only (fast, no Docker)
make test-integration  # integration tests (requires Docker)
```

---

## Kubernetes Deployment

### Prerequisites

1. **cert-manager** installed (for step-ca-issued TLS certs):
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
kubectl wait --for=condition=Ready pod -l app=cert-manager -n cert-manager --timeout=120s
```

2. **step-ca ClusterIssuer** (after PKI bootstrap):
```bash
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: step-ca-issuer
spec:
  acme:
    server: https://step-ca.kronos.svc.cluster.local:9443/acme/acme/directory
    privateKeySecretRef:
      name: step-ca-issuer-key
    solvers:
      - http01:
          ingress:
            class: nginx
EOF
```

3. **vault-agent-injector** installed:
```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install vault hashicorp/vault \
  --namespace vault --create-namespace \
  --set "server.ha.enabled=true" \
  --set "injector.enabled=true"
```

### Create required secrets

```bash
# Create namespace
kubectl create namespace kronos

# Database credentials
# replication-password is required because charts/kronos/values.yaml sets
# postgresql.architecture=replication (Gap Audit V10/X2a streaming
# replication) -- the Bitnami chart's default
# auth.secretKeys.replicationPasswordKey is "replication-password" and it
# must exist in this secret for the read replica to authenticate to the
# primary.
kubectl create secret generic kronos-postgres-secret \
  --namespace kronos \
  --from-literal=postgres-password=CHANGE_ME \
  --from-literal=password=CHANGE_ME \
  --from-literal=replication-password=CHANGE_ME

# Redis password
kubectl create secret generic kronos-redis-secret \
  --namespace kronos \
  --from-literal=redis-password=CHANGE_ME

# Keycloak client secret
kubectl create secret generic kronos-keycloak-secret \
  --namespace kronos \
  --from-literal=client-secret=CHANGE_ME

# MinIO credentials
kubectl create secret generic kronos-minio-secret \
  --namespace kronos \
  --from-literal=access-key=CHANGE_ME \
  --from-literal=secret-key=CHANGE_ME

# OpenSearch credentials
kubectl create secret generic kronos-opensearch-secret \
  --namespace kronos \
  --from-literal=username=admin \
  --from-literal=password=CHANGE_ME

# Combined app secrets (injected via envFrom)
kubectl create secret generic kronos-app-secrets \
  --namespace kronos \
  --from-literal=DATABASE_URL="postgresql+asyncpg://kronos:CHANGE_ME@postgres:5432/kronos" \
  --from-literal=REDIS_URL="redis://:CHANGE_ME@redis:6379/0" \
  --from-literal=MINIO_ACCESS_KEY="CHANGE_ME" \
  --from-literal=MINIO_SECRET_KEY="CHANGE_ME" \
  --from-literal=OPENSEARCH_USERNAME="admin" \
  --from-literal=OPENSEARCH_PASSWORD="CHANGE_ME" \
  --from-literal=KEYCLOAK_CLIENT_SECRET="CHANGE_ME" \
  --from-literal=VAULT_TOKEN="CHANGE_ME" \
  --from-literal=CELERY_BROKER_URL="redis://:CHANGE_ME@redis:6379/1" \
  --from-literal=CELERY_RESULT_BACKEND="redis://:CHANGE_ME@redis:6379/2"
```

### Install with Helm

```bash
# Development (low resources, no TLS)
make helm-install-dev

# Production
make helm-install-prod
```

**Postgres streaming replication cold-start note** (Gap Audit V10/X2a):
production values now set `postgresql.architecture: replication` +
`postgresql.readReplicas.replicaCount: 1` +
`postgresql.replication.numSynchronousReplicas: 1`. Real, empirically
confirmed risk (tested directly against the pinned `bitnami/postgresql`
image via `docker run`, not assumed -- see
`poc/postgres_replication/README.md` "real finding #2"): if
`numSynchronousReplicas: 1` is already active on a **fresh, first-ever**
install, any real write (Alembic migrations, Keycloak schema setup, the
first audit-log row) blocks indefinitely until the read-replica pod has
finished its own bootstrap and started streaming -- `synchronous_commit`
transactions wait for a synchronous standby ack that cannot exist yet.
For a first install, prefer either:
- installing once with `--set postgresql.replication.numSynchronousReplicas=0`,
  confirming `kubectl exec` into the primary pod shows
  `pg_stat_replication.state = streaming` for the replica, then
  `helm upgrade` back to the real `numSynchronousReplicas: 1` in
  `values.yaml` (`synchronous_standby_names` has `context=sighup` --
  reload-safe, no pod restart); or
- accepting a one-time delay on first migration/schema-setup jobs until
  the replica pod reports Ready.
Subsequent `helm upgrade`s of an already-running cluster are unaffected --
the replica already exists and is already streaming by then.

### Verify the installation

```bash
kubectl get pods -n kronos
kubectl get ingress -n kronos

# Test API health
kubectl port-forward svc/kronos-backend 8080:8000 -n kronos &
curl http://localhost:8080/health
```

---

## Post-Install Checklist

- [ ] All pods in `kronos` namespace are Running
- [ ] Ingress has TLS certificate (cert-manager)
- [ ] Keycloak realm `kronos` imported with dev users
- [ ] MinIO buckets provisioned: `scripts/provision_buckets.sh`
- [ ] OpenSearch index template applied (auto on first ingest)
- [ ] Wazuh agents registered on all nodes
- [ ] Vault PKI initialized and unsealed (3-of-5 Shamir shares)
- [ ] KES connected to Vault Transit engine
- [ ] MinIO SSE-KMS verified: `mc encrypt info myminio/kronos-evidence-*`

---

## OpenSearch Sizing Guidance (P2-W16)

**This repo's pinned defaults are conservative, demo/small-deployment
values, not a production sizing recommendation.** `docker/docker-compose.dev.yml`
and `docker-compose.test.yml` set `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m`;
`docker-compose.prod.yml` sets `-Xms2g -Xmx2g`. All three run a single
OpenSearch node. `charts/kronos/values.yaml`'s `opensearch:` block treats
OpenSearch as an external, pre-provisioned dependency (URL + secret
reference only, like MinIO/Vault/Keycloak) — this chart owns no
Deployment/StatefulSet or resource block for it at all, so there is
nowhere in Helm today that even expresses an OpenSearch sizing intent.

**Real heap-sizing guidance** (official OpenSearch documentation,
`docs.opensearch.org`, "Important settings" / "Tuning your cluster for
indexing speed"): heap should be set to roughly half of the node's
available system RAM ("we recommend half of system RAM" — the other half
is left for the OS page cache, which Lucene depends on for search
performance) — see [Important settings](https://docs.opensearch.org/docs/1.0/opensearch/install/important-settings/)
and [Tuning your cluster for indexing speed](https://docs.opensearch.org/latest/tuning-your-cluster/performance/).
Separately, a hard practical ceiling of **~32 GB heap** applies regardless
of how much RAM is available — above that, the JVM can no longer use
Compressed Ordinary Object Pointers (compressed 32-bit references), and
switches to full 64-bit pointers, increasing per-object memory overhead by
roughly 1.5x and effectively negating the benefit of the larger heap (this
specific mechanism is widely documented JVM/Elasticsearch/OpenSearch
operational guidance — e.g. [Opster's OpenSearch heap sizing guide](https://opster.com/guides/opensearch/opensearch-basics/opensearch-heap-size-usage-and-jvm-garbage-collection/) —
rather than restated on the specific official page fetched above, which
covers only the 50%-of-RAM rule directly).

**What a real "scales to 100+ GB evidence" production sizing claim would
still need before it could be made honestly** (none of this exists yet —
stated plainly rather than implied):

- A real measured ingest/query workload against a realistically-sized
  index (this repo has never run a sustained-volume test against
  OpenSearch — see `docs/ASSESSMENT_SYNTHESIS_2026-08.md` P2-W18 for the
  identical gap already tracked for the six EDR/SIEM connectors'
  throughput).
- A real decision on single-node-with-larger-heap vs. multi-node (official
  guidance above only sizes heap *within* a node; it does not say when a
  single node stops being appropriate — that threshold depends on
  measured shard count, query concurrency, and index size this repo has
  not yet measured for its own real ECS + `kronos.*` mapping).
- A real Helm resource block for OpenSearch (or an explicit, documented
  decision to keep treating it as an externally-managed dependency
  outside this chart's scope, matching Vault/Keycloak's existing
  treatment) — currently there is no mechanism in `charts/kronos/` to
  express a production OpenSearch sizing decision even once one is made.

Until that measurement work happens, treat this repo's pinned dev/prod
heap values as safe-for-demo defaults only, not as evidence the platform
has been sized for its own stated 100+ GB goal.

---

## Upgrading

```bash
# Pull latest chart
git pull

# Upgrade in-place (zero-downtime with 2+ replicas)
make helm-install-prod

# Rollback if needed
helm rollback kronos 1 --namespace kronos
```

---

## Troubleshooting

### Backend not starting

```bash
kubectl logs -l app.kubernetes.io/component=backend -n kronos --previous
# Check for missing environment variables or DB connectivity
```

### Keycloak realm not imported

Ensure `docker/keycloak/kronos-realm.json` is mounted and Keycloak has `--import-realm` flag.

### MinIO SSE-KMS not working

Verify KES is running and Vault Transit engine has the `kronos-evidence` key:
```bash
vault kv get secret/kronos/minio
vault write transit/keys/kronos-evidence type=aes256-gcm96
```
