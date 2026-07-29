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
kubectl create secret generic kronos-postgres-secret \
  --namespace kronos \
  --from-literal=postgres-password=CHANGE_ME \
  --from-literal=password=CHANGE_ME

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
