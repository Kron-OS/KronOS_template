#!/usr/bin/env bash
# PoC driver: Vault Transit -> KES -> MinIO SSE-KMS, end to end.
# Pinned versions: hashicorp/vault:1.17, minio/kes:2024-06-17T15-47-05Z,
# minio/minio:latest -- see README.md for the gaps this had to work around
# relative to docker/vault, docker/kes, and roadmap.md's Prompt 5.2.
#
# Isolated container names (kronos-poc-vaultkes-*) and ports
# (18200 vault, 17373 kes, 29100/29101 minio) so this doesn't collide with
# the real dev stack or other agents' PoCs running on the same host.
set -euo pipefail
cd "$(dirname "$0")"

PROJECT=kronos-poc-vaultkes
COMPOSE="docker compose -p $PROJECT -f docker-compose.poc.yml"

echo "=== 1/8: regenerate throwaway mTLS PKI (CA -> kes-server, CA -> minio-client) ==="
rm -rf certs && mkdir -p certs
pushd certs >/dev/null
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3 -out ca.crt -subj "/CN=kronos-poc-vaultkes-ca"

openssl genrsa -out kes-server.key 2048 2>/dev/null
openssl req -new -key kes-server.key -out kes-server.csr -subj "/CN=kronos-poc-vaultkes-kes"
cat > kes-server.ext <<'EOF'
subjectAltName=DNS:kronos-poc-vaultkes-kes,DNS:kes,DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in kes-server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out kes-server.crt -days 3 -sha256 -extfile kes-server.ext

openssl genrsa -out minio-client.key 2048 2>/dev/null
openssl req -new -key minio-client.key -out minio-client.csr -subj "/CN=kronos-poc-vaultkes-minio"
openssl x509 -req -in minio-client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out minio-client.crt -days 3 -sha256
popd >/dev/null

echo "=== 2/8: compute the REAL KES identity for minio-client.crt ==="
# NOTE: this is SHA256(RawSubjectPublicKeyInfo), not SHA256(full DER cert) --
# see README.md gap #4. Only the `kes identity of` command from the pinned
# image is authoritative.
IDENTITY=$(docker run --rm -v "$PWD/certs:/certs:ro" --entrypoint /kes \
  minio/kes:2024-06-17T15-47-05Z identity of /certs/minio-client.crt)
echo "identity: $IDENTITY"
sed -i "s/identities:\n.*/identities:\n      - \"$IDENTITY\"/" kes-config.yml 2>/dev/null || true
python3 - "$IDENTITY" <<'PYEOF'
import re, sys
identity = sys.argv[1]
with open("kes-config.yml") as f:
    content = f.read()
content = re.sub(r'(identities:\n\s*- ")[0-9a-f]+(")', rf'\g<1>{identity}\g<2>', content)
with open("kes-config.yml", "w") as f:
    f.write(content)
PYEOF

echo "=== 3/8: bring up Vault + vault-init (verbatim from docker/vault/docker-compose.vault.yml) ==="
mkdir -p data
$COMPOSE up -d vault vault-init
until docker exec ${PROJECT}-vault vault status >/dev/null 2>&1; do sleep 1; done
sleep 2
docker logs ${PROJECT}-vault-init

echo "=== 4/8: extend Vault policy with kv/kes-keys/* (gap #2 -- see README) and fetch AppRole creds (gap #3) ==="
export VAULT_ADDR=http://127.0.0.1:18200
export VAULT_TOKEN=kronos-poc-root-token
curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/sys/mounts/kv" \
  -d '{"type":"kv","options":{"version":"1"}}' -o /dev/null -w "mount kv: %{http_code}\n" || true
curl -s -X PUT -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/sys/policies/acl/kronos-kes" \
  -d '{"policy":"path \"transit/keys/kronos-evidence\" { capabilities = [\"read\"] }\npath \"transit/encrypt/kronos-evidence\" { capabilities = [\"update\"] }\npath \"transit/decrypt/kronos-evidence\" { capabilities = [\"update\"] }\npath \"transit/generate-data-key/kronos-evidence\" { capabilities = [\"update\"] }\npath \"transit/datakey/plaintext/kronos-evidence\" { capabilities = [\"update\"] }\npath \"kv/kes-keys/*\" { capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"] }\n"}' \
  -w "\npolicy update: %{http_code}\n"

ROLE_ID=$(curl -s -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/auth/approle/role/kronos-kes/role-id" | jq -r '.data.role_id')
SECRET_ID=$(curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/auth/approle/role/kronos-kes/secret-id" | jq -r '.data.secret_id')
cat > .env <<EOF
VAULT_APPROLE_ID=$ROLE_ID
VAULT_APPROLE_SECRET=$SECRET_ID
EOF
echo "AppRole credentials written to .env"

echo "=== 5/8: bring up KES with corrected kes-config.yml (gap #1) ==="
$COMPOSE --env-file .env up -d --force-recreate kes
sleep 5
docker logs ${PROJECT}-kes | tail -15
echo "--- mTLS status check ---"
curl -sk https://127.0.0.1:17373/v1/status --cert certs/minio-client.crt \
  --key certs/minio-client.key --cacert certs/ca.crt -w "\nHTTP %{http_code}\n"

echo "=== 6/8: bring up MinIO with MINIO_KMS_KES_CAPATH (gap #5 -- note the exact name) ==="
$COMPOSE --env-file .env up -d --force-recreate minio
sleep 6
docker logs ${PROJECT}-minio | tail -15

echo "=== 7/8: mc client -- bucket, SSE-KMS, real object, headers ==="
docker rm -f ${PROJECT}-mc >/dev/null 2>&1 || true
docker run -d --network ${PROJECT}-net --name ${PROJECT}-mc --entrypoint sh minio/mc:latest -c "sleep 3600"
docker exec ${PROJECT}-mc mc alias set kronosminio http://${PROJECT}-minio:9000 kronos_minio kronos_minio_dev_password
docker exec ${PROJECT}-mc mc admin kms key status kronosminio
docker exec ${PROJECT}-mc mc mb kronosminio/kronos-evidence-poc || true
docker exec ${PROJECT}-mc mc encrypt set sse-kms kronos-evidence kronosminio/kronos-evidence-poc
docker exec ${PROJECT}-mc mc encrypt info kronosminio/kronos-evidence-poc

CANARY="KRONOS-SSE-KMS-PLAINTEXT-CANARY-$RANDOM"
echo "This is real KronOS evidence PoC plaintext content — SHOULD NOT be readable on disk. Marker: $CANARY." > /tmp/evidence_sample.txt
docker cp /tmp/evidence_sample.txt ${PROJECT}-mc:/tmp/evidence_sample.txt
docker exec ${PROJECT}-mc mc cp /tmp/evidence_sample.txt kronosminio/kronos-evidence-poc/evidence_sample.txt
docker exec ${PROJECT}-mc mc stat kronosminio/kronos-evidence-poc/evidence_sample.txt
echo "--- real raw S3 response headers ---"
docker exec ${PROJECT}-mc mc --debug stat kronosminio/kronos-evidence-poc/evidence_sample.txt 2>&1 | grep -i "x-amz-server-side-encryption\|HTTP/1.1 200"
echo "--- GET through S3 API (should return plaintext) ---"
docker exec ${PROJECT}-mc mc cat kronosminio/kronos-evidence-poc/evidence_sample.txt

echo "=== 8/8: raw on-disk bytes must NOT contain the canary ==="
if grep -rl "$CANARY" data/ 2>/dev/null; then
  echo "FAIL: plaintext canary found on disk -- encryption is NOT effective"
  exit 1
else
  echo "PASS: canary absent from raw on-disk files -- encrypted at rest"
fi
find data -path "*kronos-evidence-poc*" -type f -exec xxd {} \; | head -40

echo "=== Done. Containers left running for inspection. Tear down with: ==="
echo "  docker compose -p $PROJECT -f docker-compose.poc.yml down -v"
echo "  docker rm -f ${PROJECT}-mc"
