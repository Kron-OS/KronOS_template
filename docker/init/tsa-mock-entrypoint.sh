#!/bin/sh
# Generates a throwaway CA + TSA certificate/key and openssl `ts` config,
# then execs the real RFC 3161 responder (tsa_mock_server.py). Same
# openssl invocations already proven against the real production
# RFC3161TimestampService in poc/rfc3161/run_poc.py and
# tests/unit/test_tsa_round_trip.py -- not reinvented here.
set -eu

WORKDIR=/tsa
mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo "extendedKeyUsage=critical,timeStamping" > tsa_ext.cnf

openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.pem \
  -days 2 -nodes -subj "/CN=KronOS Test TSA CA"
openssl req -newkey rsa:2048 -keyout tsa.key -out tsa.csr \
  -nodes -subj "/CN=KronOS Test TSA"
openssl x509 -req -in tsa.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out tsa.pem -days 2 -extfile tsa_ext.cnf

cat > tsa.cnf <<EOF
[tsa]
default_tsa = tsa_config1

[tsa_config1]
dir = $WORKDIR
serial = $WORKDIR/tsaserial
crypto_device = builtin
signer_cert = $WORKDIR/tsa.pem
certs = $WORKDIR/ca.pem
signer_key = $WORKDIR/tsa.key
signer_digest = sha256
ess_cert_id_alg = sha256
default_policy = 1.2.3.4.5.6.7.8.1
digests = sha256
accuracy = secs:1
clock_precision_digits = 0
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
EOF

echo "[tsa-mock] throwaway CA + TSA cert/key + openssl ts config ready in $WORKDIR"
exec python3 /tsa_mock_server.py
