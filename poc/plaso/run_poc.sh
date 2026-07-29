#!/usr/bin/env bash
# PoC: run the REAL docker/plaso/kronos-plaso-worker.py, inside the REAL
# pinned image (plaso==20260512, from docker/plaso/Dockerfile), against a
# real forensic artifact (Windows Prefetch, taken from Plaso's own test
# corpus - see tests/fixtures/samples/real/NOTICE.md).
#
# This does not reimplement anything: it is the exact ENTRYPOINT the
# FirecrackerLauncher (src/external/sandbox/firecracker.py) subprocess-execs
# in production, just invoked directly so the JSONL it emits can be
# inspected by hand.
set -euo pipefail
cd "$(dirname "$0")/../.."

SAMPLE=tests/fixtures/samples/real/CMD.EXE-087B4001.pf
OUT=poc/plaso/output.jsonl

docker run --rm \
  -v "$(pwd)/$SAMPLE:/mnt/evidence/CMD.EXE-087B4001.pf:ro" \
  kronos-poc-plaso:20260512 \
  --evidence-path /mnt/evidence/CMD.EXE-087B4001.pf \
  --evidence-id 00000000-0000-0000-0000-000000000001 \
  --case-id 00000000-0000-0000-0000-00000000000c \
  --org-id test-org-id \
  --org-alias testorg \
  --sha256 deadbeef \
  > "$OUT"

echo "--- record count ---"
wc -l < "$OUT"
echo "--- first record ---"
head -1 "$OUT" | python3 -m json.tool
