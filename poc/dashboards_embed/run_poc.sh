#!/usr/bin/env bash
# PoC: cases.py's GET /{case_id}/dashboard-url route -- real FastAPI route
# logic (backend side only) + the real pinned rison-node@1.0.2 library
# (matching OpenSearch Dashboards 2.11.1's own package.json) to confirm the
# hand-built _g RISON blob is genuinely well-formed, not just "looks right."
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

rm -f /tmp/kronos_poc_dashboards_embed_g.txt
source ~/venv/bin/activate 2>/dev/null || true
python3 "$SCRIPT_DIR/run_poc.py"

echo ""
echo "### Decoding the real _g RISON blob with the real pinned rison-node@1.0.2 ###"
set +e
docker run --rm -v /tmp/kronos_poc_dashboards_embed_g.txt:/g.txt:ro -w /app node:20-alpine sh -c "
mkdir -p /app && cd /app && npm install rison-node@1.0.2 --silent >/dev/null 2>&1
node -e \"
const rison = require('rison-node');
const fs = require('fs');
const str = fs.readFileSync('/g.txt', 'utf8').trim();
console.log('Input RISON:', str);
try {
  const decoded = rison.decode(str);
  console.log('DECODED OK:');
  console.log(JSON.stringify(decoded, null, 2));
  process.exit(0);
} catch (e) {
  console.log('DECODE FAILED:', e.message);
  process.exit(1);
}
\"
"
DECODE_STATUS=$?
set -e
echo "real rison-node@1.0.2 decode exit code: $DECODE_STATUS"
[ "$DECODE_STATUS" -eq 0 ]
