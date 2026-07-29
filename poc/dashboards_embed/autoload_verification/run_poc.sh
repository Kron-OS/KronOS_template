#!/usr/bin/env bash
# Decodes the real _a/_g/_q RISON blobs the updated get_dashboard_url()
# route produces with the real pinned rison-node@1.0.2 (matching
# opensearch-project/OpenSearch-Dashboards@2.11.1's own package.json).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

rm -f /tmp/kronos_poc_autoload_a.txt /tmp/kronos_poc_autoload_g.txt /tmp/kronos_poc_autoload_q.txt
source ~/venv/bin/activate 2>/dev/null || true
python3 "$SCRIPT_DIR/run_poc.py"

echo ""
echo "### Decoding the real _a/_g/_q RISON blobs with the real pinned rison-node@1.0.2 ###"
set +e
docker run --rm \
  -v /tmp/kronos_poc_autoload_a.txt:/a.txt:ro \
  -v /tmp/kronos_poc_autoload_g.txt:/g.txt:ro \
  -v /tmp/kronos_poc_autoload_q.txt:/q.txt:ro \
  -w /app node:20-alpine sh -c "
mkdir -p /app && cd /app && npm install rison-node@1.0.2 --silent >/dev/null 2>&1
node -e \"
const rison = require('rison-node');
const fs = require('fs');
for (const [name, path] of [['_a', '/a.txt'], ['_g', '/g.txt'], ['_q', '/q.txt']]) {
  const str = fs.readFileSync(path, 'utf8').trim();
  console.log(name + ' input:', str);
  try {
    const decoded = rison.decode(str);
    console.log(name + ' DECODED OK:', JSON.stringify(decoded));
  } catch (e) {
    console.log(name + ' DECODE FAILED:', e.message);
    process.exit(1);
  }
}
process.exit(0);
\"
"
DECODE_STATUS=$?
set -e
echo "real rison-node@1.0.2 decode exit code: $DECODE_STATUS"
[ "$DECODE_STATUS" -eq 0 ]
