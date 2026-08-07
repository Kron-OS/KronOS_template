#!/usr/bin/env bash
# L1 PoC: real OpenSearch query-latency workload against the live, already-
# populated kronos-dev cluster (2.11.1, pinned in docker-compose.dev.yml).
#
# Runs from inside docker-opensearch-1 (curl is present there and it avoids
# an extra network hop through nginx/TLS that would measure nginx, not
# OpenSearch). Fires N repeated, realistic queries against the real
# `kronos-*` indices left behind by this session's own H1-I2 PoC work
# (docs.count sums to 1570+ real documents across 50+ real case-scoped
# indices per `_cat/indices` -- captured separately in output.txt), and
# reports p50/p95 client-observed latency (curl's own `time_total`, i.e.
# includes TLS/HTTP overhead the same way a real caller would see it).
#
# CLAUDE.md SS B.6 baseline: "OpenSearch query: <500ms p95 latency".
#
# Usage: docker exec docker-opensearch-1 bash /tmp/opensearch_query_p95.sh

set -euo pipefail

BASE="https://localhost:9200"
AUTH="admin:admin"
N_PER_QUERY=20   # 4 query shapes x 20 = 80 total requests, within the 50-100 asked for

TIMES_FILE=$(mktemp)
trap 'rm -f "$TIMES_FILE"' EXIT

run_query() {
  local label="$1" method="$2" path="$3" body="$4"
  for i in $(seq 1 "$N_PER_QUERY"); do
    if [ -n "$body" ]; then
      t=$(curl -sk -u "$AUTH" -X "$method" "$BASE$path" \
            -H 'Content-Type: application/json' -d "$body" \
            -o /dev/null -w '%{time_total}')
    else
      t=$(curl -sk -u "$AUTH" -X "$method" "$BASE$path" \
            -o /dev/null -w '%{time_total}')
    fi
    echo "$label $t" | tee -a "$TIMES_FILE" >/dev/null
    echo "$label iter=$i time_s=$t"
  done
}

echo "=== cluster/indices context ==="
curl -sk -u "$AUTH" "$BASE/_cluster/health"
echo
curl -sk -u "$AUTH" "$BASE/kronos-*/_count"
echo
echo "=== running $((N_PER_QUERY * 4)) real queries (4 shapes x $N_PER_QUERY) ==="

run_query "count_all" GET "/kronos-*/_count" ""

run_query "match_all_size20" GET "/kronos-*/_search" \
  '{"size":20,"query":{"match_all":{}},"sort":[{"@timestamp":"desc"}]}'

run_query "term_event_code" GET "/kronos-*/_search" \
  '{"size":20,"query":{"term":{"event.code":"4624"}}}'

run_query "terms_agg_parser" GET "/kronos-*/_search" \
  '{"size":0,"aggs":{"by_parser":{"terms":{"field":"kronos.parser"}}}}'

echo "=== computing p50/p95 across all $(wc -l < "$TIMES_FILE") requests ==="
awk '{print $2}' "$TIMES_FILE" | sort -n > "${TIMES_FILE}.sorted"
n=$(wc -l < "${TIMES_FILE}.sorted")
p50_idx=$(( (n * 50 + 99) / 100 ))
p95_idx=$(( (n * 95 + 99) / 100 ))
[ "$p50_idx" -lt 1 ] && p50_idx=1
[ "$p95_idx" -lt 1 ] && p95_idx=1
[ "$p95_idx" -gt "$n" ] && p95_idx=$n
p50=$(sed -n "${p50_idx}p" "${TIMES_FILE}.sorted")
p95=$(sed -n "${p95_idx}p" "${TIMES_FILE}.sorted")
p_max=$(tail -1 "${TIMES_FILE}.sorted")
p_min=$(head -1 "${TIMES_FILE}.sorted")
mean=$(awk '{s+=$1} END {printf "%.6f", s/NR}' "${TIMES_FILE}.sorted")

echo "n_requests=$n"
echo "min_s=$p_min"
echo "p50_s=$p50"
echo "p95_s=$p95"
echo "max_s=$p_max"
echo "mean_s=$mean"
echo "BASELINE_TARGET=0.500s p95"
awk -v p95="$p95" 'BEGIN { if (p95 < 0.5) print "VERDICT=PASS"; else print "VERDICT=FAIL" }'
