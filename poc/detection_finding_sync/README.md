# C4 · Detection entity + triage FSM + audited finding sync

Verifies `src/domain/detection.py` (`Detection`, `DetectionTriageState` FSM),
`src/application/detection_sync.py` (`DetectionSyncService`),
`src/application/detection_triage.py` (`DetectionTriageService`),
`src/adapter/opensearch/findings_client.py` (`SecurityAnalyticsFindingsClient`),
and `src/adapter/repository/postgres_detection.py` against the real, live
dev-stack OpenSearch 2.11.1 Security Analytics plugin and real PostgreSQL.

## Versions pinned

OpenSearch 2.11.1 (same cluster A1-C2 verified against). PostgreSQL as
pinned in `docker-compose.dev.yml`. `sqlalchemy`/`asyncpg` as pinned in
`pyproject.toml`.

## Run

```
source ~/venv/bin/activate
python poc/detection_finding_sync/run_poc.py
```

Requires the real dev stack up, a real bootstrap detector + real findings
already present (see the module docstring in `run_poc.py` for the exact,
real setup steps — this PoC's own sync code is strictly read-only against
OpenSearch, so the bootstrap is manual, one-time PoC setup, not something
`DetectionSyncService` itself ever does).

## Result: 20 passed, 0 failed (see `output.txt` for the full real run)

## Real findings from building this

1. **The findings index name this session had assumed was wrong.** Earlier
   verification this session (checking whether real findings still existed
   from C1's work) queried `.opensearch-sap-findings-*` and got zero hits —
   which was reported as "findings were cleaned up." That index pattern
   **does not exist**: real OpenSearch 2.11.1 Security Analytics findings
   live in **per-log-type** indices, `.opensearch-sap-{log_type}-findings-*`
   (e.g. `.opensearch-sap-network-findings-*`). The real detector created
   for this PoC produced real findings immediately once queried against the
   correct index.

2. **SA detectors only evaluate documents indexed after the monitor's own
   last-run cursor — not pre-existing ones.** A detector created against an
   already-populated real case index produced zero findings until 10 of
   that index's real Suricata EVE documents were re-indexed with a fresh
   `@timestamp` (a real, non-obvious operational fact about how SA
   monitors work, not a KronOS bug).

3. **A real finding document's shape**, confirmed directly (not assumed):
   ```
   {'correlated_doc_ids', 'execution_id', 'id', 'index', 'monitor_id',
    'monitor_name', 'queries', 'related_doc_ids', 'timestamp'}
   ```
   `queries` is a **list** — a single finding can match multiple rules
   simultaneously — so `Detection.rule_matches` is a tuple, never a single
   rule id, matching what the real data actually carries (see
   `DetectionRuleMatch`'s docstring). The finding's own top-level `id` is a
   flat `keyword` field (confirmed via a live mapping check) — unlike the
   `queries` field on this same document, or the unrelated
   `detectors-config` index's `name` field that C2's idempotency bug hit —
   so it was safe to use directly as the dedup key, no nested-query
   workaround needed here.
4. **Real ATT&CK technique tags** (`attack.t1021.001` — remote-services
   lateral movement) come through on the matched rule's `tags`, exposed via
   `Detection.attack_tags` for C5's later coverage-measurement work.

## What Part 0/1 prove (real sync)

- Real findings exist for the bootstrap detector in the correct index
  (confirmed directly, not assumed) before any sync code runs.
- `DetectionSyncService.sync_org_findings()` creates real `Detection` rows
  in real Postgres from real findings — 10 created on the first run.
- Every stored `Detection.org_id` is the **syncing tenant's own** org_id
  (roadmap invariant #3 — never read from the finding document).
- Every new `Detection` starts `NEW`, carries a real `rule_id`
  (`1fc0809e-06bf-4de3-ad52-25e5263b7623`, the real t1021.001 rule), and has
  its `case_id` correctly parsed from the finding's real source index name.

## What Part 2 proves (idempotency)

- Re-running sync creates **zero** new rows — same finding_id set, same
  count, checked rigorously (not just a row-count match, which could hide
  N deleted + N different created).

## What Part 3 proves (audited triage FSM)

- A real `NEW → INVESTIGATING → TRUE_POSITIVE` transition is applied and
  persisted, confirmed by re-reading from real Postgres (not trusting the
  in-memory return value).
- Exactly 2 real `DETECTION_TRIAGE_TRANSITIONED` audit events exist for
  this detection, with the second's `prev_row_hash` matching the first's
  `row_hash` — the real hash chain link, not asserted from code reading.
- `AuditLogService.verify_chain()` confirms the **org's entire real audit
  history** (not just this run) is still intact after these mutations.

## What Part 4 proves (illegal transitions rejected)

- `NEW → TRUE_POSITIVE` (skipping `INVESTIGATING`) raises
  `DetectionStateError` for real, does **not** mutate the persisted state,
  and produces its own real `DETECTION_TRIAGE_TRANSITION_FAILED` audit
  event — a rejected attempt is itself an audited fact, not silently
  dropped.
- A terminal `TRUE_POSITIVE` detection also rejects any further
  transition — no reopen loophole.

## Cleanup

The throwaway bootstrap detector is deleted at the end (not part of any
committed `src/` path). The real findings it already produced remain in
`.opensearch-sap-network-findings-*` (findings are independent, immutable
records — deleting a detector doesn't delete its past findings), and the
real `Detection` + `audit_log` rows this PoC created are deliberately left
in Postgres as inspectable proof of the run.
