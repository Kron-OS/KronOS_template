# Timeline Ingestion Subsystem

Covers the `INGESTING → COMPLETE` transition and OpenSearch indexing.

## ECS Schema

Every indexed document must include:

```json
{
  "@timestamp": "2024-09-14T13:42:01.123Z",
  "event": {
    "kind": "event",
    "category": ["authentication"],
    "action": "logon",
    "module": "evtx",
    "dataset": "windows.security",
    "original": "<raw record, max 32 KB>",
    "timezone": "UTC"
  },
  "host": { "name": "WIN-DC01", "os": { "type": "windows" } },
  "user": { "name": "alice", "domain": "EXAMPLE" },
  "message": "...",
  "kronos": {
    "tenant_id":       "f4d8...",
    "org_alias":       "acme",
    "case_id":         "b2a9...",
    "evidence_id":     "1c77...",
    "evidence_sha256": "9af2e3...",
    "tz_fold":         0,
    "parser_version":  "plaso/20260512",
    "ingest_id":       "task-uuid-..."
  }
}
```

The `kronos.*` block is mandatory on every document. `event.original` is capped at 32 KB — oversized originals are uploaded to MinIO and referenced via `kronos.original_object_key`.

## Deterministic Document ID

```python
_id = sha1(evidence_id + ":" + parser + ":" + record_index).hexdigest()
```

This ensures idempotent upserts on retry — re-running an `index_chunk` task produces zero duplicates.

## Index Naming

```
kronos-{org_alias}-case-{case_id}-{yyyymm}
```

Write alias: `kronos-{org_alias}-case-{case_id}` (ISM rollover target).

## ISM Rollover Policy

Triggers: index size ≥ 30 GB **or** age ≥ 30 days (whichever comes first).

This bounds shard count: ≤ 1 000 shards per 16 GB of OpenSearch heap.

## Bulk Ingestion

- Batch size: 500 documents.
- Flush interval: 30 seconds.
- On retry: use `op_type=index` (upsert) instead of `op_type=create` to avoid duplicates.

## ECS Normalization Steps

Per `TimelineIngestionService`:
1. Receive raw Plaso/evtx-rs/text record.
2. Map Plaso fields → ECS field names.
3. Inject `kronos.*` provenance block.
4. Truncate `event.original` to 32 KB; spill to MinIO if over.
5. Set deterministic `_id`.
6. Add to bulk batch; flush on batch size or timeout.

## Document-Level Security

Every tenant's OpenSearch role has a DLS filter:
```yaml
dls: '{"term": {"kronos.tenant_id": "${user.name}"}}'
```

This is defence-in-depth; the primary isolation is the per-org index naming scheme.

## `finalize_evidence` Task

1. Queries OpenSearch for `doc_count` in `kronos-{org_alias}-case-{case_id}-*` scoped to this `evidence_id`.
2. Compares `indexed_docs` to `parsed_records` (stored in Redis during parse).
3. If equal: `evidence.status = COMPLETE`, writes `audit_log` action `evidence.ingest.success`.
4. If mismatch: `evidence.status = ERROR`, `error_reason = "ingest_count_mismatch"`, auto-retried once.
