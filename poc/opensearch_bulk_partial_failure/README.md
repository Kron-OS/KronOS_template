# PoC: Fix `OpenSearchClient.bulk_index` silent partial-failure bug (A4)

## Objective
Demonstrate and verify the fix for a critical data-loss defect: `OpenSearchClient.bulk_index` was silently swallowing per-document errors during bulk indexing, returning a reduced success count with no exception. This violated CLAUDE.md §1.8 ("fail loudly, never silently") and could cause timeline records to vanish from a case with no audit trail.

## Versions (pinned, verified from this repo)
- OpenSearch: **2.11.1** (`docker/docker-compose.dev.yml`, running on host at `https://localhost:9200`)
- Client library: **opensearch-py[async]>=2.6** (`pyproject.toml`, pip resolves to 3.2.0)
- Python: **3.11+** (`/home/reca/venv/bin/python3`)

## What this PoC proves

### Before: The Bug
1. A bulk request with 3 documents is sent, where document 2 will fail (invalid date format)
2. OpenSearch's `_bulk` API returns a response with `"errors": true` and item[1] containing an error dict
3. The old code at `src/adapter/opensearch/client.py:106-107` counted errors and silently returned a reduced count (2 out of 3)
4. **No exception was raised.** The caller saw only the success count and had no way to know a document failed.
5. Timeline records were lost; no audit flag; no retry signal.

**Evidence (captured before fix):**
```
bulk_index returned 2 (out of 3) with NO EXCEPTION
Expected: 2 successes, 1 failure → should have raised StorageError
Actual: returned 2 silently → timeline records are lost!
```

### After: The Fix
1. Same 3-document bulk request with 1 guaranteed failure
2. New code in `src/adapter/opensearch/client.py:96-144` now:
   - Extracts per-document errors from response["items"]
   - **Raises StorageError immediately** if any document fails
   - Includes detailed context: failed_count, succeeded_count, and a list of each failed document with its error reason
3. The exception propagates to `TimelineIngestionService._flush()` → `ingest_records()`, which catches it, logs INGEST_FAILED to audit, and re-raises.
4. Evidence state remains consistent; the parse task will be retried or marked terminal per Celery's retry policy.

**Evidence (captured after fix):**
```
✓ FIXED: bulk_index raised StorageError as expected:
  Message: OpenSearch bulk indexing had 1 document(s) fail out of 3 total. 
           Successfully indexed: 2. This is not a silent failure; 
           the documents that failed are listed in context['failed_documents'].
  Context details:
    total_documents: 3
    failed_count: 1
    succeeded_count: 2
    failed_documents:
      - doc_id=doc-2, index=kronos-poc-partial-failure, status=400
        error_type=mapper_parsing_exception
        reason=failed to parse field [@timestamp] of type [date]...
```

## Running the PoC

### Prerequisites
- Live OpenSearch 2.11.1 cluster running on `https://localhost:9200` with credentials `admin:admin` (the dev stack)
- Python venv at `/home/reca/venv/` with `opensearch-py[async]>=2.6` installed

### Execute
```bash
cd /home/reca/Claude/Kronos/KronOS_template
source /home/reca/venv/bin/activate
python poc/opensearch_bulk_partial_failure/run_poc.py
```

### What it does
1. Connects to the live cluster and verifies it's 2.11.1
2. Creates a test index with a strict date mapping (`format: strict_date_time`)
3. Prepares 3 documents; document 2 has an invalid date that will fail
4. Calls `bulk_index()` and captures the exception (or lack thereof)
5. Prints the exception details and the raw `_bulk` API response for inspection
6. Cleans up the test index

### Expected output
- **With the fix applied:** exception is raised with detailed error info (see "After: The Fix" above)
- **Without the fix:** no exception, silent return of reduced count (see "Before: The Bug" above)

## Key Design Decisions

### Why raise on ANY partial failure?
- **Simplicity & debuggability:** any signal mismatch between requested and indexed count is surfaced immediately, not silently swallowed
- **Audit trail:** the exception forces a log entry (INGEST_FAILED in audit) so operators know data didn't fully land
- **Retry semantics:** Celery can distinguish between a transient network error (causes task retry) and a document-specific parsing error (would still fail on retry). Both now raise exceptions; Celery's exception handlers + evidence state FSM determine retry policy.

### Why not retry just the failed documents?
- Retrying a subset within a batch is possible but adds complexity: need to track doc_ids, maintain partial state, and distinguish "this doc will never parse" (terminal) from "OpenSearch was temporarily overloaded" (transient)
- The current Celery retry policy (retries up to N times, then marks evidence ERROR) already handles this at the task level
- If a single document in a batch is permanently invalid (e.g., a date field that will never parse), re-running the whole batch won't fix it anyway

### Why include per-document errors in context?
- Auditable: the caller can log `exc.context["failed_documents"]` for triage
- Debuggable: operators can see which doc_id failed and what OpenSearch said was wrong
- Observable: can be fed to monitoring/alerting if needed (e.g., flag unusual error rates)

## Files Changed
- `src/adapter/opensearch/client.py`: Modified `bulk_index()` to raise `StorageError` on partial failure
- `src/application/timeline_ingest.py`: No changes needed; already has exception handling that logs INGEST_FAILED and re-raises

## Tests
Unit and integration tests are added to verify:
1. Happy path: all documents succeed, no exception, correct count returned
2. Partial failure: some documents fail, `StorageError` is raised with accurate context
3. Complete failure: all documents fail, `StorageError` is raised
4. Empty batch: returns 0, no exception

(See `tests/unit/adapter/test_opensearch_client.py` and `tests/integration/test_timeline_ingest.py` for implementation.)

## Audit & Compliance
- ✓ §1.8 "fail loudly": now raises exception on any partial failure
- ✓ §1.4 "audit every mutation": exceptions logged to INGEST_FAILED audit event
- ✓ §1.3 "derived opinions never mutate primary": no change to evidence state; Celery task retry policy determines next action
- ✓ Verification-first (§F): PoC uses real cluster, real client library, captured output stored
