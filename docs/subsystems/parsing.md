# Parsing Subsystem

Covers the `RECEIVED → PARSING → INGESTING` evidence lifecycle phases.

## Parser Slots

| Slot | Queue | Sandbox | RAM | Used for |
|---|---|---|---|---|
| `evtx_rs` | `q.parse.fast` | gVisor (`runsc`) | 1 GB | EVTX (Rust parser, 650–1600× faster than Plaso) |
| `plaso` | `q.parse.plaso` | Firecracker microVM | 2 GB | Prefetch, REGF, SQLite, journald, syslog, EML/MBOX |
| `plaso_heavy` | `q.parse.plaso.heavy` | Firecracker microVM | 4 GB | SRUM, Amcache (known to exceed 1.2 GB) |
| `text` | `q.parse.fast` | gVisor (`runsc`) | 1 GB | CSV, NDJSON, Nginx, CloudTrail, GCP, Azure |

## Sandbox Requirements

Both gVisor and Firecracker sandboxes:
- Read-only Wolfi rootfs + writable tmpfs scratch
- **No outbound network** — `--network=none` / no network device
- MinIO access via one-shot presigned GET URL injected at VM boot
- OOM (exit 137) → `error_reason="parser_oom"`, no retry

## Plaso Execution Model

```bash
# Inside Firecracker microVM
log2timeline.py \
  --parsers=win_gen \        # scoped preset, never default "everything"
  --output-time-zone=UTC \
  /tmp/scratch/{evidence_id}.plaso \
  /mnt/evidence/{evidence_id}

psort.py \
  -o json_line \
  --output-time-zone UTC \
  /tmp/scratch/{evidence_id}.plaso \
  > /tmp/scratch/{evidence_id}.jsonl
```

Plaso writes JSONL to tmpfs; the Kronos ingester worker reads it from tmpfs, normalises to ECS, and bulk-indexes. We do **not** use `psort -o opensearch` direct write.

## Celery DAG

```python
chain(
    dispatch_parse.s(evidence_id),          # RECEIVED → PARSING
    parse_artefact.s(),                      # runs parser in sandbox
    chord(
        group(index_chunk.s(i) for i in range(N_CHUNKS)),  # PARSING → INGESTING
        finalize_evidence.s(evidence_id),   # INGESTING → COMPLETE (if count matches)
    ),
)
```

## Large File Splitting (Text Only)

- Triggered when `line_count > 1_000_000` for `artefact_type in {"csv","ndjson","syslog","apache","nginx","cloudtrail","gcp_audit","azure_activity"}`.
- Split by byte offset rounded to next `\n`.
- CSV header re-emitted on every chunk (not chunk 0 only).
- Each chunk is an independent `index_chunk` Celery task.
- Binary formats (`evtx`, `regf`, `pf`, `sqlite`, `srum`, `journal`) are **never** split — their internal state makes mid-file splits incorrect.

## UTC / DST Normalisation

1. `@timestamp` always UTC with trailing `Z`.
2. If source TZ is known → `event.timezone` (IANA name).
3. DST ambiguity → `kronos.tz_fold = -1`, `@timestamp` = early candidate, `kronos.alt_timestamp` = late candidate.
4. Use `dateutil.tz.datetime_ambiguous()` and `datetime_exists()`. **Never use `pytz`.**

## Retry Policy

| Error type | Action |
|---|---|
| `OpenSearchTransportError` (5xx) | Retry up to 5×, exponential backoff 30 s → 8 min ± jitter |
| MinIO 5xx | Same |
| Firecracker/gVisor start failure | Same |
| Parser exception (format error) | Immediate `ERROR`, no retry |
| OOM (exit 137) | Immediate `ERROR`, no retry |
| Ingest count mismatch | Auto-retry once; then `ERROR` |

Orphan parse tasks running > 6 h are aborted by the `parse_orphan_sweeper` Celery beat job.
