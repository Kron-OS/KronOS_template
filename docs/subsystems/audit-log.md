# Audit Log Subsystem

The audit log is the chain-of-custody backbone — shared by all subsystems.

## Invariants

1. **Append-only** — `AuditLogRepository` exposes no `update` or `delete` methods.
2. **Tamper-detectable** — per-row hash chain: `row_hash_N = SHA256(row_hash_{N-1} || canonical_json(event_N))`.
3. **No PII** — passwords, raw file bytes, and user IPs (beyond the `ip` field) are excluded.
4. **No gaps** — every state transition writes an audit event before returning.

## Hash Chain

Genesis row hash: `SHA256(b"\x00" * 32)`.

For each subsequent row:
```python
canonical = json.dumps(event_as_dict, sort_keys=True, ensure_ascii=True)
row_hash   = hashlib.sha256(prev_row_hash + canonical.encode()).digest()
```

Deleting or modifying any row makes all subsequent hashes invalid. `kronos-attest verify --day` detects this.

## Daily Merkle Anchor

```
Celery beat: 00:05 UTC daily
  1. Collect all audit_log.row_hash values for the day
  2. Compute Merkle root (binary tree, SHA-256 nodes)
  3. POST root to Sigstore RFC 3161 TSA → receive TimeStampToken
  4. Insert audit_anchor(date, root_hash, tsa_token)
```

## Action Vocabulary

| Action | Trigger |
|---|---|
| `access.allow` | RBAC guard permits a request |
| `access.deny` | RBAC guard denies a request |
| `evidence.upload.start` | `request_upload()` |
| `evidence.upload.complete` | Client calls `finalize_upload()` |
| `evidence.scan.clean` | ClamAV returns clean |
| `evidence.scan.infected` | ClamAV finds a signature |
| `evidence.hash.verified` | Server-side SHA-256 matches client's |
| `evidence.hash.mismatch` | SHA-256 mismatch |
| `evidence.promoted` | Moved to WORM evidence bucket |
| `evidence.legal_hold.set` | `PUT /evidence/{id}/legal-hold?hold=true` |
| `evidence.legal_hold.cleared` | Same endpoint, `hold=false` |
| `evidence.download` | Original file downloaded |
| `evidence.delete` | Evidence soft-deleted |
| `evidence.parse.start` | `dispatch_parse` Celery task |
| `evidence.parse.success` | Parser reports completion |
| `evidence.parse.error` | Parser fails |
| `evidence.ingest.success` | `finalize_evidence` confirms count match |
| `evidence.ingest.error` | Count mismatch |
| `evidence.tsa.anchored` | RFC 3161 TSA token stored |

## Verification CLI

```bash
# Verify one day's audit chain against the Merkle root + TSA token
kronos-attest verify --day 2026-06-16

# Verify a specific case: re-read MinIO objects and re-check hashes
kronos-attest verify --case <case_id>

# Cheap audit-chain-only verification (no MinIO access needed)
kronos-attest verify --audit-only --day 2026-06-16
```

The verifier is **read-only**. It can be run by a third-party auditor with:
- Read-only Postgres credentials
- Read-only MinIO presigned access
- The Sigstore TSA public certificate chain

## Usage Pattern

```python
async with audit_log.audit_context(
    ctx,
    AuditEventType.EVIDENCE_PROMOTED,
    resource_type="evidence",
    resource_id=evidence.id,
    ip=request_ip,
):
    await storage.promote_to_evidence_bucket(...)
# audit_context writes "ok" on normal exit, "error" + details if exception escapes
```
