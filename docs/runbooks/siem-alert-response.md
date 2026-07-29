# KronOS SIEM Alert Response Runbook

## Alert Severity Reference

| Wazuh Level | Severity | Response SLA |
|-------------|----------|--------------|
| 15          | CRITICAL | 15 minutes   |
| 12          | HIGH     | 1 hour       |
| 10          | MEDIUM   | 4 hours      |
| 8           | LOW      | 24 hours     |

---

## Rule 100104: Audit Chain BROKEN (Level 15 — CRITICAL)

**What it means:** The SHA-256 hash chain in the audit log failed verification. Either the `row_hash` of an audit event does not match `SHA256(prev_row_hash || canonical_json(event))`, or a row was deleted/modified.

**Triage steps:**
1. Identify the breach point: `GET /api/audit/chain-verify?from=<last_known_good>` → note the first failing event ID.
2. Check Postgres WAL / archive logs for unauthorized DML (`DELETE`, `UPDATE` on `audit_events`).
3. Check MinIO Object Lock logs for any bypass attempts on the evidence bucket.
4. Escalate immediately to forensic lead + legal counsel — this is a chain-of-custody break.

**Containment:**
- Freeze the affected case (set `evidence.state = ERROR`, block all further writes).
- Snapshot the current Postgres state before any recovery.
- Do NOT attempt to re-hash or repair the chain — it must be preserved as-is for legal review.

**Evidence preservation:**
- Export the full audit table to offline WORM storage within 30 minutes.
- Anchor a Merkle root immediately via RFC 3161 TSA: `kronos-attest anchor --case <id>`.

---

## Rule 100103: Malware Detected in Evidence Upload (Level 12 — HIGH)

**What it means:** ClamAV flagged an uploaded file. The file is in the quarantine bucket; the evidence state is `ERROR`.

**Triage steps:**
1. Confirm ClamAV signature: check `audit_events` for `evidence.scan.failed` event, note `details.virus_signature`.
2. Determine if the upload was accidental or deliberate: check user's recent upload history.
3. Review Falco logs for any sandbox escape attempts during the scan.

**Containment:**
- The file is already quarantined (MinIO quarantine bucket, no Object Lock). Safe to delete after evidence collection.
- Notify the case lead immediately.
- If the user account shows other anomalous uploads, suspend the account pending investigation.

---

## Rule 100107: Repeated RBAC Denials — Privilege Escalation (Level 12 — HIGH)

**What it means:** The same `user_id` triggered >5 RBAC denials within 60 seconds. Possible brute-force role elevation or stolen credential testing.

**Triage steps:**
1. Review the audit log: `GET /api/audit?user_id=<id>&event_type=auth.rbac.denied` for the past 10 minutes.
2. Identify which endpoints were targeted — were they evidence delete or admin endpoints?
3. Check Keycloak login events for anomalous IP or device changes.

**Containment:**
- Temporarily revoke the user's Keycloak session: Keycloak Admin → Sessions → Revoke All.
- Force re-authentication with step-up MFA.
- If the account is compromised: rotate all shared secrets (no shared secrets should exist per spec).

---

## Rule 100105: Step-Up Auth Denied (Level 10 — MEDIUM)

**What it means:** A user attempted a privileged operation (evidence delete) without a valid step-up ticket.

**Triage steps:**
1. Was this a user error (forgot to complete MFA challenge)?
2. Is this a programmatic client attempting to bypass the step-up flow?
3. Check whether the request came from the frontend (`referer: kronos-spa`) or a raw API call.

**Response:**
- If user error: no action needed (the request was rejected, nothing was modified).
- If programmatic bypass attempt: treat as potential insider threat → escalate to security team.

---

## Rule 100106: Single RBAC Violation (Level 8 — LOW)

**What it means:** A user was denied access to an endpoint they don't have the required role for.

**Triage steps:**
1. Is this expected (e.g., analyst trying to access admin endpoint by mistake)?
2. If not expected: is the user's role assignment correct in Keycloak?

**Response:**
- If expected: no action.
- If not expected: review user's Keycloak role assignments.

---

## Falco: KronOS Parser Unexpected Network Egress (CRITICAL)

**What it means:** A parser sandbox container (evtx-worker or plaso-worker) opened an outbound network connection. Parser sandboxes must be fully network-isolated — this indicates a sandbox escape or embedded C2 payload in evidence.

**Immediate response (within 15 minutes):**
1. Kill the container: `docker stop <container_id>` — do NOT delete; preserve for forensic analysis.
2. Capture the network state: `ss -tnap` on the host, note destination IP.
3. Block the destination IP at the perimeter firewall.
4. Preserve the container filesystem as a disk image.
5. Escalate to security team and incident commander.

**Root cause analysis:**
- Review the evidence file that triggered the parse — extract it from quarantine bucket for sandboxed analysis.
- Examine evtx-rs / Plaso output for any RCE gadgets.
- File a CVE report if a parser vulnerability is confirmed.

---

## Wazuh Dashboard Access

- URL: `http://localhost:5602` (dev) / `https://wazuh.kronos.internal` (prod)
- KronOS rules: Security Events → filter by `rule.group: kronos`
- Audit integrity dashboard: Modules → Integrity Monitoring → Custom: `kronos-audit-*`

## Fluent Bit Monitoring

- Health: `curl http://localhost:2020/api/v1/health`
- Metrics: `curl http://localhost:2020/api/v1/metrics`
- Check for backpressure or dropped events under `output.*.drop_records`
