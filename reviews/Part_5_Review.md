# Part 5 Review — Security and Compliance

- **Date:** 2026-06-16
- **Spec section reviewed:** `Project_Specifications.md` §5
- **Tracking issues:** #5 (category), #17 (today's review)
- **Branch:** `claude/zen-cerf-m20l7p`

---

## 1. What the spec currently says

§5 today is a checklist of intentions rather than a design:

1. **Data residency / retention** — evidence stays on-prem, default 365 days (already pinned more tightly by §2).
2. **Transport security (TLS 1.3)** — HTTPS everywhere, internal components also over TLS where applicable; certificates "self-signed or enterprise CA initially", Let's Encrypt mentioned as an option.
3. **Input validation & file type restrictions** — executable blocklist; "treat all files as untrusted"; "may also run a quick antivirus scan" (concrete decision in §2: ClamAV post-store).
4. **Sandboxed parsing** — "could use a sandbox like gVisor"; performance must be measured.
5. **Logging & monitoring** — security events logged, "review periodically or integrate with a SIEM".
6. **Access control** — "least privilege" (concrete RBAC matrix already in §1).
7. **Secure configuration** — Keycloak strong passwords, OpenSearch security plugin, API rate limiting and input validation.
8. **ISO 27001 alignment** — A.8.2, A.9, A.10, A.12.3, A.12.4, A.13, A.14 listed with one-line commitments. At-rest encryption is explicitly deferred ("in the future we will consider encrypting files on rest").
9. **Tamper resistance** — "checksums or digital signatures on evidence and logs" (concrete decision in §2: SHA-256 + RFC 3161 TimeStampToken stored on every evidence row).

The text reads like a cover letter for an ISMS audit, not an implementation plan. Most controls are stated as goals without specifying the component that enforces them or the residual risk if they fail.

---

## 2. Work already done in the repo

| Artifact                                                           | Status                                                                                          |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| ISO 27001 control catalogue mapped to Kron-OS components           | Not started — only the controls list is named in prose                                          |
| Internal PKI / mTLS plan for inter-service traffic                 | Not started — spec says "self-signed initially"                                                 |
| At-rest encryption for MinIO (SSE-KMS + key custody)               | Not started — explicitly deferred in §5                                                         |
| gVisor / Firecracker parser sandbox benchmarks                     | Not started — §3 already commits to a "no-network, mem-capped container" for Plaso              |
| Tamper-evident audit-log anchoring (Merkle root + RFC 3161)        | Partial — §2 review commits to TSA-signed evidence hashes and daily Merkle root of `audit_log`  |
| SIEM integration target (Wazuh / OpenSearch Security Analytics)    | Not started — §5 only says "may integrate with a SIEM"                                          |
| Runtime threat detection (Falco)                                   | Not started                                                                                     |
| Vulnerability management (SBOM, scheduled CVE scans)               | Not started                                                                                     |
| Hardened container base images                                     | Not started                                                                                     |
| Secrets management (Vault / OpenBao) and KMS                       | Not started                                                                                     |
| Backup and disaster-recovery design                                | Not started — A.12.3 named, no RPO/RTO target                                                   |
| Network segmentation diagram                                       | Not started                                                                                     |
| Vulnerability disclosure / incident-response runbook               | Not started                                                                                     |

**Conclusion:** §5 is the most under-specified section in the document. The hand-off inputs are already firm:

- §1: identity, RBAC, audit-log schema, daily Merkle root anchored by TSA.
- §2: chain-of-custody FSM, Object Lock Compliance mode, ClamAV post-store, SHA-256 + RFC 3161, libmagic allowlist.
- §3: parser sandbox container, memory-capped queues, deterministic OpenSearch `_id`s.
- §4: CSP `frame-ancestors`, X-Frame-Options, CHIPS cookie rewrite, SSE ticket auth.

§5 must lift these into a coherent security architecture: where the trust boundaries are, where keys live, who watches whom, and how we recover when something goes wrong.

---

## 3. Feasibility research (state of the art, 2026)

### 3.1 Parser sandboxing — gVisor vs Firecracker

- **gVisor** intercepts syscalls in user space (Sentry). Measured overhead in 2026 benchmarks: **10–15% CPU**, **10–30% on I/O-heavy** workloads, sub-millisecond startup. Strong against kernel-exploit parsers; weaker against side-channel and against a parser that mass-allocates memory (still bounded by the host cgroup).[^gvisor-bench][^northflank-fc-gvisor]
- **Firecracker** boots a microVM (KVM + minimal device model) in ~125 ms with ~5 MiB overhead. Hardware-virtualised boundary is the strongest commodity isolation today; the cost is the boot time and a heavier runtime per parse task.[^firecracker][^northflank-fc-gvisor]
- **Recommendation for Kron-OS:**
  - **Slot A — `evtx-rs` / custom text parsers:** in-process under gVisor (gVisor as the default runtime for the `q.parse.fast` Celery workers via `runsc`). Startup overhead matters here because each EVTX/CSV task is short.
  - **Slot B — Plaso (untrusted forensic formats, complex C parsers):** Firecracker microVM, one VM per parse task, no network egress, 2 GB RAM cap (4 GB for SRUM). The 125 ms boot is amortised against multi-minute Plaso runs.
  - Result: strongest boundary where the risk is highest (Plaso parses 200+ formats including SQLite/REGF/EVTX C decoders, historically the source of CVEs), cheapest boundary where the risk is lowest.
- **Network egress is denied in both slots** (gVisor `--network=none`, Firecracker no network device attached). Parsers must not be able to phone home regardless of the artefact's contents.

### 3.2 At-rest encryption for MinIO (SSE-KMS + KES + Vault/OpenBao)

- MinIO does not encrypt at rest unless you turn it on. The supported path is **SSE-KMS** with **KES** (Key Encryption Service, MinIO's stateless KMS shim) backed by an external secret store.[^minio-kes-vault][^minio-secrets-vault]
- The 2026-relevant backend is **HashiCorp Vault** or its open-source fork **OpenBao** (Linux Foundation, BSL → MPL re-license). Both expose the same Transit/KV API surface KES needs.[^minio-kes-vault]
- Once `MINIO_KMS_KES_*` is configured, you `mc encrypt set sse-kms <key> myminio/kronos-evidence-*` and every object is encrypted with a per-bucket master key + per-object data key. **Decryption of the backend on restart requires KES + Vault** — losing Vault unseal keys = losing the bucket. This must be in the runbook.
- **Critical gotcha:** you cannot disable KES later or "undo" SSE configuration. SSE must be turned on at bucket-creation time, not retro-fitted; otherwise the existing objects stay unencrypted and have to be `mc cp`'d through a new encrypted bucket.[^minio-kes-vault]
- Combined with Object Lock Compliance mode (§2), this gives encrypted WORM: nobody (including the root account, including the host OS) can read or delete an evidence object without Vault unsealed and the right MinIO role.

### 3.3 TLS 1.3 everywhere — internal PKI

- The spec's "self-signed initially" is dangerous in v1 because it normalises ignoring cert warnings during ops. The 2026 baseline for an on-prem stack is a small internal CA:
  - **smallstep `step-ca`** — ACME server, short-lived certs (24–48 h), Kubernetes-friendly via `autocert`.[^smallstep-step-ca][^smallstep-autocert]
  - Alternative: **Vault PKI engine** if Vault is already deployed for SSE-KMS (one fewer moving part).[^pki-best-2026]
- Pair with **cert-manager** when we land on Kubernetes. ACME issuer for internal services, `ClusterIssuer` per environment.[^pki-best-2026]
- **mTLS** between Celery workers ↔ broker ↔ Postgres ↔ MinIO ↔ OpenSearch ↔ Keycloak — short-lived client certs, validated at every hop. Public-facing edge (the SPA-to-NGINX TLS termination) still uses Let's Encrypt or the org's commercial CA.
- TLS 1.3 only on every endpoint; legacy 1.2 leaves us exposed to retroactive downgrade attacks and is not needed by anything in our stack.

### 3.4 Tamper-evident audit log — Merkle anchoring + RFC 3161

- §2 review already commits the building blocks: a unified `audit_log` table (§1), per-evidence SHA-256 + RFC 3161 TSA token, daily Merkle root of `audit_log` rows anchored by the same Sigstore RFC 3161 TSA.
- §5 owns the **verification tool**: a `kronos-attest verify --case <id>` CLI that:
  1. Replays the day's `audit_log` rows, recomputes the Merkle root, compares against the stored root.
  2. Re-verifies the TSA TimeStampToken against the Sigstore TSA's public cert chain.
  3. Re-reads the evidence object from MinIO and recomputes SHA-256, compares against `evidence.sha256`.
- Concretely this aligns with **NIST SP 800-86** ("compute the message digest before and after the bit stream imaging") and **ISO/IEC 27037**; recent 2026 research highlights the chain-of-custody / standardised digest model as the prerequisite for legal admissibility.[^nist-800-86][^iso-27037-2026]
- The transparency log pattern (Rekor) gives us an existing append-only design to mirror; we don't run our own Rekor instance, but the daily Merkle-root anchoring + replay tool is materially the same idea at a smaller scale.[^sigstore-rekor]

### 3.5 SIEM — Wazuh + OpenSearch

- Wazuh ships as a four-component stack — **Indexer (OpenSearch)**, **Server**, **Dashboard**, **Agent** — and the indexer is literally OpenSearch. We already run OpenSearch for timeline data; with index-name namespacing (`wazuh-alerts-*` vs `kronos-{org_alias}-case-*`) and a separate Security tenant, one cluster can host both.[^wazuh-overview][^wazuh-os-integ]
- Wazuh agents on every Kron-OS host (backend, Plaso sandbox host, MinIO nodes, OpenSearch nodes, Keycloak nodes) forward file-integrity-monitoring (FIM) events, syscall events, and authentication failures.
- **Heads-up:** Wazuh 5.0 carried a critical flaw that allowed silent data destruction in the SIEM environment.[^wazuh-50-flaw] We pin a known-good Wazuh release (5.1+ once the fix lands) and monitor the Wazuh CVE feed in our own SIEM. Defence-in-depth: the SIEM cluster ships its alerts to an external retention sink (cold MinIO bucket with Object Lock) so an attacker cannot erase evidence of their own activity by compromising the SIEM.
- Forwarding into the SIEM: backend API emits structured security events to `audit-log.kronos.*` topics; Falco emits runtime alerts; Keycloak emits authentication events; OpenSearch emits Security Audit Log; MinIO emits bucket access logs. Wazuh ruleset is augmented with Kron-OS-specific rules (e.g. "more than N failed `evidence.download` from the same user in 5 min").

### 3.6 Runtime threat detection — Falco

- **Falco** (CNCF graduated) ships as a DaemonSet, captures syscalls via eBPF (CO-RE, kernel 5.8+), enriches with K8s metadata, evaluates YAML rules in real time. v0.43.0 (Jan 2026) is the current line; legacy eBPF probe docs have been dropped.[^falco][^falco-2026]
- The high-value rule packs for Kron-OS:
  - Shell spawned inside the Plaso sandbox container or the Celery parser pods.
  - Unexpected outbound connection from any backend pod.
  - Read of sensitive files (`/etc/shadow`, secret-mount paths) outside their expected owner process.
  - Container drift — file modified at runtime in an image that should be read-only.
- Falco alerts ship into Wazuh through the OpenSearch sink (Falco → fluent-bit → OpenSearch index `falco-alerts-*` → Wazuh rule).

### 3.7 Vulnerability management — SBOM + Trivy + hardened bases

- **Base images:** Chainguard Images (built on **Wolfi**) ship daily-rebuilt, near-zero-CVE images with a build-time SBOM. Independent 2026 testing across 50 images found the equivalent Chainguard Python image at zero CVEs.[^chainguard-2026][^chainguard-vs-distroless]
- **Pipeline:** every Kron-OS container image is built FROM a Chainguard/Wolfi base; CI runs `trivy image --severity HIGH,CRITICAL,UNKNOWN --exit-code 1` on every push; nightly `trivy fs` on the running images. The Chainguard Trivy image is itself zero-CVE and FIPS-validated.[^chainguard-trivy]
- **SBOM:** images publish a Syft-generated SPDX SBOM as an OCI artefact next to the image; supply-chain attestation signed via Cosign (Sigstore).

### 3.8 Backup and disaster recovery — MinIO

- MinIO 2026 supports **multi-site active-active replication** as the cornerstone HA mechanism. Buckets must have both versioning and Object Lock on (already required by §2). Mesh topology synchronises objects across two or more deployments.[^minio-replication]
- For Kron-OS v1 the operational target is two on-prem MinIO clusters (primary in production DC, warm-standby in a secondary). RPO ≈ minutes (async replication lag), RTO ≈ 15 min (DNS failover + Vault unseal on standby).
- **Erasure coding** (Reed-Solomon, configurable N+M) gives intra-cluster durability; tolerates `M` drive failures per erasure set. Plus the "rewind" feature for point-in-time recovery without restore.[^minio-erasure]
- Custody implications: MinIO Object Lock retain-until follows the object during replication, so the WORM guarantee survives the failover. Vault/KES must be replicated as well — otherwise the standby cluster cannot decrypt anything.

### 3.9 ISO 27001:2022 mapping

- The 2022 revision renumbered Annex A into **4 themes** (Organizational, People, Physical, Technological) and **93 controls**. The spec still references the legacy A.8 / A.9 / A.10 / A.12 / A.13 / A.14 numbering.[^iso-27001-2022][^iso-27001-soc2]
- The relevant controls for Kron-OS, with their 2022 numbers, are summarised in §5.7 of this review. The single most-relevant new control is **A.5.28 Collection of Evidence**, which mandates "identification, preservation, and management of evidence related to security incidents" — exactly our chain-of-custody objective.[^iso-27001-5-28][^iso-27001-5-28-checklist]
- Mapping to SOC 2 Common Criteria is a one-time exercise that pays for itself when a client asks for either attestation; both reuse the same evidence artefacts (access reviews, change tickets, key-rotation logs, custody chain).[^iso-27001-soc2]

### 3.10 Secrets management

- **HashiCorp Vault** (production) or **OpenBao** (open-source fork) is the system-of-record for: KES master keys, MinIO root credentials, Postgres app creds, OpenSearch admin certs, Keycloak admin client secrets, TSA signing key.
- Short-lived dynamic credentials via Vault's Postgres and PKI engines wherever possible — no long-lived passwords sitting in env vars.
- Vault unseal: 5 key holders, 3-of-5 threshold; key shares stored offline. **Auto-unseal in v1 is rejected** because it defeats the audit story (a single compromised cloud KMS = full Vault read).

---

## 4. Problems identified

### P1. "Self-signed initially" normalises ignored cert warnings
The spec accepts self-signed certs at start. In practice, this trains the ops team to click through TLS errors and makes mTLS impossible. We need an internal CA (step-ca or Vault PKI) from day one.

### P2. At-rest encryption is explicitly deferred
§5 says "in the future we will consider encrypting files on rest." In a chain-of-custody system this is a hard requirement, not a nice-to-have. A stolen MinIO disk reveals every uploaded artefact in clear-text. SSE-KMS + KES + Vault must land in v1.

### P3. Sandbox choice is hand-waved
"Could use gVisor; we must make performance tests." After 2026 benchmarks the right answer is not one sandbox but two: gVisor for fast parsers, Firecracker for Plaso. The spec must commit.

### P4. SIEM integration is "we'll think about it"
A multi-tenant evidence platform without a SIEM is a forensic black hole. Wazuh on the same OpenSearch cluster is the realistic v1 target; not committing leaves us with no canonical place for security alerts.

### P5. No tamper-evidence verification tool
§2 review introduced the audit-log Merkle root + TSA anchoring, but there is no CLI / API to **verify** it. Without a verifier, the tamper-resistance claim is unfalsifiable.

### P6. ISO 27001 numbers are from the 2013 revision
A.8.2, A.10, A.12.3, A.12.4, A.13, A.14 use the legacy numbering. The 2022 revision (4 themes, 93 controls) is what auditors expect today. A.5.28 (Collection of Evidence) is the central control for us and is missing.

### P7. Backup / DR is mentioned in one line
A.12.3 is named without an RPO/RTO target, replication topology, or runbook. Multi-site active-active MinIO + replicated Vault should be the v1 target.

### P8. No runtime threat detection
The spec covers static security configuration but not what happens at runtime. Falco + Wazuh agents are the standard 2026 answer; absent them, a parser breakout would be invisible until the audit log is reviewed.

### P9. Hardened base images and SBOM are absent
"Distroless / Wolfi / Chainguard" is the baseline for any new platform in 2026. Without it, we'll ship images with hundreds of HIGH-severity CVEs from inherited base layers.

### P10. Secrets management is implicit
The spec talks about "secure passwords for admin" but not about where the password lives. Vault/OpenBao + Cosign-signed images + short-lived dynamic creds is the v1 baseline.

### P11. Network segmentation is undocumented
The spec mentions "private network or localhost-only for access" once. We need an explicit zone diagram (DMZ ↔ App ↔ Data ↔ Vault) and the firewall rules that enforce it.

### P12. Vulnerability disclosure / incident response runbook is missing
ISO 27001 A.5.24 + A.5.26 + A.5.28 require it. NIST SP 800-86's collect/examine/analyse/report model is the obvious framing.[^nist-800-86]

---

## 5. Plan to reach the objective — detailed

### 5.1 Trust boundary model

```
┌─ Public zone (DMZ) ─────────────────────────────────────────────────────────┐
│  Browser  ── TLS 1.3 ─►  NGINX edge  (CSP, HSTS, rate limit, body-size cap) │
│                          │ TLS 1.3 + mTLS (internal CA)                     │
└──────────────────────────┼─────────────────────────────────────────────────┘
                           ▼
┌─ App zone ──────────────────────────────────────────────────────────────────┐
│  Backend API  ──►  Keycloak  ──►  Postgres                                  │
│      │                              │                                       │
│      │            mTLS              │  TDE not required: Vault-managed creds│
│      ▼                              ▼                                       │
│  Celery broker (Redis/RabbitMQ over TLS+mTLS)                               │
│      │                                                                      │
│      ▼                                                                      │
│  Celery workers                                                             │
│    ├─ q.parse.fast    → gVisor runtime (runsc)                              │
│    └─ q.parse.plaso   → Firecracker microVM (no network device)             │
└──────────────────────────┼──────────────────────────────────────────────────┘
                           ▼
┌─ Data zone ──────────────────────────────────────────────────────────────────┐
│  MinIO  (Object Lock Compliance, SSE-KMS) ◄── KES ◄── Vault/OpenBao         │
│  OpenSearch (timeline indices + wazuh-alerts-* + falco-alerts-*)            │
│  Sigstore RFC 3161 TSA (signing key in Vault HSM-style mount)               │
└──────────────────────────────────────────────────────────────────────────────┘
                           ▲
                           │ FIM / syscall / auth events
┌─ Observability zone ─────┴───────────────────────────────────────────────────┐
│  Wazuh Server / Dashboard (graduated alerts, rule packs, Kron-OS extensions)│
│  Falco DaemonSet (eBPF, CO-RE)                                              │
│  Cold MinIO bucket (Object Lock) for write-once alert archive               │
└──────────────────────────────────────────────────────────────────────────────┘
```

Each arrow is mTLS with short-lived certs (24 h max, auto-renewed by step-ca). The Data zone has **no inbound traffic** from anything other than the App zone; the Observability zone has read-only access to the App and Data zones over a dedicated audit user.

### 5.2 TLS / PKI (mandatory before milestone-1)

- **Internal CA:** `step-ca` deployed as a 3-node HA cluster, signing CA stored in Vault HSM-style mount. Root cert valid 10 y, intermediate 1 y.
- **Workload certs:** 24-hour validity, ACME (`step-ca` ACME server) + `cert-manager` `ClusterIssuer` once we land on Kubernetes; otherwise the `step` agent on each host.
- **mTLS:** every internal hop. Validated on **both** ends; the client verifies the server cert against the internal root, the server verifies the client cert against the same root and authorises against an SPIFFE-style identity (`spiffe://kronos.example/backend`, `spiffe://kronos.example/celery/q.parse.plaso`).
- **TLS 1.3 only.** No 1.2 fallback.
- Edge (browser-facing) TLS uses Let's Encrypt or the org's commercial CA; the internal CA stays internal.

### 5.3 At-rest encryption (SSE-KMS)

- **Vault/OpenBao** mounts: `transit/kronos-evidence-key/`, `transit/kronos-audit-key/`, `transit/kronos-tsa-signing/`.
- **KES** sidecar deployed alongside MinIO, configured against Vault's Transit engine.
- **MinIO buckets** created with `mc mb --with-lock` AND `mc encrypt set sse-kms kronos-evidence-key`. Cannot be retro-fitted, so the bootstrap script enforces this on first run.
- **Disaster recovery:** Vault unseal keys split 3-of-5; offline storage; documented in the DR runbook. Without a Vault, MinIO cannot decrypt; this is by design.

### 5.4 Parser sandboxing — final decision

| Parser slot          | Sandbox            | RAM cap | Network | Rationale                                                       |
| -------------------- | ------------------ | ------- | ------- | --------------------------------------------------------------- |
| `q.parse.fast`       | gVisor (`runsc`)   | 1 GB    | none    | evtx-rs and text parsers — startup matters, lower historical CVE rate |
| `q.parse.plaso`      | Firecracker microVM| 2 GB    | none    | Plaso C parsers — strongest boundary worth the 125 ms boot      |
| `q.parse.plaso.heavy`| Firecracker microVM| 4 GB    | none    | SRUM/Amcache only                                               |

- Each VM/sandbox starts from a read-only rootfs (Wolfi base + parser binary); writable tmpfs scratch dir; MinIO read access via a one-shot presigned URL injected at boot; **no outbound network**.
- Sandbox escape detection: Falco rules on the host kernel watch for unexpected syscalls from `runsc` and Firecracker VMM processes.

### 5.5 Audit log — tamper-evidence verifier

- The `audit_log` table (§1) already carries `who / when / action / resource / decision / ip`. §5 owns:
  - **Daily Merkle root job** (`audit_merkle_anchor` Celery beat) — computes Merkle root of all rows written that day, sends to Sigstore RFC 3161 TSA, stores `(date, root_hash, tsa_token)` in `audit_anchor` table.
  - **Per-row hash chain** — `row_hash = sha256(prev_row_hash || canonical_json(row))`. Prevents silent row deletion.
  - **Verifier CLI** `kronos-attest verify`:
    - `--day YYYY-MM-DD` recomputes the Merkle root and TSA-verifies it.
    - `--case <id>` walks every evidence object, re-reads from MinIO, recomputes SHA-256, compares to `evidence.sha256`, re-verifies the RFC 3161 token per evidence.
    - `--audit-only` skips MinIO and only verifies the audit chain (cheap, run from CI weekly).
- The verifier MUST be runnable by a third-party auditor with read-only DB + MinIO + TSA-public-key access. No write paths.

### 5.6 SIEM — Wazuh on OpenSearch

- **Topology:** Wazuh indexer = a logical index on the existing OpenSearch cluster (separate role, separate index pattern `wazuh-alerts-*`); Wazuh server in the Observability zone; Wazuh agents on every host.
- **Ingest:**
  - Backend API: structured JSON to `kronos-app-audit-*` (auth failures, RBAC denials, evidence downloads).
  - Keycloak: events plugin → OpenSearch sink.
  - MinIO: bucket access logs → OpenSearch.
  - OpenSearch Security Audit Log (DLS/FLS denials, role-mapping failures) → same cluster.
  - Falco: alerts → fluent-bit → `falco-alerts-*`.
  - System (auditd / journald): Wazuh agent → server.
- **Kron-OS detection ruleset (custom)**:
  - "RBAC denied > 5 times in 5 minutes for one user" → alert.
  - "`evidence.delete` action by anyone other than org-admin" → alert.
  - "Object Lock expiry override attempted" → critical.
  - "Vault seal/unseal event outside business hours" → critical.
  - "Falco shell-in-container in `q.parse.plaso`" → critical.
- **Cold archive:** every Wazuh alert is mirrored to a write-once MinIO bucket (`kronos-siem-archive`, Object Lock 7 y) so the SIEM itself cannot be used to cover tracks.
- Pin Wazuh ≥ 5.1 (the **5.0 flaw**[^wazuh-50-flaw] is patched in 5.1).

### 5.7 ISO 27001:2022 control matrix

| Control (2022)             | Title                                       | Kron-OS evidence / component                                                                                                                          |
| -------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A.5.15**                 | Access control                              | §1 RBAC matrix; Keycloak permission claims; per-tenant DLS on OpenSearch.                                                                             |
| **A.5.17**                 | Authentication information                  | Keycloak; refresh-token rotation with reuse detection; SSO session 24 h.                                                                              |
| **A.5.24**                 | Information security incident management    | §5.10 incident-response runbook; Wazuh alerts; on-call rotation; post-incident review template.                                                       |
| **A.5.25**                 | Assessment and decision on info-sec events  | Wazuh alert tiering (low/med/high/critical); §5.6 detection rules.                                                                                    |
| **A.5.26**                 | Response to info-sec incidents              | NIST SP 800-86 collect/examine/analyse/report workflow; chain-of-custody on every incident artefact.                                                  |
| **A.5.28**                 | Collection of evidence                      | The whole product. §2 FSM + RFC 3161 + Merkle root + verifier CLI.                                                                                    |
| **A.5.30**                 | ICT readiness for business continuity       | MinIO active-active replication; Vault HA; OpenSearch cross-cluster replication; documented RPO 5 min / RTO 15 min.                                   |
| **A.5.33**                 | Protection of records                       | Object Lock Compliance mode; Legal Hold; SSE-KMS at-rest encryption.                                                                                  |
| **A.8.2** (2022)           | Privileged access rights                    | Vault dynamic creds; PIM-style break-glass procedure; admin actions logged to `audit_log`.                                                            |
| **A.8.5**                  | Secure authentication                       | Keycloak with PKCE; mandatory MFA for org-admin; password policy.                                                                                     |
| **A.8.6**                  | Capacity management                         | OpenSearch ISM rollover; Celery queue length alarms; MinIO capacity Wazuh rule.                                                                       |
| **A.8.7**                  | Protection against malware                  | ClamAV pre-promotion scan (§2); Falco runtime detection; Trivy in CI.                                                                                 |
| **A.8.9**                  | Configuration management                    | Everything as IaC (Terraform / Helm); GitOps audited.                                                                                                 |
| **A.8.10**                 | Information deletion                        | §2 retention purge; Legal Hold override; soft-delete preserving the custody trail.                                                                    |
| **A.8.13**                 | Information backup                          | MinIO active-active + erasure coding; Postgres WAL ship; Vault snapshot.                                                                              |
| **A.8.15**                 | Logging                                     | `audit_log` (§1) + Wazuh; daily Merkle anchor.                                                                                                        |
| **A.8.16**                 | Monitoring activities                       | Wazuh dashboards; Falco eBPF runtime monitoring; OS Security Audit Log.                                                                               |
| **A.8.20**                 | Network security                            | §5.1 zone diagram; mTLS everywhere; firewall rules; no inbound from data zone.                                                                        |
| **A.8.23**                 | Web filtering                               | No outbound network from parser sandboxes; egress allowlist on app zone.                                                                              |
| **A.8.24**                 | Use of cryptography                         | TLS 1.3 in transit; SSE-KMS at rest; RFC 3161 signing; Sigstore Cosign for images.                                                                    |
| **A.8.25**                 | Secure development life cycle               | CI: Trivy + Cosign + SBOM publish; PR review gate; secret-scan pre-commit hook.                                                                       |
| **A.8.28**                 | Secure coding                               | Standard SAST (Semgrep) in CI; dependency review; CodeQL scheduled scan.                                                                              |

The above replaces the legacy A.8.2 / A.9 / A.10 / A.12.3 / A.12.4 / A.13 / A.14 list in the current spec.

### 5.8 Vulnerability management

- **Base images:** Chainguard Wolfi.
- **CI gates:** `trivy image --severity HIGH,CRITICAL --exit-code 1` on every PR; SBOM published as OCI artefact; Cosign signature with key from Vault Transit.
- **Runtime scans:** nightly `trivy fs` on running images; results into `vuln-scan-*` index → Wazuh.
- **Patch SLA:** CRITICAL = 24 h, HIGH = 7 d, MEDIUM = 30 d.
- **Dependency scanning:** Renovate bot; security advisories from GitHub.

### 5.9 Runtime threat detection (Falco)

- DaemonSet on every node (or sidecar in non-K8s deployments).
- Rule packs: default Falco rules + Kron-OS overlay (§5.6 examples).
- Alerts → fluent-bit → `falco-alerts-*` → Wazuh.
- False-positive curation: every rule that triggers > 3× in 7 d without action goes to review; we want signal density ≥ 80 %.

### 5.10 Incident response runbook (NIST SP 800-86)

- **Collect:** Wazuh and `audit_log` are the canonical sources; preserve a Snapshot of the relevant OS Dashboards saved searches in the case tenant.
- **Examine:** dedicated forensic case is opened in Kron-OS itself (eat our own dog food) with the incident's raw logs uploaded as evidence.
- **Analyse:** timeline analysis in OS Dashboards; correlate across Wazuh / app audit / Falco indices.
- **Report:** templated incident report; chain-of-custody attestation via `kronos-attest verify`.

### 5.11 Secrets management

- **Vault/OpenBao** is the single source of truth. No secrets in env vars, ConfigMaps, or git.
- AppRole or K8s auth for service identity; dynamic Postgres creds where supported.
- Quarterly key rotation; emergency rotation runbook tied to A.5.26.
- Vault audit log shipped to Wazuh (so even Vault operators are watched).

### 5.12 Backup and DR

- **MinIO:** active-active replication to a warm-standby cluster; intra-cluster Reed-Solomon erasure coding (10+4 default).
- **Postgres:** continuous WAL archive to MinIO (encrypted with a different SSE key than evidence); 7-day PITR.
- **Vault:** integrated storage snapshots every 6 h to the same encrypted backup bucket; recover-key shares offline.
- **OpenSearch:** snapshot repository on MinIO; daily snapshots; tested restore every quarter.
- **DR targets:** RPO 5 min, RTO 15 min, tested twice a year.

### 5.13 Rate-limiting and API hardening

- NGINX edge: per-IP `limit_req`; per-token `limit_req` keyed off a hash of the `sub` claim.
- Backend: Keycloak brute-force detection on the IDP side; backend's own per-user soft rate limit on `POST /evidence` (prevents a runaway upload bot).
- Request-body cap at the edge; pre-presigned-URL flow means the cap is small for app-server-touched traffic (§2).
- HSTS, CSP (`frame-ancestors` per §4), `Referrer-Policy: strict-origin-when-cross-origin`, `X-Content-Type-Options: nosniff`.

### 5.14 Milestones

| Milestone | Content                                                                                                  | Exit criterion                                                                                                          |
| --------- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| M5.1      | Internal CA bring-up (`step-ca` HA), TLS 1.3 + mTLS between all services                                 | Every internal hop refuses non-mTLS; cert lifespan ≤ 24 h; renewal automated                                            |
| M5.2      | Vault/OpenBao + KES + MinIO SSE-KMS at bucket creation                                                   | `mc admin info` reports SSE-KMS on all evidence buckets; backend restart cannot decrypt without Vault unsealed          |
| M5.3      | gVisor (`q.parse.fast`) + Firecracker (`q.parse.plaso`) sandboxes with `network=none`                    | Synthetic malicious-EVTX test cannot make an outbound DNS lookup                                                        |
| M5.4      | `audit_log` per-row hash chain + daily Merkle anchor (Sigstore TSA) + `kronos-attest verify` CLI         | Auditor can verify a 30-day window against a printed Merkle root                                                        |
| M5.5      | Wazuh deployment, ruleset, OpenSearch indices, cold MinIO archive                                        | All hosts forward FIM + syscall + auth events; sample malicious action triggers a Wazuh alert in < 60 s                  |
| M5.6      | Falco DaemonSet with Kron-OS rule pack                                                                   | Shell-in-container test triggers a critical alert                                                                       |
| M5.7      | Chainguard base images + Trivy CI gate + Cosign-signed SBOMs                                             | CI fails on any HIGH/CRITICAL CVE; every image carries a Cosign signature and an attached SPDX SBOM                     |
| M5.8      | MinIO active-active replication + Postgres WAL ship + Vault snapshot                                     | DR drill restores read access in < RTO target                                                                           |
| M5.9      | Incident-response runbook + post-incident-review template                                                | Tabletop exercise completes end-to-end using Kron-OS itself as the forensic platform                                    |
| M5.10     | ISO 27001:2022 control matrix audited internally                                                         | Each of the controls in §5.7 has a named evidence artefact and a quarterly review owner                                 |

Each milestone lands as its own PR referencing issue #5.

---

## 6. Open questions for the reviewer

1. **Vault vs OpenBao** — production Vault (BSL) or OpenBao (MPL fork)? Same API; legal/licensing implications.
2. **Auto-unseal** — confirmed off, even at the cost of operator wake-ups for restarts?
3. **Firecracker vs gVisor for Plaso** — accept the 125 ms boot cost for Firecracker, or stay on gVisor everywhere with a stricter seccomp profile?
4. **Wazuh on the same OpenSearch cluster** — or a separate cluster for blast-radius isolation? (Cost vs containment.)
5. **Cold SIEM archive retention** — 7 years (default) or aligned with regulator? (GDPR vs NIS2 vs sector-specific.)
6. **Internal CA choice** — `step-ca` or Vault PKI? If Vault is already in for SSE-KMS, Vault PKI removes a moving part.
7. **MFA scope** — mandatory for org-admin only, or extended to case-lead?
8. **At-rest encryption key custody** — single Vault, or HSM-backed Transit? (HSM doubles cost, raises assurance.)
9. **Egress allowlist** — list of permitted external endpoints from the app zone (Keycloak admin, TSA, OpenAI/LLM features if any) needs explicit enumeration.
10. **Public bug-bounty / VDP** — opt-in for v1 or post-launch?

---

## 7. Next-day plan

Tomorrow's review should target **Part 6 — Identity, Authorization, and SSO**. Most of §6's substance has already been pinned by §1 (Keycloak Organizations, flat `roles` claim for OS Security, 15-min access tokens, refresh rotation), so §6 is more about validating the integration: end-to-end OIDC flow with OS Dashboards (`cht42/opensearch-keycloak`), token-lifespan tuning revisited with the §5 mTLS context, Admin Fine-Grained Permissions for the backend service account, Keycloak event-log integration into the Wazuh SIEM established here. The biggest open item left for §6 is **federation** (LDAP / SAML upstream IDPs) which today's review touched only tangentially.

---

## References

[^gvisor-bench]: [Firecracker vs gVisor — Northflank, 2026](https://northflank.com/blog/firecracker-vs-gvisor)
[^northflank-fc-gvisor]: [How to sandbox AI agents in 2026: MicroVMs, gVisor & isolation strategies — Northflank](https://northflank.com/blog/how-to-sandbox-ai-agents)
[^firecracker]: [Firecracker microVM — overview](https://firecracker-microvm.github.io/)
[^minio-kes-vault]: [MinIO Server-Side Encryption with Hashicorp Vault Root KMS — MinIO docs](https://min.io/docs/minio/kubernetes/aks/operations/server-side-encryption/configure-minio-kes-hashicorp.html)
[^minio-secrets-vault]: [Secrets Made Easy with MinIO and HashiCorp Vault — MinIO blog](https://blog.min.io/minio-and-hashicorp-vault/)
[^smallstep-step-ca]: [step-ca Certificate Authority Overview — Smallstep](https://smallstep.com/docs/step-ca/)
[^smallstep-autocert]: [smallstep/autocert — kubernetes mTLS injector](https://github.com/smallstep/autocert)
[^pki-best-2026]: [Internal PKI Certificate Management — Complete Guide (2026)](https://www.decryptiondigest.com/blog/internal-pki-certificate-management-guide)
[^nist-800-86]: [NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf)
[^iso-27037-2026]: [Comparison Study of NIST SP 800-86 and ISO/IEC 27037 Standards — ResearchGate, 2026](https://www.researchgate.net/publication/382816264_Comparison_Study_of_NIST_SP_800-86_and_ISOIEC_27037_Standards_as_A_Framework_for_Digital_Forensic_Evidence_Analysis)
[^sigstore-rekor]: [Catching Malicious Package Releases with Rekor Transparency Log Monitoring — OpenSSF](https://openssf.org/blog/2025/12/19/catching-malicious-package-releases-using-a-transparency-log/)
[^wazuh-overview]: [Wazuh — Open Source XDR / SIEM](https://wazuh.com/)
[^wazuh-os-integ]: [Extending Wazuh detection with OpenSearch integration — Wazuh blog](https://wazuh.com/blog/detection-with-opensearch-integration/)
[^wazuh-50-flaw]: [Critical Wazuh 5.0 flaw exposes SIEM environments — Undercode News](https://undercodenews.com/critical-wazuh-50-flaw-exposes-entire-siem-environments-to-silent-data-destruction-and-evidence-erasure-video/)
[^falco]: [Falco — runtime threat detection](https://falco.org/)
[^falco-2026]: [Falco 2026: CNCF Runtime Threat Detection for K8s — AppSecSanta](https://appsecsanta.com/falco)
[^chainguard-2026]: [Chainguard 2026: 2,000+ Zero-CVE Container Images — AppSecSanta](https://appsecsanta.com/chainguard)
[^chainguard-vs-distroless]: [Distroless vs Chainguard vs Wolfi: Real Differences — Safeguard](https://safeguard.sh/resources/blog/distroless-vs-chainguard-vs-wolfi-base-images)
[^chainguard-trivy]: [trivy / trivy-fips secure-by-default container image — Chainguard](https://images.chainguard.dev/directory/image/trivy/overview)
[^minio-replication]: [MinIO Replication Best Practices — MinIO blog](https://www.min.io/blog/minio-replication-best-practices)
[^minio-erasure]: [Erasure Coding — MinIO AIStor Documentation](https://docs.min.io/aistor/operations/core-concepts/erasure-coding/)
[^iso-27001-2022]: [ISO 27001:2022 Annex A Controls List — Scrut](https://www.scrut.io/hub/iso-27001/iso-27001-controls)
[^iso-27001-soc2]: [ISO 27001 to SOC 2 Mapping — Chill Compliance](https://chillcompliance.com/blogs/our-blog/iso-27001-to-soc-2-mapping-guide)
[^iso-27001-5-28]: [ISO 27001:2022 Annex A 5.28 — Collection of Evidence (ISMS.online)](https://www.isms.online/iso-27001/annex-a-2022/5-28-collection-of-evidence-2022/)
[^iso-27001-5-28-checklist]: [ISO 27001:2022 Annex A 5.28 Checklist — ISMS.online](https://www.isms.online/iso-27001/checklist/annex-a-5-28-checklist/)
