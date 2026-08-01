#!/usr/bin/env python3
"""L3 chain PoC (roadmap M3/D6, docs/NEXTGEN_SOC_ROADMAP.md):

    real mTLS collector ingest (D2) -> real Redis stream (D1) -> real
    BatchSealingService seal (D3, Merkle+TSA+WORM) -> real
    StreamNormalizationService normalize+index (D4, ECS in real OpenSearch)
    -> a real Security Analytics detector firing on the resulting document
    (C1/C2) -> real DetectionSyncService.sync_org_findings() (C4) writing a
    real Detection row in real Postgres.

This is D6's whole job: chain ALL of D1-D5/C1-C4's already-separately-
verified real components together for the *continuous telemetry* path, the
way C5 (poc/chain_detect_from_evidence/) already did for the *evidence
upload* path. No new subsystem is built here -- this only wires existing,
already-shipped classes and reports what actually happened when run for
real, exactly like C5 did.

Pinned versions (read from this repo/host, not assumed -- matches
poc/collector_ingest_mtls/, poc/stream_normalization/, poc/stream_backpressure_dlq/):
  - step-ca: docker-step-ca-1 (smallstep/step-ca), real "admin" JWK
    provisioner (the only one actually configured on the live container).
  - Redis: docker-redis-1 (redis:7-alpine), stream DB 3.
  - Postgres: docker-postgres-1 (postgres:16-alpine).
  - MinIO: docker-minio-1 (minio/minio:latest).
  - OpenSearch: docker-opensearch-1 (opensearchproject/opensearch:2.11.1).
  - RFC 3161 TSA: same real openssl-ts-backed substitute as poc/rfc3161/,
    poc/batch_sealing/, poc/stream_normalization/, poc/stream_backpressure_dlq/
    (the dev-compose `tsa` stub returns an empty body, not a real ASN.1
    responder -- poc/rfc3161/README.md).

## The C5 timestamp pitfall, applied to the continuous-telemetry case

C5's own STATUS note (docs/NEXTGEN_SOC_ROADMAP.md) found that OpenSearch
Security Analytics monitors evaluate documents by whether their own
``@timestamp`` falls within a recent execution window -- real, historically
timestamped forensic *evidence* (e.g. a 2015-era EVTX record) structurally
can't fire them. Continuous telemetry is naturally the opposite case: every
synthetic event this script produces uses ``ts = time.time()`` (real wall
clock) at the moment it's produced -- NOT the fixed 2025-01-01 constant
poc/stream_normalization/poc/stream_backpressure_dlq use for their own,
narrower unit-style checks.

This script additionally hedges against the *other* plausible mechanism
(OpenSearch document-level monitors are also documented to baseline a
per-shard sequence-number cursor AT MONITOR CREATION and only ever evaluate
documents indexed after that point, independent of the documents' own
``@timestamp`` value): it deliberately runs TWO rounds --

  Round 1 (before the detector exists): a few benign events, just to get a
  real index to exist so the field-alias mapping and the detector itself
  have something to attach to.

  Round 2 (strictly after the detector is created): a fresh mTLS POST,
  including one event shaped to trip a specific, real, already-known-good
  prepackaged Sigma rule (see below), so the triggering document is both
  freshly timestamped AND indexed after the monitor's own creation --
  satisfying either candidate mechanism, not just one guess about which is
  real.

## Which real rule this targets

Reused directly from C1's own real measurement
(poc/security_analytics_field_mappings/README.md): the ``network`` log
type's one real firing prepackaged rule, `1fc0809e-06bf-4de3-ad52-25e5263b7623`
("Publicly Accessible RDP Service", attack.t1021.001) -- confirmed here by
directly fetching its real Sigma body from the live cluster before writing
this script. Its actual (only) condition is ``not (id.orig_h startswith
<private-prefix-list>)`` -- i.e. it fires for ANY event whose originator
address is a public/routable IP, regardless of destination port. C1's own
`_network_table` field-alias (`id.orig_h -> source.ip`, etc.) is re-applied
here to our own new stream index, since SA's alias mappings are per real
index, not templated -- confirmed absent from index_template.json.

Run: ~/venv/bin/python3 poc/l3_chain_collector_to_detect/run_poc.py
"""

from __future__ import annotations

import asyncio
import http.server
import json
import shutil
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from redis.asyncio import Redis as AsyncRedis  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.adapter.opensearch.findings_client import SecurityAnalyticsFindingsClient  # noqa: E402
from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_dead_letter import PostgresDeadLetterSink  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.adapter.repository.postgres_sealed_batch import PostgresSealedBatchRepository  # noqa: E402
from src.adapter.storage.sealed_batch_storage import S3SealedBatchStorage  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.batch_sealing import BatchSealingService  # noqa: E402
from src.application.detection_sync import DetectionSyncService  # noqa: E402
from src.application.sealing_trigger_policy import SizeBoundTriggerPolicy  # noqa: E402
from src.application.stream_normalization import StreamNormalizationService  # noqa: E402
from src.application.stream_source_registry import get_default_stream_normalizer_registry  # noqa: E402
from src.application.timeline_ingest import TimelineIngestionService  # noqa: E402
from src.application.timeline_normalization import build_stream_index_name  # noqa: E402
from src.application.timestamping import RFC3161TimestampService  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402

STEP_CONTAINER = "docker-step-ca-1"
STEP_CA_URL = "https://localhost:9000"
STEP_PASSWORD = "step_ca_dev_password"
LISTENER_HOST = "127.0.0.1"
LISTENER_PORT = 8544  # distinct from poc/collector_ingest_mtls's own 8543
REDIS_DSN = "redis://localhost:6379/3"
DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
MINIO_ENDPOINT = "http://localhost:9000"
MINIO_ACCESS_KEY = "kronos_minio"
MINIO_SECRET_KEY = "kronos_minio_dev_password"
OS_URL = "https://localhost:9200"
OS_ADMIN = ("admin", "admin")

TSA_HOST = "127.0.0.1"
TSA_PORT = 20323  # distinct from rfc3161(20318)/batch_sealing(20319)/stream_normalization(20320)/backpressure_dlq(20321)

# The one real prepackaged rule C1 already confirmed fires for the
# "network" log type against real ECS-shaped source.ip/destination.ip/
# destination.port fields -- re-verified against the live cluster
# immediately before writing this script (see module docstring).
TARGET_RULE_ID = "1fc0809e-06bf-4de3-ad52-25e5263b7623"
TARGET_RULE_TAG = "attack.t1021.001"

CHECKS: list[tuple[str, bool]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((label, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""), flush=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def _run(*args: str) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True)  # noqa: S603
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {args}\nSTDOUT:{result.stdout}\nSTDERR:{result.stderr}")
    return result


def docker_exec(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "exec", STEP_CONTAINER, *args], capture_output=True, text=True, check=False)  # noqa: S603


# ---------------------------------------------------------------------------
# step-ca real cert issuance (identical technique to poc/collector_ingest_mtls/)
# ---------------------------------------------------------------------------


def issue_cert(work_dir: Path, name: str, sans: list[str], not_after: str = "2h") -> tuple[Path, Path]:
    container_dir = f"/tmp/d6poc-{name}"
    docker_exec("mkdir", "-p", container_dir)
    san_args = []
    for s in sans:
        san_args += ["--san", s]
    result = docker_exec(
        "sh", "-c",
        f"step ca certificate '{name}' {container_dir}/{name}.crt {container_dir}/{name}.key "
        f"{' '.join(san_args)} --provisioner admin "
        f"--password-file <(printf '%s' '{STEP_PASSWORD}') "
        f"--ca-url {STEP_CA_URL} --root /home/step/certs/root_ca.crt "
        f"--not-after {not_after} --force",
    )
    if result.returncode != 0:
        raise RuntimeError(f"step ca certificate failed for {name}: {result.stderr}")
    crt_path = work_dir / f"{name}.crt"
    key_path = work_dir / f"{name}.key"
    subprocess.run(["docker", "cp", f"{STEP_CONTAINER}:{container_dir}/{name}.crt", str(crt_path)], check=True)  # noqa: S603,S607
    subprocess.run(["docker", "cp", f"{STEP_CONTAINER}:{container_dir}/{name}.key", str(key_path)], check=True)  # noqa: S603,S607
    return crt_path, key_path


def fetch_root_ca(work_dir: Path) -> Path:
    root_path = work_dir / "root_ca.crt"
    subprocess.run(["docker", "cp", f"{STEP_CONTAINER}:/home/step/certs/root_ca.crt", str(root_path)], check=True)  # noqa: S603,S607
    return root_path


def client_ssl_context(ca_path: Path, cert_path: Path | None = None, key_path: Path | None = None) -> ssl.SSLContext:
    """Real, empirically-confirmed finding from poc/collector_ingest_mtls/:
    httpx 0.28.1's convenience ``cert=``/``verify=<path str>`` tuple form
    fails this exact mTLS handshake -- an explicit ``ssl.SSLContext`` works.
    Not re-litigated here, just reused."""
    ctx = ssl.create_default_context(cafile=str(ca_path))
    if cert_path is not None:
        ctx.load_cert_chain(str(cert_path), str(key_path) if key_path else None)
    return ctx


# ---------------------------------------------------------------------------
# Throwaway RFC 3161 TSA responder (identical technique to poc/batch_sealing/,
# poc/stream_normalization/, poc/stream_backpressure_dlq/)
# ---------------------------------------------------------------------------


def build_throwaway_tsa(workdir: Path) -> Path:
    ca_key, ca_pem = workdir / "ca.key", workdir / "ca.pem"
    tsa_key, tsa_csr, tsa_pem = workdir / "tsa.key", workdir / "tsa.csr", workdir / "tsa.pem"
    ext_cnf = workdir / "tsa_ext.cnf"
    ext_cnf.write_text("extendedKeyUsage=critical,timeStamping\n")

    _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(ca_key),
         "-out", str(ca_pem), "-days", "2", "-nodes", "-subj", "/CN=Test CA")
    _run("openssl", "req", "-newkey", "rsa:2048", "-keyout", str(tsa_key),
         "-out", str(tsa_csr), "-nodes", "-subj", "/CN=Test TSA")
    _run("openssl", "x509", "-req", "-in", str(tsa_csr), "-CA", str(ca_pem),
         "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(tsa_pem),
         "-days", "2", "-extfile", str(ext_cnf))

    tsa_cnf = workdir / "tsa.cnf"
    tsa_cnf.write_text(f"""\
[tsa]
default_tsa = tsa_config1

[tsa_config1]
dir = {workdir}
serial = {workdir}/tsaserial
crypto_device = builtin
signer_cert = {tsa_pem}
certs = {ca_pem}
signer_key = {tsa_key}
signer_digest = sha256
ess_cert_id_alg = sha256
default_policy = 1.2.3.4.5.6.7.8.1
digests = sha256
accuracy = secs:1
clock_precision_digits = 0
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
""")
    return tsa_cnf


def make_tsa_handler(tsa_cnf: Path, workdir: Path):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            req_der = self.rfile.read(length)
            with tempfile.NamedTemporaryFile(dir=workdir, suffix=".tsq", delete=False) as reqf:
                reqf.write(req_der)
                req_path = reqf.name
            resp_path = req_path.replace(".tsq", ".tsr")
            result = subprocess.run(  # noqa: S603
                ["openssl", "ts", "-reply", "-config", str(tsa_cnf), "-queryfile", req_path, "-out", resp_path],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                self.send_response(500)
                self.end_headers()
                return
            resp_der = Path(resp_path).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(resp_der)))
            self.end_headers()
            self.wfile.write(resp_der)

        def log_message(self, fmt: str, *args) -> None:  # noqa: A002
            pass

    return Handler


# ---------------------------------------------------------------------------
# Real, near-"now" Zeek conn.log-shaped events (the C5 pitfall's own fix)
# ---------------------------------------------------------------------------


def benign_event(i: int) -> dict:
    now = time.time()
    return {
        "ts": now + i * 0.01,
        "uid": f"CBENIGN{i:012x}",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 50000 + i,
        "id.resp_h": "10.0.0.1",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 1.2 + i * 0.1,
        "orig_bytes": 500 + i,
        "resp_bytes": 4000 + i,
        "conn_state": "SF",
        "orig_pkts": 6,
        "resp_pkts": 5,
    }


def malicious_rdp_event(public_ip: str) -> dict:
    """Shaped to trip the real prepackaged rule TARGET_RULE_ID: a connection
    FROM a public/routable IP (the rule's ONLY condition -- see module
    docstring). dst_port 3389/service "rdp" for narrative realism only; the
    rule itself does not condition on them."""
    now = time.time()
    return {
        "ts": now,
        "uid": f"CMALICIOUS{uuid.uuid4().hex[:8]}",
        "id.orig_h": public_ip,
        "id.orig_p": 51413,
        "id.resp_h": "10.0.0.9",
        "id.resp_p": 3389,
        "proto": "tcp",
        "service": "rdp",
        "duration": 4.5,
        "orig_bytes": 900,
        "resp_bytes": 12000,
        "conn_state": "SF",
        "orig_pkts": 20,
        "resp_pkts": 18,
    }


async def main() -> int:  # noqa: PLR0915
    log("=" * 78)
    log("D6 PoC: real mTLS collector -> Redis stream -> sealed batch -> ECS index -> SA detector -> Detection")
    log("=" * 78)
    if shutil.which("openssl") is None:
        log("FATAL: openssl binary not found on PATH")
        return 1

    work_dir = Path(tempfile.mkdtemp(prefix="kronos_poc_d6_"))
    listener_proc: subprocess.Popen | None = None
    tsa_server: socketserver.ThreadingTCPServer | None = None

    org_id = uuid.uuid4()
    org_alias = f"poc-l3-chain-{uuid.uuid4().hex[:8]}"
    source_id = "zeek-conn-log"
    detector_name = f"kronos-{org_alias}-network-detector"

    try:
        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("0. Real TSA responder + real step-ca client cert issuance")
        print("=" * 78)
        tsa_cnf = build_throwaway_tsa(work_dir)
        tsa_handler = make_tsa_handler(tsa_cnf, work_dir)
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        tsa_server = socketserver.ThreadingTCPServer((TSA_HOST, TSA_PORT), tsa_handler)
        threading.Thread(target=tsa_server.serve_forever, daemon=True).start()
        log(f"Real local TSA responder listening on http://{TSA_HOST}:{TSA_PORT}")

        version = docker_exec("step", "version").stdout.strip()
        check("real step CLI reachable in the running step-ca container", "Smallstep" in version, version.splitlines()[0] if version else "")

        root_ca = fetch_root_ca(work_dir)
        collector_crt, collector_key = issue_cert(
            work_dir, "d6-collector", [f"urn:kronos:collector:org:{org_id}:source:{source_id}"]
        )
        check("real client cert issued for this run's collector identity (org_id/source_id)", collector_crt.exists())
        server_crt, server_key = issue_cert(work_dir, "d6-collector-listener", ["kronos-collector.local", "127.0.0.1"])
        check("real server cert issued for the mTLS listener itself", server_crt.exists())

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("1. Start the real mTLS collector listener (D2) as a subprocess")
        print("=" * 78)
        import os

        env = {
            **os.environ,
            "DATABASE_URL": "postgresql+asyncpg://unused:unused@localhost:1/unused",
            "REDIS_URL": "redis://localhost:6379/0",
            "STREAM_REDIS_DB": "3",
            "MINIO_ENDPOINT": "localhost:1", "MINIO_ACCESS_KEY": "unused", "MINIO_SECRET_KEY": "unused",
            "OPENSEARCH_URL": "https://localhost:1", "OPENSEARCH_USERNAME": "unused", "OPENSEARCH_PASSWORD": "unused",
            "KEYCLOAK_URL": "https://localhost:1", "KEYCLOAK_CLIENT_SECRET": "unused",
            "VAULT_URL": "https://localhost:1", "VAULT_TOKEN": "unused",
            "CELERY_BROKER_URL": "redis://localhost:6379/1", "CELERY_RESULT_BACKEND": "redis://localhost:6379/2",
            "COLLECTOR_MAX_STREAM_LENGTH": "10000",
            "COLLECTOR_DEDUP_TTL_SECONDS": "3600",
        }
        listener_proc = subprocess.Popen(  # noqa: S603
            [
                sys.executable, "-m", "src.external.run_dual_listener",
                "--host", LISTENER_HOST, "--port", str(LISTENER_PORT),
                "--server-cert", str(server_crt), "--server-key", str(server_key),
                "--client-ca", str(root_ca),
            ],
            cwd=str(REPO_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        base_url = f"https://{LISTENER_HOST}:{LISTENER_PORT}"
        ctx = client_ssl_context(root_ca, collector_crt, collector_key)
        ready = False
        for _ in range(30):
            time.sleep(0.5)
            try:
                httpx.get(base_url, verify=ctx, timeout=2)
                ready = True
                break
            except (httpx.ConnectError, httpx.ConnectTimeout):
                continue
            except Exception:  # noqa: BLE001 -- any HTTP response (even 404) means it's up
                ready = True
                break
        check("real mTLS listener process is up and accepts TLS connections", ready)

        client = httpx.Client(base_url=base_url, verify=ctx, timeout=15)

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("2. ROUND 1: real mTLS POST of benign events (establishes the real index)")
        print("=" * 78)
        round1_events = [benign_event(i) for i in range(3)]
        resp1 = client.post("/api/collector/ingest", json={"events": round1_events})
        check("round 1: real mTLS collector ingest accepted (202)", resp1.status_code == 202, f"status={resp1.status_code} body={resp1.text[:200]}")
        resp1.raise_for_status()
        outcomes1 = resp1.json()["results"]
        check("round 1: all 3 real events accepted, none flagged duplicate", all(o["accepted"] and not o["duplicate"] for o in outcomes1))

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("3. Confirm round-1 events landed on the REAL Redis stream (D1)")
        print("=" * 78)
        redis = AsyncRedis.from_url(REDIS_DSN)
        stream_key = f"kronos:stream:{org_id}:{source_id}"
        entries = await redis.xrange(stream_key)
        check("real Redis XRANGE shows exactly 3 entries after round 1", len(entries) == 3, f"count={len(entries)}")
        first_payload = json.loads(entries[0][1][b"payload"])
        check("real stream entry's payload is genuinely near wall-clock 'now' (not a fixed historical constant)",
              abs(first_payload["ts"] - time.time()) < 60,
              f"ts={first_payload['ts']} now={time.time()}")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("4. Real BatchSealingService.seal_pending() -- batch #1 (D3)")
        print("=" * 78)
        engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
        await PostgresSealedBatchRepository.create_tables(engine)
        await PostgresAuditLogRepository.create_tables(engine)
        await PostgresDeadLetterSink.create_tables(engine)
        await PostgresDetectionRepository.create_tables(engine)

        stream_adapter = RedisStreamIngestAdapter(redis)
        sealed_batch_repo = PostgresSealedBatchRepository(engine)
        audit_repo = PostgresAuditLogRepository(engine)
        audit_log = AuditLogService(audit_repo)
        dead_letter_sink = PostgresDeadLetterSink(engine)
        tsa_service = RFC3161TimestampService(tsa_url=f"http://{TSA_HOST}:{TSA_PORT}/")
        storage = S3SealedBatchStorage(
            endpoint_url=MINIO_ENDPOINT, access_key=MINIO_ACCESS_KEY, secret_key=MINIO_SECRET_KEY,
            bucket_prefix="kronos-poc-l3-chain", retention_days=1,
        )
        opensearch = OpenSearchClient(
            hosts=[{"host": "localhost", "port": 9200}], http_auth=OS_ADMIN, use_ssl=True, verify_certs=False,
        )
        ingestion = TimelineIngestionService(opensearch=opensearch, audit_log=audit_log)
        normalizer_registry = get_default_stream_normalizer_registry()
        normalization_service = StreamNormalizationService(
            sealed_batch_repo, storage, ingestion, normalizer_registry, dead_letter_sink, audit_log,
        )
        sealing_service = BatchSealingService(
            stream_adapter, storage, tsa_service, audit_log, sealed_batch_repo,
            SizeBoundTriggerPolicy(max_events=3), consumer_name="d6-poc-sealer",
        )

        sealed1 = await sealing_service.seal_pending(org_id, source_id)
        check("real batch #1 sealed (real WORM manifest + real TSA token + real Postgres row)", sealed1 is not None)
        assert sealed1 is not None
        log(f"sealed batch #1: batch_id={sealed1.batch_id} event_count={sealed1.event_count}")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("5. Real StreamNormalizationService.normalize_batch() -- batch #1 -> real OpenSearch (D4)")
        print("=" * 78)
        result1 = await normalization_service.normalize_batch(org_id, sealed1.batch_id, org_alias=org_alias)
        check("real normalize_batch() indexed all 3 round-1 events, 0 dead-lettered",
              result1.indexed_count == 3 and result1.dead_lettered_count == 0,
              f"indexed={result1.indexed_count} dead_lettered={result1.dead_lettered_count}")

        index_name = build_stream_index_name(org_alias, source_id, datetime.now(UTC))
        await asyncio.sleep(1.5)
        os_client = httpx.Client(base_url=OS_URL, auth=OS_ADMIN, verify=False, timeout=30)
        search1 = os_client.post(f"/{index_name}/_search", json={"query": {"match_all": {}}, "size": 10})
        check("real OpenSearch _search on the new stream index returns 200", search1.status_code == 200, search1.text[:300])
        hits1 = search1.json().get("hits", {}).get("hits", [])
        check("real OpenSearch index contains exactly 3 documents after round 1", len(hits1) == 3, f"count={len(hits1)}")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("6. Real SA field-alias mapping for 'network' log type (C1's own verified table)")
        print("=" * 78)
        alias_mappings = {
            "properties": {
                "id.orig_h": {"type": "alias", "path": "source.ip"},
                "id.resp_h": {"type": "alias", "path": "destination.ip"},
                "id.resp_p": {"type": "alias", "path": "destination.port"},
            }
        }
        map_resp = os_client.post(
            "/_plugins/_security_analytics/mappings",
            json={"index_name": index_name, "rule_topic": "network", "partial": True, "alias_mappings": alias_mappings},
        )
        check("real SA field-alias mapping POST accepted (200)", map_resp.status_code == 200, map_resp.text[:300])

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print(f"7. Real per-org SA detector created AFTER the index exists: {detector_name}")
        print("=" * 78)
        rules_resp = os_client.post(
            "/_plugins/_security_analytics/rules/_search",
            params={"pre_packaged": "true"},
            json={"size": 10000, "query": {"nested": {"path": "rule", "query": {"match": {"rule.category": "network"}}}}},
        )
        rules_resp.raise_for_status()
        rule_ids = [hit["_id"] for hit in rules_resp.json().get("hits", {}).get("hits", [])]
        check("real prepackaged 'network' rules fetched, including our known-good target rule",
              TARGET_RULE_ID in rule_ids, f"count={len(rule_ids)} target_present={TARGET_RULE_ID in rule_ids}")

        stream_index_pattern = f"kronos-{org_alias.lower()}-stream-{source_id}-*"
        detector_body = {
            "name": detector_name,
            "detector_type": "network",
            "enabled": True,
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
            "inputs": [
                {
                    "detector_input": {
                        "description": "D6 L3 chain PoC -- scoped to this run's own fresh stream index",
                        "indices": [stream_index_pattern],
                        "pre_packaged_rules": [{"id": rid} for rid in rule_ids],
                        "custom_rules": [],
                    }
                }
            ],
            "triggers": [],
        }
        detector_resp = os_client.post("/_plugins/_security_analytics/detectors", json=detector_body)
        check("real detector created (201), AFTER round-1 index already existed", detector_resp.status_code == 201, detector_resp.text[:300])
        detector_resp.raise_for_status()
        detector_id = detector_resp.json()["_id"]
        log(f"real detector created: {detector_name} id={detector_id} indices={stream_index_pattern}")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("8. ROUND 2 (strictly AFTER detector creation): real mTLS POST including the trigger event")
        print("=" * 78)
        public_source_ip = "203.0.113.77"  # TEST-NET-3 (RFC 5737) -- public/documentation range,
        # deliberately NOT matching any of the rule's private-prefix list (192.168./10./172.16-31./fd/2620:83:800f).
        round2_events = [benign_event(100), malicious_rdp_event(public_source_ip)]
        resp2 = client.post("/api/collector/ingest", json={"events": round2_events})
        check("round 2: real mTLS collector ingest accepted (202)", resp2.status_code == 202, f"status={resp2.status_code}")
        resp2.raise_for_status()
        outcomes2 = resp2.json()["results"]
        check("round 2: both real events accepted, none flagged duplicate", all(o["accepted"] and not o["duplicate"] for o in outcomes2))

        entries_after_r2 = await redis.xrange(stream_key)
        new_entries = entries_after_r2[3:]
        check("round 2's 2 events landed on the same real cert-derived Redis stream key",
              len(new_entries) == 2, f"total={len(entries_after_r2)}")

        client.close()
        listener_proc.terminate()
        try:
            listener_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            listener_proc.kill()
        listener_stdout = listener_proc.stdout.read() if listener_proc.stdout else ""
        listener_proc = None

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("9. Real BatchSealingService.seal_pending() -- batch #2 (the trigger event)")
        print("=" * 78)
        sealing_service_2 = BatchSealingService(
            stream_adapter, storage, tsa_service, audit_log, sealed_batch_repo,
            SizeBoundTriggerPolicy(max_events=2), consumer_name="d6-poc-sealer",
        )
        sealed2 = await sealing_service_2.seal_pending(org_id, source_id)
        check("real batch #2 sealed (contains the RDP-shaped trigger event)", sealed2 is not None)
        assert sealed2 is not None
        log(f"sealed batch #2: batch_id={sealed2.batch_id} event_count={sealed2.event_count}")

        result2 = await normalization_service.normalize_batch(org_id, sealed2.batch_id, org_alias=org_alias)
        check("real normalize_batch() indexed both round-2 events, 0 dead-lettered",
              result2.indexed_count == 2 and result2.dead_lettered_count == 0,
              f"indexed={result2.indexed_count} dead_lettered={result2.dead_lettered_count}")

        await asyncio.sleep(1.5)
        search2 = os_client.post(f"/{index_name}/_search", json={"query": {"term": {"kronos.batch_id": str(sealed2.batch_id)}}, "size": 10})
        hits2 = search2.json().get("hits", {}).get("hits", [])
        check("real OpenSearch index now also has the 2 round-2 documents (5 total across both batches)", len(hits2) == 2, f"count={len(hits2)}")
        trigger_doc = next((h for h in hits2 if h["_source"].get("source", {}).get("ip") == public_source_ip), None)
        check("the real indexed trigger document's source.ip alias-resolves correctly (public IP, not private)",
              trigger_doc is not None, f"hits2 sources.ip={[h['_source'].get('source', {}).get('ip') for h in hits2]}")
        trigger_doc_id = trigger_doc["_id"] if trigger_doc else None

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("10. Wait for the real SA monitor's own scheduled execution to actually fire")
        print("=" * 78)
        deadline = time.time() + 600
        findings_hits: list[dict] = []
        while time.time() < deadline:
            fr = os_client.post(
                "/.opensearch-sap-*-findings-*/_search",
                json={"size": 50, "query": {"term": {"monitor_name": detector_name}}},
            )
            if fr.status_code == 200:
                findings_hits = fr.json().get("hits", {}).get("hits", [])
            total = len(findings_hits)
            log(f"findings poll (monitor={detector_name}): total={total} (elapsed={int(time.time() - (deadline - 600))}s)")
            if total > 0:
                break
            time.sleep(20)
        check("at least one real SA finding produced for this run's own fresh detector", len(findings_hits) > 0, f"total={len(findings_hits)}")

        if findings_hits:
            for f in findings_hits[:5]:
                src = f["_source"]
                log(f"  real finding {f['_id']}: monitor={src.get('monitor_name')} related_doc_ids={src.get('related_doc_ids')} "
                    f"queries={[q.get('tags') for q in src.get('queries', [])]}")
            check("at least one real finding carries our real target rule's ATT&CK tag",
                  any(TARGET_RULE_TAG in q.get("tags", []) for f in findings_hits for q in f["_source"].get("queries", [])),
                  str([q.get("tags") for f in findings_hits for q in f["_source"].get("queries", [])]))

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("11. Real DetectionSyncService.sync_org_findings() -- unmodified src/ code (C4)")
        print("=" * 78)
        detection_repo = PostgresDetectionRepository(engine)
        findings_client = SecurityAnalyticsFindingsClient(OS_URL, "admin", "admin")
        sync_service = DetectionSyncService(findings_client, detection_repo, audit_log)

        tenant = TenantContext(
            org_id=org_id, org_alias=org_alias, user_id=uuid.uuid4(), username="d6-poc-user",
            roles=frozenset({Role.ANALYST}), correlation_id=str(uuid.uuid4()),
        )
        created = await sync_service.sync_org_findings(tenant)
        check("real sync_org_findings() created at least one new Detection row", created > 0, f"created={created}")

        all_detections = [d async for d in detection_repo.stream_by_org(org_id)]
        check("at least one real Detection row exists for this run's own org_id", len(all_detections) > 0, f"count={len(all_detections)}")
        check("every real Detection row's org_id == the syncing tenant's real org_id (computed, never read from the finding)",
              all(d.org_id == org_id for d in all_detections))
        check("every real Detection row's case_id is None (stream-sourced, correctly un-triaged -- honest, not fabricated)",
              all(d.case_id is None for d in all_detections))
        all_tags = sorted({tag for d in all_detections for tag in d.attack_tags})
        check("at least one real Detection row carries the real ATT&CK tag", TARGET_RULE_TAG in all_tags, str(all_tags))

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("12. Honest provenance-linkage check: Detection -> matched_document_ids -> real OpenSearch doc -> kronos.batch_id/event_offset")
        print("=" * 78)
        # Detection has NO first-class stream-provenance field of its own
        # (case_id is the only correlation field, and it's None here by
        # design -- a stream event has no case at ingest time). The
        # honest way "linked back to this event's provenance" holds is via
        # matched_document_ids (populated straight from the real finding's
        # own related_doc_ids) pointing at the exact same deterministic
        # OpenSearch _id StreamNormalizationService assigned
        # (sha1(f"{batch_id}:{event_offset}")) -- verified here by actually
        # fetching that document back and reading its own kronos.* fields,
        # not assumed from the Detection row alone.
        linked_detection = next((d for d in all_detections if trigger_doc_id in d.matched_document_ids), None)
        check("a real Detection row's matched_document_ids includes the real trigger document's own _id",
              linked_detection is not None, f"trigger_doc_id={trigger_doc_id}")
        if linked_detection is not None:
            doc_get = os_client.get(f"/{index_name}/_doc/{trigger_doc_id}")
            check("real GET of that exact document succeeds", doc_get.status_code == 200)
            doc_kronos = doc_get.json().get("_source", {}).get("kronos", {})
            check("the linked document's real kronos.batch_id matches our real sealed batch #2",
                  doc_kronos.get("batch_id") == str(sealed2.batch_id), f"doc kronos.batch_id={doc_kronos.get('batch_id')}")
            check("the linked document's real kronos.source_id matches our real source_id",
                  doc_kronos.get("source_id") == source_id, f"doc kronos.source_id={doc_kronos.get('source_id')}")
            check("the linked document's real kronos.event_offset is a valid int (>=0) within batch #2",
                  isinstance(doc_kronos.get("event_offset"), int) and doc_kronos.get("event_offset") >= 0,
                  f"event_offset={doc_kronos.get('event_offset')}")
            log(f"  Honest linkage: Detection {linked_detection.detection_id} -> finding {linked_detection.finding_id} "
                f"-> OpenSearch doc {trigger_doc_id} -> StreamProvenance(batch_id={doc_kronos.get('batch_id')}, "
                f"source_id={doc_kronos.get('source_id')}, event_offset={doc_kronos.get('event_offset')})")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("13. Idempotent re-run (same precedent as C4/C5)")
        print("=" * 78)
        created_again = await sync_service.sync_org_findings(tenant)
        check("re-running sync creates zero new rows for the same real findings (idempotency)", created_again == 0, f"created={created_again}")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("Cleanup: remove the throwaway detector (not part of any committed src/ path)")
        print("=" * 78)
        os_client.delete(f"/_plugins/_security_analytics/detectors/{detector_id}")
        log("NOTE: real Redis stream entries, real sealed batches (Postgres+MinIO+TSA), real OpenSearch "
            "documents, real findings, and real Detection/audit_log rows this run created are deliberately "
            "left in place as inspectable proof, matching C4/C5's own precedent.")

        await engine.dispose()
        await opensearch._client.close()
        await redis.aclose()

        print(f"\n{sum(1 for _, ok in CHECKS if ok)} passed, {sum(1 for _, ok in CHECKS if not ok)} failed")
        failed = [label for label, ok in CHECKS if not ok]
        if failed:
            print("FAILURES:")
            for label in failed:
                print(f"  - {label}")
            if listener_stdout:
                print("\n--- listener process stdout/stderr (last 4000 chars) ---")
                print(listener_stdout[-4000:])
            return 1
        return 0

    finally:
        if listener_proc is not None:
            listener_proc.terminate()
            try:
                listener_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                listener_proc.kill()
        if tsa_server is not None:
            tsa_server.shutdown()
            tsa_server.server_close()
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
